//! Diagnostic only: the sole remote operations here are AFC stat/open/read/close.
//! No injection, symlink, move, Books modification, or fallback escape.

use super::{connect_tunnel, ALLogCallback, AppDeviceTunnel, Logger};
use idevice::afc::{opcode::AfcFopenMode, AfcClient};
use idevice::IdeviceError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ffi::{c_char, c_void};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const TARGET: &str = "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist";
const MAX_BYTES: usize = 16 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(20);
type StatusCodes = Arc<Mutex<Vec<u64>>>;

fn take_codes(codes: &StatusCodes) -> Vec<u64> {
    std::mem::take(&mut *codes.lock().expect("probe status lock poisoned"))
}

fn error_kind(code: Option<u64>) -> &'static str {
    match code {
        Some(8) => "afc_object_not_found",
        Some(10) => "afc_permission_denied",
        Some(_) => "afc_error",
        None => "transport_or_protocol_error",
    }
}

fn failure(status: &str, detail: String, codes: Vec<u64>) -> Value {
    let code = codes.iter().rev().find(|&&c| c != 0).copied();
    json!({
        "status": status, "errorKind": error_kind(code),
        "rawAfcCode": code, "rawAfcStatusCodes": codes, "detail": detail,
        "interpretation": if code == Some(8) {
            "Path not visible in current AFC namespace"
        } else { "No conclusion about access outside the current AFC namespace" }
    })
}

fn connection_unusable(report: &Value) -> bool {
    ["stat", "open", "read", "close"].iter().any(|stage| {
        report[*stage]["errorKind"] == "transport_or_protocol_error"
            || report[*stage]["status"] == "close_failed"
    })
}

fn outcome(
    status: &str,
    result: Result<Result<(), IdeviceError>, tokio::time::error::Elapsed>,
    codes: &StatusCodes,
) -> Value {
    let raw = take_codes(codes);
    match result {
        Ok(Ok(())) => json!({"status": status, "rawAfcStatusCodes": raw}),
        Ok(Err(e)) => failure("close_failed", format!("{e:?}"), raw),
        Err(_) => failure("close_failed", "timeout".into(), raw),
    }
}

/// Returns content separately from the report so logs never contain file bytes.
async fn inspect(
    afc: &mut AfcClient,
    path: &str,
    codes: &StatusCodes,
    logger: &Logger,
) -> (Value, Option<Vec<u8>>) {
    let mut report = json!({"path": path, "stat": {"status": "not_attempted"},
        "open": {"status": "not_attempted"}, "read": {"status": "not_attempted"},
        "close": {"status": "not_attempted"}});
    take_codes(codes);
    let stat = match tokio::time::timeout(IO_TIMEOUT, afc.get_file_info(path)).await {
        Ok(Ok(info)) => {
            report["stat"] = json!({"status": "stat_success", "rawAfcStatusCodes": take_codes(codes),
                "size": info.size, "fileType": info.st_ifmt, "linkTarget": info.st_link_target});
            info
        }
        result => {
            let detail = match result {
                Ok(Err(e)) => format!("{e:?}"),
                _ => "timeout".into(),
            };
            let raw = take_codes(codes);
            let status = error_kind(raw.iter().rev().find(|&&c| c != 0).copied());
            report["stat"] = failure(status, detail, raw);
            logger.log(format!("mobilegestalt_probe: {report}"));
            return (report, None);
        }
    };
    logger.log(format!(
        "mobilegestalt_probe: stat {path}: {}",
        report["stat"]
    ));
    // Never follow a reported leaf symlink or allocate unbounded file content.
    if stat.st_ifmt != "S_IFREG" || stat.st_link_target.is_some() || stat.size > MAX_BYTES {
        report["read"] = json!({"status": "read_not_attempted", "detail": "Not a regular file, leaf symlink, or exceeds 16 MiB limit"});
        return (report, None);
    }
    take_codes(codes);
    let mut fd = match tokio::time::timeout(IO_TIMEOUT, afc.open(path, AfcFopenMode::RdOnly)).await
    {
        Ok(Ok(fd)) => {
            report["open"] =
                json!({"status": "readonly_open_success", "rawAfcStatusCodes": take_codes(codes)});
            fd
        }
        result => {
            let detail = match result {
                Ok(Err(e)) => format!("{e:?}"),
                _ => "timeout".into(),
            };
            report["open"] = failure("readonly_open_failed", detail, take_codes(codes));
            logger.log(format!("mobilegestalt_probe: {report}"));
            return (report, None);
        }
    };
    logger.log(format!(
        "mobilegestalt_probe: open {path}: {}",
        report["open"]
    ));
    let result = tokio::time::timeout(IO_TIMEOUT, fd.read_entire()).await;
    let raw = take_codes(codes);
    let bytes = match result {
        Ok(Ok(bytes)) if bytes.len() == stat.size => {
            report["read"] = json!({"status": "read_success", "size": bytes.len(),
                "sha256": hex::encode(Sha256::digest(&bytes)), "rawAfcStatusCodes": raw});
            Some(bytes)
        }
        Ok(Ok(bytes)) => {
            report["read"] = failure(
                "read_failed",
                format!(
                    "Size changed or incomplete read: stat={}, read={}",
                    stat.size,
                    bytes.len()
                ),
                raw,
            );
            report["read"]["errorKind"] = json!("read_size_mismatch");
            None
        }
        Ok(Err(e)) => {
            report["read"] = failure("read_failed", format!("{e:?}"), raw);
            None
        }
        Err(_) => {
            report["read"] = failure(
                "read_failed",
                "timeout; AFC stream will not be reused".into(),
                raw,
            );
            None
        }
    };
    // On timeout, cancellation may leave the protocol mid-packet. Drop the
    // connection rather than issue another request on that stream.
    if report["read"]["errorKind"] == "transport_or_protocol_error" {
        report["close"] =
            json!({"status": "connection_discarded_after_transport_or_protocol_error"});
        drop(fd);
    } else {
        let close = tokio::time::timeout(IO_TIMEOUT, fd.close()).await;
        report["close"] = outcome("close_success", close, codes);
    }
    logger.log(format!("mobilegestalt_probe: {report}"));
    (report, bytes)
}

async fn probe(pairing_path: String, logger: &Logger) -> Value {
    let mut report = json!({"schemaVersion": 1, "targetPath": TARGET,
        "namespace": "Current AFC service namespace; absolute path does not prove system-root visibility",
        "transport": {"status": "not_attempted"}, "media": {"status": "not_attempted", "attempts": []},
        "target": {"stat": {"status": "not_attempted"}, "open": {"status": "not_attempted"}, "read": {"status": "not_attempted"}}});
    let pairing = match std::fs::read(pairing_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            report["transport"] = json!({"status": "transport_error", "stage": "pairing_file", "detail": e.to_string()});
            return report;
        }
    };
    let mut tunnel =
        match tokio::time::timeout(Duration::from_secs(90), connect_tunnel(&pairing, logger)).await
        {
            Ok(Ok(tunnel)) => tunnel,
            result => {
                let detail = match result {
                    Ok(Err(e)) => e,
                    _ => "tunnel timeout".into(),
                };
                report["transport"] =
                    json!({"status": "transport_error", "stage": "tunnel", "detail": detail});
                return report;
            }
        };
    report["route"] = json!(match &tunnel {
        AppDeviceTunnel::Rsd { .. } => "RSD: com.apple.afc.shim.remote",
        AppDeviceTunnel::Lockdown { .. } => "Lockdown: com.apple.afc",
    });
    let mut afc = match tokio::time::timeout(IO_TIMEOUT, tunnel.connect_afc(logger)).await {
        Ok(Ok(afc)) => afc,
        result => {
            let detail = match result {
                Ok(Err(e)) => e,
                _ => "AFC connect timeout".into(),
            };
            report["transport"] =
                json!({"status": "transport_error", "stage": "afc_connect", "detail": detail});
            return report;
        }
    };
    report["transport"] = json!({"status": "transport_success"});
    let codes: StatusCodes = Arc::new(Mutex::new(Vec::new()));
    afc.observe_status_codes(codes.clone());
    // Existing small Media files only. Missing candidates are reported, never created.
    let mut attempts = Vec::new();
    let mut media_ok = false;
    for path in [
        "Books/Sync/Books.plist",
        "iTunes_Control/iTunes/iTunesPrefs",
        "iTunes_Control/iTunes/IC-Info.sidb",
    ] {
        let (attempt, bytes) = inspect(&mut afc, path, &codes, logger).await;
        media_ok = bytes.is_some();
        let failed = connection_unusable(&attempt);
        attempts.push(attempt);
        if failed {
            report["media"] = json!({"status": "media_control_failed", "attempts": attempts});
            report["transport"] = json!({"status": "transport_error", "stage": "media_control", "detail": "Connection discarded after transport/protocol or close failure"});
            return report;
        }
        if media_ok {
            break;
        }
    }
    report["media"] = json!({"status": if media_ok { "media_control_success" } else { "media_control_failed" }, "attempts": attempts});
    // A failed Media control stays visible; target stat still provides evidence.
    let (target, bytes) = inspect(&mut afc, TARGET, &codes, logger).await;
    if connection_unusable(&target) {
        report["transport"] = json!({"status": "transport_error", "stage": "target_connection", "detail": "Initial AFC connection succeeded; later transport/protocol or close failure (see target stages)"});
    }
    report["target"] = target;
    if let Some(bytes) = bytes {
        report["bytesHex"] = json!(hex::encode(bytes));
    }
    report
}

/// # Safety
/// Pairing path is a valid C string; callback/context remain valid until return.
pub unsafe fn run(
    pairing_path: *const c_char,
    cb: ALLogCallback,
    ctx: *mut c_void,
) -> Result<String, String> {
    let pairing_path = crate::ffi_util::opt_str(pairing_path, "");
    let context = ctx as usize;
    crate::ffi_util::run_with_large_stack("mobilegestalt_probe", move || {
        let logger = Logger {
            cb,
            ctx: context as *mut c_void,
        };
        let report = idevice_ffi::run_sync_local(probe(pairing_path, &logger));
        serde_json::to_string(&report).map_err(|e| e.to_string())
    })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use idevice::afc::{
        opcode::AfcOpcode,
        packet::{AfcPacket, AfcPacketHeader},
        MAGIC,
    };

    fn response(op: AfcOpcode, header_payload: Vec<u8>, payload: Vec<u8>) -> AfcPacket {
        let header_len = AfcPacketHeader::LEN + header_payload.len() as u64;
        AfcPacket {
            header: AfcPacketHeader {
                magic: MAGIC,
                entire_len: header_len + payload.len() as u64,
                header_payload_len: header_len,
                packet_num: 0,
                operation: op,
            },
            header_payload,
            payload,
        }
    }

    fn stat_response(size: usize) -> AfcPacket {
        let size = size.to_string();
        let text = [
            "st_size",
            &size,
            "st_blocks",
            "1",
            "st_birthtime",
            "0",
            "st_mtime",
            "0",
            "st_nlink",
            "1",
            "st_ifmt",
            "S_IFREG",
            "",
        ]
        .join("\0");
        response(AfcOpcode::Data, vec![], text.into_bytes())
    }

    async fn fixture(replies: Vec<(AfcOpcode, AfcPacket)>) -> (Value, Option<Vec<u8>>) {
        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut device = idevice::Idevice::new(Box::new(server), "probe-fixture");
            for (expected, reply) in replies {
                let request = AfcPacket::read(&mut device).await.unwrap();
                assert_eq!(request.header.operation, expected);
                if expected == AfcOpcode::FileOpen {
                    let mode = u64::from_le_bytes(request.header_payload[..8].try_into().unwrap());
                    assert_eq!(mode, AfcFopenMode::RdOnly as u64);
                }
                if expected == AfcOpcode::GetFileInfo {
                    assert_eq!(request.header_payload, TARGET.as_bytes());
                }
                device.send_raw(&reply.serialize()).await.unwrap();
            }
        });
        let mut afc = AfcClient::new(idevice::Idevice::new(Box::new(client), "probe-fixture"));
        let codes = Arc::new(Mutex::new(vec![]));
        afc.observe_status_codes(codes.clone());
        let logger = Logger {
            cb: None,
            ctx: std::ptr::null_mut(),
        };
        let result = inspect(&mut afc, TARGET, &codes, &logger).await;
        server_task.await.unwrap();
        result
    }

    #[tokio::test]
    async fn stat_failure_never_opens_and_keeps_wire_code() {
        for code in [8_u64, 10, 9876] {
            let (report, bytes) = fixture(vec![(
                AfcOpcode::GetFileInfo,
                response(AfcOpcode::Status, code.to_le_bytes().to_vec(), vec![]),
            )])
            .await;
            assert_eq!(report["stat"]["rawAfcCode"], code);
            assert_eq!(report["open"]["status"], "not_attempted");
            assert!(bytes.is_none());
        }
    }

    #[tokio::test]
    async fn readonly_open_denied_never_reads() {
        let (report, bytes) = fixture(vec![
            (AfcOpcode::GetFileInfo, stat_response(3)),
            (
                AfcOpcode::FileOpen,
                response(AfcOpcode::Status, 10_u64.to_le_bytes().to_vec(), vec![]),
            ),
        ])
        .await;
        assert_eq!(report["stat"]["status"], "stat_success");
        assert_eq!(report["open"]["status"], "readonly_open_failed");
        assert_eq!(report["open"]["rawAfcCode"], 10);
        assert_eq!(report["read"]["status"], "not_attempted");
        assert!(bytes.is_none());
    }

    #[tokio::test]
    async fn complete_read_uses_only_stat_readonly_open_tell_read_close() {
        let original = vec![0, 255, 128];
        let (report, bytes) = fixture(vec![
            (AfcOpcode::GetFileInfo, stat_response(3)),
            (
                AfcOpcode::FileOpen,
                response(AfcOpcode::FileOpenRes, 1_u64.to_le_bytes().to_vec(), vec![]),
            ),
            (
                AfcOpcode::FileTell,
                response(AfcOpcode::FileTellRes, 0_u64.to_le_bytes().to_vec(), vec![]),
            ),
            (AfcOpcode::GetFileInfo, stat_response(3)),
            (
                AfcOpcode::Read,
                response(AfcOpcode::Data, vec![], original.clone()),
            ),
            (
                AfcOpcode::FileClose,
                response(AfcOpcode::Status, 0_u64.to_le_bytes().to_vec(), vec![]),
            ),
        ])
        .await;
        assert_eq!(report["open"]["status"], "readonly_open_success");
        assert_eq!(report["read"]["status"], "read_success");
        assert_eq!(report["read"]["size"], 3);
        assert_eq!(report["close"]["status"], "close_success");
        assert_eq!(bytes, Some(original));
        assert!(!report.to_string().contains("bytesHex"));
    }

    #[tokio::test]
    async fn read_error_returns_no_content_and_closes_readonly_handle() {
        let (report, bytes) = fixture(vec![
            (AfcOpcode::GetFileInfo, stat_response(3)),
            (
                AfcOpcode::FileOpen,
                response(AfcOpcode::FileOpenRes, 1_u64.to_le_bytes().to_vec(), vec![]),
            ),
            (
                AfcOpcode::FileTell,
                response(AfcOpcode::FileTellRes, 0_u64.to_le_bytes().to_vec(), vec![]),
            ),
            (AfcOpcode::GetFileInfo, stat_response(3)),
            (
                AfcOpcode::Read,
                response(AfcOpcode::Status, 4_u64.to_le_bytes().to_vec(), vec![]),
            ),
            (
                AfcOpcode::FileClose,
                response(AfcOpcode::Status, 0_u64.to_le_bytes().to_vec(), vec![]),
            ),
        ])
        .await;
        assert_eq!(report["open"]["status"], "readonly_open_success");
        assert_eq!(report["read"]["status"], "read_failed");
        assert_eq!(report["read"]["rawAfcCode"], 4);
        assert_eq!(report["close"]["status"], "close_success");
        assert!(bytes.is_none());
    }

    #[test]
    fn namespace_errors_preserve_raw_unknown_codes() {
        let missing = failure(
            "afc_object_not_found",
            "Afc(ObjectNotFound)".into(),
            vec![8],
        );
        assert_eq!(
            missing["interpretation"],
            "Path not visible in current AFC namespace"
        );
        assert_eq!(missing["rawAfcCode"], 8);
        let denied = failure("readonly_open_failed", "Afc(PermDenied)".into(), vec![10]);
        assert_eq!(denied["status"], "readonly_open_failed");
        assert_eq!(denied["errorKind"], "afc_permission_denied");
        let unknown = failure("read_failed", "Afc(UnknownError)".into(), vec![9876]);
        assert_eq!(unknown["rawAfcCode"], 9876);
    }
}
