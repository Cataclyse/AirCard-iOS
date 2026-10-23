//! Passive instrumentation. No device connection, filesystem operation or writer.
use idevice::{afc::AfcClient, IdeviceError};
use serde_json::{json, Value};
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Instant,
};

#[derive(Clone)]
struct Context {
    id: String,
    parent: Option<String>,
    operation: String,
    category: String,
    destination: String,
    codes: Arc<Mutex<Vec<u64>>>,
    start: Instant,
}

tokio::task_local! { static CURRENT: Context; }
static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

// This selects which EXISTING calls to log, not which paths a writer can access.
fn category(path: &str) -> Option<&'static str> {
    if path.starts_with("/var/mobile/Library/Passes/Cards/") {
        Some("Wallet")
    } else if [
        "/var/mobile/Library/Caches/TelephonyUI-8",
        "/var/mobile/Library/Caches/TelephonyUI-9",
        "/var/mobile/Library/Caches/TelephonyUI-10",
    ]
    .contains(&path)
    {
        Some("TelephonyUI")
    } else if path == "/var/mobile/Library/Preferences"
        || (path.starts_with("/var/mobile/Containers/Data/Application/")
            && (path.contains("/Library/Application Support/PRBPosterExtensionDataStore/")
                || path.ends_with("/Library/Preferences")))
    {
        Some("PosterBoard")
    } else if path == "/var/mobile/Media" || path.starts_with("/var/mobile/Media/") {
        Some("Media")
    } else {
        None
    }
}

pub(super) fn record(step: &str, status: &str, extra: Value) {
    let _ = CURRENT.try_with(|context| {
        let event = json!({"schema": 1, "operationId": context.id, "parentId": context.parent,
            "operation": context.operation, "category": context.category,
            "destination": context.destination, "elapsedMs": context.start.elapsed().as_millis() as u64,
            "step": step, "status": status, "finalTargetVerified": false, "evidence": extra});
        tracing::info!("AIRTRAFFIC_DIAGNOSTIC {event}");
    });
}

pub(super) async fn operation<T>(
    name: &str,
    destination: &str,
    future: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let Some(category) = category(destination) else {
        return future.await;
    };
    let parent = CURRENT.try_with(Clone::clone).ok();
    let context = Context {
        id: format!(
            "atd-{}",
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ),
        parent: parent.as_ref().map(|p| p.id.clone()),
        operation: name.into(),
        category: category.into(),
        destination: destination.into(),
        codes: parent.map(|p| p.codes).unwrap_or_default(),
        start: Instant::now(),
    };
    CURRENT.scope(context, async {
        record("operation", "started", json!({"verification": "No final-target stat or readback is added"}));
        let result = future.await;
        match &result {
            Ok(_) => record("operation", "returned_ok_unverified", json!({"detail": "Function returned Ok; final destination content was not checked"})),
            Err(error) => record("operation", "returned_error", json!({"detail": error,
                "rawCode": null, "codeAvailability": "See preceding AFC/IO/ATC events; String result alone has no numeric code"})),
        }
        result
    }).await
}

pub(super) fn attach_afc(afc: &mut AfcClient) {
    let _ = CURRENT.try_with(|context| afc.observe_status_codes(context.codes.clone()));
}

pub(super) async fn transport<T>(
    service: &str,
    future: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    record("transport", "started", json!({"service": service}));
    let result = future.await;
    record(
        "transport",
        if result.is_ok() { "success" } else { "error" },
        json!({"service": service, "detail": result.as_ref().err(), "rawCode": null,
        "codeAvailability": "Existing transport API returns String; no numeric code inferred"}),
    );
    result
}

fn take_codes() -> Vec<u64> {
    CURRENT
        .try_with(|context| {
            context
                .codes
                .lock()
                .map(|mut c| std::mem::take(&mut *c))
                .unwrap_or_default()
        })
        .unwrap_or_default()
}

pub(super) async fn afc<T>(
    step: &str,
    path: &str,
    future: impl Future<Output = Result<T, IdeviceError>>,
) -> Result<T, IdeviceError> {
    take_codes();
    record(step, "started", json!({"service": "AFC", "path": path}));
    let result = future.await;
    let raw = take_codes();
    let error_code = raw.iter().rev().find(|&&code| code != 0).copied();
    record(
        step,
        if result.is_ok() { "success" } else { "error" },
        json!({
            "service": "AFC", "path": path, "rawStatusCodes": raw, "rawErrorCode": error_code,
            "detail": result.as_ref().err().map(|e| format!("{e:?}")),
            "interpretation": if error_code == Some(8) { "Path not visible in current AFC namespace" } else { "No final-target verification" },
            "codeAvailability": "Only codes actually received in AFC Status packets; null is not zero"
        }),
    );
    result
}

pub(super) fn io_error(step: &str, error: &std::io::Error) {
    record(
        step,
        "io_error",
        json!({"rawOsError": error.raw_os_error(), "kind": format!("{:?}", error.kind()), "detail": error.to_string()}),
    );
}

pub(super) fn staging(source: &str, destination: &str, archive_len: usize) {
    record(
        "archive",
        "built_locally",
        json!({"staging": format!("/var/mobile/Media/{source}"),
        "mediaSubdir": source, "existingDestination": destination, "archiveBytes": archive_len,
        "service": "com.apple.streaming_zip_conduit", "verified": false}),
    );
}

/// Hash the bytes already supplied to a writer. No filesystem/device operation.
pub(super) fn payload_manifest(destination: &str, files: &[(&str, &[u8])]) {
    use sha2::{Digest, Sha256};
    record(
        "payload_manifest",
        "expected_bytes_recorded",
        json!({
            "payloads": files.iter().map(|(name, bytes)| json!({
                "path": format!("{destination}/{name}"), "size": bytes.len(),
                "sha256": hex::encode(Sha256::digest(bytes))
            })).collect::<Vec<_>>()
        }),
    );
}

pub(super) fn atc_received(dict: &plist::Dictionary) {
    let mut errors = Vec::new();
    collect_errors(dict, "", &mut errors);
    let name = super::atc_message_name(dict);
    record(
        "atc_receive",
        if name.as_deref() == Some("SyncFailed") {
            "error_message_received"
        } else {
            "message_received"
        },
        json!({"service": "com.apple.atc",
        "message": name, "session": super::atc_session_number(dict),
        "rawErrorFields": errors, "detail": "Received message; not a final-target readback"}),
    );
}

fn collect_errors(dict: &plist::Dictionary, prefix: &str, output: &mut Vec<Value>) {
    for (key, value) in dict {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        if key.to_lowercase().contains("error") {
            output.push(json!({"field": path, "value": serde_json::to_value(value)
                .unwrap_or_else(|_| json!(format!("{value:?}")))}));
        } else if let Some(nested) = value.as_dictionary() {
            collect_errors(nested, &path, output);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_are_only_existing_ui_destinations() {
        assert_eq!(
            category("/var/mobile/Library/Caches/TelephonyUI-10"),
            Some("TelephonyUI")
        );
        assert_eq!(
            category("/var/mobile/Library/Passes/Cards/example.pkpass"),
            Some("Wallet")
        );
        assert_eq!(
            category("/var/mobile/Containers/Data/Application/UUID/Library/Preferences"),
            Some("PosterBoard")
        );
        assert_eq!(
            category("/var/mobile/Media/airlift-src-example"),
            Some("Media")
        );
        assert_eq!(category("/var/containers/Shared/SystemGroup/example"), None);
        assert_eq!(category("/var/mobile/Library/Caches/TelephonyUI-100"), None);
    }

    #[tokio::test]
    async fn instrumentation_preserves_failure_and_runs_future_once() {
        let calls = std::sync::atomic::AtomicU64::new(0);
        let result: Result<(), String> = operation(
            "fixture",
            "/var/mobile/Library/Caches/TelephonyUI-10",
            async {
                calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err("original failure".into())
            },
        )
        .await;
        assert_eq!(result, Err("original failure".into()));
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn nested_atc_error_codes_are_kept_without_dumping_host_tokens() {
        let mut params = plist::Dictionary::new();
        params.insert("ErrorCode".into(), plist::Value::Integer(123.into()));
        params.insert(
            "GrappaClientRequest".into(),
            plist::Value::Data(vec![1, 2, 3]),
        );
        let mut dict = plist::Dictionary::new();
        dict.insert("Parameters".into(), plist::Value::Dictionary(params));
        let mut errors = Vec::new();
        collect_errors(&dict, "", &mut errors);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0]["field"], "Parameters.ErrorCode");
        assert_eq!(errors[0]["value"], 123);
        assert!(!serde_json::to_string(&errors).unwrap().contains("Grappa"));
    }
}
