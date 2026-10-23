import Foundation
import CryptoKit
import Darwin

struct WalletPayload: Codable, Equatable {
    let path: String
    let size: Int
    let sha256: String
}

enum DestinationVerificationStatus: String, Codable {
    case verified = "destination_verified"
    case effectObserved = "destination_effect_observed"
    case unverifiable = "destination_unverifiable"
    case failed = "destination_verification_failed"

    var label: String {
        switch self {
        case .verified: return "VERIFIED"
        case .effectObserved: return "EFFECT OBSERVED"
        case .unverifiable: return "UNVERIFIED"
        case .failed: return "FAILED"
        }
    }
}

struct WalletVerificationResult: Codable {
    let operationId: String
    let checkedAt: Date
    let status: DestinationVerificationStatus
    let source: String
    let detail: String
    let files: [FileCheck]

    struct FileCheck: Codable {
        let path: String
        let status: DestinationVerificationStatus
        let size: Int?
        let sha256: String?
        let rawErrno: Int32?
        let detail: String
    }
}

/// Independent normal-sandbox read. No AFC, token, service, file write or move.
enum WalletDestinationVerifier {
    static let root = "/var/mobile/Library/Passes/Cards/"
    static let imageNames: Set<String> = [
        "cardBackgroundCombined@3x.png", "cardBackgroundCombined@2x.png",
        "diffuse@3x.png", "diffuse@2x.png", "background@3x.png", "background@2x.png",
        "strip@3x.png", "strip@2x.png", "cardBackgroundCombined.pdf", "background.pdf", "strip.pdf"
    ]

    static func accepts(destination: String, payloads: [WalletPayload]) -> Bool {
        guard destination.hasPrefix(root), !payloads.isEmpty, payloads.count <= 128,
              Set(payloads.map(\.path)).count == payloads.count else { return false }
        let component = String(destination.dropFirst(root.count))
        guard !component.contains("/"), let suffix = [".pkpass", ".cache", ".pkcache"].first(where: component.hasSuffix) else { return false }
        let identifier = String(component.dropLast(suffix.count))
        let alphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+=-")
        guard (20...64).contains(identifier.count), identifier.allSatisfy({ alphabet.contains($0) }) else { return false }
        let names = suffix == ".pkpass" ? imageNames : Set(["FrontFace", "Preview", "PlaceHolder"])
        return payloads.allSatisfy { payload in
            let name = String(payload.path.dropFirst(destination.count + 1))
            return payload.path == destination + "/" + name && names.contains(name) &&
                (0...32 * 1024 * 1024).contains(payload.size) && payload.sha256.count == 64 &&
                payload.sha256.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
        } && payloads.reduce(0, { $0 + $1.size }) <= 128 * 1024 * 1024
    }

    static func verify(operationId: String, destination: String, payloads: [WalletPayload]) -> WalletVerificationResult {
        guard accepts(destination: destination, payloads: payloads) else {
            return WalletVerificationResult(operationId: operationId, checkedAt: Date(), status: .unverifiable,
                source: "normal_app_filesystem_read", detail: "Missing/invalid expected-byte manifest or unsupported Wallet asset; no file opened.", files: [])
        }
        var files: [WalletVerificationResult.FileCheck] = []
        for payload in payloads {
            let check = read(payload)
            files.append(check)
            if check.status != .verified { break }
        }
        let status: DestinationVerificationStatus = files.contains { $0.status == .failed } ? .failed :
            (files.count == payloads.count && files.allSatisfy { $0.status == .verified } ? .verified : .unverifiable)
        return WalletVerificationResult(operationId: operationId, checkedAt: Date(), status: status,
            source: "normal_app_filesystem_read",
            detail: "Independent read-only snapshot at the stated time. VERIFIED requires exact opened path, stable file identity, size and SHA-256 for every payload. It does not prove Wallet rendered that artwork. No permission or namespace fallback is attempted.", files: files)
    }

    private static func read(_ payload: WalletPayload) -> WalletVerificationResult.FileCheck {
        func result(_ status: DestinationVerificationStatus, _ detail: String, code: Int32? = nil,
                    size: Int? = nil, hash: String? = nil) -> WalletVerificationResult.FileCheck {
            .init(path: payload.path, status: status, size: size, sha256: hash, rawErrno: code, detail: detail)
        }
        let fd = Darwin.open(payload.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else {
            let code = errno
            return result(.unverifiable, "Normal app filesystem open refused/failed; no additional permission requested.", code: code)
        }
        defer { Darwin.close(fd) }
        var openedPath = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let pathRC = openedPath.withUnsafeMutableBytes { Darwin.fcntl(fd, F_GETPATH, $0.baseAddress!) }
        guard pathRC == 0 else { return result(.unverifiable, "Cannot independently identify opened path.", code: errno) }
        let actualPath = String(cString: openedPath)
        guard actualPath == payload.path || actualPath == "/private" + payload.path else {
            return result(.unverifiable, "Opened file does not identify the exact expected Wallet path.")
        }
        var before = stat()
        guard fstat(fd, &before) == 0 else { return result(.unverifiable, "fstat failed.", code: errno) }
        guard (before.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG), before.st_size >= 0,
              before.st_size <= 32 * 1024 * 1024 else { return result(.unverifiable, "Not a bounded regular file.") }
        var hasher = SHA256()
        var size = 0
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
            if count < 0 {
                let code = errno
                if code == EINTR { continue }
                return result(.unverifiable, "Read failed.", code: code)
            }
            if count == 0 { break }
            size += count
            guard size <= 32 * 1024 * 1024 else { return result(.unverifiable, "File grew beyond read limit.") }
            hasher.update(data: Data(buffer.prefix(count)))
        }
        var after = stat()
        var current = stat()
        guard fstat(fd, &after) == 0, lstat(payload.path, &current) == 0 else {
            return result(.unverifiable, "Cannot confirm final file identity.", code: errno)
        }
        guard before.st_ino == after.st_ino, before.st_dev == after.st_dev,
              after.st_ino == current.st_ino, after.st_dev == current.st_dev,
              before.st_size == after.st_size, after.st_size == current.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
              after.st_mtimespec.tv_sec == current.st_mtimespec.tv_sec,
              after.st_mtimespec.tv_nsec == current.st_mtimespec.tv_nsec,
              after.st_ctimespec.tv_sec == current.st_ctimespec.tv_sec,
              after.st_ctimespec.tv_nsec == current.st_ctimespec.tv_nsec,
              after.st_size == off_t(size) else { return result(.unverifiable, "File changed or was replaced while being read.") }
        let hash = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        let matches = size == payload.size && hash == payload.sha256
        return result(matches ? .verified : .failed,
            matches ? "Stable independent read matches expected payload bytes." : "Independent read differs from expected payload size/SHA-256.", size: size, hash: hash)
    }
}

struct AirTrafficOperationSummary: Identifiable {
    let id: String
    let parentId: String?
    let category: String
    let destination: String
    let payloadCount: Int?
    let payloads: [WalletPayload]
    let streamingZIP: String
    let atc: String
    let fileCompleteCount: Int
    let cleanup: String
    let returned: String
    let protocolCompleted: Bool
    let protocolFailed: Bool
    let historyComplete: Bool
    let attemptIds: [String]
    let verification: WalletVerificationResult?

    var finalStatus: DestinationVerificationStatus { verification?.status ?? .unverifiable }

    // Decode the response already logged by the writer, without another device
    // request. DataComplete acknowledges staging, never final destination bytes.
    static func zipStatus(_ events: [AirTrafficDiagnosticEvent]) -> String {
        guard let hex = events.last(where: { $0.step == "staging_response" })?.evidence?.rawResponseHex,
              hex.count <= 131072, hex.count % 2 == 0 else { return "UNKNOWN / NOT OBSERVED" }
        var data = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let end = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<end], radix: 16) else { return "INVALID RESPONSE HEX" }
            data.append(byte)
            index = end
        }
        guard let dict = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any],
              let status = dict["Status"] as? String else { return "RESPONSE RECEIVED / STATUS UNKNOWN" }
        return status == "DataComplete" ? "DataComplete (staging only)" : "OTHER STATUS: \(status)"
    }
    var text: String {
        """
        Operation: \(id)
        Destination: \(destination)
        Payloads: \(payloadCount.map(String.init) ?? "unknown")
        Streaming ZIP: \(streamingZIP)
        ATC result: \(atc)
        FileComplete sent: \(fileCompleteCount)
        Cleanup: \(cleanup)
        AirTraffic protocol: \(protocolCompleted ? "SUCCESS (protocol_completed)" : (protocolFailed ? "FAILED" : "INCOMPLETE / UNKNOWN"))
        Writer returned: \(returned)
        Final target verification: \(finalStatus.label) (\(finalStatus.rawValue))
        Attempts: \(attemptIds.joined(separator: ", "))
        History complete: \(historyComplete)
        """
    }

    static func build(events: [AirTrafficDiagnosticEvent], discarded: Bool,
                      verifications: [String: WalletVerificationResult]) -> [Self] {
        var order: [String] = []
        var groups: [String: [AirTrafficDiagnosticEvent]] = [:]
        for event in events {
            if groups[event.operationId] == nil { order.append(event.operationId) }
            groups[event.operationId, default: []].append(event)
        }
        return order.compactMap { id in
            guard let own = groups[id], let first = own.first else { return nil }
            var ids: Set<String> = [id]
            var changed = true
            while changed {
                changed = false
                for key in order where !ids.contains(key) {
                    if let event = groups[key]?.first, event.destination == first.destination,
                       let parent = event.parentId, ids.contains(parent) { ids.insert(key); changed = true }
                }
            }
            let all = events.filter { ids.contains($0.operationId) }
            let attempts = order.filter { ids.contains($0) && groups[$0]?.first?.operation != "exploit_write_dir" }
            let complete = !discarded && ids.allSatisfy { key in
                groups[key]?.contains { $0.step == "operation" && $0.status == "started" } == true
            }
            func count(_ list: [AirTrafficDiagnosticEvent]) -> Int? {
                for event in list {
                    if let payloads = event.evidence?.payloads { return payloads.count }
                    if let files = event.evidence?.files { return files.count }
                    if let paths = event.evidence?.paths { return paths.count }
                    if event.step == "payload_destination" { return 1 }
                }
                return nil
            }
            func sent(_ list: [AirTrafficDiagnosticEvent]) -> Int {
                list.filter { $0.step == "atc_send" && $0.status == "stream_write_completed" && $0.evidence?.message == "FileComplete" }.count
            }
            func failed(_ list: [AirTrafficDiagnosticEvent]) -> Bool {
                list.contains { ($0.step == "atc_receive" && ($0.status == "error_message_received" || $0.evidence?.message == "SyncFailed")) || $0.status == "io_error" }
            }
            let protocolFailed = attempts.contains { failed(groups[$0] ?? []) }
            let protocolCompleted = complete && !attempts.isEmpty && attempts.allSatisfy { key in
                let list = groups[key] ?? []
                guard let payloadCount = count(list), payloadCount > 0 else { return false }
                let received = Set(list.filter { $0.step == "atc_receive" }.compactMap { $0.evidence?.message })
                let starts = list.filter { $0.step == "atc_send" && $0.status == "started" && $0.evidence?.message == "FileComplete" }.count
                let errorFields = list.contains { $0.step == "atc_receive" && !($0.evidence?.rawErrorFields ?? []).isEmpty }
                return !failed(list) && !errorFields && zipStatus(list) == "DataComplete (staging only)" &&
                    received.contains("ReadyForSync") && received.contains("AssetManifest") &&
                    sent(list) == payloadCount + 1 && starts == sent(list)
            }
            let cleanupEvents = all.filter { $0.step == "media_cleanup" }
            let successes = cleanupEvents.filter { $0.status == "success" }.count
            let errors = cleanupEvents.filter { $0.status == "error" }.count
            let pending = max(0, cleanupEvents.filter { $0.status == "started" }.count - successes - errors)
            let cleanup = cleanupEvents.isEmpty ? "NOT OBSERVED" : "\(successes) success / \(errors) errors / \(pending) pending; no post-cleanup stat"
            let zipStates = attempts.map { key -> String in
                let list = groups[key] ?? []
                let response = list.contains { $0.step == "staging_response" && $0.status == "response_received_not_interpreted" }
                let stats = list.filter { $0.step == "staging_stat" && $0.status == "success" }.count
                let error = list.contains { $0.step == "staging_stat" && $0.status == "error" }
                return "\(zipStatus(list)); AFC staging stats: \(stats) success; \(response && stats >= 3 && !error ? "STAGING OBSERVED" : "INCOMPLETE / ERROR / NOT OBSERVED")"
            }
            let terminal = own.last { $0.step == "operation" && $0.status != "started" }
            let returned = terminal?.status == "returned_ok_unverified" ? "OK" : (terminal?.status == "returned_error" ? "ERROR" : "PENDING / UNKNOWN")
            let payloads = own.compactMap { $0.evidence?.payloads }.last ?? []
            return Self(id: id, parentId: first.parentId, category: first.category, destination: first.destination,
                payloadCount: count(own), payloads: payloads,
                streamingZIP: zipStates.isEmpty ? "NOT OBSERVED" : Array(Set(zipStates)).sorted().joined(separator: "; "),
                atc: protocolCompleted ? "ReadyForSync + AssetManifest + expected FileComplete sends; no destination acknowledgement" : (protocolFailed ? "ERROR OBSERVED" : "INCOMPLETE / UNKNOWN"),
                fileCompleteCount: sent(all), cleanup: cleanup, returned: returned, protocolCompleted: protocolCompleted,
                protocolFailed: protocolFailed, historyComplete: complete, attemptIds: attempts, verification: verifications[id])
        }
    }
}
