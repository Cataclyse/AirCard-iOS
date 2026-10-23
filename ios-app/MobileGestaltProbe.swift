import SwiftUI
import Foundation
import CryptoKit
import Darwin
import AirliftFFI

enum MobileGestaltProbe {
    static let expectedBuild = "24B5089g"
    static let expectedMachine = "iPhone17,3" // iPhone 16
    static let targetPath = "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"

    static func systemString(_ key: String) -> String {
        var length = 0
        guard sysctlbyname(key, nil, &length, nil, 0) == 0, length > 0 else { return "unknown" }
        var buffer = [CChar](repeating: 0, count: length)
        let result = buffer.withUnsafeMutableBufferPointer {
            sysctlbyname(key, $0.baseAddress, &length, nil, 0)
        }
        guard result == 0 else { return "unknown" }
        return String(cString: buffer)
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func decodeHex(_ hex: String) throws -> Data {
        let chars = Array(hex.utf8)
        guard chars.count.isMultiple(of: 2) else { throw ProbeError.invalidBytes }
        func nibble(_ c: UInt8) -> UInt8? {
            switch c {
            case 48...57: return c - 48
            case 97...102: return c - 87
            default: return nil
            }
        }
        var bytes = Data(capacity: chars.count / 2)
        for index in stride(from: 0, to: chars.count, by: 2) {
            guard let high = nibble(chars[index]), let low = nibble(chars[index + 1]) else {
                throw ProbeError.invalidBytes
            }
            bytes.append(high * 16 + low)
        }
        return bytes
    }

    enum ProbeError: LocalizedError {
        case invalidBytes, backupDiffers, verificationFailed, malformedReport
        var errorDescription: String? {
            switch self {
            case .invalidBytes: return "Read payload failed hex/size/SHA-256 verification."
            case .backupDiffers: return "Existing original backup differs; it was preserved."
            case .verificationFailed: return "Local backup bytes or SHA-256 differ."
            case .malformedReport: return "FFI returned a malformed or inconsistent diagnostic report."
            }
        }
    }

    // Called only with the app's Documents URL in production. Tests use an isolated
    // local directory. Never replaces an existing original with different bytes.
    static func saveBackup(_ bytes: Data, documents: URL) throws -> URL {
        let url = documents.appendingPathComponent("MobileGestalt-original-\(expectedBuild).plist")
        let fm = FileManager.default
        if fm.fileExists(atPath: url.path) {
            guard try Data(contentsOf: url) == bytes else { throw ProbeError.backupDiffers }
        } else {
            try bytes.write(to: url, options: .withoutOverwriting)
        }
        let recovered = try Data(contentsOf: url)
        guard recovered == bytes, sha256(recovered) == sha256(bytes) else {
            throw ProbeError.verificationFailed
        }
        return url
    }

    struct Stage: Decodable {
        let status: String
        var errorKind: String?
        var rawAfcCode: UInt64?
        var rawAfcStatusCodes: [UInt64]?
        var detail: String?
        var interpretation: String?
        var size: Int?
        var sha256: String?

        var display: String {
            var lines = [status]
            if let errorKind { lines.append(errorKind) }
            if let rawAfcCode { lines.append("Raw AFC error: \(rawAfcCode)") }
            if let rawAfcStatusCodes {
                lines.append("Raw AFC Status packets: \(rawAfcStatusCodes.map(String.init).joined(separator: ", "))\(rawAfcStatusCodes.isEmpty ? "none (no Status packet)" : "")")
            }
            if let interpretation { lines.append(interpretation) }
            if let detail { lines.append(detail) }
            return lines.joined(separator: "\n")
        }
    }

    struct FileResult: Decodable {
        var path: String?
        let stat: Stage
        let open: Stage
        let read: Stage
        var close: Stage?
    }

    struct Report: Decodable {
        let schemaVersion: Int
        let targetPath: String
        let transport: Stage
        let media: Media
        let target: FileResult
        let bytesHex: String?
        struct Media: Decodable {
            let status: String
            let attempts: [FileResult]
        }
    }

    struct Execution {
        var report: Report?
        var log: String
        var backupStatus = "not_attempted"
        var backupName: String?
    }

    static func sanitizedReport(_ data: Data) throws -> String {
        guard var object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ProbeError.malformedReport
        }
        object.removeValue(forKey: "bytesHex")
        let sanitized = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        return String(decoding: sanitized, as: UTF8.self)
    }

    static func execute(pairingPath: String) -> Execution {
        var output: UnsafeMutablePointer<CChar>?
        var error: UnsafeMutablePointer<CChar>?
        let rc = pairingPath.withCString {
            al_mobilegestalt_probe($0, nil, nil, &output, &error)
        }
        defer {
            if let output { al_string_free(output) }
            if let error { al_string_free(error) }
        }
        guard rc == 0, let output else {
            let detail = error.map { String(cString: $0) } ?? "No error string returned"
            return Execution(log: "ffi_error rc=\(rc): \(detail)")
        }
        let data = Data(String(cString: output).utf8)
        var execution = Execution(log: "")
        do {
            // Strip content BEFORE producing any log or exported report.
            execution.log = try sanitizedReport(data)
            let report = try JSONDecoder().decode(Report.self, from: data)
            guard report.schemaVersion == 1, report.targetPath == targetPath else { throw ProbeError.malformedReport }
            execution.report = report
            guard report.target.read.status == "read_success" else { return execution }
            execution.backupStatus = "backup_failed"
            guard report.target.stat.status == "stat_success",
                  report.target.open.status == "readonly_open_success",
                  let hex = report.bytesHex, let size = report.target.read.size,
                  let hash = report.target.read.sha256 else { throw ProbeError.malformedReport }
            let bytes = try decodeHex(hex)
            guard bytes.count == size, sha256(bytes) == hash else { throw ProbeError.invalidBytes }
            // Preserve exactly the bytes AFC returned, without parsing/reserializing.
            let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            let url = try saveBackup(bytes, documents: documents)
            execution.backupName = url.lastPathComponent
            execution.backupStatus = "backup_verified"
            execution.log += "\nbackup_verified — BACKUP VERIFIED\nfile=\(url.lastPathComponent)\nsize=\(bytes.count)\nsha256=\(hash)"
        } catch {
            if execution.backupStatus != "backup_failed" { execution.backupStatus = "report_failed" }
            execution.log += "\n\(execution.backupStatus): \(error.localizedDescription)"
        }
        return execution
    }
}

@MainActor
final class MobileGestaltProbeModel: ObservableObject {
    @Published var running = false
    @Published var execution: MobileGestaltProbe.Execution?
    @Published var liveStatus = "idle"
    let build = MobileGestaltProbe.systemString("kern.osversion")
    let machine = MobileGestaltProbe.systemString("hw.machine")

    var targetMatches: Bool {
        build == MobileGestaltProbe.expectedBuild && machine == MobileGestaltProbe.expectedMachine
    }

    func start(pairingPath: String) {
        guard !running else { return }
        guard targetMatches else { liveStatus = "unsupported_target: expected iPhone16 / 24B5089g"; return }
        running = true
        execution = nil
        liveStatus = "Opening existing tunnel and testing Media, then exact MobileGestalt path…"
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = MobileGestaltProbe.execute(pairingPath: pairingPath)
            DispatchQueue.main.async {
                self?.execution = result
                self?.running = false
                self?.liveStatus = "Diagnostic finished — inspect each stage below."
            }
        }
    }
}

struct MobileGestaltProbeView: View {
    @EnvironmentObject private var vm: AppViewModel
    @StateObject private var model = MobileGestaltProbeModel()

    private var transcript: String {
        "MobileGestalt Probe\nmodel=\(model.machine)\nbuild=\(model.build)\nos=\(ProcessInfo.processInfo.operatingSystemVersionString)\npath=\(MobileGestaltProbe.targetPath)\n\(model.execution?.log ?? model.liveStatus)"
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("MobileGestalt Probe") {
                    LabeledContent("Detected model", value: model.machine)
                    LabeledContent("Detected build", value: model.build)
                    Text(MobileGestaltProbe.targetPath).font(.caption.monospaced()).textSelection(.enabled)
                    Text("Stat and read only in the current AFC namespace. A successful read alone does not prove this is the system cache.")
                        .font(.caption)
                    if !model.targetMatches {
                        Text("Probe restricted to iPhone 16 (iPhone17,3), build 24B5089g.").foregroundStyle(.orange)
                    }
                    Button("Probe MobileGestalt") {
                        vm.syncTargetHostsToRust()
                        model.start(pairingPath: PairingController.pairingFilePath())
                    }
                    .disabled(model.running || !model.targetMatches || !vm.hasPairingFile ||
                              vm.isScanningCards || vm.cardFlashPhase == .running ||
                              vm.passthmFlashPhase == .running || vm.tendiesFlashPhase == .running)
                    if !vm.hasPairingFile { Text("Select a pairing file in Pairing first.") }
                    if model.running { ProgressView() }
                    Text(model.liveStatus).font(.caption)
                }
                if let execution = model.execution {
                    if let report = execution.report {
                        Section("Transport") { Text(report.transport.display) }
                        Section("Media control") {
                            Text(report.media.status)
                            ForEach(Array(report.media.attempts.enumerated()), id: \.offset) { _, attempt in
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(attempt.path ?? "Media candidate").font(.caption.monospaced())
                                    Text("stat: \(attempt.stat.display)")
                                    Text("open: \(attempt.open.display)")
                                    Text("read: \(attempt.read.display)")
                                }.font(.caption)
                            }
                        }
                        Section("MobileGestalt AFC results") {
                            Text("get_file_info: \(report.target.stat.display)")
                            Text("open RdOnly: \(report.target.open.display)")
                            Text("read_entire: \(report.target.read.display)")
                            if let size = report.target.read.size { LabeledContent("Bytes read", value: String(size)) }
                            if let hash = report.target.read.sha256 { Text("SHA-256: \(hash)").font(.caption.monospaced()) }
                            if let close = report.target.close { Text("close: \(close.display)") }
                        }
                    }
                    Section("Local Documents backup") {
                        Text(execution.backupStatus == "backup_verified" ? "BACKUP VERIFIED (backup_verified)" : execution.backupStatus)
                        if let name = execution.backupName { Text(name).font(.caption.monospaced()) }
                    }
                    Section("Diagnostic report") {
                        ShareLink(item: transcript) { Label("Share diagnostic log", systemImage: "square.and.arrow.up") }
                        Text(transcript).font(.caption.monospaced()).textSelection(.enabled)
                    }
                }
            }
            .navigationTitle("Experimental")
        }
    }
}
