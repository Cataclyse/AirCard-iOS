import SwiftUI
import Foundation

struct AirTrafficDiagnosticEvent: Decodable, Identifiable {
    var id = UUID()
    let operationId: String
    let parentId: String?
    let operation: String
    let category: String
    let destination: String
    let elapsedMs: UInt64
    let step: String
    let status: String
    let finalTargetVerified: Bool
    let evidence: Evidence?

    struct Evidence: Decodable {
        let message: String?
        let payloads: [WalletPayload]?
        let paths: [String]?
        let files: [SourceFile]?
        let rawResponseHex: String?
        let rawErrorFields: [ErrorField]?
        struct SourceFile: Decodable { let name: String; let bytes: Int }
        struct ErrorField: Decodable { let field: String }
    }

    enum CodingKeys: String, CodingKey {
        case operationId, parentId, operation, category, destination, elapsedMs
        case step, status, finalTargetVerified, evidence
    }

    static func parse(_ line: String) -> (AirTrafficDiagnosticEvent, String)? {
        let marker = "AIRTRAFFIC_DIAGNOSTIC "
        guard let range = line.range(of: marker) else { return nil }
        let json = String(line[range.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let event = try? JSONDecoder().decode(Self.self, from: Data(json.utf8)) else { return nil }
        return (event, json)
    }
}

@MainActor
final class AirTrafficDiagnosticsStore: ObservableObject {
    static let shared = AirTrafficDiagnosticsStore()
    @Published private(set) var entries: [Entry] = []
    @Published private(set) var discardedCount = 0
    @Published private(set) var verifications: [String: WalletVerificationResult] = [:]
    @Published private(set) var verifyingOperationId: String?
    private var generation = UUID()
    private let limit = 1500

    struct Entry: Identifiable {
        let event: AirTrafficDiagnosticEvent
        let json: String
        var id: UUID { event.id }
    }

    func ingest(_ line: String) {
        guard let (event, json) = AirTrafficDiagnosticEvent.parse(line) else { return }
        entries.append(Entry(event: event, json: json))
        if entries.count > limit {
            let overflow = entries.count - limit
            entries.removeFirst(overflow)
            discardedCount += overflow
        }
    }

    func clear() {
        generation = UUID()
        verifyingOperationId = nil
        verifications.removeAll()
        entries.removeAll()
        discardedCount = 0
    }

    var summaries: [AirTrafficOperationSummary] {
        AirTrafficOperationSummary.build(events: entries.map(\.event), discarded: discardedCount > 0,
                                         verifications: verifications)
    }

    // Only the latest completed root operation for this destination can be
    // checked. Nested attempts retain their own protocol-only summaries.
    func isCurrent(_ summary: AirTrafficOperationSummary) -> Bool {
        guard summary.parentId == nil, let latest = summaries.last(where: {
            $0.parentId == nil && $0.destination == summary.destination
        }) else { return false }
        return latest.id == summary.id && latest.category == "Wallet" && latest.historyComplete && latest.returned == "OK"
    }

    func canReadBack(_ summary: AirTrafficOperationSummary) -> Bool {
        isCurrent(summary) && summary.payloadCount == summary.payloads.count &&
        WalletDestinationVerifier.accepts(destination: summary.destination, payloads: summary.payloads)
    }

    func verify(_ summary: AirTrafficOperationSummary) {
        guard verifyingOperationId == nil, canReadBack(summary) else { return }
        verifyingOperationId = summary.id
        let capturedGeneration = generation
        DispatchQueue.global(qos: .utility).async {
            let result = WalletDestinationVerifier.verify(operationId: summary.id,
                destination: summary.destination, payloads: summary.payloads)
            DispatchQueue.main.async { [weak self] in
                guard let self = self, self.generation == capturedGeneration else { return }
                self.verifyingOperationId = nil
                guard self.isCurrent(summary) else { return }
                self.verifications[summary.id] = result
            }
        }
    }

    func observeVisualEffect(_ summary: AirTrafficOperationSummary) {
        guard verifyingOperationId == nil, isCurrent(summary), summary.destination.hasSuffix(".pkpass"),
              verifications[summary.id]?.status != .verified, verifications[summary.id]?.status != .failed else { return }
        verifications[summary.id] = WalletVerificationResult(operationId: summary.id, checkedAt: Date(),
            status: .effectObserved, source: "user_visual_confirmation",
            detail: "User explicitly confirms the expected NEW artwork appeared on this exact card in Wallet after this operation. Visual attestation only; file bytes and cache directories are not verified.", files: [])
    }

    func verificationJSON(_ result: WalletVerificationResult) -> String {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(result), let text = String(data: data, encoding: .utf8) else {
            return "Verification export failed"
        }
        return text
    }

    var transcript: String {
        let header = "AirTraffic Diagnostics\nmodel=\(MobileGestaltProbe.systemString("hw.machine"))\nbuild=\(MobileGestaltProbe.systemString("kern.osversion"))\ndiscardedEvents=\(discardedCount)\nWriters remain unverified. Optional explicit readback uses normal app permissions only.\n"
        let reports = summaries.map { summary in
            summary.text + (summary.verification.map { "\nIndependent evidence: " + verificationJSON($0) } ?? "")
        }.joined(separator: "\n\n")
        return header + reports + "\n\nRaw events:\n" + entries.map(\.json).joined(separator: "\n")
    }
}

struct ExperimentalView: View {
    var body: some View {
        NavigationStack {
            List {
                NavigationLink("MobileGestalt Probe") { MobileGestaltProbeView() }
                NavigationLink("AirTraffic Diagnostics") { AirTrafficDiagnosticsView() }
            }
            .navigationTitle("Experimental")
        }
    }
}

struct AirTrafficDiagnosticsView: View {
    @ObservedObject private var store = AirTrafficDiagnosticsStore.shared
    @EnvironmentObject private var vm: AppViewModel
    @State private var visualConfirmation: AirTrafficOperationSummary?

    var body: some View {
        List {
            Section {
                Text("Passive observation of existing Wallet, Passcode and Wallpapers operations. Opening this screen starts no connection or injection.")
                Text("VERIFIED requires an independent exact file readback. EFFECT OBSERVED is your explicit visual confirmation in Wallet. UNVERIFIED means no sufficient evidence. FAILED means an independently read file differs from the expected payload.")
                    .foregroundStyle(.orange)
                Text("Raw codes are shown only when received. null means unavailable, not success. AFC ObjectNotFound means: Path not visible in current AFC namespace.")
                    .font(.caption)
                Text("Only executed stages emit events. A started stage without a result is incomplete; no success is inferred.")
                    .font(.caption)
                if store.discardedCount > 0 {
                    Text("\(store.discardedCount) older events discarded; the report is incomplete.").foregroundStyle(.orange)
                }
                ShareLink(item: store.transcript) { Label("Share diagnostic log", systemImage: "square.and.arrow.up") }
                Button("Clear local log", role: .destructive) { store.clear() }
            }
            if store.entries.isEmpty {
                Section { Text("No captured AirTraffic events in this app session.") }
            }
            ForEach(store.summaries) { summary in
                Section("Operation summary · \(summary.id)") {
                    Text(summary.text).font(.caption.monospaced()).textSelection(.enabled)
                    if let verification = summary.verification {
                        Text(store.verificationJSON(verification)).font(.caption.monospaced()).textSelection(.enabled)
                    }
                    if summary.category == "Wallet" && summary.parentId == nil {
                        Button("Read back existing Wallet payloads (read-only)") { store.verify(summary) }
                            .disabled(!store.canReadBack(summary) || store.verifyingOperationId != nil || vm.cardFlashPhase == .running)
                        Text("Uses normal app filesystem permissions; denial remains UNVERIFIED. No AFC namespace assumption, extra permission or fallback. Requires a new run with the expected-byte manifest; only the latest operation per destination can be checked.")
                            .font(.caption)
                        if store.verifyingOperationId == summary.id { ProgressView("Reading existing Wallet assets…") }
                        if summary.destination.hasSuffix(".pkpass") {
                            Button("Record visual effect observed in Wallet…") { visualConfirmation = summary }
                                .disabled(!store.isCurrent(summary) || store.verifyingOperationId != nil || vm.cardFlashPhase == .running || summary.finalStatus == .verified || summary.finalStatus == .failed)
                        }
                    }
                }
            }
            ForEach(store.entries) { entry in
                Section("\(entry.event.category) · \(entry.event.operationId) · \(entry.event.step)") {
                    Text(entry.event.status).font(.headline)
                    Text("Destination: \(entry.event.destination)").font(.caption.monospaced())
                    Text("Writer-reported flag (not independent evidence): \(entry.event.finalTargetVerified ? "true" : "false")")
                    // Preserve all evidence fields, including actual service, Media
                    // staging path, raw status codes and ignored cleanup failures.
                    Text(entry.json).font(.caption.monospaced()).textSelection(.enabled)
                }
            }
        }
        .navigationTitle("AirTraffic Diagnostics")
        .alert("Confirm observed Wallet effect", isPresented: Binding(
            get: { visualConfirmation != nil }, set: { if !$0 { visualConfirmation = nil } }
        )) {
            Button("Cancel", role: .cancel) { visualConfirmation = nil }
            Button("I observed the new artwork") {
                if let summary = visualConfirmation { store.observeVisualEffect(summary) }
                visualConfirmation = nil
            }
        } message: {
            Text("Only confirm after opening this exact card in Wallet and seeing the expected NEW artwork after this operation. This records EFFECT OBSERVED, not byte verification.\n\(visualConfirmation?.destination ?? "")")
        }
    }
}
