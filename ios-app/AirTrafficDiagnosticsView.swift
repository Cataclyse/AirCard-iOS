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

    enum CodingKeys: String, CodingKey {
        case operationId, parentId, operation, category, destination, elapsedMs
        case step, status, finalTargetVerified
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
        entries.removeAll()
        discardedCount = 0
    }

    var transcript: String {
        let header = "AirTraffic Diagnostics\nmodel=\(MobileGestaltProbe.systemString("hw.machine"))\nbuild=\(MobileGestaltProbe.systemString("kern.osversion"))\ndiscardedEvents=\(discardedCount)\nPassive log; no device operation initiated from this screen.\n"
        return header + entries.map(\.json).joined(separator: "\n")
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

    var body: some View {
        List {
            Section {
                Text("Passive observation of existing Wallet, Passcode and Wallpapers operations. Opening this screen starts no connection or injection.")
                Text("Final target verification: NOT PERFORMED by the existing injection writers. A successful send or staging stat is not proof of final file content.")
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
            ForEach(store.entries) { entry in
                Section("\(entry.event.category) · \(entry.event.operationId) · \(entry.event.step)") {
                    Text(entry.event.status).font(.headline)
                    Text("Destination: \(entry.event.destination)").font(.caption.monospaced())
                    Text("Final target verified: \(entry.event.finalTargetVerified ? "YES" : "NO")")
                    // Preserve all evidence fields, including actual service, Media
                    // staging path, raw status codes and ignored cleanup failures.
                    Text(entry.json).font(.caption.monospaced()).textSelection(.enabled)
                }
            }
        }
        .navigationTitle("AirTraffic Diagnostics")
    }
}
