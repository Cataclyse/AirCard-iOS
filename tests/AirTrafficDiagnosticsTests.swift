import XCTest
@testable import AirCard_iOS

final class AirTrafficDiagnosticsTests: XCTestCase {
    private let destination = "/var/mobile/Library/Passes/Cards/ABCDEFGHIJKLMNOPQRSTUVWX123=.pkpass"

    private func event(_ id: String = "root", parent: String? = nil,
                       operation: String = "exploit_write_batch", step: String, status: String,
                       evidence: [String: Any] = [:], legacyVerified: Bool = false) throws -> AirTrafficDiagnosticEvent {
        let object: [String: Any] = ["operationId": id, "parentId": parent.map { $0 as Any } ?? NSNull(),
            "operation": operation, "category": "Wallet", "destination": destination,
            "elapsedMs": 1, "step": step, "status": status, "evidence": evidence,
            "finalTargetVerified": legacyVerified]
        return try JSONDecoder().decode(AirTrafficDiagnosticEvent.self, from: JSONSerialization.data(withJSONObject: object))
    }

    private func completedAttempt(_ id: String = "root", parent: String? = nil, count: Int = 3) throws -> [AirTrafficDiagnosticEvent] {
        var events = [try event(id, parent: parent, step: "operation", status: "started"),
            try event(id, parent: parent, step: "payload_destinations", status: "existing_destinations",
                      evidence: ["paths": (0..<count).map { destination + "/asset\($0)" }])]
        let response = try PropertyListSerialization.data(fromPropertyList: ["Status": "DataComplete"], format: .binary, options: 0)
        events.append(try event(id, parent: parent, step: "staging_response", status: "response_received_not_interpreted",
                                evidence: ["rawResponseHex": response.map { String(format: "%02x", $0) }.joined()]))
        for _ in 0..<3 { events.append(try event(id, parent: parent, step: "staging_stat", status: "success")) }
        for message in ["ReadyForSync", "AssetManifest"] {
            events.append(try event(id, parent: parent, step: "atc_receive", status: "message_received", evidence: ["message": message]))
        }
        for _ in 0..<(count + 1) {
            for status in ["started", "stream_write_completed"] {
                events.append(try event(id, parent: parent, step: "atc_send", status: status, evidence: ["message": "FileComplete"]))
            }
        }
        for _ in 0..<2 {
            for status in ["started", "success"] { events.append(try event(id, parent: parent, step: "media_cleanup", status: status)) }
        }
        events.append(try event(id, parent: parent, step: "operation", status: "returned_ok_unverified"))
        return events
    }

    func testParentAggregatesAttemptWithoutCountingPayloadsTwice() throws {
        var events = [try event(operation: "exploit_write_dir", step: "operation", status: "started"),
            try event(operation: "exploit_write_dir", step: "local_source", status: "files_loaded",
                      evidence: ["files": (0..<11).map { ["name": "asset\($0)", "bytes": 1] }])]
        events += try completedAttempt("child", parent: "root", count: 11)
        for status in ["started", "success"] {
            events.append(try event(operation: "exploit_write_dir", step: "media_cleanup", status: status))
        }
        events.append(try event(operation: "exploit_write_dir", step: "operation", status: "returned_ok_unverified"))
        let summaries = AirTrafficOperationSummary.build(events: events, discarded: false, verifications: [:])
        XCTAssertEqual(summaries.count, 2)
        let root = try XCTUnwrap(summaries.first)
        XCTAssertEqual(root.payloadCount, 11)
        XCTAssertEqual(root.fileCompleteCount, 12)
        XCTAssertEqual(root.attemptIds, ["child"])
        XCTAssertTrue(root.cleanup.contains("3 success / 0 errors / 0 pending"))
        XCTAssertTrue(root.protocolCompleted)
        XCTAssertEqual(root.returned, "OK")
        XCTAssertEqual(root.finalStatus, .unverifiable)
        XCTAssertTrue(root.streamingZIP.contains("DataComplete"))
        XCTAssertTrue(root.text.contains("Final target verification: UNVERIFIED"))
    }

    func testOKAndLegacyFlagNeverVerifyDestination() throws {
        let events = [try event(step: "operation", status: "started"),
            try event(step: "atc_send", status: "stream_write_completed", evidence: ["message": "FileComplete"]),
            try event(step: "operation", status: "returned_ok_unverified", legacyVerified: true)]
        let summary = try XCTUnwrap(AirTrafficOperationSummary.build(events: events, discarded: false, verifications: [:]).first)
        XCTAssertFalse(summary.protocolCompleted)
        XCTAssertEqual(summary.finalStatus, .unverifiable)
    }

    func testLostHistoryOrMissingManifestCannotCompleteProtocol() throws {
        let complete = try completedAttempt()
        for events in [Array(complete.dropFirst()), complete.filter { $0.evidence?.message != "AssetManifest" }] {
            XCTAssertFalse(try XCTUnwrap(AirTrafficOperationSummary.build(events: events, discarded: false, verifications: [:]).first).protocolCompleted)
        }
        XCTAssertFalse(try XCTUnwrap(AirTrafficOperationSummary.build(events: complete, discarded: true, verifications: [:]).first).protocolCompleted)
    }

    func testProtocolFailureDoesNotInventDestinationFailure() throws {
        var events = try completedAttempt()
        events.insert(try event(step: "atc_receive", status: "error_message_received", evidence: ["message": "SyncFailed"]), at: events.count - 1)
        let summary = try XCTUnwrap(AirTrafficOperationSummary.build(events: events, discarded: false, verifications: [:]).first)
        XCTAssertTrue(summary.protocolFailed)
        XCTAssertFalse(summary.protocolCompleted)
        XCTAssertEqual(summary.returned, "OK")
        XCTAssertEqual(summary.finalStatus, .unverifiable)
    }

    func testRetryMessagesAreNotCombinedIntoFalseProtocolCompletion() throws {
        var events = [try event(operation: "exploit_write_dir", step: "operation", status: "started")]
        events += try completedAttempt("first", parent: "root").filter { $0.evidence?.message != "AssetManifest" }
        events += try completedAttempt("retry", parent: "root").filter { $0.evidence?.message != "ReadyForSync" }
        events.append(try event(operation: "exploit_write_dir", step: "operation", status: "returned_ok_unverified"))
        let summary = try XCTUnwrap(AirTrafficOperationSummary.build(events: events, discarded: false, verifications: [:]).first)
        XCTAssertFalse(summary.protocolCompleted)
        XCTAssertEqual(summary.attemptIds, ["first", "retry"])
        XCTAssertEqual(summary.finalStatus, .unverifiable)
    }

    func testIgnoredCleanupErrorRemainsVisibleSeparatelyFromWriterOK() throws {
        var events = try completedAttempt()
        events.insert(try event(step: "media_cleanup", status: "started"), at: events.count - 1)
        events.insert(try event(step: "media_cleanup", status: "error", evidence: ["rawErrorCode": 10]), at: events.count - 1)
        let summary = try XCTUnwrap(AirTrafficOperationSummary.build(events: events, discarded: false, verifications: [:]).first)
        XCTAssertTrue(summary.protocolCompleted)
        XCTAssertEqual(summary.returned, "OK")
        XCTAssertTrue(summary.cleanup.contains("2 success / 1 errors / 0 pending"))
        XCTAssertEqual(summary.finalStatus, .unverifiable)
    }

    func testUnknownATCErrorFieldsAndUnknownZIPStatusPreventSuccess() throws {
        var events = try completedAttempt()
        events.insert(try event(step: "atc_receive", status: "message_received",
                                evidence: ["rawErrorFields": [["field": "ErrorCode", "value": 0]]]), at: 1)
        XCTAssertFalse(try XCTUnwrap(AirTrafficOperationSummary.build(events: events, discarded: false, verifications: [:]).first).protocolCompleted)
        let noZIP = try completedAttempt().filter { $0.step != "staging_response" }
        XCTAssertFalse(try XCTUnwrap(AirTrafficOperationSummary.build(events: noZIP, discarded: false, verifications: [:]).first).protocolCompleted)
    }

    func testOnlyExplicitIndependentEvidenceChangesFinalStatus() throws {
        let events = try completedAttempt()
        for status in [DestinationVerificationStatus.verified, .effectObserved, .unverifiable, .failed] {
            let result = WalletVerificationResult(operationId: "root", checkedAt: Date(), status: status,
                source: status == .effectObserved ? "user_visual_confirmation" : "normal_app_filesystem_read", detail: "fixture", files: [])
            let summary = try XCTUnwrap(AirTrafficOperationSummary.build(events: events, discarded: false, verifications: ["root": result]).first)
            XCTAssertEqual(summary.finalStatus, status)
        }
    }

    func testReadbackRejectsPathsOutsideExactExistingWalletAssets() {
        let payload = WalletPayload(path: destination + "/background.pdf", size: 1, sha256: String(repeating: "a", count: 64))
        XCTAssertTrue(WalletDestinationVerifier.accepts(destination: destination, payloads: [payload]))
        XCTAssertFalse(WalletDestinationVerifier.accepts(destination: destination, payloads: []))
        XCTAssertFalse(WalletDestinationVerifier.accepts(destination: destination, payloads: [payload, payload]))
        for path in [destination + "/../background.pdf", destination + "/unknown", "/var/containers/Shared/SystemGroup/example/file"] {
            XCTAssertFalse(WalletDestinationVerifier.accepts(destination: destination,
                payloads: [.init(path: path, size: 1, sha256: payload.sha256)]))
        }
        let result = WalletDestinationVerifier.verify(operationId: "invalid", destination: "/unsupported", payloads: [payload])
        XCTAssertEqual(result.status, .unverifiable)
        XCTAssertTrue(result.files.isEmpty) // Rejected before any open.
    }

    @MainActor
    func testVisualObservationIsExplicitAndBoundToLatestRoot() throws {
        let store = AirTrafficDiagnosticsStore()
        func ingest(_ events: [AirTrafficDiagnosticEvent]) throws {
            for event in events {
                // Replay the envelope via the real parser; visual confirmation
                // deliberately requires no file-byte evidence.
                let object: [String: Any] = ["operationId": event.operationId, "operation": event.operation,
                    "category": event.category, "destination": event.destination, "elapsedMs": 1,
                    "step": event.step, "status": event.status, "finalTargetVerified": false]
                let data = try JSONSerialization.data(withJSONObject: object)
                store.ingest("AIRTRAFFIC_DIAGNOSTIC " + String(decoding: data, as: UTF8.self))
            }
        }
        try ingest(completedAttempt())
        let root = try XCTUnwrap(store.summaries.first)
        XCTAssertEqual(root.finalStatus, .unverifiable)
        store.observeVisualEffect(root)
        XCTAssertEqual(store.summaries.first?.finalStatus, .effectObserved)
        XCTAssertTrue(store.transcript.contains("user_visual_confirmation"))
        try ingest([event("new", step: "operation", status: "started")])
        XCTAssertFalse(store.isCurrent(root))
        XCTAssertFalse(store.canReadBack(root))
        store.clear()
        XCTAssertTrue(store.verifications.isEmpty)
    }

    func testEventKeepsNamespaceFailureAndDoesNotClaimVerification() throws {
        let line = #"INFO AIRTRAFFIC_DIAGNOSTIC {"operationId":"atd-1","parentId":null,"operation":"exploit_write_batch","category":"Wallet","destination":"/var/mobile/Library/Passes/Cards/example.pkpass","elapsedMs":12,"step":"staging_stat","status":"error","finalTargetVerified":false,"evidence":{"rawErrorCode":8,"interpretation":"Path not visible in current AFC namespace"}}"#
        let parsed = try XCTUnwrap(AirTrafficDiagnosticEvent.parse(line))
        XCTAssertFalse(parsed.0.finalTargetVerified)
        XCTAssertEqual(parsed.0.status, "error")
        XCTAssertTrue(parsed.1.contains("\"rawErrorCode\":8"))
        XCTAssertTrue(parsed.1.contains("Path not visible in current AFC namespace"))
        XCTAssertNil(AirTrafficDiagnosticEvent.parse("ordinary Rust log"))
        XCTAssertNil(AirTrafficDiagnosticEvent.parse("AIRTRAFFIC_DIAGNOSTIC invalid-json"))
    }

    @MainActor
    func testCaptureLimitReportsLostHistory() {
        let store = AirTrafficDiagnosticsStore()
        let line = #"AIRTRAFFIC_DIAGNOSTIC {"operationId":"atd-1","parentId":null,"operation":"exploit_write_batch","category":"TelephonyUI","destination":"/var/mobile/Library/Caches/TelephonyUI-10","elapsedMs":1,"step":"operation","status":"returned_ok_unverified","finalTargetVerified":false}"#
        for _ in 0..<1502 { store.ingest(line) }
        XCTAssertEqual(store.entries.count, 1500)
        XCTAssertEqual(store.discardedCount, 2)
        XCTAssertTrue(store.transcript.contains("discardedEvents=2"))
        store.clear()
        XCTAssertEqual(store.discardedCount, 0)
        XCTAssertTrue(store.entries.isEmpty)
    }
}
