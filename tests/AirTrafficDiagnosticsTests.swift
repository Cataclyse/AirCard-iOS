import XCTest
@testable import AirCard_iOS

final class AirTrafficDiagnosticsTests: XCTestCase {
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
