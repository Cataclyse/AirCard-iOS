import XCTest
@testable import AirCard_iOS

final class MobileGestaltProbeTests: XCTestCase {
    func testBackupPreservesEveryByteAndDoesNotOverwriteOriginal() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let bytes = Data([0, 255, 128, 0, 10, 13, 42])
        let backup = try MobileGestaltProbe.saveBackup(bytes, documents: directory)
        XCTAssertEqual(try Data(contentsOf: backup), bytes)
        XCTAssertEqual(try MobileGestaltProbe.saveBackup(bytes, documents: directory), backup)
        XCTAssertThrowsError(try MobileGestaltProbe.saveBackup(Data([1, 2]), documents: directory))
        XCTAssertEqual(try Data(contentsOf: backup), bytes)
    }

    func testPayloadVerificationRejectsMalformedHex() throws {
        XCTAssertEqual(try MobileGestaltProbe.decodeHex("00ff80000a0d2a"), Data([0, 255, 128, 0, 10, 13, 42]))
        XCTAssertThrowsError(try MobileGestaltProbe.decodeHex("0"))
        XCTAssertThrowsError(try MobileGestaltProbe.decodeHex("zz"))
        XCTAssertEqual(MobileGestaltProbe.sha256(Data()), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    func testReportOmitsFileContentAndPreservesUnknownStatusCode() throws {
        let wire = Data(#"{"bytesHex":"sensitive-file-content","target":{"stat":{"status":"afc_error","rawAfcCode":9876,"rawAfcStatusCodes":[9876]}}}"#.utf8)
        let sanitized = try MobileGestaltProbe.sanitizedReport(wire)
        XCTAssertFalse(sanitized.contains("bytesHex"))
        XCTAssertFalse(sanitized.contains("sensitive-file-content"))
        XCTAssertTrue(sanitized.contains("9876"))
        let stage = try JSONDecoder().decode(MobileGestaltProbe.Stage.self,
            from: Data(#"{"status":"afc_object_not_found","rawAfcCode":8,"interpretation":"Path not visible in current AFC namespace"}"#.utf8))
        XCTAssertTrue(stage.display.contains("Path not visible in current AFC namespace"))
        XCTAssertTrue(stage.display.contains("Raw AFC error: 8"))
    }
}
