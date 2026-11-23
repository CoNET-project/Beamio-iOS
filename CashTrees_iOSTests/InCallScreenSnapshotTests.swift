import SwiftUI
import XCTest
@testable import CashTrees_iOS

/// Renders the native call screen to a PNG so its layout can be reviewed without a
/// live call. Output path: the `IN_CALL_SNAPSHOT_PATH` environment variable.
final class InCallScreenSnapshotTests: XCTestCase {
	@MainActor
	func testRenderCallScreen() throws {
		let model = BeamioInCallScreenModel.shared
		model.begin(
			callId: "snapshot-call",
			sessionId: "snapshot-session",
			tag: "@rrr01",
			address: "0x909f82221b1005c071db358d9d6d43f4cbc5bf50"
		)
		let view = BeamioInCallScreen(model: model)
			.frame(width: 375, height: 667)
		let renderer = ImageRenderer(content: view)
		renderer.scale = 2
		guard let image = renderer.uiImage, let data = image.pngData() else {
			XCTFail("Could not render the call screen")
			return
		}
		// Write to a directory the test may create (the sandboxed test host has no /tmp/chat-sdk-accept). Parent is created first.
		let path = ProcessInfo.processInfo.environment["IN_CALL_SNAPSHOT_PATH"]
			?? FileManager.default.temporaryDirectory.appendingPathComponent("chat-sdk-accept/incall-render.png").path
		let url = URL(fileURLWithPath: path)
		try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
		try data.write(to: url)
		model.end(callId: "snapshot-call")
		let written = try Data(contentsOf: url)
		XCTAssertFalse(written.isEmpty, "the written PNG is not empty")
		XCTAssertEqual(Array(written.prefix(8)), [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], "the written file is a PNG")
		XCTAssertGreaterThan(written.count, 10_000)
	}
}
