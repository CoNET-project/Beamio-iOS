import XCTest

/// Device QA control chain: drives the app already installed on the device by bundle id, without installing the app
/// under test (run from an .xctestrun whose DependentProductPaths has no app and whose UITargetAppPath is the Runner).
/// Logs only allowlisted button labels, never page text, wallet data or credentials.
/// - testInspectButtons: brings Beamio to the foreground and reports which allowlisted buttons are visible. No tap.
/// - testTapTryAgainOnce: taps the "Try again" button once when it exists. Nothing else.
/// - testSendAgreedText: only on an open chat page (composer and Send button both present), types AGREED_TEXT
///   (must match QA-<ios|and>-<HHMMSS>) into the composer and sends it. Refuses any other text; types nothing when
///   the chat page is not found.
final class DeviceControlUITests: XCTestCase {
	private let bundleId = "com.beamio.beamio"

	/// The only button labels this suite ever prints. Any other button is counted, never named.
	static let reportedLabels: Set<String> = ["Try again", "Restore Wallet", "Send"]

	/// The only text testSendAgreedText accepts.
	static let agreedTextPattern = #"^QA-(ios|and)-[0-9]{6}$"#

	private func shot(_ name: String) {
		let a = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
		a.name = name
		a.lifetime = .keepAlways
		add(a)
	}

	private func app() -> XCUIApplication {
		let app = XCUIApplication(bundleIdentifier: bundleId)
		app.activate()
		_ = app.wait(for: .runningForeground, timeout: 10)
		return app
	}

	@MainActor
	func testInspectButtons() throws {
		let app = app()
		sleep(2)
		let buttons = app.buttons.allElementsBoundByIndex
		var other = 0
		print("[DeviceControl] state=\(app.state.rawValue) buttons=\(buttons.count)")
		for b in buttons where b.exists {
			if Self.reportedLabels.contains(b.label) {
				print("[DeviceControl] button label=\"\(b.label)\" hittable=\(b.isHittable) frame=\(b.frame)")
			} else {
				other += 1
			}
		}
		print("[DeviceControl] other buttons (not named)=\(other)")
		let tryAgain = app.buttons["Try again"]
		print("[DeviceControl] tryAgain exists=\(tryAgain.exists) hittable=\(tryAgain.exists && tryAgain.isHittable)")
		shot("inspect")
	}

	@MainActor
	func testTapTryAgainOnce() throws {
		let app = app()
		let tryAgain = app.buttons["Try again"]
		guard tryAgain.waitForExistence(timeout: 5), tryAgain.isHittable else {
			print("[DeviceControl] tryAgain not found; no tap")
			shot("no-try-again")
			return
		}
		shot("before-try-again")
		print("[DeviceControl] tap Try again at \(Date().timeIntervalSince1970)")
		tryAgain.tap()
		sleep(10)
		shot("after-try-again-10s")
		sleep(20)
		shot("after-try-again-30s")
	}

	@MainActor
	func testSendAgreedText() throws {
		let env = ProcessInfo.processInfo.environment
		let text = env["AGREED_TEXT"] ?? ""
		guard text.range(of: Self.agreedTextPattern, options: .regularExpression) != nil else {
			XCTFail("refused: AGREED_TEXT must match QA-<ios|and>-<HHMMSS>")
			return
		}
		let app = app()
		// Chat page check before any input: a composer and a Send button must both be present.
		let composer = app.textViews.firstMatch.exists ? app.textViews.firstMatch : app.textFields.firstMatch
		let send = app.buttons["Send"]
		guard composer.waitForExistence(timeout: 5), send.waitForExistence(timeout: 3) else {
			print("[DeviceControl] chat page not found (composer or Send missing); nothing typed")
			shot("no-chat-page")
			return
		}
		composer.tap()
		composer.typeText(text)
		shot("typed")
		send.tap()
		print("[DeviceControl] sent at \(Date().timeIntervalSince1970)")
		sleep(3)
		shot("sent")
	}
}
