import Foundation
import Testing
@testable import CashTrees_iOS

/// External links (`openURL`) are opened without the bundle trust check; the URL rules still apply; every other action keeps
/// the trust check. Synthetic URLs and a recording opener only: nothing is opened.
struct BeamioExternalURLTests {
	private static let appStore = "https://apps.apple.com/us/app/beamio-smart-local-pass/id6755375110"

	@Test func openURLIsRoutedToTheOpenerWhenTheTrustCheckFails() {
		// An untrusted result (for example a HashRouter route such as #/chat, or a generation mismatch) still opens the link.
		#expect(BeamioBridgeRoute.route(action: "openURL", trusted: false) == .openExternal)
		#expect(BeamioBridgeRoute.route(action: "openURL", trusted: true) == .openExternal)
		var opened: [URL] = []
		let route = BeamioBridgeRoute.route(action: "openURL", trusted: false)
		if route == .openExternal { BeamioExternalURL.open(Self.appStore, opener: { opened.append($0) }) }
		#expect(opened == [URL(string: Self.appStore)!])
	}

	@Test func allowlistedSchemesAreOpenedAsGiven() {
		for raw in [Self.appStore, "https://beamio.ca/terms", "http://example.com/a?b=1#c", "mailto:support@example.com", "tel:+15550100",
		            "ethereum:0x000000000000000000000000000000000000dEaD@8453/transfer?value=1", "metamask://x", "cbwallet://x"] {
			var opened: [URL] = []
			#expect(BeamioExternalURL.open(raw, opener: { opened.append($0) }) == true)
			#expect(opened.map(\.absoluteString) == [raw])
		}
		// Surrounding whitespace is trimmed; scheme case does not matter.
		var opened: [URL] = []
		#expect(BeamioExternalURL.open("  HTTPS://beamio.ca/help \n", opener: { opened.append($0) }) == true)
		#expect(opened.map(\.absoluteString) == ["HTTPS://beamio.ca/help"])
	}

	@Test func schemesOffTheAllowlistAndBadValuesAreRefused() {
		for raw in ["javascript:alert(1)", "file:///etc/hosts", "data:text/html,x", "itms-apps://apps.apple.com/app/id6755375110",
		            "sms:+15550100", "cashtrees-local://localhost/index.html", "beamio://x", "no-scheme", "", "   "] {
			var opened: [URL] = []
			#expect(BeamioExternalURL.open(raw, opener: { opened.append($0) }) == false)
			#expect(opened.isEmpty)
		}
		var opened: [URL] = []
		#expect(BeamioExternalURL.open(nil, opener: { opened.append($0) }) == false)
		#expect(opened.isEmpty)
	}

	@Test func otherActionsKeepTheTrustCheck() {
		// No other action is opened up by the openURL change: untrusted is refused, trusted is dispatched.
		for action in ["chatModuleCommand", "openInAppBrowser", "startSystemCall", "endSystemCall", "reportIncomingCall",
		               "queryInstalledApps", "startPhysicalCardBind", "consoleLog", "webContentReady", "openurl", "OpenURL", ""] {
			#expect(BeamioBridgeRoute.route(action: action, trusted: false) == .refuse)
			#expect(BeamioBridgeRoute.route(action: action, trusted: true) == .dispatch)
		}
	}

	@Test func theShellRoutesOpenURLBeforeTheTrustGuardAndKeepsTheGuard() throws {
		// Source check of the host file: the route is taken before `guard trustedNativeSource`, the old switch case is gone,
		// and the guard is still there for every other action.
		let src = try String(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
			.appendingPathComponent("CashTrees_iOS/ContentView.swift"), encoding: .utf8)
		let route = try #require(src.range(of: "BeamioBridgeRoute.route(action: action, trusted: trustedNativeSource) == .openExternal"))
		let guardRange = try #require(src.range(of: "guard trustedNativeSource else {"))
		#expect(route.lowerBound < guardRange.lowerBound)
		#expect(!src.contains("case \"openURL\":"))
		#expect(!src.contains("openExternalURLFromBridge"))
	}
}
