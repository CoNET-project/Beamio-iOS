import Foundation
import Testing
@testable import CashTrees_iOS

/// External links (`openURL`) are opened without the bundle trust check and without a scheme allowlist; only a basic parse
/// check applies; every other action keeps the trust check. Synthetic URLs and a recording opener only: nothing is opened.
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

	@Test func anySchemeThatParsesIsHandedToTheSystem() {
		for raw in [Self.appStore, "https://beamio.ca/terms", "http://example.com/a?b=1#c", "mailto:support@example.com", "tel:+15550100",
		            "ethereum:0x000000000000000000000000000000000000dEaD@8453/transfer?value=1", "metamask://x", "cbwallet://x",
		            "itms-apps://apps.apple.com/app/id6755375110", "sms:+15550100", "someapp://path?x=1", "javascript:void(0)"] {
			var opened: [URL] = []
			#expect(BeamioExternalURL.open(raw, opener: { opened.append($0) }) == true)
			#expect(opened.map(\.absoluteString) == [raw])
		}
		// Surrounding whitespace is trimmed.
		var opened: [URL] = []
		#expect(BeamioExternalURL.open("  HTTPS://beamio.ca/help \n", opener: { opened.append($0) }) == true)
		#expect(opened.map(\.absoluteString) == ["HTTPS://beamio.ca/help"])
	}

	@Test func emptyUnparsableOrSchemelessValuesAreDropped() {
		for raw in ["", "   ", "\n", "no-scheme", "/relative/path", "a b c"] {
			var opened: [URL] = []
			#expect(BeamioExternalURL.open(raw, opener: { opened.append($0) }) == false, "\(raw.debugDescription) is dropped")
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
}
