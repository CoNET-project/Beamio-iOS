import Testing
import WebKit
@testable import CashTrees_iOS

/// Web Inspector only in Debug and QA builds. Unit tests run in a Debug build, so this checks the
/// Debug side and that the switch is a compile-time constant; the Release side is checked on the built app by
/// scripts/verify-ios-webinspector-off.sh (no setInspectable: reference in any Mach-O file).
struct CashTreesWebInspectionTests {
    @Test func debugOrQaBuildEnablesInspection() {
        #if DEBUG || BEAMIO_QA
        #expect(CashTreesWebInspection.enabled)
        #else
        #expect(!CashTreesWebInspection.enabled, "a Release build without BEAMIO_QA is not inspectable")
        #endif
    }

    @MainActor @Test func applyMatchesTheBuildSetting() {
        let webView = WKWebView(frame: .zero)
        CashTreesWebInspection.apply(to: webView)
        if #available(iOS 16.4, *) {
            #expect(webView.isInspectable == CashTreesWebInspection.enabled)
        }
    }

    @MainActor @Test func aFreshWebViewIsNotInspectable() {
        // The Release path relies on WebKit's default: nothing is called, so the WebView stays not inspectable.
        if #available(iOS 16.4, *) {
            #expect(WKWebView(frame: .zero).isInspectable == false)
        }
    }
}
