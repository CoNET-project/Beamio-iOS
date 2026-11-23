import WebKit

/// Web content inspection (Safari Web Inspector) of the shell's WebView.
/// On only in Debug and internal QA builds (BEAMIO_QA). A Release or App Store build compiles the `false` branch, so the binary
/// does not reference `setInspectable:` at all; `scripts/verify-ios-webinspector-off.sh` checks that on the built app.
enum CashTreesWebInspection {
    #if DEBUG || BEAMIO_QA
    static let enabled = true
    #else
    static let enabled = false
    #endif

    /// Applies the build's setting to `webView`. A Release build leaves WebKit's default (not inspectable) untouched.
    static func apply(to webView: WKWebView) {
        #if DEBUG || BEAMIO_QA
        if #available(iOS 16.4, *) {
            webView.isInspectable = true
        }
        #endif
    }
}
