import Foundation
import Testing
import WebKit
@testable import CashTrees_iOS

/// Serves two synthetic probe pages under the embedded PWA scheme (a main frame and one sub-frame). No app data, no network.
private final class ProbeSchemeHandler: NSObject, WKURLSchemeHandler {
    func webView(_ webView: WKWebView, start urlSchemeTask: WKURLSchemeTask) {
        guard let url = urlSchemeTask.request.url else {
            urlSchemeTask.didFailWithError(URLError(.badURL))
            return
        }
        let html: String
        if url.path == "/probe.html" {
            html = "<!doctype html><html><body>probe<iframe src=\"cashtrees-local://localhost/frame.html\"></iframe></body></html>"
        } else {
            html = "<!doctype html><html><body>frame</body></html>"
        }
        let data = Data(html.utf8)
        let response = HTTPURLResponse(
            url: url,
            statusCode: 200,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "text/html", "Content-Length": String(data.count)]
        )!
        urlSchemeTask.didReceive(response)
        urlSchemeTask.didReceive(data)
        urlSchemeTask.didFinish()
    }

    func webView(_ webView: WKWebView, stop urlSchemeTask: WKURLSchemeTask) {}
}

/// Records what WebKit reports for each frame that posts a probe message, from the native side only.
private final class ProbeMessageSink: NSObject, WKScriptMessageHandler {
    struct Record {
        let href: String
        let isMainFrame: Bool
        let scheme: String
        let host: String
        let port: Int
    }

    private(set) var records: [Record] = []

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        let body = message.body as? [String: Any]
        let origin = message.frameInfo.securityOrigin
        records.append(Record(
            href: body?["href"] as? String ?? "",
            isMainFrame: message.frameInfo.isMainFrame,
            scheme: origin.protocol,
            host: origin.host,
            port: origin.port
        ))
    }
}

/// Runs in the simulator's real WKWebView (the same message channel and WKFrameInfo the shell reads).
@MainActor
struct PwaWalletSyncOriginProbeTests {
    private static let probeScript = """
    window.webkit.messageHandlers.OriginProbe.postMessage({href: location.href, top: window === window.top});
    """

    @Test func webKitReportsTheEmbeddedSchemeOriginForTheMainFrameOnly() async throws {
        let sink = ProbeMessageSink()
        let config = WKWebViewConfiguration()
        config.setURLSchemeHandler(ProbeSchemeHandler(), forURLScheme: CashTreesPWAScheme.scheme)
        config.userContentController.addUserScript(
            WKUserScript(source: Self.probeScript, injectionTime: .atDocumentEnd, forMainFrameOnly: false)
        )
        config.userContentController.add(sink, name: "OriginProbe")
        defer { config.userContentController.removeScriptMessageHandler(forName: "OriginProbe") }

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.load(URLRequest(url: CashTreesPWAScheme.entryURL(path: "/probe.html")))

        // Wait up to 15 s for the main frame and the sub-frame to report.
        let deadline = Date().addingTimeInterval(15)
        while sink.records.count < 2, Date() < deadline {
            try await Task.sleep(nanoseconds: 50_000_000)
        }

        // Measured values, kept as a test attachment (stdout of a simulator test does not reach the xcodebuild log).
        let measured = sink.records.map {
            "href=\($0.href) isMainFrame=\($0.isMainFrame) protocol=\($0.scheme) host=\($0.host) port=\($0.port)"
        }.joined(separator: "\n")
        Attachment.record(measured, named: "pwa-origin-probe.txt")

        let main = sink.records.first { $0.isMainFrame }
        let sub = sink.records.first { !$0.isMainFrame }
        #expect(main != nil, "the main frame reported a message")
        #expect(sub != nil, "the sub-frame reported a message")
        if let main {
            #expect(main.scheme == CashTreesPWAScheme.scheme, "measured protocol of the embedded main frame")
            #expect(main.host == CashTreesPWAScheme.host, "measured host of the embedded main frame")
            #expect(PwaWalletSyncTrust.isTrusted(isMainFrame: main.isMainFrame, scheme: main.scheme, host: main.host))
        }
        if let sub {
            #expect(!PwaWalletSyncTrust.isTrusted(isMainFrame: sub.isMainFrame, scheme: sub.scheme, host: sub.host))
        }
    }
}
