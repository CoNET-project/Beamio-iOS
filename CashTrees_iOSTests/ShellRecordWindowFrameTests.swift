import Foundation
import Testing
import WebKit
import ConetChatSDK
@testable import CashTrees_iOS

// §25.52Y.44 item 7 (review R-1): a window-channel reply goes back to the frame that sent the message. Real WKWebView, synthetic pages
// under the embedded scheme (a main frame and one same-origin child frame), a stand-in SDK. No app data, no network.

private final class FramePagesHandler: NSObject, WKURLSchemeHandler {
    func webView(_ webView: WKWebView, start urlSchemeTask: WKURLSchemeTask) {
        guard let url = urlSchemeTask.request.url else { urlSchemeTask.didFailWithError(URLError(.badURL)); return }
        let html = url.path == "/main.html"
            ? "<!doctype html><html><body>main<iframe src=\"cashtrees-local://localhost/frame.html\"></iframe></body></html>"
            : "<!doctype html><html><body>frame</body></html>"
        let data = Data(html.utf8)
        urlSchemeTask.didReceive(HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1",
                                                 headerFields: ["Content-Type": "text/html", "Content-Length": String(data.count)])!)
        urlSchemeTask.didReceive(data)
        urlSchemeTask.didFinish()
    }
    func webView(_ webView: WKWebView, stop urlSchemeTask: WKURLSchemeTask) {}
}

/// The shell side as ContentView wires it: verdict per message (the bundle counted as trusted here), routing, delivery to the sender.
@MainActor
private final class WindowChannelHost: NSObject, WKScriptMessageHandler {
    weak var webView: WKWebView?
    var childFrame: WKFrameInfo?
    var mainFrame: WKFrameInfo?
    var delivered = 0

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        let frame = message.frameInfo
        if frame.isMainFrame { mainFrame = frame } else { childFrame = frame }
        let trust = CashTreesShellRecordWindow.trust(isMainFrame: frame.isMainFrame, scheme: frame.securityOrigin.protocol,
                                                     host: frame.securityOrigin.host, port: frame.securityOrigin.port, bundleTrusted: true)
        var sdk = CashTreesShellRecordWindow.Sdk()
        sdk.walletEoaAddress = { reqId, _, emit in
            emit(["type": "ack", "reqId": reqId ?? NSNull(), "ok": true, "result": ["eoa": "0x" + String(repeating: "1", count: 40)]])
        }
        CashTreesShellRecordWindow.handle(body: message.body, trust: trust, sdk: sdk, syncGate: { _, _, _ in }) { [weak self] reply in
            guard let self, let webView = self.webView else { return }
            CashTreesShellRecordWindow.deliver(reply, trust: trust, to: frame, in: webView)
            self.delivered += 1
        }
    }
}

/// Reports load state from WebKit: the main navigation's finish or failure, and each frame's "ready" message (sent by the page script
/// once that frame's document has run), with its WKFrameInfo. The test sends nothing before both frames are ready.
@MainActor
private final class LoadWatcher: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
    var mainFinished = false
    var navigationError: String?
    var mainReady: WKFrameInfo?
    var childReady: WKFrameInfo?
    var readyURLs: [String] = []

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { mainFinished = true }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { navigationError = "\(error)" }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { navigationError = "\(error)" }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        readyURLs.append("\(message.frameInfo.isMainFrame ? "main" : "child")=\(message.frameInfo.request.url?.absoluteString ?? "?")")
        if message.frameInfo.isMainFrame { mainReady = message.frameInfo } else { childReady = message.frameInfo }
    }

    var allReady: Bool { mainFinished && mainReady != nil && childReady != nil }
}

@MainActor
struct ShellRecordWindowFrameTests {
    /// Every frame records what reaches its own `window.BeamioShellRecord.onmessage`. The main frame has the injected object; the child
    /// frame (which gets no injection) defines a look-alike object, so a reply sent there would be visible. Each frame then reports ready;
    /// the messages are sent by the test, after both frames are ready (no timer).
    private static let pageScript = """
    (function(){
      window.__got = [];
      if (window.top === window.self) {
        window.BeamioShellRecord.onmessage = function(e){ window.__got.push(JSON.parse(e.data)); };
      } else {
        window.BeamioShellRecord = { onmessage: function(e){ window.__got.push(JSON.parse(e.data)); } };
      }
      window.webkit.messageHandlers.FrameReady.postMessage(location.href);
    })();
    """
    private static let readyHandler = "FrameReady"

    private func run(_ js: String, _ webView: WKWebView, in frame: WKFrameInfo?) async -> Any? {
        await withCheckedContinuation { cont in
            webView.evaluateJavaScript(js, in: frame, in: .page) { result in
                if case .success(let value) = result { cont.resume(returning: value) } else { cont.resume(returning: nil) }
            }
        }
    }

    private func got(_ webView: WKWebView, in frame: WKFrameInfo?) async -> [[String: Any]] {
        guard let text = await run("JSON.stringify(window.__got || [])", webView, in: frame) as? String,
              let list = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [[String: Any]] else { return [] }
        return list
    }

    /// Polls `condition` every 50 ms up to `seconds`.
    private func wait(_ seconds: TimeInterval, _ condition: () async -> Bool) async throws -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if await condition() { return true }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        return await condition()
    }

    @Test func aChildFrameReplyGoesToTheChildFrameAndNeverToTheMainFrame() async throws {
        let host = WindowChannelHost()
        let watcher = LoadWatcher()
        let config = WKWebViewConfiguration()
        config.setURLSchemeHandler(FramePagesHandler(), forURLScheme: CashTreesPWAScheme.scheme)
        config.userContentController.add(host, name: CashTreesShellRecordWindow.handlerName)
        config.userContentController.add(watcher, name: Self.readyHandler)
        defer {
            config.userContentController.removeScriptMessageHandler(forName: CashTreesShellRecordWindow.handlerName)
            config.userContentController.removeScriptMessageHandler(forName: Self.readyHandler)
        }
        config.userContentController.addUserScript(WKUserScript(source: CashTreesShellRecordWindow.injectionScript(),
                                                                injectionTime: .atDocumentStart, forMainFrameOnly: true))
        config.userContentController.addUserScript(WKUserScript(source: Self.pageScript, injectionTime: .atDocumentEnd, forMainFrameOnly: false))
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = watcher
        host.webView = webView
        webView.load(URLRequest(url: CashTreesPWAScheme.entryURL(path: "/main.html")))

        func diagnostics(_ stage: String) -> String {
            "stage=\(stage) mainFinished=\(watcher.mainFinished) navigationError=\(watcher.navigationError ?? "none") ready=\(watcher.readyURLs) "
                + "delivered=\(host.delivered) mainFrame=\(host.mainFrame?.request.url?.absoluteString ?? "-") childFrame=\(host.childFrame?.request.url?.absoluteString ?? "-")"
        }

        // 1. Both frames loaded (main didFinish, and each frame's ready report). A cold simulator can be slow: up to 60 s.
        let loaded = try await wait(60) { watcher.allReady }
        Attachment.record(diagnostics("loaded"), named: "window-channel-frames-load.txt")
        try #require(loaded, Comment(rawValue: diagnostics("load")))

        // 2. Each frame sends its own message, from its own context.
        _ = await run("window.BeamioShellRecord.postMessage(JSON.stringify({type:'walletEoaAddress', reqId: 8})); true", webView, in: watcher.mainReady)
        _ = await run("window.webkit.messageHandlers.BeamioShellRecord.postMessage(JSON.stringify({type:'walletEoaAddress', reqId: 7})); true",
                      webView, in: watcher.childReady)

        // 3. Both replies delivered, then each frame's onmessage has run (polled, no fixed sleep).
        let delivered = try await wait(30) { host.delivered >= 2 }
        try #require(delivered, Comment(rawValue: diagnostics("deliver")))
        var mainGot: [[String: Any]] = []
        var childGot: [[String: Any]] = []
        _ = try await wait(10) {
            mainGot = await got(webView, in: watcher.mainReady)
            childGot = await got(webView, in: watcher.childReady)
            return !mainGot.isEmpty && !childGot.isEmpty
        }
        // a short settle, then read again: a stray cross-frame reply would show up here
        try await Task.sleep(nanoseconds: 200_000_000)
        mainGot = await got(webView, in: watcher.mainReady)
        childGot = await got(webView, in: watcher.childReady)
        Attachment.record("\(diagnostics("result")) main=\(mainGot) child=\(childGot)", named: "window-channel-frames.txt")

        #expect(host.delivered == 2, Comment(rawValue: "one reply for each frame's message; " + diagnostics("result")))
        #expect(host.childFrame != nil, "the child frame posted to the handler")
        #expect(mainGot.count == 1, Comment(rawValue: "the main frame sees only its own reply; main=\(mainGot)"))
        #expect((mainGot.first?["reqId"] as? NSNumber)?.intValue == 8)
        #expect(mainGot.first?["ok"] as? Bool == true)
        #expect(!mainGot.contains { ($0["reqId"] as? NSNumber)?.intValue == 7 }, "R-1: the child frame's origin_refused never reaches the main page")
        #expect(childGot.count == 1, Comment(rawValue: "the child frame gets its own reply; child=\(childGot)"))
        #expect((childGot.first?["reqId"] as? NSNumber)?.intValue == 7)
        #expect(childGot.first?["error"] as? String == "origin_refused" && childGot.first?["result"] == nil)
    }

    @Test func onlyARefusedSourceReplySkipsTheTopFrameOriginCheck() throws {
        typealias W = CashTreesShellRecordWindow
        #expect(W.requiresFixedTopOrigin(trust: .trusted, senderIsMainFrame: true))
        #expect(W.requiresFixedTopOrigin(trust: .notTrusted, senderIsMainFrame: true))
        #expect(!W.requiresFixedTopOrigin(trust: .originRefused, senderIsMainFrame: false))
        #expect(!W.requiresFixedTopOrigin(trust: .originRefused, senderIsMainFrame: true))
        let held = try #require(W.deliveryScript(["type": "ack", "reqId": 1, "ok": true, "result": ["eoa": "0x" + String(repeating: "a", count: 40)]]))
        #expect(held.contains("window.top!==window.self") && held.contains("location.protocol!=='cashtrees-local:'")
                && held.contains("location.hostname!=='localhost'") && held.contains("location.port!==''"))
        let refused = try #require(W.deliveryScript(["type": "ack", "reqId": 1, "ok": false, "error": "origin_refused"], requireFixedTopOrigin: false))
        #expect(!refused.contains("window.top!==window.self"))
    }
}
