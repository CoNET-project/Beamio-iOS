import Foundation
import WebKit
import ConetChatSDK

/// The window channel `window.BeamioShellRecord` (spec r3oq (a), §25.52Y.42 item 5, §25.52Y.44; vectors pub6 CP-28/29/30, CN-11).
/// It carries six page commands: walletEoaAddress, walletCredential, shellRecordRead, shellRecordWrite, pwaWalletSync and
/// nativeMnemonicPreread. Each goes to the same SDK handler as on the other paths: the four record and wallet commands to the SDK's
/// window entries (BeamioWindowWallet), the two page-sync commands to the shell's PwaWalletSyncGate (the CashTreesIOS gate).
///
/// - The object is injected at document start in the main frame only, and defines itself only on the fixed origin
///   `cashtrees-local://localhost` in the top frame (the page decides its transport by the object's presence).
/// - Every message is judged again natively: main frame, fixed origin, and the trusted bundle (NativeBridgeTrust). A source or frame
///   mismatch is `origin_refused`; the SDK reads nothing for it. The page-sync commands keep their gate's `untrusted_source` (as on Android).
/// - The reply goes back to the frame that sent the message (§25.52Y.44 item 7), to its `window.BeamioShellRecord.onmessage({data})`.
///   A reply to the trusted main frame runs only if that frame is still the top frame on the fixed origin; an origin_refused reply goes
///   only to the sending frame (a child frame without the object gets nothing). A reply whose reqId differs from the request is dropped;
///   a walletEoaAddress success leaves only with `result` exactly `{eoa}` (a lowercase address).
/// - The CashTreesIOS channel is not changed by this file.
enum CashTreesShellRecordWindow {
    static let handlerName = "BeamioShellRecord"
    static let pageOrigin = "cashtrees-local://localhost"

    static let walletEoaAddress = "walletEoaAddress"
    static let walletCredential = "walletCredential"
    static let shellRecordRead = "shellRecordRead"
    static let shellRecordWrite = "shellRecordWrite"
    static let commands: Set<String> = [
        walletEoaAddress, walletCredential, shellRecordRead, shellRecordWrite,
        PwaWalletSyncBridge.syncCommand, PwaWalletSyncBridge.prereadCommand,
    ]

    /// The SDK entries the channel calls. Tests replace them; the default is the SDK.
    struct Sdk {
        var walletEoaAddress: (_ reqId: Any?, _ trust: WindowTrust, _ emit: ([String: Any]) -> Void) -> Void = { reqId, trust, emit in
            BeamioWindowWallet.walletEoaAddress(reqId: reqId, trust: trust, emit: emit)
        }
        var walletCredential: (_ body: [String: Any], _ trust: WindowTrust, _ emit: ([String: Any]) -> Void) -> Void = { body, trust, emit in
            BeamioWindowWallet.walletCredential(body, trust: trust, emit: emit)
        }
        var shellRecordRead: (_ body: [String: Any], _ trust: WindowTrust, _ emit: ([String: Any]) -> Void) -> Void = { body, trust, emit in
            BeamioWindowWallet.shellRecordRead(body, trust: trust, emit: emit)
        }
        var shellRecordWrite: (_ body: [String: Any], _ trust: WindowTrust, _ emit: ([String: Any]) -> Void) -> Void = { body, trust, emit in
            BeamioWindowWallet.shellRecordWrite(body, trust: trust, emit: emit)
        }
    }

    /// The page-sync gate (PwaWalletSyncGate.handle): command, trusted, reply (the reply is wrapped for the chat event; it is unwrapped here).
    typealias SyncGate = (_ command: [String: Any], _ trusted: Bool, _ reply: @escaping ([String: Any]) -> Void) -> Void

    // MARK: - Source

    /// The shell's verdict for one message. Frame and origin first (originRefused), then the bundle (notTrusted).
    static func trust(isMainFrame: Bool, scheme: String, host: String, port: Int, bundleTrusted: Bool) -> WindowTrust {
        guard isMainFrame,
              scheme.lowercased() == CashTreesPWAScheme.scheme,
              host.lowercased() == CashTreesPWAScheme.host,
              port == 0
        else { return .originRefused }
        return bundleTrusted ? .trusted : .notTrusted
    }

    // MARK: - Request

    /// The page sends `postMessage(JSON.stringify(cmd))`: a JSON object in a string. Anything else is not a request.
    static func parse(_ body: Any) -> [String: Any]? {
        guard let text = body as? String, let data = text.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data), let dict = object as? [String: Any]
        else { return nil }
        return dict
    }

    /// A reqId the reply may echo: a non-negative integer or a non-empty string (as the SDK's echo rule); otherwise null.
    static func echo(_ value: Any?) -> Any {
        if let s = value as? String, !s.isEmpty { return s }
        if let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() {
            let d = n.doubleValue
            if d.isFinite, d >= 0, d == d.rounded(.towardZero) { return n }
        }
        return NSNull()
    }

    static func refusal(reqId: Any?, error: String) -> [String: Any] {
        ["type": "ack", "reqId": echo(reqId), "ok": false, "error": error]
    }

    /// Credential-shaped field names on walletEoaAddress (it takes only type and reqId): refused without echoing a value.
    private static func walletEoaAddressFieldRefusal(_ body: [String: Any]) -> String? {
        if body.keys.contains(where: { PwaWalletSyncBridge.forbiddenCredentialFields.contains($0.lowercased()) }) { return "key_over_bridge_refused" }
        if body.keys.contains(where: { $0 != "type" && $0 != "reqId" }) { return "bad_request" }
        return nil
    }

    // MARK: - Routing

    /// Routes one message. `emit` receives at most one reply (none when the exit filter drops it).
    static func handle(body: Any, trust: WindowTrust, sdk: Sdk = Sdk(), syncGate: SyncGate, emit: @escaping ([String: Any]) -> Void) {
        guard var request = parse(body) else {
            // Not a JSON object: one answer, nothing reaches the SDK. A refused source is refused first.
            emit(refusal(reqId: nil, error: trust == .originRefused ? "origin_refused" : "bad_request"))
            return
        }
        // The page's own trust claim never reaches a handler on this channel.
        request.removeValue(forKey: "trustedOrigin")
        let type = request["type"] as? String ?? ""
        let reqId = request["reqId"]
        let exit: ([String: Any]) -> Void = { reply in
            if let passed = exitFilter(type: type, requestReqId: reqId, reply: reply) { emit(passed) }
        }

        // The page-sync commands: their gate answers (untrusted_source for an untrusted source), as on the CashTreesIOS path and on Android.
        if PwaWalletSyncBridge.handles(request) {
            syncGate(request, trust == .trusted) { wrapped in
                exit((wrapped["event"] as? [String: Any]) ?? wrapped)
            }
            return
        }
        // §25.52Y.44 item 4 / CN-11: a source or frame mismatch is origin_refused, envelope level, exactly once; the SDK is not called.
        if trust == .originRefused {
            exit(refusal(reqId: reqId, error: "origin_refused"))
            return
        }
        switch type {
        case walletEoaAddress:
            if trust == .trusted, let refused = walletEoaAddressFieldRefusal(request) {
                exit(refusal(reqId: reqId, error: refused))
                return
            }
            sdk.walletEoaAddress(reqId, trust, exit)
        case walletCredential:
            sdk.walletCredential(request, trust, exit)
        case shellRecordRead:
            sdk.shellRecordRead(request, trust, exit)
        case shellRecordWrite:
            sdk.shellRecordWrite(request, trust, exit)
        default:
            // An unknown command or an old action without a type: one answer, nothing reaches the SDK.
            exit(refusal(reqId: reqId, error: "bad_request"))
        }
    }

    // MARK: - Exit

    /// The reply leaves only when it is an ack for the same reqId. A walletEoaAddress success leaves only with result exactly {eoa}
    /// (a lowercase 0x address); any other success shape is answered `unavailable` (the page treats it as "no eoa for now", CP-30).
    static func exitFilter(type: String, requestReqId: Any?, reply: [String: Any]) -> [String: Any]? {
        guard reply["type"] as? String == "ack" else { return nil }
        guard sameReqId(echo(requestReqId), reply["reqId"]) else { return nil }
        guard type == walletEoaAddress, reply["ok"] as? Bool == true else { return reply }
        guard let result = reply["result"] as? [String: Any], Set(result.keys) == ["eoa"],
              let eoa = result["eoa"] as? String, PwaWalletSyncBridge.isLowercaseAddress(eoa)
        else { return refusal(reqId: requestReqId, error: "unavailable") }
        return ["type": "ack", "reqId": echo(requestReqId), "ok": true, "result": ["eoa": eoa]]
    }

    static func sameReqId(_ a: Any?, _ b: Any?) -> Bool {
        switch (a, b) {
        case (nil, nil), (is NSNull, nil), (nil, is NSNull), (is NSNull, is NSNull): return true
        case let (x as String, y as String): return x == y
        case let (x as NSNumber, y as NSNumber):
            if CFGetTypeID(x) == CFBooleanGetTypeID() || CFGetTypeID(y) == CFBooleanGetTypeID() { return false }
            return x.doubleValue == y.doubleValue
        default: return false
        }
    }

    // MARK: - Page scripts

    /// Injected at document start, main frame only. Defines the object only on the fixed origin in the top frame; the object cannot be
    /// replaced by the page (non-writable, non-configurable), its postMessage is fixed, and the page sets its own onmessage.
    static func injectionScript() -> String {
        """
        (function(){
          try {
            if (window.top !== window.self) return;
            if (location.protocol !== '\(CashTreesPWAScheme.scheme):' || location.hostname !== '\(CashTreesPWAScheme.host)' || location.port !== '') return;
            if ('\(handlerName)' in window) return;
            var mh = window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers['\(handlerName)'];
            if (!mh) return;
            var obj = {};
            Object.defineProperty(obj, 'postMessage', { value: function(m) { mh.postMessage(typeof m === 'string' ? m : JSON.stringify(m)); }, enumerable: true });
            Object.defineProperty(obj, 'allowedOrigins', { value: Object.freeze(['\(pageOrigin)']), enumerable: true });
            obj.onmessage = null;
            Object.defineProperty(window, '\(handlerName)', { value: obj, writable: false, configurable: false, enumerable: false });
          } catch (e) {}
        })();
        """
    }

    /// The reply script: hands the ack, as a JSON string, to the frame's onmessage. nil when the reply cannot be encoded.
    /// `requireFixedTopOrigin`: the script runs only in the top frame on cashtrees-local://localhost (a reply to the trusted main frame
    /// never reaches a page the frame navigated to after the request).
    static func deliveryScript(_ reply: [String: Any], requireFixedTopOrigin: Bool = true) -> String? {
        guard JSONSerialization.isValidJSONObject(reply),
              let json = try? JSONSerialization.data(withJSONObject: reply, options: [.sortedKeys]),
              let jsonText = String(data: json, encoding: .utf8),
              let literalData = try? JSONSerialization.data(withJSONObject: [jsonText]),
              var literal = String(data: literalData, encoding: .utf8)
        else { return nil }
        // [ "..." ] → "..." : a JSON string literal is a valid JS string literal; U+2028 and U+2029 are escaped as well.
        literal = String(literal.dropFirst().dropLast())
            .replacingOccurrences(of: "\u{2028}", with: "\\u2028")
            .replacingOccurrences(of: "\u{2029}", with: "\\u2029")
        let guardText = requireFixedTopOrigin
            ? "if(window.top!==window.self)return;if(location.protocol!=='\(CashTreesPWAScheme.scheme):'||location.hostname!=='\(CashTreesPWAScheme.host)'||location.port!=='')return;"
            : ""
        return "(function(){\(guardText)var o=window.\(handlerName);if(o&&typeof o.onmessage==='function'){o.onmessage({data:\(literal)});}})();"
    }

    /// Whether a reply is held to the top frame on the fixed origin: every reply except one to a refused source (that one goes only
    /// to the sending frame, whatever it is).
    static func requiresFixedTopOrigin(trust: WindowTrust, senderIsMainFrame: Bool) -> Bool {
        trust != .originRefused && senderIsMainFrame
    }

    /// Delivers one reply to the frame that sent the message, in the page world.
    @MainActor
    static func deliver(_ reply: [String: Any], trust: WindowTrust, to frame: WKFrameInfo, in webView: WKWebView) {
        guard let script = deliveryScript(reply, requireFixedTopOrigin: requiresFixedTopOrigin(trust: trust, senderIsMainFrame: frame.isMainFrame))
        else { return }
        webView.evaluateJavaScript(script, in: frame, in: .page, completionHandler: nil)
    }
}
