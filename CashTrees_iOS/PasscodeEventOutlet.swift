import Foundation

/// The document that the last trusted reply came from (frozen passcode protocol v1, section one, item 4).
nonisolated struct PasscodeReplyProxy: Equatable, Sendable {
    let scheme: String
    let host: String
    let port: Int
    let documentURL: String
    let documentTreeSHA256: String
}

/// Delivery of the passcode events to the page. An event goes out only when the page that is loaded now is the same trusted
/// document that sent the last trusted request. Pure decisions, so they are testable without a web view.
nonisolated enum PasscodeEventOutlet {
    /// The event types routed through this outlet (`chatModuleEvent`, `event.type`).
    static let eventTypes: Set<String> = ["passcodeState", "nativeRepairRequest", "nativeRepairResult", "nativeCallHangup"]

    enum Decision: String, Equatable {
        case deliver
        /// No trusted request has been seen on this channel (or the channel was rebuilt): nothing is sent.
        case noEventTarget = "no_event_target"
        /// The current document is not the trusted document that sent the last request (remote, sub-frame, changed tree).
        case mismatch
    }

    /// Whether a payload is a passcode event. Other events keep their existing path.
    static func isPasscodeEvent(_ payload: [String: Any]) -> Bool {
        guard payload["action"] as? String == "chatModuleEvent",
              let event = payload["event"] as? [String: Any],
              let type = event["type"] as? String
        else { return false }
        return eventTypes.contains(type)
    }

    /// Log fields for a passcode event: the type and the reqId only, never a value of any credential field.
    static func logFields(_ payload: [String: Any]) -> String {
        let event = payload["event"] as? [String: Any]
        let type = (event?["type"] as? String) ?? "?"
        let reqId = event?["reqId"].map { "\($0)" } ?? "-"
        return "type=\(type) reqId=\(reqId)"
    }

    /// The proxy of a request or of the current document. nil unless the trust gate passed.
    static func proxy(
        trusted: Bool,
        scheme: String,
        host: String,
        port: Int,
        documentURL: String?,
        documentTreeSHA256: String?
    ) -> PasscodeReplyProxy? {
        guard trusted, let documentURL, let documentTreeSHA256 else { return nil }
        return PasscodeReplyProxy(
            scheme: scheme.lowercased(),
            host: host.lowercased(),
            port: port,
            documentURL: documentURL,
            documentTreeSHA256: documentTreeSHA256.lowercased()
        )
    }

    /// Delivery decision. `recorded` is the last trusted reply's proxy; `current` is the loaded document's proxy (nil when untrusted).
    static func decide(recorded: PasscodeReplyProxy?, current: PasscodeReplyProxy?) -> Decision {
        guard let recorded else { return .noEventTarget }
        guard let current, current == recorded else { return .mismatch }
        return .deliver
    }
}

/// The recorded reply proxy of one window channel. Only a trusted request updates it; a rebuilt channel starts empty.
final class PasscodeReplyProxyStore {
    private let lock = NSLock()
    private var proxy: PasscodeReplyProxy?

    /// Records a trusted proxy. nil (an untrusted request) leaves the last trusted proxy in place.
    func record(_ next: PasscodeReplyProxy?) {
        guard let next else { return }
        lock.lock()
        proxy = next
        lock.unlock()
    }

    func current() -> PasscodeReplyProxy? {
        lock.lock()
        defer { lock.unlock() }
        return proxy
    }

    /// Clears the proxy: called when the channel is created or torn down.
    func reset() {
        lock.lock()
        proxy = nil
        lock.unlock()
    }
}
