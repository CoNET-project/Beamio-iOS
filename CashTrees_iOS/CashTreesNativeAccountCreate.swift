import ConetChatSDK
import Foundation

/// New-account onboarding on the PWA page. The shell has no create UI.
///
/// - `nativeAccountCreateOpen` (SDK command) calls `BeamioNativeAccountCreate.onCreateRequired`. The shell answers true and
///   runs the SDK creation in the background; the SDK sends the one `nativeAccountCreateResult` itself (eoa only, never a
///   phrase or a key). Nothing is presented.
/// - `accountCreateRegister {reqId, tag, password}` comes from the trusted page only (main frame, fixed local origin,
///   trusted bundle) and is forwarded to the SDK unchanged; the same command over `chatModuleCommand` is refused.
/// - `secureScreen {on}` asks for the app-switcher cover while the page shows the recovery code.
///
/// Nothing here logs, stores or echoes a tag, a password or a recovery code.

/// The headless creation. `create()` needs the SDK's page to be open, which the SDK records only after the host
/// returns; until then it answers `not_available` (never sent to the page), so the attempt is repeated briefly.
final class CashTreesAccountCreateSession {
    static let shared = CashTreesAccountCreateSession()

    var create: () -> BeamioNativeAccountCreate.CreateOutcome = { BeamioNativeAccountCreate.create() }
    var close: () -> Bool = { BeamioNativeAccountCreate.close() }
    /// Where the creation runs. Tests run it inline.
    var work: (@escaping () -> Void) -> Void = { job in DispatchQueue.global(qos: .userInitiated).async(execute: job) }
    /// The pause between attempts while the page is not open yet. Tests use 0.
    var retryDelay: TimeInterval = 0.05
    static let maxAttempts = 40

    private let lock = NSLock()
    private var running = false

    var isRunning: Bool { lock.lock(); defer { lock.unlock() }; return running }

    /// `onCreateRequired`: starts one background creation. Always true (the SDK refuses a second page itself).
    func start() -> Bool {
        lock.lock()
        if running { lock.unlock(); return true }
        running = true
        lock.unlock()
        BeamioQALog.write("native account create started")
        work { [weak self] in
            guard let self else { return }
            var outcome = self.create()
            var attempts = 1
            while outcome == .failed(.notAvailable), attempts < Self.maxAttempts {
                if self.retryDelay > 0 { Thread.sleep(forTimeInterval: self.retryDelay) }
                outcome = self.create()
                attempts += 1
            }
            self.lock.lock(); self.running = false; self.lock.unlock()
            switch outcome {
            case .ok: BeamioQALog.write("native account create ok")
            case .failed(let code): BeamioQALog.write("native account create \(code.rawValue)")
            }
        }
        return true
    }

    /// A page reload, a navigation away or a content-process exit: the page that opened the creation is gone.
    /// The SDK sends `cancelled` only when no result was produced for that page.
    func pageLeft() {
        _ = close()
    }
}

/// Installs the headless host for the SDK (`onCreateRequired`).
enum CashTreesNativeAccountCreateRoute {
    private static let lock = NSLock()
    private static var installed = false

    static func installOnce() {
        lock.lock()
        defer { lock.unlock() }
        guard !installed else { return }
        installed = true
        BeamioNativeAccountCreate.onCreateRequired = { CashTreesAccountCreateSession.shared.start() }
    }
}

/// The page actions of the create flow and their answers.
enum CashTreesAccountCreateBridge {
    static let registerAction = "accountCreateRegister"
    static let secureScreenAction = "secureScreen"
    /// Declared to the page in `window.__CT_IOS_CAPS__`.
    static let capability = "account.page-create.v1"

    static func handles(_ action: String) -> Bool { action == registerAction || action == secureScreenAction }

    /// The SDK command for a trusted `accountCreateRegister` body, or nil (bad_request). Only `reqId`, `tag` and `password`
    /// are carried; their contents are judged by the SDK.
    static func registerCommand(from body: [String: Any]) -> [String: Any]? {
        guard Set(body.keys).isSubset(of: ["action", "reqId", "tag", "password"]) else { return nil }
        guard let reqId = body["reqId"], reqId is NSNumber || reqId is String,
              let tag = body["tag"] as? String, let password = body["password"] as? String
        else { return nil }
        return ["type": registerAction, "reqId": reqId, "tag": tag, "password": password]
    }

    /// A refused `accountCreateRegister`, in the SDK's ack envelope (a chatModuleEvent), never echoing a field but the reqId.
    static func refusal(reqId: Any?, error: String) -> [String: Any] {
        let echo: Any = (reqId is NSNumber || reqId is String) ? reqId! : NSNull()
        return ["action": "chatModuleEvent", "event": ["type": "ack", "reqId": echo, "ok": false, "error": error]]
    }

    /// `secureScreen {on}`: the answer, after applying it to the shield. `trusted` as for the recovery actions.
    static func secureScreenAnswer(body: [String: Any], trusted: Bool, shield: CashTreesG0PrivacyShield) -> [String: Any] {
        guard trusted else { return ["action": secureScreenAction, "ok": false, "error": "origin_refused"] }
        guard Set(body.keys).isSubset(of: ["action", "on"]), let on = body["on"] as? Bool else {
            return ["action": secureScreenAction, "ok": false, "error": "bad_args"]
        }
        shield.setSecureScreen(on)
        return ["action": secureScreenAction, "ok": true]
    }
}
