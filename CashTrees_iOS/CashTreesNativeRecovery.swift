import ConetChatSDK
import Foundation
import UIKit

/// Onboarding recovery without a native page. The recovery form is the PWA page; the shell has no recovery UI.
///
/// - `nativeRecoveryOpen` (SDK command) calls `BeamioNativeRecovery.onRecoveryRequired`. The shell only opens a session and
///   answers true; nothing is presented.
/// - The trusted PWA (main frame, verified bundle) sends `nativeRecoverySubmit` with the recovery code, or the BeamioTag and
///   password. The shell turns the secret into bytes, hands it to the SDK recovery engine off the main queue and wipes its
///   copy. The SDK sends the one `nativeRecoveryResult` for the session (reqId of the open) through `finish`.
/// - `nativeRecoveryCancel`, a page reload or navigation, a content-process exit, or more than `backgroundTimeout` in the background
///   ends the session with `cancelled`.
/// - The engine itself refuses a device that already has a native key (`already_exists`); nothing is switched or overwritten.
///
/// Nothing here logs, stores or echoes a code, a name or a password; only the action and the result code are written.

/// Result codes of `nativeRecoveryResult` (§25.42.8).
enum CashTreesRecoveryCode: String, CaseIterable {
    case ok, cancelled
    case invalidFormat = "invalid_format"
    case badPin = "bad_pin"
    case backoff
    case notFound = "not_found"
    case networkError = "network_error"
    case alreadyExists = "already_exists"
    case recordInvalid = "record_invalid"
    case writeFailed = "write_failed"
    case readbackFailed = "readback_failed"
    case legacyRecord = "legacy_record"
    case notSupported = "not_supported"
}

/// What reaches the engine. The secret is bytes the engine wipes after use.
enum CashTreesRecoveryRequest {
    case code(secret: [UInt8])
    case account(name: String, password: [UInt8])
}

/// The engine seam: `CashTreesSdkRecoveryEngine` in the app, a fake in tests. `restore` runs off the main queue.
protocol CashTreesRecoveryEngine: AnyObject {
    /// One attempt. Returns the result code, the account (ok only) and the cooldown (backoff only). Wipes the secret.
    func restore(_ request: CashTreesRecoveryRequest) -> (code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?)
    /// Sends the session's result to the page (the SDK `nativeRecoveryResult`). Main queue.
    func finish(_ code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?)
}

/// The SDK engine (BeamioNativeRecovery, spec 25.42.5).
final class CashTreesSdkRecoveryEngine: CashTreesRecoveryEngine {
    func restore(_ request: CashTreesRecoveryRequest) -> (code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?) {
        let outcome: BeamioNativeRecovery.RestoreOutcome
        switch request {
        case .code(var bytes):
            // The SDK takes the code as a String (recorded limit: Swift strings cannot be wiped, §25.42.9).
            let code = String(decoding: bytes, as: UTF8.self)
            for i in bytes.indices { bytes[i] = 0 }
            outcome = BeamioNativeRecovery.restore(.recoveryCode(code))
        case .account(let name, var password):
            outcome = BeamioNativeRecovery.restore(.account(name: name, password: password))
            for i in password.indices { password[i] = 0 }
        }
        let (code, eoa, cooldown) = Self.map(outcome)
        return (CashTreesRecoveryCode(rawValue: code.rawValue) ?? .notSupported, eoa, cooldown)
    }

    func finish(_ code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?) {
        let sdkCode = BeamioNativeRecovery.ResultCode(rawValue: code.rawValue) ?? .notSupported
        BeamioNativeRecovery.finish(sdkCode, eoa: eoa, cooldownSec: cooldownSec)
    }

    static func map(_ o: BeamioNativeRecovery.RestoreOutcome) -> (BeamioNativeRecovery.ResultCode, String?, Int?) {
        switch o {
        case .ok(let eoa): return (.ok, eoa, nil)
        case .backoff(let s): return (.backoff, nil, s)
        case .failed(let c): return (c, nil, nil)
        }
    }
}

/// The headless recovery session. Main-queue state; one submit in flight at a time.
final class CashTreesRecoverySession {
    static let shared = CashTreesRecoverySession()

    /// The answer to a page action, before any result.
    enum Answer: String {
        case accepted
        case notAvailable = "not_available"
        case badArgs = "bad_args"
    }

    private(set) var isOpen = false
    private(set) var inFlight = false
    /// A cancel (or reset) that came while an attempt was running: applied when it returns.
    private var cancelPending = false

    var engine: CashTreesRecoveryEngine
    /// Where `restore` runs. Tests run it inline.
    var work: (@escaping () -> Void) -> Void = { job in DispatchQueue.global(qos: .userInitiated).async(execute: job) }
    /// How the result comes back to the main queue. Tests run it inline.
    var main: (@escaping () -> Void) -> Void = { job in DispatchQueue.main.async(execute: job) }

    init(engine: CashTreesRecoveryEngine = CashTreesSdkRecoveryEngine()) {
        self.engine = engine
    }

    /// `onRecoveryRequired`: opens the session. Nothing is presented. Always true (the SDK refuses a second open itself).
    func open() -> Bool {
        isOpen = true
        cancelPending = false
        BeamioQALog.write("native recovery session opened")
        return true
    }

    /// `nativeRecoverySubmit`. `args` is the page body; only `path` and its fields are read.
    func submit(_ args: [String: Any]) -> Answer {
        guard isOpen, !inFlight, !cancelPending else { return .notAvailable }
        guard let request = Self.request(from: args) else { return .badArgs }
        inFlight = true
        BeamioQALog.write("native recovery submit")
        let engine = self.engine
        work { [weak self] in
            let result = engine.restore(request)
            self?.main { self?.complete(result) }
        }
        return .accepted
    }

    /// `nativeRecoveryCancel`: ends the open session with `cancelled`. While an attempt runs, the cancel waits for it.
    func cancel() -> Answer {
        guard isOpen else { return .notAvailable }
        if inFlight {
            cancelPending = true
            return .accepted
        }
        close(with: .cancelled)
        return .accepted
    }

    /// How long the app may stay in the background with an open session. Longer: the session ends with `cancelled` on return.
    static let backgroundTimeout: TimeInterval = 300  // the same on both platforms: room to fetch the code from a password manager
    private var backgroundedAt: Date?

    func noteDidEnterBackground(now: Date = Date()) {
        backgroundedAt = now
    }

    func noteWillEnterForeground(now: Date = Date()) {
        defer { backgroundedAt = nil }
        guard let since = backgroundedAt, now.timeIntervalSince(since) >= Self.backgroundTimeout else { return }
        reset()
    }

    /// A page reload, a navigation away, a content-process exit or a background timeout: the page that opened the session is gone.
    func reset() {
        guard isOpen else { return }
        if inFlight { cancelPending = true } else { close(with: .cancelled) }
    }

    private func complete(_ result: (code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?)) {
        inFlight = false
        BeamioQALog.write("native recovery result \(result.code.rawValue)")  // the code only, never the input
        if result.code == .ok {
            // the key is written: the page must learn it, whatever a pending cancel says
            cancelPending = false
            isOpen = false
            engine.finish(.ok, eoa: result.eoa, cooldownSec: nil)
            return
        }
        if cancelPending {
            close(with: .cancelled)
            return
        }
        // a failure keeps the session open for a retry (§25.42.8)
        engine.finish(result.code, eoa: nil, cooldownSec: result.cooldownSec)
    }

    private func close(with code: CashTreesRecoveryCode) {
        cancelPending = false
        isOpen = false
        engine.finish(code, eoa: nil, cooldownSec: nil)
    }

    /// The page args → an engine request, or nil (`bad_args`). Both platforms check the shape and the UTF-8 length only:
    /// the formats (the recovery code, the BeamioTag) are judged by the engine, which answers `invalid_format`; nothing is
    /// normalised here.
    static let maxCodeBytes = 64
    static let maxNameBytes = 128
    static let maxPasswordBytes = 256

    static func request(from args: [String: Any]) -> CashTreesRecoveryRequest? {
        guard let path = args["path"] as? String else { return nil }
        let allowed: Set<String>
        switch path {
        case "code": allowed = ["action", "path", "code"]
        case "account": allowed = ["action", "path", "name", "password"]
        default: return nil
        }
        guard Set(args.keys).isSubset(of: allowed) else { return nil }
        if path == "code" {
            guard let code = args["code"] as? String, code.utf8.count <= maxCodeBytes else { return nil }
            return .code(secret: Array(code.utf8))
        }
        guard let name = args["name"] as? String, name.utf8.count <= maxNameBytes,
              let password = args["password"] as? String, password.utf8.count <= maxPasswordBytes
        else { return nil }
        return .account(name: name, password: Array(password.utf8))
    }
}

/// Installs the headless host for the SDK (`onRecoveryRequired`).
enum CashTreesNativeRecoveryRoute {
    private static let lock = NSLock()
    private static var installed = false
    private static var observers: [NSObjectProtocol] = []

    static func installOnce() {
        lock.lock()
        defer { lock.unlock() }
        guard !installed else { return }
        installed = true
        let nc = NotificationCenter.default
        observers.append(nc.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main) { _ in
            CashTreesRecoverySession.shared.noteDidEnterBackground()
        })
        observers.append(nc.addObserver(forName: UIApplication.willEnterForegroundNotification, object: nil, queue: .main) { _ in
            CashTreesRecoverySession.shared.noteWillEnterForeground()
        })
        BeamioNativeRecovery.onRecoveryRequired = { _ in
            if Thread.isMainThread { return CashTreesRecoverySession.shared.open() }
            return DispatchQueue.main.sync { CashTreesRecoverySession.shared.open() }
        }
    }
}

/// The page actions of the headless recovery (`nativeRecoverySubmit`, `nativeRecoveryCancel`) and their answers.
enum CashTreesRecoveryBridge {
    static let submitAction = "nativeRecoverySubmit"
    static let cancelAction = "nativeRecoveryCancel"
    /// Declared to the page in `window.__CT_IOS_CAPS__`.
    static let capability = "recovery.page-input.v1"

    static func handles(_ action: String) -> Bool { action == submitAction || action == cancelAction }

    /// Each check on its own (the capability is a hint for the page, never trust): the main frame, the fixed local origin
    /// (`cashtrees-local://localhost`, no port), and the shell's bundle trust (NativeBridgeTrust) for this message.
    static func isTrustedSource(isMainFrame: Bool, scheme: String, host: String, port: Int, bundleTrusted: Bool) -> Bool {
        isMainFrame
            && scheme.lowercased() == CashTreesPWAScheme.scheme
            && host.lowercased() == CashTreesPWAScheme.host
            && port == 0
            && bundleTrusted
    }

    /// `trusted`: the shell's bundle trust for this message AND the main frame. An untrusted source reaches no engine.
    /// The answer carries the action and the outcome only; it never echoes an arg.
    static func answer(action: String, body: [String: Any], trusted: Bool, session: CashTreesRecoverySession) -> [String: Any] {
        guard trusted else { return ["action": action, "ok": false, "error": "origin_refused"] }
        let outcome = action == submitAction ? session.submit(body) : session.cancel()
        if outcome == .accepted { return ["action": action, "ok": true] }
        return ["action": action, "ok": false, "error": outcome.rawValue]
    }
}

/// Input checks kept from the removed native page. The engine does its own checks; these stay for reuse and their tests.
enum CashTreesNativeRecoveryInput {
    /// ASCII whitespace trimmed from both ends of the recovery code.
    private static let asciiSpace = CharacterSet(charactersIn: " \t\n\r\u{0B}\u{0C}")
    private static let alnum = CharacterSet(charactersIn: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

    /// Path A: 22 characters of [0-9A-Za-z] after trimming ASCII whitespace. Nil means `invalid_format`.
    static func normalizedCode(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: asciiSpace)
        guard s.unicodeScalars.count == 22, s.unicodeScalars.allSatisfy({ alnum.contains($0) }) else { return nil }
        return s
    }

    /// Path B, the BeamioTag rule of the PWA (beamio-UI `normalizeBeamioTagInput`, then `BEAMIO_TAG_PATTERN`): every "@" removed,
    /// trimmed, NFKC, zero-width characters (U+200B to U+200D, U+FEFF) removed; then 3 to 26 characters of [a-zA-Z0-9_.].
    /// Case is kept (the registry key is case-sensitive). Nil means the name is not a BeamioTag: no query is made.
    static func beamioTagName(_ raw: String) -> String? {
        let noAt = raw.replacingOccurrences(of: "@", with: "")
        let trimmed = noAt.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalised = trimmed.precomposedStringWithCompatibilityMapping
        var stripped = String.UnicodeScalarView()
        stripped.append(contentsOf: normalised.unicodeScalars.filter { !((0x200B ... 0x200D).contains($0.value) || $0.value == 0xFEFF) })
        let name = String(stripped)
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.")
        guard (3 ... 26).contains(name.unicodeScalars.count), name.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return nil }
        return name
    }

    static func wipe(_ request: CashTreesRecoveryRequest) {
        switch request {
        case .code(var s): for i in s.indices { s[i] = 0 }
        case .account(_, var p): for i in p.indices { p[i] = 0 }
        }
    }
}
