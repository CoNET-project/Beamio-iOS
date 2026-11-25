import Foundation
import Testing
@testable import CashTrees_iOS

// The shell cases of native-recovery-page-input-vectors.v1 (pub3, 46 cases), materialised with synthetic values only.
// The vectors write the request as {action, args:{...}}; the iOS page bridge posts the same fields flat in the message body
// ({action, path, code} or {action, path, name, password}), so `args` here is the body without the action.
// Cases that are page-side (RP-09, RP-10), Android-only (RN-01, RP-14, RP-15, RN-19), SDK-side (RN-13) or runtime
// (RN-15 canary) are not in this file; RP-12, RP-13, RP-16 and RN-14 are covered by NativeRecoverySessionTests and
// NativeRecoveryTrustTests.

private final class VectorEngine: CashTreesRecoveryEngine {
    var answer: (code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?) = (.ok, "0x0000000000000000000000000000000000000001", nil)
    private(set) var calls = 0
    private(set) var finishes: [String] = []
    func restore(_ request: CashTreesRecoveryRequest) -> (code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?) {
        calls += 1
        return answer
    }
    func finish(_ code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?) { finishes.append(code.rawValue) }
}

private struct Env {
    var mainFrame = true
    var scheme = "cashtrees-local"
    var host = "localhost"
    var port = 0
    var bundleTrusted = true
    var sessionOpen = true
}

/// One vector run: a fresh session in the given environment, then the action. Returns the answer and the engine.
private func run(_ action: String, _ args: [String: Any], env: Env = Env(), engineAnswer: CashTreesRecoveryCode = .ok) -> ([String: Any], VectorEngine) {
    let engine = VectorEngine()
    engine.answer = (engineAnswer, engineAnswer == .ok ? "0x0000000000000000000000000000000000000001" : nil, nil)
    let session = CashTreesRecoverySession(engine: engine)
    session.work = { $0() }
    session.main = { $0() }
    if env.sessionOpen { _ = session.open() }
    let trusted = CashTreesRecoveryBridge.isTrustedSource(isMainFrame: env.mainFrame, scheme: env.scheme, host: env.host, port: env.port, bundleTrusted: env.bundleTrusted)
    var body = args
    body["action"] = action
    return (CashTreesRecoveryBridge.answer(action: action, body: body, trusted: trusted, session: session), engine)
}

private func isOk(_ a: [String: Any], _ action: String = "nativeRecoverySubmit") -> Bool {
    a as NSDictionary == ["action": action, "ok": true] as NSDictionary
}

private func isError(_ a: [String: Any], _ error: String, _ action: String = "nativeRecoverySubmit") -> Bool {
    a as NSDictionary == ["action": action, "ok": false, "error": error] as NSDictionary
}

private let code22 = "Syn0Code0Value0Abcdefg"  // 22 characters, synthetic
private let tag = "syn_vector_tag"
private let pw = "Syn-Vector-Pw-01"
private func ascii(_ n: Int) -> String { String(repeating: "a", count: n) }
private func loneSurrogates(_ n: Int) -> String {
    NSString(characters: [UInt16](repeating: 0xD800, count: n), length: n) as String
}

@MainActor
struct NativeRecoveryPageInputVectorTests {
    // MARK: positive

    @Test func rp01_rp02_bothPathsAreAcceptedOnceWithoutEcho() {
        for args: [String: Any] in [["path": "code", "code": code22], ["path": "account", "name": tag, "password": pw]] {
            let (a, e) = run("nativeRecoverySubmit", args)
            #expect(isOk(a) && e.calls == 1, "\(args["path"]!)")
            #expect(!String(describing: a).contains(code22) && !String(describing: a).contains(pw), "no echo")
        }
    }

    @Test func rp03_cancelIsAccepted() {
        let (a, e) = run("nativeRecoveryCancel", [:])
        #expect(isOk(a, "nativeRecoveryCancel") && e.finishes == ["cancelled"])
    }

    @Test func rp07_rp08_engineOutcomesComeAsResultsNotAsBridgeErrors() {
        let (a1, e1) = run("nativeRecoverySubmit", ["path": "code", "code": code22], engineAnswer: .alreadyExists)
        #expect(isOk(a1) && e1.finishes == ["already_exists"], "RP-07: already_exists in the result event")
        let (a2, e2) = run("nativeRecoverySubmit", ["path": "account", "name": tag, "password": "Syn-Wrong-Pw"], engineAnswer: .badPin)
        #expect(isOk(a2) && e2.finishes == ["bad_pin"], "RP-08: bad_pin in the result event")
    }

    @Test func rp17_rp18_formatsAndEmptyValuesGoToTheEngine() {
        let variants: [[String: Any]] = [
            ["path": "code", "code": "Syn10Chars"],
            ["path": "code", "code": ""], ["path": "account", "name": tag, "password": ""],
            ["path": "account", "name": "   ", "password": pw], ["path": "code", "code": "   "],
        ]
        for args in variants {
            let (a, e) = run("nativeRecoverySubmit", args, engineAnswer: .invalidFormat)
            #expect(isOk(a) && e.calls == 1 && e.finishes == ["invalid_format"], "\(args)")
        }
    }

    @Test func rp19_to_rp22_lengthsAtTheLimitAreAccepted() {
        let variants: [(String, [String: Any])] = [
            ("RP-19 code 64", ["path": "code", "code": ascii(64)]),
            ("RP-19 name 128", ["path": "account", "name": ascii(128), "password": pw]),
            ("RP-19 password 256", ["path": "account", "name": tag, "password": ascii(256)]),
            ("RP-20 85 CJK = 255 bytes", ["path": "account", "name": tag, "password": String(repeating: "字", count: 85)]),
            ("RP-21 16 four-byte = 64 bytes", ["path": "code", "code": String(repeating: "😀", count: 16)]),
            ("RP-22 21 lone surrogates = 63 bytes", ["path": "code", "code": loneSurrogates(21)]),
        ]
        for (name, args) in variants {
            let (a, e) = run("nativeRecoverySubmit", args, engineAnswer: .invalidFormat)
            #expect(isOk(a) && e.calls == 1, "\(name)")
        }
        #expect(loneSurrogates(21).utf8.count == 63, "a lone surrogate counts as U+FFFD, 3 bytes")
    }

    // MARK: negative

    @Test func rp04_rp11_noSessionOrAnAttemptInFlightIsNotAvailable() {
        let (a, e) = run("nativeRecoverySubmit", ["path": "code", "code": code22], env: Env(sessionOpen: false))
        #expect(isError(a, "not_available") && e.calls == 0, "RP-04")

        let engine = VectorEngine()
        let s = CashTreesRecoverySession(engine: engine)
        var held: [() -> Void] = []
        s.work = { held.append($0) }
        s.main = { $0() }
        _ = s.open()
        let first = CashTreesRecoveryBridge.answer(action: "nativeRecoverySubmit", body: ["action": "nativeRecoverySubmit", "path": "code", "code": code22], trusted: true, session: s)
        let second = CashTreesRecoveryBridge.answer(action: "nativeRecoverySubmit", body: ["action": "nativeRecoverySubmit", "path": "code", "code": code22], trusted: true, session: s)
        #expect(isOk(first) && isError(second, "not_available"), "RP-11")
        held.forEach { $0() }
        #expect(engine.calls == 1)
    }

    @Test func rp05_rp06_shapeErrorsAreBadArgs() {
        let variants: [[String: Any]] = [
            ["path": NSNull()], ["path": "other"], ["path": "code", "code": "x", "name": "n"], ["path": "account", "name": "n"],
            ["path": "account", "password": "p"], ["path": "code", "code": 1], ["path": "code", "code": code22, "mnemonic": "syn"],
            [:], ["code": code22], ["path": "code", "code": code22, "args": [:]],
        ]
        for args in variants {
            let (a, e) = run("nativeRecoverySubmit", args)
            #expect(isError(a, "bad_args") && e.calls == 0, "\(args)")
        }
    }

    @Test func rn02_to_rn12_rn16_untrustedSourcesAreOriginRefused() {
        let envs: [(String, Env)] = [
            ("RN-02/03/10 sub-frame", Env(mainFrame: false)),
            ("RN-04 sandboxed (null origin)", Env(mainFrame: false, scheme: "", host: "")),
            ("RN-05 external", Env(scheme: "https", host: "example.com")),
            ("RN-06 spoofed host", Env(host: "localhost.example.com")),
            ("RN-06 spoofed scheme", Env(scheme: "cashtrees-localx")),
            ("RN-07 file", Env(scheme: "file", host: "")),
            ("RN-07 data", Env(scheme: "data", host: "")),
            ("RN-07 blob", Env(scheme: "blob", host: "localhost")),
            ("RN-07 javascript", Env(scheme: "javascript", host: "")),
            ("RN-08/09/11 untrusted bundle", Env(bundleTrusted: false)),
            ("RN-16 sub-frame and untrusted", Env(mainFrame: false, bundleTrusted: false)),
            ("port", Env(port: 8080)),
        ]
        for (name, env) in envs {
            let (a, e) = run("nativeRecoverySubmit", ["path": "code", "code": code22], env: env)
            #expect(isError(a, "origin_refused") && e.calls == 0 && e.finishes.isEmpty, "\(name)")
        }
        let (c, ce) = run("nativeRecoveryCancel", [:], env: Env(mainFrame: false))
        #expect(isError(c, "origin_refused", "nativeRecoveryCancel") && ce.finishes.isEmpty, "RN-12")
    }

    @Test func rn18_to_rn24_overLimitIsBadArgs() {
        let variants: [(String, [String: Any])] = [
            ("RN-18 code 300", ["path": "code", "code": ascii(300)]),
            ("RN-18 name 200", ["path": "account", "name": ascii(200), "password": pw]),
            ("RN-18 password 300", ["path": "account", "name": tag, "password": ascii(300)]),
            ("RN-20 code 65", ["path": "code", "code": ascii(65)]),
            ("RN-20 name 129", ["path": "account", "name": ascii(129), "password": pw]),
            ("RN-20 password 257", ["path": "account", "name": tag, "password": ascii(257)]),
            ("RN-21 86 CJK = 258 bytes", ["path": "account", "name": tag, "password": String(repeating: "字", count: 86)]),
            ("RN-22 17 four-byte = 68 bytes", ["path": "code", "code": String(repeating: "😀", count: 17)]),
            ("RN-23 22 lone surrogates = 66 bytes", ["path": "code", "code": loneSurrogates(22)]),
            ("RN-24 leading space + 128", ["path": "account", "name": " " + ascii(128), "password": pw]),
        ]
        for (name, args) in variants {
            let (a, e) = run("nativeRecoverySubmit", args)
            #expect(isError(a, "bad_args") && e.calls == 0, "\(name)")
        }
    }
}
