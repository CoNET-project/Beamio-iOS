import Foundation
import Testing
import UIKit
@testable import ConetChatSDK
@testable import CashTrees_iOS

// Onboarding recovery on the PWA page: the native recovery page is removed. The SDK hook onRecoveryRequired opens a headless
// session; the trusted PWA page hands its input with nativeRecoverySubmit / nativeRecoveryCancel. Synthetic values from the shared vectors
// (SHA256 817957b9bb63fd31de9bb82f739405260ca998752b3fe7afc660601604c12b80); production KDF; fixture registry.
// Synthetic recovery code from the native-recovery-vectors.v1 vectors (gen-native-recovery-vectors.mjs, CODE_A_OK, 22 chars). Not a QA account code.
private let codePathA = "3kRz8mQ2vLpN7wXy1sTcFh"
private let namePathB = "syn_recover_0001"
private let passwordPathB = "SYN-pin-2026"
private let accountA = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
private let fixturePathA = "eyJzdG9yZWQiOnsiYWxnbyI6ImFyZ29uMmlkIiwidiI6MTksIm0iOjMyNzY4LCJ0IjozLCJwIjoxLCJzYWx0IjoiVTFsT0xWTkJURlF0TURBd01EQXdNUT09IiwiaGFzaCI6Ik41Sm5zRFJVRUppQmxmWlVYaENRK09EV2ZzaVJCOVE0MXpCb0l6SG1xZ2M9In0sImltZyI6IlUxbE9TVll0TURBd01EQXh4VVpZbnl5a0RsSm84eHI1L1g5OFArQVRBK3dFeW10WEZDZVlmZThjTlYvTnE2QVI4U3BBc2pWUUIxRDNtckd1Y1NNRlhTVG1qcGxHczYvbk5xRVBXLzdaWDkrQitsODBpbk0vamhWREpoS0hMRlBGUU9KTHkwVlNlSUFJZ2xOSENvMzViMFU3MFNHeVRnbEpnRG1ibmdmWmlhYlprTFlLYmNMbzE2VTUwdStiWVdkZ2VpUFU0blZxWE53PSJ9"
private let fixturePathB = "eyJzdG9yZWQiOnsiYWxnbyI6ImFyZ29uMmlkIiwidiI6MTksIm0iOjMyNzY4LCJ0IjozLCJwIjoxLCJzYWx0IjoiVTFsT0xWTkJURlF0TURBd01EQXdNUT09IiwiaGFzaCI6Ik41Sm5zRFJVRUppQmxmWlVYaENRK09EV2ZzaVJCOVE0MXpCb0l6SG1xZ2M9In0sImltZyI6IlUxbE9TVll0TURBd01EQXgvOFBHRUR1b1FPK0FBVEo0MWRwZC9EL2pZbU5WOTNYNnpqeHBUM0g0QTlibTRzTE1UL1dyL2RzUXYzNnlQR3QvTmxtbDB2Zk1senhRWXg3d0p4MjdwdXZ2QzNrZDBsZHBkQXJQNk9WQzV1QmlSTWdHNVI5UFVaNThnN21DZUU5WndrMnN0N0FYNDUzd1M3UnpxQlVYeDR0T2xDOHpBZlFKallrQ21LRnlyOXd4N2xjZEtGQ0JpdHUya3FvPSJ9"

private struct PageFixtureRegistry: BeamioRecoveryRegistryReading {
    func recordByNameHash(_ nameHash: [UInt8]) -> Result<String, Error> {
        let hex = "0x" + nameHash.map { String(format: "%02x", $0) }.joined()
        return hex == "0xc994c0e53eb8fa2986fd8ef845c5cf46067a6440b22e0fb2e3554a421b6ef173" ? .success(fixturePathA) : .success("")
    }
    func recordByAccountName(_ name: String) -> Result<String, Error> { name == namePathB ? .success(fixturePathB) : .success("") }
    func legacyRecordByAccountName(_ name: String) -> Result<String, Error> { .success("") }
}

private final class PageMemoryPinAttempts: BeamioNativeRecovery.PinAttemptStoring {
    private var failures = 0
    private var last: Date?
    func load() -> (failures: Int, lastFailure: Date?) { (failures, last) }
    func save(failures: Int, lastFailure: Date?) { self.failures = failures; self.last = lastFailure }
}


/// A scripted engine: records each request (the secret only as a length) and each finish.
private final class ScriptedEngine: CashTreesRecoveryEngine {
    var answers: [(code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?)] = []
    private(set) var requests: [String] = []
    private(set) var finishes: [String] = []
    func restore(_ request: CashTreesRecoveryRequest) -> (code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?) {
        switch request {
        case .code(let bytes): requests.append("code:" + String(decoding: bytes, as: UTF8.self))
        case .account(let name, let password): requests.append("account:\(name):\(password.count)")
        }
        return answers.isEmpty ? (.ok, accountA, nil) : answers.removeFirst()
    }
    func finish(_ code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?) {
        finishes.append([code.rawValue, eoa ?? "", cooldownSec.map(String.init) ?? ""].joined(separator: "|"))
    }
}

/// The SDK engine for restore, with the finishes recorded (no SDK session is pending in a unit test).
private final class SdkRestoreRecordingFinish: CashTreesRecoveryEngine {
    let sdk = CashTreesSdkRecoveryEngine()
    private(set) var finishes: [String] = []
    func restore(_ request: CashTreesRecoveryRequest) -> (code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?) { sdk.restore(request) }
    func finish(_ code: CashTreesRecoveryCode, eoa: String?, cooldownSec: Int?) { finishes.append(code.rawValue + "|" + (eoa ?? "")) }
}

/// A session that runs the engine inline (no queues), so each step is observable at once.
private func inlineSession(_ engine: CashTreesRecoveryEngine) -> CashTreesRecoverySession {
    let s = CashTreesRecoverySession(engine: engine)
    s.work = { $0() }
    s.main = { $0() }
    return s
}

extension SdkStateSuite {
@MainActor
@Suite(.serialized)
struct NativeRecoverySessionTests {
    init() {
        BeamioNativeAccountPointer.clear()
        BeamioNativeKeySnapshot.invalidate()
    }

    private func clearDevice() -> () -> Void {
        let savedItems = BeamioChatWalletTestMemory.items
        let savedStore = BeamioNativeWallet.keyStore
        let savedRegistry = BeamioNativeRecovery.registry
        let savedAttempts = BeamioNativeRecovery.attempts
        BeamioChatWalletTestMemory.items = [:]
        BeamioNativeWallet.keyStore = BeamioPasscodeWalletStore.standard
        BeamioNativeRecovery.registry = PageFixtureRegistry()
        BeamioNativeRecovery.attempts = PageMemoryPinAttempts()
        BeamioNativeAccountPointer.clear()
        return {
            BeamioChatWalletTestMemory.items = savedItems
            BeamioNativeWallet.keyStore = savedStore
            BeamioNativeRecovery.registry = savedRegistry
            BeamioNativeRecovery.attempts = savedAttempts
        }
    }

    @Test func theSdkHookOpensAHeadlessSessionAndPresentsNothing() {
        CashTreesNativeRecoveryRoute.installOnce()
        #expect(BeamioNativeRecovery.onRecoveryRequired != nil, "the shell installs the SDK recovery hook")
        let before = topMostController()
        let opened = BeamioNativeRecovery.onRecoveryRequired?(accountA) ?? false
        #expect(opened, "onRecoveryRequired answers true (the session is open)")
        #expect(CashTreesRecoverySession.shared.isOpen)
        #expect(topMostController() === before, "nothing is presented")
        #expect(before?.presentedViewController == nil, "no modal page")
        // leave the shared session closed for the other tests
        CashTreesRecoverySession.shared.engine = ScriptedEngine()
        _ = CashTreesRecoverySession.shared.cancel()
        CashTreesRecoverySession.shared.engine = CashTreesSdkRecoveryEngine()
    }

    @Test func bothEntriesReachTheEngineAndAFailureKeepsTheSessionOpen() {
        let engine = ScriptedEngine()
        engine.answers = [(.badPin, nil, nil), (.backoff, nil, 30), (.ok, accountA, nil)]
        let s = inlineSession(engine)
        #expect(s.submit(["path": "code", "code": codePathA]) == .notAvailable, "no session, no submit")
        #expect(s.open())
        #expect(s.submit(["action": "nativeRecoverySubmit", "path": "account", "name": namePathB, "password": passwordPathB]) == .accepted)
        #expect(s.isOpen, "bad_pin keeps the session open for a retry")
        #expect(s.submit(["path": "account", "name": "  @Syn.Recover  ", "password": passwordPathB]) == .accepted, "the name is passed as given")
        #expect(s.isOpen, "backoff keeps the session open")
        #expect(s.submit(["path": "code", "code": codePathA]) == .accepted)
        #expect(!s.isOpen, "ok closes the session")
        #expect(engine.requests == ["account:\(namePathB):\(passwordPathB.utf8.count)", "account:  @Syn.Recover  :\(passwordPathB.utf8.count)",
                                    "code:" + codePathA], "each entry reaches the engine unchanged; the engine judges the formats")
        #expect(engine.finishes == ["bad_pin||", "backoff||30", "ok|\(accountA)|"], "one result per attempt, eoa only with ok, cooldown only with backoff")
    }

    @Test func malformedArgsAreBadArgsAndReachNoEngine() {
        let engine = ScriptedEngine()
        let s = inlineSession(engine)
        _ = s.open()
        let bad: [[String: Any]] = [
            [:], ["path": "mnemonic", "code": codePathA], ["path": "code"], ["path": "code", "code": 123],
            ["path": "code", "code": codePathA, "password": passwordPathB], ["path": "code", "code": codePathA, "mnemonic": "x"],
            ["path": "account", "name": namePathB], ["path": "account", "password": passwordPathB],
            ["path": "account", "name": namePathB, "password": passwordPathB, "code": codePathA],
            ["path": "account", "name": namePathB, "password": passwordPathB, "privateKey": "x"],
            ["path": "account", "name": 7, "password": passwordPathB],
        ]
        for args in bad { #expect(s.submit(args) == .badArgs, "\(args.keys.sorted())") }
        #expect(engine.requests.isEmpty, "no malformed request reaches the engine")
        #expect(engine.finishes.isEmpty, "and no result is sent")
        #expect(s.isOpen, "the session stays open")
    }

    @Test func onlyTheUtf8LengthIsCheckedWithTheAgreedLimits() {
        let engine = ScriptedEngine()
        engine.answers = Array(repeating: (.invalidFormat, nil, nil), count: 20)
        let s = inlineSession(engine)
        func submit(_ args: [String: Any]) -> CashTreesRecoverySession.Answer {
            _ = s.open()
            return s.submit(args)
        }
        let a = { (n: Int) in String(repeating: "a", count: n) }
        // code: 64 bytes
        #expect(submit(["path": "code", "code": a(64)]) == .accepted, "64 bytes: accepted (the engine judges the format)")
        #expect(submit(["path": "code", "code": a(65)]) == .badArgs, "65 bytes: bad_args")
        #expect(submit(["path": "code", "code": a(300)]) == .badArgs, "300 bytes: bad_args")
        #expect(submit(["path": "code", "code": String(repeating: "é", count: 32)]) == .accepted, "32 two-byte characters = 64 bytes")
        #expect(submit(["path": "code", "code": String(repeating: "é", count: 33)]) == .badArgs, "33 two-byte characters = 66 bytes")
        #expect(submit(["path": "code", "code": ""]) == .accepted, "empty: passed on, the engine answers invalid_format")
        // name: 128 bytes; password: 256 bytes
        #expect(submit(["path": "account", "name": a(128), "password": a(256)]) == .accepted)
        #expect(submit(["path": "account", "name": a(129), "password": passwordPathB]) == .badArgs)
        #expect(submit(["path": "account", "name": a(300), "password": passwordPathB]) == .badArgs)
        #expect(submit(["path": "account", "name": namePathB, "password": a(257)]) == .badArgs)
        #expect(submit(["path": "account", "name": namePathB, "password": a(300)]) == .badArgs)
        // no format check and no normalisation in the shell
        #expect(submit(["path": "account", "name": "bad name!", "password": passwordPathB]) == .accepted)
        #expect(submit(["path": "code", "code": "not-a-recovery-code"]) == .accepted)
        #expect(engine.requests.contains("account:bad name!:\(passwordPathB.utf8.count)"), "the name reaches the engine as given")
        #expect(engine.requests.count == 6, "only the six accepted requests reached the engine")
        #expect(!engine.requests.contains { $0.count > 400 }, "no over-length value reached the engine")
    }

    @Test func cancelSendsCancelledAndACancelDuringAnAttemptWaitsForIt() {
        let engine = ScriptedEngine()
        let s = inlineSession(engine)
        #expect(s.cancel() == .notAvailable, "no session, nothing to cancel")
        _ = s.open()
        #expect(s.cancel() == .accepted)
        #expect(!s.isOpen && engine.finishes == ["cancelled||"], "cancel ends the session with cancelled")

        // an attempt in flight: the cancel waits; a failure then ends with cancelled, an ok is still reported as ok
        var pending: [() -> Void] = []
        let held = CashTreesRecoverySession(engine: engine)
        held.work = { pending.append($0) }
        held.main = { $0() }
        engine.answers = [(.notFound, nil, nil), (.ok, accountA, nil)]
        _ = held.open()
        #expect(held.submit(["path": "code", "code": codePathA]) == .accepted)
        #expect(held.submit(["path": "code", "code": codePathA]) == .notAvailable, "one attempt at a time")
        #expect(held.cancel() == .accepted)
        #expect(held.submit(["path": "code", "code": codePathA]) == .notAvailable, "no submit after a cancel")
        pending.removeFirst()()
        #expect(!held.isOpen && engine.finishes.last == "cancelled||", "the failed attempt ends with cancelled, not not_found")
        _ = held.open()
        #expect(held.submit(["path": "code", "code": codePathA]) == .accepted)
        held.reset()
        pending.removeFirst()()
        #expect(engine.finishes.last == "ok|\(accountA)|", "a written key is reported as ok even after a reset")
        #expect(!held.isOpen)
    }

    @Test func aPageReloadEndsTheSession() {
        let engine = ScriptedEngine()
        let s = inlineSession(engine)
        s.reset()
        #expect(engine.finishes.isEmpty, "no session, nothing sent")
        _ = s.open()
        s.reset()
        #expect(!s.isOpen && engine.finishes == ["cancelled||"], "a reload ends the open session with cancelled")
        #expect(s.open(), "a new page can open a new session")
    }

    @Test func theBridgeRefusesAnUntrustedSourceBeforeTheEngine() {
        let engine = ScriptedEngine()
        let s = inlineSession(engine)
        _ = s.open()
        let args: [String: Any] = ["action": "nativeRecoverySubmit", "path": "code", "code": codePathA]
        let refused = CashTreesRecoveryBridge.answer(action: "nativeRecoverySubmit", body: args, trusted: false, session: s)
        #expect(refused as NSDictionary == ["action": "nativeRecoverySubmit", "ok": false, "error": "origin_refused"] as NSDictionary)
        let cancelRefused = CashTreesRecoveryBridge.answer(action: "nativeRecoveryCancel", body: [:], trusted: false, session: s)
        #expect(cancelRefused["error"] as? String == "origin_refused")
        #expect(engine.requests.isEmpty && engine.finishes.isEmpty && s.isOpen, "an untrusted source reaches no engine and does not end the session")
        let accepted = CashTreesRecoveryBridge.answer(action: "nativeRecoverySubmit", body: args, trusted: true, session: s)
        #expect(accepted as NSDictionary == ["action": "nativeRecoverySubmit", "ok": true] as NSDictionary)
        let after = CashTreesRecoveryBridge.answer(action: "nativeRecoveryCancel", body: [:], trusted: true, session: s)
        #expect(after as NSDictionary == ["action": "nativeRecoveryCancel", "ok": false, "error": "not_available"] as NSDictionary)
        let bad = CashTreesRecoveryBridge.answer(action: "nativeRecoverySubmit", body: ["path": "x"], trusted: true, session: s)
        #expect(bad["error"] as? String == "not_available", "the session closed with ok")
        // no answer ever echoes an arg
        for answer in [refused, cancelRefused, accepted, after, bad] {
            let text = String(describing: answer)
            #expect(!text.contains(codePathA) && !text.contains(passwordPathB))
        }
    }

    @Test func theInjectedBridgeHasNoRecoveryScanAndDeclaresThePageInputCapability() {
        let script = CashTreesWebCoordinator.bridgeInjectionScript(nfcStatus: "no_bridge", embeddedVer: "0.0.0", pendingVer: "")
        #expect(!script.contains("scanRecoveryQr"), "scanRecoveryQr is removed from the shim")
        #expect(script.contains("nativeRecoverySubmit") && script.contains("nativeRecoveryCancel"))
        #expect(script.contains("'recovery.page-input.v1':true"), "the capability is declared")
        #expect(script.contains("scanQr:function"), "scanQr stays")
    }

    @Test func recoveryCodeEntryRestoresTheOriginalAccountThroughTheSdk() {
        let restore = clearDevice()
        defer { restore() }
        let engine = SdkRestoreRecordingFinish()
        let s = inlineSession(engine)
        _ = s.open()
        #expect(s.submit(["path": "code", "code": codePathA]) == .accepted)
        #expect(engine.finishes == ["ok|\(accountA)"], "the recovery code entry restores through the SDK")
        #expect(BeamioNativeWallet.keyStore.read(eoa: accountA)?.count == 32, "the derived account holds the restored key, read through the product store")
    }

    @Test func beamioTagAndPasswordEntryRestoresAndASecondAccountIsAlreadyExists() {
        let restore = clearDevice()
        defer { restore() }
        let engine = SdkRestoreRecordingFinish()
        let s = inlineSession(engine)
        _ = s.open()
        #expect(s.submit(["path": "account", "name": namePathB, "password": passwordPathB]) == .accepted)
        #expect(engine.finishes == ["ok|\(accountA)"], "the BeamioTag and password entry restores through the SDK")
        let key = BeamioNativeWallet.keyStore.read(eoa: accountA)
        #expect(key?.count == 32)
        // a device with a native key: the engine answers already_exists and changes nothing
        _ = s.open()
        #expect(s.submit(["path": "code", "code": codePathA]) == .accepted)
        #expect(engine.finishes.last == "already_exists|", "already_exists, no switch")
        #expect(BeamioNativeWallet.keyStore.read(eoa: accountA) == key, "the existing key is not changed")
        #expect(s.isOpen, "already_exists keeps the session open (the page closes it with cancel)")
    }
}
}

@MainActor
private func topMostController() -> UIViewController? {
    let windows = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.flatMap { $0.windows }
    var top = (windows.first(where: { $0.isKeyWindow }) ?? windows.first)?.rootViewController
    while let p = top?.presentedViewController { top = p }
    return top
}
