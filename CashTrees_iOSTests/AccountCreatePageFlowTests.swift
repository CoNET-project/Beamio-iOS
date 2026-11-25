import Foundation
import Testing
import UIKit
@testable import ConetChatSDK
@testable import CashTrees_iOS

// New-account onboarding on the PWA page: the headless create host, the trusted accountCreateRegister action, secureScreen.
// Synthetic values only.

@MainActor
struct AccountCreatePageFlowTests {
    private func inlineSession(_ outcomes: [BeamioNativeAccountCreate.CreateOutcome]) -> (CashTreesAccountCreateSession, () -> Int, () -> Int) {
        let s = CashTreesAccountCreateSession()
        var queue = outcomes
        var creates = 0
        var closes = 0
        s.create = { creates += 1; return queue.isEmpty ? .failed(.notAvailable) : queue.removeFirst() }
        s.close = { closes += 1; return true }
        s.work = { $0() }
        s.retryDelay = 0
        return (s, { creates }, { closes })
    }

    @Test func theHostRunsTheCreationInTheBackgroundAndPresentsNothing() {
        let (s, creates, _) = inlineSession([.failed(.notAvailable), .failed(.notAvailable), .ok(eoa: "0x0000000000000000000000000000000000000001")])
        #expect(s.start(), "onCreateRequired answers true")
        #expect(creates() == 3, "not_available (page not recorded yet) is retried until the SDK runs the creation")
        #expect(!s.isRunning)
    }

    @Test func aRealFailureIsNotRetriedAndTheRetryIsBounded() {
        let (s, creates, _) = inlineSession([.failed(.writeFailed)])
        _ = s.start()
        #expect(creates() == 1, "write_failed is the SDK's result to the page; no second creation")
        let (s2, creates2, _) = inlineSession([])
        _ = s2.start()
        #expect(creates2() == CashTreesAccountCreateSession.maxAttempts, "a page that never opens stops after the bound")
    }

    @Test func leavingThePageClosesTheSdkPage() {
        let (s, _, closes) = inlineSession([])
        s.pageLeft()
        #expect(closes() == 1)
    }

    @Test func installingTheRouteSetsTheSdkHost() {
        CashTreesNativeAccountCreateRoute.installOnce()
        #expect(BeamioNativeAccountCreate.onCreateRequired != nil)
    }

    @Test func registerCarriesOnlyTheThreeFieldsAndRefusalsEchoNothing() {
        let ok = CashTreesAccountCreateBridge.registerCommand(from: ["action": "accountCreateRegister", "reqId": 7, "tag": "syn_tag", "password": "Syn-Pw-1"])
        #expect(ok as NSDictionary? == ["type": "accountCreateRegister", "reqId": 7, "tag": "syn_tag", "password": "Syn-Pw-1"] as NSDictionary)
        #expect(CashTreesAccountCreateBridge.registerCommand(from: ["reqId": "r1", "tag": "t", "password": "p"]) != nil, "a string reqId")
        let bad: [[String: Any]] = [
            ["reqId": 7, "tag": "t"], ["reqId": 7, "password": "p"], ["tag": "t", "password": "p"], ["reqId": 7, "tag": 1, "password": "p"],
            ["reqId": [1], "tag": "t", "password": "p"], ["reqId": 7, "tag": "t", "password": "p", "mnemonic": "x"],
            ["reqId": 7, "tag": "t", "password": "p", "privateKey": "x"],
        ]
        for b in bad { #expect(CashTreesAccountCreateBridge.registerCommand(from: b) == nil, "\(b.keys.sorted())") }
        let refused = CashTreesAccountCreateBridge.refusal(reqId: 7, error: "origin_refused")
        #expect(refused as NSDictionary == ["action": "chatModuleEvent", "event": ["type": "ack", "reqId": 7, "ok": false, "error": "origin_refused"]] as NSDictionary)
        let noId = CashTreesAccountCreateBridge.refusal(reqId: ["x"], error: "bad_request")
        #expect((noId["event"] as? [String: Any])?["reqId"] is NSNull, "a malformed reqId is not echoed")
    }

    @Test func secureScreenIsTrustedOnlyAndCoversEvenWithAnAccountUntilItEnds() {
        let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 100, height: 100))
        window.isHidden = false
        let shield = CashTreesG0PrivacyShield()
        shield.windows = { [window] }
        shield.isG0 = { false }  // the key exists after the creation step
        var clock = Date(timeIntervalSince1970: 1_800_000_000)
        shield.now = { clock }

        let refused = CashTreesAccountCreateBridge.secureScreenAnswer(body: ["action": "secureScreen", "on": true], trusted: false, shield: shield)
        #expect(refused["error"] as? String == "origin_refused")
        shield.cover()
        #expect(!shield.isCovered, "an untrusted request changes nothing")
        #expect(CashTreesAccountCreateBridge.secureScreenAnswer(body: ["on": "yes"], trusted: true, shield: shield)["error"] as? String == "bad_args")
        #expect(CashTreesAccountCreateBridge.secureScreenAnswer(body: ["on": true, "x": 1], trusted: true, shield: shield)["error"] as? String == "bad_args")

        let on = CashTreesAccountCreateBridge.secureScreenAnswer(body: ["action": "secureScreen", "on": true], trusted: true, shield: shield)
        #expect(on as NSDictionary == ["action": "secureScreen", "ok": true] as NSDictionary)
        shield.cover()
        #expect(shield.isCovered, "with the request on, the switcher is covered even though the device has an account")
        shield.uncover()
        clock = clock.addingTimeInterval(CashTreesG0PrivacyShield.secureScreenLimit)
        shield.cover()
        #expect(!shield.isCovered, "the request ends by itself after 10 minutes")

        _ = CashTreesAccountCreateBridge.secureScreenAnswer(body: ["on": true], trusted: true, shield: shield)
        _ = CashTreesAccountCreateBridge.secureScreenAnswer(body: ["on": false], trusted: true, shield: shield)
        shield.cover()
        #expect(!shield.isCovered, "on:false ends it")
    }

    @Test func aRepeatedOnDoesNotRestartTheTenMinutes() {
        let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 100, height: 100))
        window.isHidden = false
        let shield = CashTreesG0PrivacyShield()
        shield.windows = { [window] }
        shield.isG0 = { false }
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        var clock = t0
        shield.now = { clock }
        _ = CashTreesAccountCreateBridge.secureScreenAnswer(body: ["on": true], trusted: true, shield: shield)
        clock = t0.addingTimeInterval(300)
        let again = CashTreesAccountCreateBridge.secureScreenAnswer(body: ["on": true], trusted: true, shield: shield)
        #expect(again as NSDictionary == ["action": "secureScreen", "ok": true] as NSDictionary, "a repeated on:true is answered ok")
        clock = t0.addingTimeInterval(CashTreesG0PrivacyShield.secureScreenLimit - 1)
        #expect(shield.secureScreenActive, "still on just before the first deadline")
        clock = t0.addingTimeInterval(CashTreesG0PrivacyShield.secureScreenLimit)
        #expect(!shield.secureScreenActive, "ends at the first deadline (t0 + 600), not 600 after the repeat")
        // after it ended, a new on:true starts a new 10 minutes
        _ = CashTreesAccountCreateBridge.secureScreenAnswer(body: ["on": true], trusted: true, shield: shield)
        clock = t0.addingTimeInterval(CashTreesG0PrivacyShield.secureScreenLimit * 2 - 1)
        #expect(shield.secureScreenActive, "a new request after the end gets its own 10 minutes")
    }

    @Test func theInjectedBridgeDeclaresTheCreateCapabilityAndActions() {
        let script = CashTreesWebCoordinator.bridgeInjectionScript(nfcStatus: "no_bridge", embeddedVer: "0.0.0", pendingVer: "")
        #expect(script.contains("'account.page-create.v1':true") && script.contains("'recovery.page-input.v1':true"))
        #expect(script.contains("accountCreateRegister:function") && script.contains("secureScreen:function"))
    }
}
