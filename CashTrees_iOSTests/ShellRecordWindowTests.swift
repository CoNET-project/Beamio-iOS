#if BEAMIO_TEST_HOOKS
import Foundation
import Testing
@testable import CashTrees_iOS
@testable import ConetChatSDK

// window.BeamioShellRecord (spec r3oq (a), §25.52Y.44; vectors pub6 CP-28/29/30, CN-11). Synthetic values only.
// The G1 case restores the synthetic account of NativeRecoveryAcceptanceTests (same public fixtures, copied here file-private).

private let syntheticAccount = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
private let syntheticCode = "3kRz8mQ2vLpN7wXy1sTcFh"
private let syntheticName = "syn_recover_0001"
private let syntheticPassword = "SYN-pin-2026"
// Registry record for keccak256(code) (path A) and for the account name (path B), from the fixtures.
private let fixturePathA = "eyJzdG9yZWQiOnsiYWxnbyI6ImFyZ29uMmlkIiwidiI6MTksIm0iOjMyNzY4LCJ0IjozLCJwIjoxLCJzYWx0IjoiVTFsT0xWTkJURlF0TURBd01EQXdNUT09IiwiaGFzaCI6Ik41Sm5zRFJVRUppQmxmWlVYaENRK09EV2ZzaVJCOVE0MXpCb0l6SG1xZ2M9In0sImltZyI6IlUxbE9TVll0TURBd01EQXh4VVpZbnl5a0RsSm84eHI1L1g5OFArQVRBK3dFeW10WEZDZVlmZThjTlYvTnE2QVI4U3BBc2pWUUIxRDNtckd1Y1NNRlhTVG1qcGxHczYvbk5xRVBXLzdaWDkrQitsODBpbk0vamhWREpoS0hMRlBGUU9KTHkwVlNlSUFJZ2xOSENvMzViMFU3MFNHeVRnbEpnRG1ibmdmWmlhYlprTFlLYmNMbzE2VTUwdStiWVdkZ2VpUFU0blZxWE53PSJ9"
private let fixturePathB = "eyJzdG9yZWQiOnsiYWxnbyI6ImFyZ29uMmlkIiwidiI6MTksIm0iOjMyNzY4LCJ0IjozLCJwIjoxLCJzYWx0IjoiVTFsT0xWTkJURlF0TURBd01EQXdNUT09IiwiaGFzaCI6Ik41Sm5zRFJVRUppQmxmWlVYaENRK09EV2ZzaVJCOVE0MXpCb0l6SG1xZ2M9In0sImltZyI6IlUxbE9TVll0TURBd01EQXgvOFBHRUR1b1FPK0FBVEo0MWRwZC9EL2pZbU5WOTNYNnpqeHBUM0g0QTlibTRzTE1UL1dyL2RzUXYzNnlQR3QvTmxtbDB2Zk1senhRWXg3d0p4MjdwdXZ2QzNrZDBsZHBkQXJQNk9WQzV1QmlSTWdHNVI5UFVaNThnN21DZUU5WndrMnN0N0FYNDUzd1M3UnpxQlVYeDR0T2xDOHpBZlFKallrQ21LRnlyOXd4N2xjZEtGQ0JpdHUya3FvPSJ9"

private struct FixtureRegistry: BeamioRecoveryRegistryReading {
    func recordByNameHash(_ nameHash: [UInt8]) -> Result<String, Error> {
        let hex = "0x" + nameHash.map { String(format: "%02x", $0) }.joined()
        return hex == "0xc994c0e53eb8fa2986fd8ef845c5cf46067a6440b22e0fb2e3554a421b6ef173" ? .success(fixturePathA) : .success("")
    }
    func recordByAccountName(_ name: String) -> Result<String, Error> {
        name == syntheticName ? .success(fixturePathB) : .success("")
    }
    func legacyRecordByAccountName(_ name: String) -> Result<String, Error> { .success("") }
}

private final class MemoryPinAttempts: BeamioNativeRecovery.PinAttemptStoring {
    private var failures = 0
    private var last: Date?
    func load() -> (failures: Int, lastFailure: Date?) { (failures, last) }
    func save(failures: Int, lastFailure: Date?) { self.failures = failures; self.last = lastFailure }
}

/// Records what the channel handed to each SDK entry and to the page-sync gate.
private final class Calls {
    var sdk: [(String, WindowTrust)] = []
    var gate: [(String, Bool)] = []
    var replies: [[String: Any]] = []
}

private func fakeSdk(_ calls: Calls, eoaResult: [String: Any] = ["eoa": "0x0000000000000000000000000000000000000001"]) -> CashTreesShellRecordWindow.Sdk {
    var sdk = CashTreesShellRecordWindow.Sdk()
    sdk.walletEoaAddress = { reqId, trust, emit in
        calls.sdk.append(("walletEoaAddress", trust))
        emit(["type": "ack", "reqId": reqId ?? NSNull(), "ok": true, "result": eoaResult])
    }
    sdk.walletCredential = { body, trust, emit in
        calls.sdk.append(("walletCredential", trust))
        emit(["type": "ack", "reqId": body["reqId"] ?? NSNull(), "ok": false, "error": "not_trusted"])
    }
    sdk.shellRecordRead = { body, trust, emit in
        calls.sdk.append(("shellRecordRead", trust))
        emit(["type": "ack", "reqId": body["reqId"] ?? NSNull(), "ok": true, "result": ["code": "absent"]])
    }
    sdk.shellRecordWrite = { body, trust, emit in
        calls.sdk.append(("shellRecordWrite", trust))
        emit(["type": "ack", "reqId": body["reqId"] ?? NSNull(), "ok": true, "result": ["code": "ok", "rev": 1]])
    }
    return sdk
}

private func fakeGate(_ calls: Calls) -> CashTreesShellRecordWindow.SyncGate {
    { command, trusted, reply in
        calls.gate.append((command["type"] as? String ?? "", trusted))
        let reqId = command["reqId"] ?? NSNull()
        let ack: [String: Any] = trusted
            ? ["type": "ack", "reqId": reqId, "ok": true, "result": ["code": "confirmed_missing"]]
            : ["type": "ack", "reqId": reqId, "ok": false, "error": "untrusted_source"]
        reply(PwaWalletSyncBridge.wrapForPage(ack))
    }
}

private func json(_ object: [String: Any]) -> String {
    String(data: try! JSONSerialization.data(withJSONObject: object), encoding: .utf8)!
}

private func send(_ object: [String: Any], trust: WindowTrust, calls: Calls, sdk: CashTreesShellRecordWindow.Sdk? = nil) {
    CashTreesShellRecordWindow.handle(body: json(object), trust: trust, sdk: sdk ?? fakeSdk(calls), syncGate: fakeGate(calls)) { calls.replies.append($0) }
}

struct ShellRecordWindowTests {
    @Test func theVerdictIsFrameAndOriginFirstThenTheBundle() {
        typealias W = CashTreesShellRecordWindow
        #expect(W.trust(isMainFrame: true, scheme: "cashtrees-local", host: "localhost", port: 0, bundleTrusted: true) == .trusted)
        #expect(W.trust(isMainFrame: true, scheme: "cashtrees-local", host: "localhost", port: 0, bundleTrusted: false) == .notTrusted)
        #expect(W.trust(isMainFrame: false, scheme: "cashtrees-local", host: "localhost", port: 0, bundleTrusted: true) == .originRefused, "a child frame")
        #expect(W.trust(isMainFrame: true, scheme: "https", host: "beamio.ca", port: 0, bundleTrusted: true) == .originRefused, "a remote page")
        #expect(W.trust(isMainFrame: true, scheme: "cashtrees-local", host: "evil", port: 0, bundleTrusted: true) == .originRefused)
        #expect(W.trust(isMainFrame: true, scheme: "cashtrees-local", host: "localhost", port: 8080, bundleTrusted: true) == .originRefused)
    }

    @Test func theSixCommandsReachTheirHandlersOnATrustedMainFrame() {
        let calls = Calls()
        send(["type": "walletEoaAddress", "reqId": 1], trust: .trusted, calls: calls)
        send(["type": "walletCredential", "reqId": 2], trust: .trusted, calls: calls)
        send(["type": "shellRecordRead", "reqId": 3], trust: .trusted, calls: calls)
        send(["type": "shellRecordWrite", "reqId": 4, "record": [:], "rev": 0], trust: .trusted, calls: calls)
        send(["type": "pwaWalletSync", "reqId": 5, "seq": 1], trust: .trusted, calls: calls)
        send(["type": "nativeMnemonicPreread", "reqId": 6, "seq": 1], trust: .trusted, calls: calls)
        #expect(calls.sdk.map(\.0) == ["walletEoaAddress", "walletCredential", "shellRecordRead", "shellRecordWrite"])
        #expect(calls.sdk.allSatisfy { $0.1 == .trusted })
        #expect(calls.gate.map(\.0) == ["pwaWalletSync", "nativeMnemonicPreread"])
        #expect(calls.gate.allSatisfy { $0.1 })
        #expect(calls.replies.count == 6, "one reply each")
        #expect(calls.replies.map { ($0["reqId"] as? NSNumber)?.intValue } == [1, 2, 3, 4, 5, 6], "each reply echoes its own reqId")
        #expect(calls.replies[0]["result"] as? [String: String] == ["eoa": "0x0000000000000000000000000000000000000001"], "walletEoaAddress answers {eoa}")
        #expect(calls.replies[4]["action"] == nil && calls.replies[4]["type"] as? String == "ack", "the page-sync ack is unwrapped from the chat event")
    }

    @Test func aChildFrameOrRemotePageIsOriginRefusedAndTheSdkIsNotCalled() {
        let calls = Calls()
        for type in ["walletEoaAddress", "walletCredential", "shellRecordRead", "shellRecordWrite", "unknownThing"] {
            send(["type": type, "reqId": 9], trust: .originRefused, calls: calls)
        }
        #expect(calls.sdk.isEmpty, "CN-11: nothing reaches the SDK")
        #expect(calls.replies.count == 5)
        #expect(calls.replies.allSatisfy { $0["ok"] as? Bool == false && $0["error"] as? String == "origin_refused" && $0["result"] == nil })
        // the page-sync commands keep their gate's answer (untrusted_source), as on CashTreesIOS and Android
        send(["type": "nativeMnemonicPreread", "reqId": 10, "seq": 1], trust: .originRefused, calls: calls)
        #expect(calls.gate.last?.1 == false)
        #expect(calls.replies.last?["error"] as? String == "untrusted_source")
    }

    @Test func anUntrustedBundleIsPassedToTheSdkAsNotTrusted() {
        let calls = Calls()
        send(["type": "walletEoaAddress", "reqId": 11], trust: .notTrusted, calls: calls, sdk: CashTreesShellRecordWindow.Sdk())
        send(["type": "shellRecordRead", "reqId": 12], trust: .notTrusted, calls: calls, sdk: CashTreesShellRecordWindow.Sdk())
        #expect(calls.replies.count == 2)
        #expect(calls.replies[0]["error"] as? String == "not_trusted", "the SDK's answer for walletEoaAddress")
        #expect(calls.replies[1]["error"] as? String == "origin_refused", "the record commands map a package failure to origin_refused")
        #expect(calls.replies.allSatisfy { $0["result"] == nil })
    }

    @Test func aReplyForAnotherReqIdIsDroppedAndOnlyExactEoaLeaves() {
        typealias W = CashTreesShellRecordWindow
        #expect(W.exitFilter(type: "walletEoaAddress", requestReqId: 1, reply: ["type": "ack", "reqId": 2, "ok": true, "result": ["eoa": "0x" + String(repeating: "a", count: 40)]]) == nil, "reqId mismatch: dropped")
        #expect(W.exitFilter(type: "shellRecordRead", requestReqId: "r1", reply: ["type": "ack", "reqId": "r2", "ok": true, "result": ["code": "absent"]]) == nil)
        #expect(W.exitFilter(type: "shellRecordRead", requestReqId: 1, reply: ["type": "event", "reqId": 1]) == nil, "not an ack: dropped")
        let extra = W.exitFilter(type: "walletEoaAddress", requestReqId: 3, reply: ["type": "ack", "reqId": 3, "ok": true, "result": ["eoa": "0x" + String(repeating: "b", count: 40), "privateKey": "x"]])
        #expect(extra?["ok"] as? Bool == false && extra?["error"] as? String == "unavailable" && extra?["result"] == nil, "a result other than exactly {eoa} does not leave")
        let upper = W.exitFilter(type: "walletEoaAddress", requestReqId: 4, reply: ["type": "ack", "reqId": 4, "ok": true, "result": ["eoa": "0x" + String(repeating: "B", count: 40)]])
        #expect(upper?["error"] as? String == "unavailable", "not a lowercase address")
        let good = W.exitFilter(type: "walletEoaAddress", requestReqId: 5, reply: ["type": "ack", "reqId": 5, "ok": true, "result": ["eoa": "0x" + String(repeating: "c", count: 40)]])
        #expect(good?["result"] as? [String: String] == ["eoa": "0x" + String(repeating: "c", count: 40)])
        let noKey = W.exitFilter(type: "walletEoaAddress", requestReqId: 6, reply: ["type": "ack", "reqId": 6, "ok": false, "error": "no_key"])
        #expect(noKey?["error"] as? String == "no_key", "an error passes as it is")
    }

    @Test func walletEoaAddressTakesOnlyTypeAndReqId() {
        let calls = Calls()
        send(["type": "walletEoaAddress", "reqId": 20, "password": "x"], trust: .trusted, calls: calls)
        send(["type": "walletEoaAddress", "reqId": 21, "extra": 1], trust: .trusted, calls: calls)
        #expect(calls.sdk.isEmpty)
        #expect(calls.replies.map { $0["error"] as? String } == ["key_over_bridge_refused", "bad_request"])
        #expect(!json(calls.replies[0]).contains("\"x\""), "no value is echoed")
    }

    @Test func aMessageThatIsNotAJsonObjectStringGetsOneAnswer() {
        let calls = Calls()
        for (body, trust) in [("not json", WindowTrust.trusted), ("[1,2]", .trusted), ("not json", .originRefused)] as [(String, WindowTrust)] {
            CashTreesShellRecordWindow.handle(body: body, trust: trust, sdk: fakeSdk(calls), syncGate: fakeGate(calls)) { calls.replies.append($0) }
        }
        CashTreesShellRecordWindow.handle(body: ["type": "walletEoaAddress"] as [String: Any], trust: .trusted, sdk: fakeSdk(calls), syncGate: fakeGate(calls)) { calls.replies.append($0) }
        #expect(calls.sdk.isEmpty && calls.gate.isEmpty)
        #expect(calls.replies.map { $0["error"] as? String } == ["bad_request", "bad_request", "origin_refused", "bad_request"])
        #expect(calls.replies.allSatisfy { $0["reqId"] is NSNull })
    }

    @Test func thePageTrustClaimNeverReachesAHandler() {
        let calls = Calls()
        var seen: [String: Any]?
        let gate: CashTreesShellRecordWindow.SyncGate = { command, trusted, reply in seen = command; reply(["type": "ack", "reqId": command["reqId"] ?? NSNull(), "ok": true, "result": [:]]) }
        CashTreesShellRecordWindow.handle(body: json(["type": "pwaWalletSync", "reqId": 30, "trustedOrigin": true]), trust: .notTrusted, sdk: fakeSdk(calls), syncGate: gate) { calls.replies.append($0) }
        #expect(seen?["trustedOrigin"] == nil)
    }

    @Test func theScriptsDefineTheObjectOnTheFixedOriginAndEncodeTheReplySafely() throws {
        let script = CashTreesShellRecordWindow.injectionScript()
        #expect(script.contains("window.top !== window.self"))
        #expect(script.contains("location.protocol !== 'cashtrees-local:'") && script.contains("location.hostname !== 'localhost'"))
        #expect(script.contains("allowedOrigins") && script.contains("'cashtrees-local://localhost'"))
        #expect(script.contains("configurable: false") && script.contains("writable: false"))
        let reply: [String: Any] = ["type": "ack", "reqId": 7, "ok": false, "error": "a\"b'</script>\u{2028}"]
        let delivery = try #require(CashTreesShellRecordWindow.deliveryScript(reply))
        #expect(!delivery.contains("\u{2028}"))
        // the literal between {data: and }); is one JS/JSON string whose content is the reply's JSON
        let start = try #require(delivery.range(of: "{data:"))
        let end = try #require(delivery.range(of: "});}})();", options: .backwards))
        let literal = String(delivery[start.upperBound..<end.lowerBound])
        let inner = try #require(try JSONSerialization.jsonObject(with: Data(("[" + literal + "]").utf8)) as? [String])
        let decoded = try #require(try JSONSerialization.jsonObject(with: Data(inner[0].utf8)) as? [String: Any])
        #expect(decoded["error"] as? String == "a\"b'</script>\u{2028}")
    }
}

extension SdkStateSuite {
@Suite(.serialized)
struct ShellRecordWindowSdkTests {
    private func withCleanDevice(_ body: () -> Void) {
        let savedStore = BeamioNativeWallet.keyStore
        let savedRegistry = BeamioNativeRecovery.registry
        let savedAttempts = BeamioNativeRecovery.attempts
        let savedItems = BeamioChatWalletTestMemory.items
        defer {
            BeamioNativeWallet.keyStore = savedStore
            BeamioNativeRecovery.registry = savedRegistry
            BeamioNativeRecovery.attempts = savedAttempts
            BeamioChatWalletTestMemory.items = savedItems
            BeamioNativeAccountPointer.clear()
            BeamioNativeKeySnapshot.invalidate()
        }
        BeamioChatWalletTestMemory.items = [:]
        let store = BeamioPasscodeWalletStore.standard
        BeamioNativeWallet.keyStore = store
        BeamioNativeRecovery.registry = FixtureRegistry()
        BeamioNativeRecovery.attempts = MemoryPinAttempts()
        BeamioNativeAccountPointer.clear()
        BeamioNativeKeySnapshot.invalidate()
        store.delete(eoa: syntheticAccount)
        body()
    }

    private func ask(_ trust: WindowTrust, reqId: Int) -> [String: Any]? {
        var out: [String: Any]?
        CashTreesShellRecordWindow.handle(body: json(["type": "walletEoaAddress", "reqId": reqId]), trust: trust,
                                          syncGate: { _, _, _ in }) { out = $0 }
        return out
    }

    @Test func g0AnswersNoKeyThroughTheRealSdk() {
        withCleanDevice {
            let reply = ask(.trusted, reqId: 40)
            #expect(reply?["ok"] as? Bool == false && reply?["error"] as? String == "no_key", "CP-29: G0 answers no_key")
            #expect((reply?["reqId"] as? NSNumber)?.intValue == 40)
        }
    }

    @Test func g1AnswersExactlyTheEoaThroughTheRealSdk() {
        #expect(BeamioPGPNative.linked, "the production KDF needs X-19 linked in this build")
        withCleanDevice {
            let outcome = BeamioNativeRecovery.restore(.recoveryCode(syntheticCode))
            #expect(outcome == .ok(eoa: syntheticAccount), "fixture: the synthetic account is restored (G1, no init)")
            let reply = ask(.trusted, reqId: 41)
            #expect(reply?["ok"] as? Bool == true, "CP-28: G1 answers ok")
            #expect(reply?["result"] as? [String: String] == ["eoa": syntheticAccount], "result is exactly {eoa}")
            #expect((reply?["reqId"] as? NSNumber)?.intValue == 41)
            // CN-11 on the same device: a child frame or a remote page gets origin_refused and no address
            let refused = ask(.originRefused, reqId: 42)
            #expect(refused?["error"] as? String == "origin_refused" && refused?["result"] == nil)
        }
    }
}
}
#endif
