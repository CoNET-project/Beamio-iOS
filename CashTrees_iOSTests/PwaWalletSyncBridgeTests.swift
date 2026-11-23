import Foundation
import Testing
@testable import CashTrees_iOS

/// Synthetic values only: a public BIP-39 test phrase and a placeholder address. No real wallet data.
private let syntheticPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
private let syntheticEoa = "0x1111111111111111111111111111111111111111"
private let syntheticReqId = 900_000_001

/// Records what the gate hands to the engine and answers with a scripted ack.
private final class RecordingEngine: PwaWalletSyncEngine {
    var syncCalls: [(reqId: Int, seq: Int, eoa: String, phrase: String)] = []
    var prereadCalls: [(reqId: Int, seq: Int)] = []
    var syncAck: [String: Any] = ["type": "ack", "reqId": syntheticReqId, "ok": true, "result": ["sync": "updated"]]
    var prereadAck: [String: Any] = ["type": "ack", "reqId": syntheticReqId, "ok": true, "result": ["code": "confirmed_missing"]]

    var cipherCalls: [(reqId: Int, seq: Int, eoa: String, cipher: [String: Any], passcode: String?)] = []

    func pwaWalletSync(reqId: Int, seq: Int, eoa: String, phrase: String, reply: @escaping ([String: Any]) -> Void) {
        syncCalls.append((reqId, seq, eoa, phrase))
        reply(syncAck)
    }

    func pwaWalletSyncCipher(reqId: Int, seq: Int, eoa: String, cipher: [String: Any], passcode: String?, reply: @escaping ([String: Any]) -> Void) {
        cipherCalls.append((reqId, seq, eoa, cipher, passcode))
        reply(syncAck)
    }

    func nativeMnemonicPreread(reqId: Int, seq: Int, reply: @escaping ([String: Any]) -> Void) {
        prereadCalls.append((reqId, seq))
        reply(prereadAck)
    }
}

/// A test double for the SDK's durable reply behaviour: the first answer for a reqId/seq pair is stored and replayed.
/// It stands in for the SDK only; it proves the shell passes replays through unchanged, not what the SDK does.
private final class DurableReplyEngine: PwaWalletSyncEngine {
    let store: ReplyStore
    init(store: ReplyStore) { self.store = store }

    func pwaWalletSync(reqId: Int, seq: Int, eoa: String, phrase: String, reply: @escaping ([String: Any]) -> Void) {
        let key = "\(reqId):\(seq)"
        if let stored = store.values[key] { reply(stored); return }
        let ack: [String: Any] = ["type": "ack", "reqId": reqId, "ok": true, "result": ["sync": "updated"]]
        store.values[key] = ack
        reply(ack)
    }

    func pwaWalletSyncCipher(reqId: Int, seq: Int, eoa: String, cipher: [String: Any], passcode: String?, reply: @escaping ([String: Any]) -> Void) {
        reply(["type": "ack", "reqId": reqId, "ok": false, "error": "write_failed", "reason": "internal_state"])
    }

    func nativeMnemonicPreread(reqId: Int, seq: Int, reply: @escaping ([String: Any]) -> Void) {
        reply(["type": "ack", "reqId": reqId, "ok": true, "result": ["code": "read_error"]])
    }
}

private final class ReplyStore {
    var values: [String: [String: Any]] = [:]
}

private func syncCommand(
    reqId: Any = syntheticReqId,
    seq: Any = 5,
    eoa: Any = syntheticEoa,
    phrase: Any = syntheticPhrase
) -> [String: Any] {
    ["type": "pwaWalletSync", "reqId": reqId, "eoa": eoa, "phrase": phrase, "seq": seq]
}

private func prereadCommand(reqId: Any = syntheticReqId, seq: Any = 5) -> [String: Any] {
    ["type": "nativeMnemonicPreread", "reqId": reqId, "seq": seq]
}

/// Runs the gate once and returns the single reply the page would receive.
private func run(_ gate: PwaWalletSyncGate, _ command: [String: Any], trusted: Bool = true) -> [String: Any] {
    var out: [String: Any] = [:]
    var count = 0
    gate.handle(command: command, trustedOrigin: trusted) { reply in
        out = reply
        count += 1
    }
    #expect(count == 1, "exactly one reply per command")
    return out
}

private func ackOf(_ wrapped: [String: Any]) -> [String: Any] {
    #expect(wrapped["action"] as? String == "chatModuleEvent", "the page reads only the chatModuleEvent wrapper")
    return wrapped["event"] as? [String: Any] ?? [:]
}

/// Canonical JSON text, so two replies can be compared exactly (order-independent).
private func canonical(_ value: [String: Any]) -> String {
    let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    return data.flatMap { String(data: $0, encoding: .utf8) } ?? "<invalid>"
}

private func errorOf(_ wrapped: [String: Any]) -> String? {
    ackOf(wrapped)["error"] as? String
}

struct PwaWalletSyncBridgeTests {
    // MARK: trusted origin (section 11, step 1)

    @Test func mainFrameOfEmbeddedPwaIsTrusted() {
        #expect(PwaWalletSyncTrust.isTrusted(isMainFrame: true, scheme: "cashtrees-local", host: "localhost"))
        #expect(PwaWalletSyncTrust.isTrusted(isMainFrame: true, scheme: "CASHTREES-LOCAL", host: "LocalHost"))
    }

    @Test func subFramesRemotePagesAndLookalikesAreNotTrusted() {
        #expect(!PwaWalletSyncTrust.isTrusted(isMainFrame: false, scheme: "cashtrees-local", host: "localhost"))
        #expect(!PwaWalletSyncTrust.isTrusted(isMainFrame: true, scheme: "https", host: "beamio.ca"))
        #expect(!PwaWalletSyncTrust.isTrusted(isMainFrame: true, scheme: "https", host: "localhost"))
        #expect(!PwaWalletSyncTrust.isTrusted(isMainFrame: true, scheme: "cashtrees-local", host: "localhost.evil.example"))
        #expect(!PwaWalletSyncTrust.isTrusted(isMainFrame: true, scheme: "cashtrees-local", host: ""))
    }

    @Test func untrustedSyncIsRefusedBeforeAnythingElse() {
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        let out = run(gate, syncCommand(), trusted: false)
        #expect(errorOf(out) == "untrusted_source")
        #expect(ackOf(out)["ok"] as? Bool == false)
        #expect(ackOf(out)["reqId"] as? Int == syntheticReqId)
        #expect(engine.syncCalls.isEmpty, "nothing is read or written for an untrusted source")
        #expect(!canonical(out).contains(syntheticPhrase), "a refusal never echoes the phrase")
    }

    @Test func pageSentTrustedOriginCannotOverrideTheShell() {
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        var cmd = syncCommand()
        cmd["trustedOrigin"] = true
        let out = run(gate, cmd, trusted: false)
        #expect(errorOf(out) == "untrusted_source")
        #expect(engine.syncCalls.isEmpty)
    }

    @Test func pageSentTrustedOriginFalseDoesNotBlockTrustedShell() {
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        var cmd = syncCommand()
        cmd["trustedOrigin"] = false
        _ = run(gate, cmd, trusted: true)
        #expect(engine.syncCalls.count == 1, "the shell's value decides; the page field is ignored")
    }

    @Test func untrustedPrereadReturnsNoMnemonicField() {
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        let out = run(gate, prereadCommand(), trusted: false)
        #expect(errorOf(out) == "untrusted_source")
        #expect(ackOf(out)["result"] == nil)
        #expect(engine.prereadCalls.isEmpty)
        #expect(!canonical(out).contains("phrase"))
        #expect(!canonical(out).contains("eoa"))
    }

    // MARK: forbidden fields (step 2)

    @Test func credentialFieldsAreRefusedWithoutEchoingTheirValue() {
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        let fields = ["privateKeyHex", "privateKey", "PRIVATEKEYHEX", "mnemonic", "recoveryCode", "pin", "password", "seedPhrase"]
        for field in fields {
            var cmd = syncCommand()
            cmd[field] = "SYNTHETIC-VALUE-NOT-REAL"
            let out = run(gate, cmd)
            #expect(errorOf(out) == "key_over_bridge_refused", "field \(field)")
            #expect(!canonical(out).contains("SYNTHETIC-VALUE-NOT-REAL"), "field \(field) is never echoed")
        }
        #expect(engine.syncCalls.isEmpty)
    }

    @Test func similarButNonCredentialFieldNamesAreNotRefused() {
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        var cmd = syncCommand()
        cmd["pinned"] = true
        cmd["passwordHint"] = "x"
        _ = run(gate, cmd)
        #expect(engine.syncCalls.count == 1, "only whole credential names are refused")
    }

    @Test func forbiddenFieldBeatsFormatError() {
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        var cmd = syncCommand(phrase: "too short")
        cmd["mnemonic"] = syntheticPhrase
        #expect(errorOf(run(gate, cmd)) == "key_over_bridge_refused")
    }

    @Test func untrustedBeatsForbiddenField() {
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        var cmd = syncCommand()
        cmd["mnemonic"] = syntheticPhrase
        #expect(errorOf(run(gate, cmd, trusted: false)) == "untrusted_source")
    }

    // MARK: format (step 3)

    @Test func badReqIdIsBadRequestAndNotEchoed() {
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        for bad in [0, -1, "900000001", true, 1.5, NSNull()] as [Any] {
            let out = run(gate, syncCommand(reqId: bad))
            #expect(errorOf(out) == "bad_request", "reqId \(bad)")
            #expect(ackOf(out)["reqId"] is NSNull, "an unusable reqId is answered as null")
        }
        var missing = syncCommand()
        missing.removeValue(forKey: "reqId")
        #expect(errorOf(run(gate, missing)) == "bad_request")
        #expect(engine.syncCalls.isEmpty)
    }

    @Test func badSeqIsBadRequestWithReqIdEchoed() {
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        // errata E3: seq lower bound is 0; negatives, non-integers, strings, booleans and values above 2^53-1 are bad_request
        for bad in [-1, -3, "5", false, true, 2.5, 9_007_199_254_740_992] as [Any] {
            let out = run(gate, syncCommand(seq: bad))
            #expect(errorOf(out) == "bad_request", "seq \(bad)")
            #expect(ackOf(out)["reqId"] as? Int == syntheticReqId)
        }
        var missing = syncCommand()
        missing.removeValue(forKey: "seq")
        #expect(errorOf(run(gate, missing)) == "bad_request")
        #expect(engine.syncCalls.isEmpty)
    }

    @Test func seqZeroIsAcceptedAndPassedToTheEngine() {
        // errata E3: 0 is a legal seq; whether it is stale is the SDK's decision (highest accepted seq).
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        _ = run(gate, syncCommand(seq: 0))
        #expect(engine.syncCalls.count == 1)
        #expect(engine.syncCalls.first?.seq == 0)
        _ = run(gate, prereadCommand(seq: 0))
        #expect(engine.prereadCalls.count == 1)
        #expect(engine.prereadCalls.first?.seq == 0)
    }

    @Test func badEoaIsBadRequest() {
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        let bad = [
            "0x1111111111111111111111111111111111111111".uppercased(),
            "0X1111111111111111111111111111111111111111",
            "1111111111111111111111111111111111111111",
            "0x111111111111111111111111111111111111111",
            "0x11111111111111111111111111111111111111111",
            "0x111111111111111111111111111111111111111g",
            "",
        ]
        for value in bad {
            #expect(errorOf(run(gate, syncCommand(eoa: value))) == "bad_request", "eoa \(value)")
        }
        #expect(errorOf(run(gate, syncCommand(eoa: NSNull()))) == "bad_request")
        #expect(engine.syncCalls.isEmpty)
    }

    @Test func badPhraseIsBadRequest() {
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        let eleven = Array(repeating: "abandon", count: 11).joined(separator: " ")
        let thirteen = Array(repeating: "abandon", count: 13).joined(separator: " ")
        let bad = [
            eleven,
            thirteen,
            syntheticPhrase.replacingOccurrences(of: " about", with: "  about"),
            " " + syntheticPhrase,
            syntheticPhrase + " ",
            syntheticPhrase.uppercased(),
            syntheticPhrase.replacingOccurrences(of: "about", with: "abou1"),
            "",
        ]
        for value in bad {
            #expect(errorOf(run(gate, syncCommand(phrase: value))) == "bad_request", "phrase word count \(value.split(separator: " ").count)")
        }
        #expect(errorOf(run(gate, syncCommand(phrase: NSNull()))) == "bad_request")
        #expect(engine.syncCalls.isEmpty)
    }

    @Test func wellFormedPhraseLengthsReachTheEngine() {
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        for count in [12, 15, 18, 21, 24] {
            let phrase = Array(repeating: "abandon", count: count).joined(separator: " ")
            _ = run(gate, syncCommand(phrase: phrase))
        }
        #expect(engine.syncCalls.count == 5)
    }

    @Test func unknownFieldsAreNotForwardedToTheEngine() {
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        var cmd = syncCommand()
        cmd["extra"] = "ignored"
        _ = run(gate, cmd)
        #expect(engine.syncCalls.count == 1)
        #expect(engine.syncCalls[0].eoa == syntheticEoa)
        #expect(engine.syncCalls[0].phrase == syntheticPhrase)
    }

    // MARK: engine answers pass through unchanged (section 11 table)

    @Test func everyEngineAnswerIsReturnedVerbatim() {
        let answers: [[String: Any]] = [
            ["type": "ack", "reqId": syntheticReqId, "ok": true, "result": ["sync": "updated"]],
            ["type": "ack", "reqId": syntheticReqId, "ok": true, "result": ["sync": "idempotent"]],
            ["type": "ack", "reqId": syntheticReqId, "ok": false, "error": "untrusted_source"],
            ["type": "ack", "reqId": syntheticReqId, "ok": false, "error": "key_over_bridge_refused"],
            ["type": "ack", "reqId": syntheticReqId, "ok": false, "error": "bad_request"],
            ["type": "ack", "reqId": syntheticReqId, "ok": false, "error": "stale_seq"],
            ["type": "ack", "reqId": syntheticReqId, "ok": false, "error": "write_failed", "reason": "internal_state"],
            ["type": "ack", "reqId": syntheticReqId, "ok": false, "error": "write_failed", "reason": "storage_write"],
        ]
        for answer in answers {
            let engine = RecordingEngine()
            engine.syncAck = answer
            let out = run(PwaWalletSyncGate(engine: engine), syncCommand())
            #expect(canonical(ackOf(out)) == canonical(answer), "answer \(canonical(answer))")
            #expect(JSONSerialization.isValidJSONObject(out))
        }
    }

    @Test func staleSeqFromTheEngineIsPassedOnAndNotRewritten() {
        let engine = RecordingEngine()
        engine.syncAck = ["type": "ack", "reqId": syntheticReqId, "ok": false, "error": "stale_seq"]
        let out = run(PwaWalletSyncGate(engine: engine), syncCommand(seq: 1))
        #expect(errorOf(out) == "stale_seq")
        #expect(engine.syncCalls.first?.seq == 1, "the sequence number reaches the engine, which decides staleness")
    }

    // MARK: nativeMnemonicPreread

    @Test func prereadAnswersAreReturnedVerbatim() {
        let valid: [String: Any] = [
            "type": "ack", "reqId": syntheticReqId, "ok": true,
            "result": ["code": "ok", "eoa": syntheticEoa, "mnemonic": syntheticPhrase],
        ]
        let engine = RecordingEngine()
        engine.prereadAck = valid
        let out = run(PwaWalletSyncGate(engine: engine), prereadCommand())
        #expect(canonical(ackOf(out)) == canonical(valid))
        #expect(engine.prereadCalls.first?.seq == 5)
    }

    // Approval 2026-11-17 (preread restricted return): the answer with the mnemonic goes only to the trusted main frame.

    @Test func trustedMainFramePrereadReachesTheEngineAndReturnsItsAnswer() {
        let valid: [String: Any] = [
            "type": "ack", "reqId": syntheticReqId, "ok": true,
            "result": ["code": "ok", "eoa": syntheticEoa, "mnemonic": syntheticPhrase],
        ]
        let engine = RecordingEngine()
        engine.prereadAck = valid
        let trusted = PwaWalletSyncTrust.isTrusted(isMainFrame: true, scheme: "cashtrees-local", host: "localhost")
        #expect(trusted)
        let out = run(PwaWalletSyncGate(engine: engine), prereadCommand(), trusted: trusted)
        #expect(engine.prereadCalls.count == 1, "the trusted main frame reaches the engine once")
        #expect(canonical(ackOf(out)) == canonical(valid), "the engine answer is returned")
    }

    @Test func subFramePrereadGetsUntrustedSourceAndTheEngineIsNotCalled() {
        let engine = RecordingEngine()
        engine.prereadAck = ["type": "ack", "reqId": syntheticReqId, "ok": true,
                             "result": ["code": "ok", "eoa": syntheticEoa, "mnemonic": syntheticPhrase]]
        let trusted = PwaWalletSyncTrust.isTrusted(isMainFrame: false, scheme: "cashtrees-local", host: "localhost")
        #expect(!trusted, "a sub-frame is never trusted")
        let out = run(PwaWalletSyncGate(engine: engine), prereadCommand(), trusted: trusted)
        #expect(errorOf(out) == "untrusted_source")
        #expect(engine.prereadCalls.isEmpty, "the engine is not called for a sub-frame")
        #expect(!canonical(out).contains(syntheticPhrase))
        #expect(!canonical(out).contains(syntheticEoa))
    }

    @Test func nonTrustedOriginPrereadGetsUntrustedSourceAndTheEngineIsNotCalled() {
        // E6 NE-05: a main frame of a non-trusted origin (remote page, or another local scheme) is not trusted either
        let engine = RecordingEngine()
        engine.prereadAck = ["type": "ack", "reqId": syntheticReqId, "ok": true,
                             "result": ["code": "ok", "eoa": syntheticEoa, "mnemonic": syntheticPhrase]]
        let remote = PwaWalletSyncTrust.isTrusted(isMainFrame: true, scheme: "https", host: "beamio.ca")
        let otherScheme = PwaWalletSyncTrust.isTrusted(isMainFrame: true, scheme: "https", host: "localhost")
        #expect(!remote && !otherScheme)
        for trusted in [remote, otherScheme] {
            let out = run(PwaWalletSyncGate(engine: engine), prereadCommand(), trusted: trusted)
            #expect(errorOf(out) == "untrusted_source")
            #expect(!canonical(out).contains(syntheticPhrase))
        }
        #expect(engine.prereadCalls.isEmpty, "the engine is not called for a non-trusted origin")
    }

    // Interface specification: the preread answer is filtered on the closed set of `result.code` values.

    @Test func prereadOkWithMnemonicPassesCodeMnemonicAndEoaUnchanged() {
        let engine = RecordingEngine()
        engine.prereadAck = ["type": "ack", "reqId": syntheticReqId, "ok": true,
                             "result": ["code": "ok", "mnemonic": syntheticPhrase, "eoa": syntheticEoa, "extra": "dropped"]]
        let result = ackOf(run(PwaWalletSyncGate(engine: engine), prereadCommand()))["result"] as? [String: Any]
        #expect(result?.keys.sorted() == ["code", "eoa", "mnemonic"], "only the ok keys pass")
        #expect(result?["code"] as? String == "ok")
        #expect(result?["mnemonic"] as? String == syntheticPhrase)
        #expect(result?["eoa"] as? String == syntheticEoa)
    }

    @Test func prereadOkWithCipherPassesTheCipherObjectUnchanged() {
        let cipher: [String: Any] = ["v": 3, "kdf": "argon2id", "ct": "SYNTHETIC-CIPHERTEXT"]
        let engine = RecordingEngine()
        engine.prereadAck = ["type": "ack", "reqId": syntheticReqId, "ok": true,
                             "result": ["code": "ok", "cipher": cipher, "eoa": syntheticEoa]]
        let result = ackOf(run(PwaWalletSyncGate(engine: engine), prereadCommand()))["result"] as? [String: Any]
        #expect(result?.keys.sorted() == ["cipher", "code", "eoa"])
        #expect(canonical(result?["cipher"] as? [String: Any] ?? [:]) == canonical(cipher), "the cipher object is passed as it is")
        #expect(result?["mnemonic"] == nil)
    }

    @Test func prereadCodesWithoutPayloadCarryOnlyTheCode() {
        for code in ["confirmed_missing", "read_error", "not_ready"] {
            let engine = RecordingEngine()
            engine.prereadAck = ["type": "ack", "reqId": syntheticReqId, "ok": true, "result": ["code": code]]
            let ack = ackOf(run(PwaWalletSyncGate(engine: engine), prereadCommand()))
            let result = ack["result"] as? [String: Any]
            #expect(result?.keys.sorted() == ["code"], "code \(code)")
            #expect(result?["code"] as? String == code, "code \(code) is kept")
            #expect(ack["reqId"] as? Int == syntheticReqId, "code \(code): reqId echoed")
        }
    }

    @Test func prereadCodeOutsideTheClosedSetBecomesReadError() {
        let outside: [[String: Any]] = [
            ["code": "valid"], ["code": "absent"], ["code": "OK"], ["code": ""], ["code": 1],
            ["state": "valid", "phrase": syntheticPhrase, "eoa": syntheticEoa], ["state": "absent"], [:],
        ]
        for result in outside {
            let engine = RecordingEngine()
            engine.prereadAck = ["type": "ack", "reqId": syntheticReqId, "ok": true, "result": result]
            let out = run(PwaWalletSyncGate(engine: engine), prereadCommand())
            let filtered = ackOf(out)["result"] as? [String: Any]
            #expect(filtered?.keys.sorted() == ["code"], "\(canonical(result))")
            #expect(filtered?["code"] as? String == "read_error", "\(canonical(result)) -> read_error")
            #expect(!canonical(out).contains(syntheticPhrase), "\(canonical(result)): no phrase")
            #expect(!canonical(out).contains(syntheticEoa), "\(canonical(result)): no eoa")
        }
    }

    @Test func prereadNonOkCodesStripMnemonicEoaAndCipher() {
        // A buggy or hostile engine answer: material attached to a non-ok code never reaches the page.
        for code in ["confirmed_missing", "read_error", "not_ready", "unexpected"] {
            let engine = RecordingEngine()
            engine.prereadAck = ["type": "ack", "reqId": syntheticReqId, "ok": true,
                                 "result": ["code": code, "mnemonic": syntheticPhrase, "eoa": syntheticEoa,
                                            "cipher": ["ct": "SYNTHETIC-CIPHERTEXT"]]]
            let out = run(PwaWalletSyncGate(engine: engine), prereadCommand())
            let result = ackOf(out)["result"] as? [String: Any]
            #expect(result?.keys.sorted() == ["code"], "code \(code)")
            #expect(!canonical(out).contains(syntheticPhrase), "code \(code): no phrase")
            #expect(!canonical(out).contains(syntheticEoa), "code \(code): no eoa")
            #expect(!canonical(out).contains("SYNTHETIC-CIPHERTEXT"), "code \(code): no cipher")
        }
    }

    @Test func prereadErrorAckWithoutResultPassesUnchanged() {
        let engine = RecordingEngine()
        let error: [String: Any] = ["type": "ack", "reqId": syntheticReqId, "ok": false, "error": "not_ready"]
        engine.prereadAck = error
        #expect(canonical(ackOf(run(PwaWalletSyncGate(engine: engine), prereadCommand()))) == canonical(error))
    }

    @Test func prereadWithCredentialFieldIsRefused() {
        let engine = RecordingEngine()
        var cmd = prereadCommand()
        cmd["privateKeyHex"] = "SYNTHETIC-VALUE-NOT-REAL"
        let out = run(PwaWalletSyncGate(engine: engine), cmd)
        #expect(errorOf(out) == "key_over_bridge_refused")
        #expect(engine.prereadCalls.isEmpty)
    }

    @Test func prereadBadSeqIsBadRequest() {
        let engine = RecordingEngine()
        #expect(errorOf(run(PwaWalletSyncGate(engine: engine), prereadCommand(seq: -1))) == "bad_request")
        #expect(errorOf(run(PwaWalletSyncGate(engine: engine), prereadCommand(seq: "1"))) == "bad_request")
        #expect(engine.prereadCalls.isEmpty)
    }

    @Test func prereadWithPhraseIsRefusedWithoutEchoingIt() {
        // errata E1: the phrase exception covers pwaWalletSync only; a preread request carrying a phrase is refused
        let engine = RecordingEngine()
        var cmd = prereadCommand()
        cmd["phrase"] = syntheticPhrase
        let out = run(PwaWalletSyncGate(engine: engine), cmd)
        #expect(errorOf(out) == "key_over_bridge_refused")
        #expect(engine.prereadCalls.isEmpty)
        #expect(!canonical(out).contains(syntheticPhrase))
    }

    // MARK: routing of both body shapes (review finding 1: a flat body must not bypass the gate)

    @Test func nestedCommandIsRoutedToTheGate() {
        let body: [String: Any] = ["action": "chatModuleCommand", "command": syncCommand()]
        #expect(PwaWalletSyncBridge.walletSyncCommand(in: body)?["type"] as? String == "pwaWalletSync")
    }

    @Test func flatBodyIsRoutedToTheGateAndCannotBypassIt() {
        var flat = syncCommand()
        flat["action"] = "chatModuleCommand"
        let routed = PwaWalletSyncBridge.walletSyncCommand(in: flat)
        #expect(routed != nil, "a flat pwaWalletSync body must reach the gate")

        // reached the gate untrusted: refused, and the engine is never called
        let engine = RecordingEngine()
        let gate = PwaWalletSyncGate(engine: engine)
        if let routed {
            #expect(errorOf(run(gate, routed, trusted: false)) == "untrusted_source")
            #expect(engine.syncCalls.isEmpty)
        }
    }

    @Test func flatPrereadBodyIsRouted() {
        let flat: [String: Any] = ["action": "chatModuleCommand", "type": "nativeMnemonicPreread", "reqId": syntheticReqId, "seq": 3]
        #expect(PwaWalletSyncBridge.walletSyncCommand(in: flat)?["type"] as? String == "nativeMnemonicPreread")
    }

    @Test func nonStringOrNonDictionaryCommandStillRoutesAFlatWalletSyncBody() {
        let flat: [String: Any] = ["action": "chatModuleCommand", "command": "not-a-dictionary", "type": "pwaWalletSync"]
        #expect(PwaWalletSyncBridge.walletSyncCommand(in: flat) != nil)
    }

    @Test func otherCommandsAreNotRouted() {
        #expect(PwaWalletSyncBridge.walletSyncCommand(in: ["action": "chatModuleCommand", "command": ["type": "walletStatus", "reqId": 1]]) == nil)
        #expect(PwaWalletSyncBridge.walletSyncCommand(in: ["action": "chatModuleCommand", "type": "init"]) == nil)
        #expect(PwaWalletSyncBridge.walletSyncCommand(in: ["action": "consoleLog", "level": "log"]) == nil)
    }

    // MARK: fail-closed default (SDK not yet wired)

    @Test func notWiredEngineFailsClosed() {
        let gate = PwaWalletSyncGate(engine: PwaWalletSyncNotWiredEngine())
        let sync = run(gate, syncCommand())
        #expect(errorOf(sync) == "write_failed")
        #expect(ackOf(sync)["reason"] as? String == "internal_state")
        let preread = run(gate, prereadCommand())
        #expect((ackOf(preread)["result"] as? [String: Any])?["code"] as? String == "read_error")
        #expect(!canonical(preread).contains(syntheticPhrase))
    }

    // MARK: restart and repeat (section 11, retry)

    @Test func repeatedReqIdAndSeqGiveTheSameAnswerAfterRestart() {
        let store = ReplyStore()
        let first = run(PwaWalletSyncGate(engine: DurableReplyEngine(store: store)), syncCommand(seq: 7))
        // a new gate and engine instance simulates an app restart; the store survives it
        let afterRestart = run(PwaWalletSyncGate(engine: DurableReplyEngine(store: store)), syncCommand(seq: 7))
        #expect(canonical(first) == canonical(afterRestart))
    }

    @Test func commandOwnershipIsLimitedToTheTwoWalletSyncCommands() {
        #expect(PwaWalletSyncBridge.handles(syncCommand()))
        #expect(PwaWalletSyncBridge.handles(prereadCommand()))
        #expect(!PwaWalletSyncBridge.handles(["type": "walletStatus", "reqId": 1]))
        #expect(!PwaWalletSyncBridge.handles(["reqId": 1]))
    }
}
