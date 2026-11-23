import Foundation
import Testing
@testable import CashTrees_iOS

// M6 method Y: the shell gate for pwaWalletSync{eoa, cipher, passcode, seq}.
// Spec: the unlock-sync spec, section 2.2.
// Vectors: the spec's gate cases MG-01 ... MG-10, unchanged in its second revision, which adds SC-04 (sc04NoReplyCarriesThePasscode below; the source check is scripts/verify-ios-passcode-no-logging.sh).
// Synthetic values only: the envelope below has the v3 shape with placeholder fields (no real ciphertext), the passcode is a
// placeholder, and no value is logged. The placeholder fields have the v3 sizes (salt 16, iv 12, ct 24 bytes) but are not ciphertext. The gate checks shapes only; decryption is the SDK's.

private let eoa = "0x2222222222222222222222222222222222222222"
private let reqIdValue = 900_100_001
private let passcodeValue = "246813"
private let syntheticPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
private let envelope: [String: Any] = [
    "v": 3, "mode": "passcode", "eoa": "0x2222222222222222222222222222222222222222",
    "kdf": "argon2id/m=32768/t=3/p=1/dkLen=32", "salt": "U1lOVEhFVElDLVNBTFQxNg==", "iv": "U1lOVEgtSVYtMTJC",
    "alg": "AES-256-GCM", "ct": "U1lOVEhFVElDLUNULU5PVC1SRUFMLTAw",
]

private final class Engine: PwaWalletSyncEngine {
    var phraseCalls = 0
    var cipherCalls: [(eoa: String, cipher: [String: Any], passcode: String?, seq: Int)] = []
    var prereadCalls = 0
    let ack: [String: Any] = ["type": "ack", "reqId": 900_100_001, "ok": true,
                              "result": ["code": "ok", "decrypted": true, "stored": true, "readback": "match"]]

    func pwaWalletSync(reqId: Int, seq: Int, eoa: String, phrase: String, reply: @escaping ([String: Any]) -> Void) {
        phraseCalls += 1
        reply(ack)
    }

    func pwaWalletSyncCipher(reqId: Int, seq: Int, eoa: String, cipher: [String: Any], passcode: String?, reply: @escaping ([String: Any]) -> Void) {
        cipherCalls.append((eoa, cipher, passcode, seq))
        reply(ack)
    }

    func nativeMnemonicPreread(reqId: Int, seq: Int, reply: @escaping ([String: Any]) -> Void) {
        prereadCalls += 1
        reply(["type": "ack", "reqId": reqId, "ok": true, "result": ["code": "confirmed_missing"]])
    }

    var reachedSdk: Bool { phraseCalls + cipherCalls.count + prereadCalls > 0 }
}

private final class FailingEngine: PwaWalletSyncEngine {
    func pwaWalletSync(reqId: Int, seq: Int, eoa: String, phrase: String, reply: @escaping ([String: Any]) -> Void) {
        reply(["type": "ack", "reqId": reqId, "ok": false, "error": "write_failed", "reason": "internal_state"])
    }
    func pwaWalletSyncCipher(reqId: Int, seq: Int, eoa: String, cipher: [String: Any], passcode: String?, reply: @escaping ([String: Any]) -> Void) {
        reply(["type": "ack", "reqId": reqId, "ok": true, "result": ["code": "unlock_failed"]])
    }
    func nativeMnemonicPreread(reqId: Int, seq: Int, reply: @escaping ([String: Any]) -> Void) {
        reply(["type": "ack", "reqId": reqId, "ok": true, "result": ["code": "read_error"]])
    }
}

private func command(_ fields: [String: Any]) -> [String: Any] {
    var c: [String: Any] = ["type": "pwaWalletSync", "reqId": reqIdValue, "seq": 7]
    for (k, v) in fields { c[k] = v }
    return c
}

private func run(_ engine: Engine, _ command: [String: Any], trusted: Bool = true) -> [String: Any] {
    var out: [String: Any] = [:]
    var count = 0
    PwaWalletSyncGate(engine: engine).handle(command: command, trustedOrigin: trusted) { reply in
        out = reply
        count += 1
    }
    #expect(count == 1, "exactly one reply per command")
    return out["event"] as? [String: Any] ?? [:]
}

private func text(_ value: [String: Any]) -> String {
    (try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])).flatMap { String(data: $0, encoding: .utf8) } ?? ""
}

struct PwaWalletSyncPasscodeGateTests {
    @Test func mg01CipherWithSixDigitPasscodeIsForwardedUnchanged() {
        let engine = Engine()
        let ack = run(engine, command(["eoa": eoa, "cipher": envelope, "passcode": passcodeValue]))
        #expect(engine.cipherCalls.count == 1, "forwarded to the SDK once")
        #expect(engine.phraseCalls == 0)
        #expect(engine.cipherCalls.first?.eoa == eoa)
        #expect(engine.cipherCalls.first?.passcode == passcodeValue)
        #expect(engine.cipherCalls.first?.seq == 7)
        #expect(text(engine.cipherCalls.first?.cipher ?? [:]) == text(envelope), "the envelope reaches the SDK as it was sent")
        #expect(text(ack) == text(engine.ack), "the SDK's ack is returned unchanged")
    }

    @Test func mg02ForwardingDoesNotDependOnTheCapability() {
        // The gate takes no capability input: the same command is forwarded whatever the hello declared (wallet.passcode.v1 gates
        // only the passcode commands, which do not pass through this gate; see mg10).
        for _ in [true, false] {
            let engine = Engine()
            _ = run(engine, command(["eoa": eoa, "cipher": envelope, "passcode": passcodeValue]))
            #expect(engine.cipherCalls.count == 1)
        }
    }

    @Test func mg03PasscodeWithPhraseAndNoCipherIsRefusedBeforeTheSdk() {
        let engine = Engine()
        let ack = run(engine, command(["eoa": eoa, "phrase": syntheticPhrase, "passcode": passcodeValue]))
        #expect(ack["ok"] as? Bool == false)
        #expect(ack["error"] as? String == "key_over_bridge_refused")
        #expect(!engine.reachedSdk)
        #expect(!text(ack).contains(passcodeValue) && !text(ack).contains(syntheticPhrase), "no value is echoed")
    }

    @Test func mg04PasscodeAloneIsRefused() {
        let engine = Engine()
        let ack = run(engine, command(["eoa": eoa, "passcode": passcodeValue]))
        #expect(ack["error"] as? String == "key_over_bridge_refused")
        #expect(!engine.reachedSdk)
    }

    @Test func mg05CipherTogetherWithPhraseIsRefused() {
        let engine = Engine()
        let ack = run(engine, command(["eoa": eoa, "cipher": envelope, "phrase": syntheticPhrase]))
        #expect(ack["error"] as? String == "key_over_bridge_refused")
        #expect(!engine.reachedSdk)
        let withPasscode = run(engine, command(["eoa": eoa, "cipher": envelope, "phrase": syntheticPhrase, "passcode": passcodeValue]))
        #expect(withPasscode["error"] as? String == "key_over_bridge_refused")
        #expect(!engine.reachedSdk)
    }

    @Test func mg06PasscodeThatIsNotSixDigitsIsBadRequest() {
        let bad: [Any] = ["12345", "1234567", "abcdef", 123456, NSNull(), "12 456", "１２３４５６", ""]
        for value in bad {
            let engine = Engine()
            let ack = run(engine, command(["eoa": eoa, "cipher": envelope, "passcode": value]))
            #expect(ack["ok"] as? Bool == false, "\(type(of: value))")
            #expect(ack["error"] as? String == "bad_request", "\(type(of: value))")
            #expect(!engine.reachedSdk, "nothing is forwarded")
        }
    }

    @Test func mg07CipherThatIsNotAV3PasscodeEnvelopeIsBadRequest() {
        var v2 = envelope
        v2["v"] = 2
        var keychainMode = envelope
        keychainMode["mode"] = "keychain"
        var boolVersion = envelope
        boolVersion["v"] = true
        let bad: [Any] = ["text", 1, NSNull(), [Any](), ["v": 2], v2, keychainMode, boolVersion]
        for value in bad {
            let engine = Engine()
            let ack = run(engine, command(["eoa": eoa, "cipher": value, "passcode": passcodeValue]))
            #expect(ack["error"] as? String == "bad_request", "\(type(of: value))")
            #expect(!engine.reachedSdk)
        }
    }

    @Test func mg08OtherCredentialFieldsAreRefusedWithOrWithoutCipher() {
        for field in ["privateKey", "mnemonic", "recoveryCode", "password", "pin", "seed"] {
            for withCipher in [true, false] {
                let engine = Engine()
                var fields: [String: Any] = ["eoa": eoa, field: "SYNTHETIC-NOT-A-SECRET"]
                if withCipher {
                    fields["cipher"] = envelope
                    fields["passcode"] = passcodeValue
                } else {
                    fields["phrase"] = syntheticPhrase
                }
                let ack = run(engine, command(fields))
                #expect(ack["error"] as? String == "key_over_bridge_refused", "\(field) cipher=\(withCipher)")
                #expect(!engine.reachedSdk)
            }
        }
        // A case variant of an accepted credential name is refused, never read under its exact spelling.
        let engine = Engine()
        let ack = run(engine, command(["eoa": eoa, "cipher": envelope, "Passcode": passcodeValue]))
        #expect(ack["error"] as? String == "key_over_bridge_refused")
        #expect(!engine.reachedSdk)
    }

    @Test func mg09UntrustedSourceIsRefusedForEveryForm() {
        let forms: [[String: Any]] = [
            ["eoa": eoa, "cipher": envelope, "passcode": passcodeValue],
            ["eoa": eoa, "cipher": envelope],
            ["eoa": eoa, "phrase": syntheticPhrase],
            ["eoa": eoa, "passcode": passcodeValue],
        ]
        for fields in forms {
            let engine = Engine()
            let ack = run(engine, command(fields), trusted: false)
            #expect(ack["error"] as? String == "untrusted_source")
            #expect(!engine.reachedSdk)
        }
        // nativeMnemonicPreread may not carry cipher or passcode either (errata E1 extended).
        let engine = Engine()
        let ack = run(engine, ["type": "nativeMnemonicPreread", "reqId": reqIdValue, "seq": 1, "cipher": envelope])
        #expect(ack["error"] as? String == "key_over_bridge_refused")
        #expect(!engine.reachedSdk)
    }

    @Test func mg10PasscodeCommandsKeepTheirOwnPath() {
        // The passcode commands are not handled by this gate: they keep the chatModuleCommand path to the SDK, gated by wallet.passcode.v1.
        for type in ["passcodeProvision", "passcodeUnlock", "passcodeChange", "passcodeDisable", "passcodeStatus"] {
            let body: [String: Any] = ["type": type, "reqId": reqIdValue, "eoa": eoa, "passcode": passcodeValue]
            #expect(!PwaWalletSyncBridge.handles(body), "\(type) is not taken by the wallet-sync gate")
            #expect(PwaWalletSyncBridge.walletSyncCommand(in: ["action": "chatModuleCommand", "command": body]) == nil)
        }
    }

    @Test func cipherWithoutPasscodeIsForwardedForTheStoreOnlyMirror() {
        // unlock-sync spec §2.4, last item: an envelope without a passcode is a store-only mirror (decrypted: false) decided by the SDK.
        let engine = Engine()
        _ = run(engine, command(["eoa": eoa, "cipher": envelope]))
        #expect(engine.cipherCalls.count == 1)
        #expect(engine.cipherCalls.first?.passcode == nil)
    }

    @Test func cipherWithMalformedEoaIsBadRequest() {
        let engine = Engine()
        let ack = run(engine, command(["eoa": "0xABC", "cipher": envelope, "passcode": passcodeValue]))
        #expect(ack["error"] as? String == "bad_request")
        #expect(!engine.reachedSdk)
    }

    @Test func productAdapterForwardsToTheSdkCipherEntry() {
        // The product adapter calls the chat SDK's public cipher entry. A request whose eoa differs from the envelope's eoa is answered
        // before any decryption (SDK: ok, code verify_failed; nothing read, decrypted or written), which shows the call reached
        // the SDK without needing real material.
        var mismatched = envelope
        mismatched["eoa"] = "0x3333333333333333333333333333333333333333"
        var out: [String: Any] = [:]
        PwaWalletSyncSdkEngine().pwaWalletSyncCipher(reqId: reqIdValue, seq: 7, eoa: eoa, cipher: mismatched, passcode: passcodeValue) { out = $0 }
        #expect(out["type"] as? String == "ack")
        #expect(out["ok"] as? Bool == true)
        #expect((out["result"] as? [String: Any])?["code"] as? String == "verify_failed", "the SDK refuses the eoa mismatch before decrypting")
        #expect((out["result"] as? [String: Any])?["decrypted"] == nil, "nothing is reported as decrypted")
        #expect(!text(out).contains(passcodeValue), "the answer does not echo the passcode")
    }

    // SC-04 (vectors v2): the shell never stores, logs or forwards the passcode; it checks the shape and hands it on in memory.

    @Test func sc04NoReplyCarriesThePasscode() {
        let forms: [[String: Any]] = [
            ["eoa": eoa, "cipher": envelope, "passcode": passcodeValue],
            ["eoa": eoa, "passcode": passcodeValue],
            ["eoa": eoa, "phrase": syntheticPhrase, "passcode": passcodeValue],
            ["eoa": eoa, "cipher": "text", "passcode": passcodeValue],
            ["eoa": eoa, "cipher": envelope, "passcode": passcodeValue, "privateKey": "SYNTHETIC"],
        ]
        for fields in forms {
            for trusted in [true, false] {
                let engine = FailingEngine()
                var out: [String: Any] = [:]
                PwaWalletSyncGate(engine: engine).handle(command: command(fields), trustedOrigin: trusted) { out = $0 }
                #expect(!text(out).contains(passcodeValue), "no reply echoes the passcode (trusted=\(trusted))")
            }
        }
    }

    // The SC-04 source check (no logging on the passcode path) runs on the host: scripts/verify-ios-passcode-no-logging.sh, with its stub
    // cases in scripts/test-ios-passcode-no-logging.sh. The simulator test host may not read the sources (macOS privacy protection).
}
