import Foundation
import Testing
@testable import ConetChatSDK
@testable import CashTrees_iOS

// Synthetic accounts only: the public BIP-39 test phrases and their standard m/44'/60'/0'/0/0 addresses.
// The reference signatures were produced independently with ethers (signMessage, RFC 6979); SHA256 of the
// vector file: d38b2f14e40c21dd000da68aae72ab88fbce0da3f633e64bffe1411d83611746.
private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
private let phraseB = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
private let eoaA = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
private let eoaB = "0xfc2077ca7f403cbeca41b1b0f62d91b5ea631b5e"

private let referenceA: [(String, String)] = [
        ("", "0x195c2781d9d0611afba721326ff367703626865825ef108cc19da092d14d48bb15ffba03245302210654019fd45cf1378e15474689c2d2aee77ae080266044101b"),
        ("trial-route-a sign 1", "0x7aa77c102f240165aecad7e373486ce595970a35d798042a2e654bd97d35b6d23ce9a6391897daf03e7a7b48c18bff499cbd354a5d3a3ddf918e2f75af622c321c"),
        ("语音 签名 🙂 multi-byte", "0xe08af6a76e2b71a30c37ced15ebd2511772d57e72737b3944fcf232c3fb093286802554cb800cade846c0cde5d36302c279c5a4c1a8bb4dde19560b4ffe4ef2c1b"),
        (String(repeating: "x", count: 300), "0x590bb23a3196c3c763af345106aa28d37c30ac0751a1c5044d0a69d3ba74843411acb70776ac169c390a41c4e8304c3ca6764eaf1aacdb9ee6654380474644d21b"),
]
private let referenceB: [(String, String)] = [
        ("", "0x442e0c42626a11c67be2d7474fc3876380e67e7d4cf0fe86f05ce58ac2e122d90c53bc430434d9f617cd46f2cf06972eda213ab549d38d12145b325939d846231c"),
        ("trial-route-a sign 1", "0x4e46ca151a9ab61e12a215b05f38f72785aa67616ae7eb914b40c98058b1df5b5a665e811c9de9a77030df417832d0e985255506092083dcf43fbac7c225b70a1b"),
        ("语音 签名 🙂 multi-byte", "0xfb71a1d0f46d71c3eedf6791da8d44b52adf6c81601f16cfeca689747e18e04d3a10fbd98a17f9f21ba20fb5d159670528b17923fcbf8e9021aebc376c4983771c"),
        (String(repeating: "x", count: 300), "0x853f6aeb1907d5f0c559b4b62d27025056483d5fed795050f350002011981828657f95e7cb43aec364bc0a8dfa9dbc5b6c1e58e0e6a03fae58ac08ea51333a5b1b"),
]

/// Counts the calls that reach the wrapped engine, and keeps its ack.
private final class CountingEngine: PwaWalletSyncEngine {
    let inner: PwaWalletSyncEngine
    private(set) var calls = 0
    init(_ inner: PwaWalletSyncEngine) { self.inner = inner }

    func pwaWalletSync(reqId: Int, seq: Int, eoa: String, phrase: String, reply: @escaping ([String: Any]) -> Void) {
        calls += 1
        inner.pwaWalletSync(reqId: reqId, seq: seq, eoa: eoa, phrase: phrase, reply: reply)
    }

    func pwaWalletSyncCipher(reqId: Int, seq: Int, eoa: String, cipher: [String: Any], passcode: String?, reply: @escaping ([String: Any]) -> Void) {
        calls += 1
        inner.pwaWalletSyncCipher(reqId: reqId, seq: seq, eoa: eoa, cipher: cipher, passcode: passcode, reply: reply)
    }

    func nativeMnemonicPreread(reqId: Int, seq: Int, reply: @escaping ([String: Any]) -> Void) {
        calls += 1
        inner.nativeMnemonicPreread(reqId: reqId, seq: seq, reply: reply)
    }
}

private func canonical(_ value: [String: Any]) -> String {
    let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    return data.flatMap { String(data: $0, encoding: .utf8) } ?? "<invalid>"
}

/// Runs the gate once; returns the single reply the page would receive (already wrapped).
private func run(_ gate: PwaWalletSyncGate, _ command: [String: Any], trusted: Bool) -> [String: Any] {
    var out: [String: Any] = [:]
    var n = 0
    gate.handle(command: command, trustedOrigin: trusted) { out = $0; n += 1 }
    #expect(n == 1, "exactly one reply")
    return out
}

private func ack(_ wrapped: [String: Any]) -> [String: Any] {
    #expect(wrapped["action"] as? String == "chatModuleEvent")
    return wrapped["event"] as? [String: Any] ?? [:]
}

private func syncCmd(_ reqId: Int, _ seq: Int, _ eoa: String, _ phrase: String) -> [String: Any] {
    ["type": "pwaWalletSync", "reqId": reqId, "seq": seq, "eoa": eoa, "phrase": phrase]
}

private func prereadCmd(_ reqId: Int, _ seq: Int) -> [String: Any] {
    ["type": "nativeMnemonicPreread", "reqId": reqId, "seq": seq]
}

/// The device state of a fresh test device: the legacy store is confirmed empty and no write failure is latched, so the
/// creation admission holds (the same state the SDK's own tests install). Test builds only (BEAMIO_TEST_HOOKS).
private final class AdmittedDevice: BeamioShellRecord.DeviceStateStore {
    var state = BeamioShellRecord.DeviceState(accountEstablished: false, legacyUnreadable: false, legacyConfirmedAbsent: true, legacyFound: false)
    func load() -> BeamioShellRecord.DeviceState { state }
    @discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
}

// Synthetic OpenPGP fixture: the recipient key and two openpgp.js 6.3.0 ciphertexts from the shared interop vectors
// (pgp-native-interop-vectors.v1.json, SHA256 edf7f7f8aa137f5813b160018b6ff09affd228e877ee080fe8d8ad97e04366fb).
private let pgpPrivateArmored = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nxVgEavZtBxYJKwYBBAHaRw8BAQdAANdU7dbJb188EeYnJma8txGCM6hXUwj8\nt/Mr85f54jgAAP9b78ceSZlPUEyb8cPgKrbi2zrxLt6lEbWjP0Wuf0m+IBHk\nzT9zeW50aGV0aWMgcmVjaXBpZW50IGEgPHN5bnRoZXRpYy5yZWNpcGllbnQu\nYUBzeW50aGV0aWMuaW52YWxpZD7CwBMEExYKAIUFgmr2bQcDCwkHCRD1sJfO\nTxZP4UUUAAAAAAAcACBzYWx0QG5vdGF0aW9ucy5vcGVucGdwanMub3Jnctc4\njBirrtpfZa9EcVYvTcGISk5pPUdUjoWpRJ8OICsFFQoIDgwEFgACAQIZAQKb\nAwIeARYhBB1qpGoXmyeAchscQPWwl85PFk/hAAC4+wD9Fwic78GN7G7DE5e0\neQHcR9LRjNC5F4nNKVvxU9n1iZMA/iZ2MLLtYfeRBcfEw8ete7vZGBNomV/w\nV27Z0IlwE+YIx10EavZtBxIKKwYBBAGXVQEFAQEHQGB1WYDs0+DDukDYTKdu\nKdSq4tK0pSOPqNnspKihOo8fAwEIBwAA/0fwHmUP5LjiTDdjV1HZVWgkGC3Q\nbdqCcM00TLaa1vzoETPCvgQYFgoAcAWCavZtBwkQ9bCXzk8WT+FFFAAAAAAA\nHAAgc2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ0VM92NVetIHezNgapzL\nJstfwZNzxt2Su9Yop38ufdM/ApsMFiEEHWqkahebJ4ByGxxA9bCXzk8WT+EA\nAJs6AP4w2EMTLWY1/S3fRGN+9i5N1Dd5UjEBXn4CWn/piuyxygD/ZH9KumZm\nODur4bKHTTWXVMrkZNP4Hy+7mQ56PwZQYQI=\n=5xhe\n-----END PGP PRIVATE KEY BLOCK-----\n"
private let pgpPublicArmored = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEavZtBxYJKwYBBAHaRw8BAQdAANdU7dbJb188EeYnJma8txGCM6hXUwj8\nt/Mr85f54jjNP3N5bnRoZXRpYyByZWNpcGllbnQgYSA8c3ludGhldGljLnJl\nY2lwaWVudC5hQHN5bnRoZXRpYy5pbnZhbGlkPsLAEwQTFgoAhQWCavZtBwML\nCQcJEPWwl85PFk/hRRQAAAAAABwAIHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bq\ncy5vcmdy1ziMGKuu2l9lr0RxVi9NwYhKTmk9R1SOhalEnw4gKwUVCggODAQW\nAAIBAhkBApsDAh4BFiEEHWqkahebJ4ByGxxA9bCXzk8WT+EAALj7AP0XCJzv\nwY3sbsMTl7R5AdxH0tGM0LkXic0pW/FT2fWJkwD+JnYwsu1h95EFx8TDx617\nu9kYE2iZX/BXbtnQiXAT5gjOOARq9m0HEgorBgEEAZdVAQUBAQdAYHVZgOzT\n4MO6QNhMp24p1Kri0rSlI4+o2eykqKE6jx8DAQgHwr4EGBYKAHAFgmr2bQcJ\nEPWwl85PFk/hRRQAAAAAABwAIHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5v\ncmdFTPdjVXrSB3szYGqcyybLX8GTc8bdkrvWKKd/Ln3TPwKbDBYhBB1qpGoX\nmyeAchscQPWwl85PFk/hAACbOgD+MNhDEy1mNf0t30RjfvYuTdQ3eVIxAV5+\nAlp/6YrsscoA/2R/SrpmZjg7q+Gyh001l1TK5GTT+B8vu5kOej8GUGEC\n=mCFC\n-----END PGP PUBLIC KEY BLOCK-----\n"
private let pgpCases: [(id: String, plaintext: String, ciphertext: String)] = [
    ("JS-E1", "synthetic interop v1 plaintext", "-----BEGIN PGP MESSAGE-----\n\nwV4DJxGMD6ego0QSAQdAwK0cpUZDDr+51SlsMXpRSRt9DVMZcAOLifsdcMBu\nJWQwQq4aZqEySF17CEL4iiatp9cXs47bIjf5elLfrxhvHVeKGf09Ti4yjYpz\ngMW1sXEq0sBbAUlNd0UyxVHty9vAqnwa8+8Rlw/J3iUS4R7fZl0o00uzvs2p\nTLTjrfef8bcSXYbaolSPU1gayBCp8MeEKbFgcPRMZU+1pKGuSPHbsSUzpv/t\ny67z19Sz/pbCiL4LtiVA+rO12r+wmZ+NO3IFRKZY8y8SeK4vCt2nqyc77cIp\njMGAtMy2G6mtEAn7OXsIsDXX9udC5dHFq99ikGx/fmMkUxkemTygDxJFU47Q\nExDtoQISFqU7xgHVaoy8lap920CKfqC8FRelZzrRciY8PibZZ9bDgBBYDAKl\n1l3CakJgdj7B0q6/dK9jeYCRRKKa3czPHdPq1VG5jOZcaxxKMFuLbUrBUYi6\nCda3zr1bwoE2nWq8SPL+p1I/frcw0g==\n=H3tR\n-----END PGP MESSAGE-----\n"),
    ("JS-E2", "synthetic interop v2: line one\nline two, \u{4e2d}\u{6587}\u{4e00}\u{884c}", "-----BEGIN PGP MESSAGE-----\n\nwV4DJxGMD6ego0QSAQdAbGjTu459bAJxbvRE0pzawBsCB/Rd3DIF+gJJXHap\nsREwntvJZrs2gVPcnkOv/7+HFczEkfYDxBddLutImvuPI5tDEz1NLRlMPD3S\nsUJDvO6U0sBzAULARWskg1v4QY5KdUVbDmhzly/GuzblOxIuJzLoa/Byz+hT\nG20VxOYevnyCmwCKqwPvbVu18q86WLC5ycNSeqarFZnugL39wBF9Tb1OhcDf\nwmSM5sxz5mW20BPple/+sJYfugk8AdtMGY0wO8ngLET3psCZ/fyq+I1m21VO\nvMCGBAI40tfW6R7dbr+2Feue4qIa1sqfFLNS42mi4i5jQMxY04o9U3367sqD\nfakEx42iehcykYZ7D+lntNUNiQ0vOmFKvb9LJA7Om8UVb8ng9ZAygT4lDKBd\nQGiqlWtL5u+3SAGTieNSAZDfkXZ9fQP3FnNisIwXSn0yTzygWw16dzpHG4m9\nk6tktwff2Et3Y5twOCJPZVIajhpkRrvfpbg+61MJRu8PSeNMW+d2gkop93Xv\n8A==\n=Uzfn\n-----END PGP MESSAGE-----\n"),
]

extension SdkStateSuite {
@Suite(.serialized)
struct PwaWalletSyncSdkWiringTests {
    init() {
        BeamioShellRecord.testDeviceOverride = AdmittedDevice()
        BeamioShellRecord.setLegacyReportWriteFailed(false)
        BeamioNativeAccountPointer.clear()
        BeamioNativeKeySnapshot.invalidate()
        // The product keyStore (BeamioPasscodeWalletStore), answered from memory in the test build (BEAMIO_TEST_HOOKS).
        // The SDK owns the no-passcode set items (mnemonic.set.<eoa> and the cipher form), so pwaWalletSync writes through it and an
        // account synced with its mnemonic has its key derived from the set.
        BeamioNativeWallet.keyStore = BeamioPasscodeWalletStore.standard
    }

    // Steps 1 to 6: the trusted main frame reaches the real SDK engine; same account is idempotent; a different account
    // is sealed, read back and written; the SDK signer reproduces the independent signatures for the active account.
    @Test func trustedMainFrameDrivesTheRealEngineOverSyntheticAccounts() throws {
        BeamioPwaWalletSync.restartForTests()
        let counting = CountingEngine(PwaWalletSyncSdkEngine())
        let gate = PwaWalletSyncGate(engine: counting)
        let trusted = PwaWalletSyncTrust.isTrusted(isMainFrame: true, scheme: "cashtrees-local", host: "localhost")
        #expect(trusted)
        var transcript: [String] = []
        func step(_ label: String, _ cmd: [String: Any]) -> [String: Any] {
            let out = ack(run(gate, cmd, trusted: trusted))
            transcript.append("\(label) -> \(canonical(out))")
            return out
        }

        let a1 = step("1 sync A seq1", syncCmd(900_000_001, 1, eoaA, phraseA))
        let a2 = step("2 sync A seq2 same account", syncCmd(900_000_002, 2, eoaA, phraseA))
        let b3 = step("3 sync B seq3 different account", syncCmd(900_000_003, 3, eoaB, phraseB))
        let p4 = step("4 preread seq4", prereadCmd(900_000_004, 4))
        let s5 = step("5 sync A seq1 again", syncCmd(900_000_005, 1, eoaA, phraseA))
        transcript.append("engine calls reaching the SDK: \(counting.calls)")

        Attachment.record(transcript.joined(separator: "\n"), named: "sdk-bridge-transcript.txt")

        #expect(a1["ok"] as? Bool == true)
        #expect((a1["result"] as? [String: Any])?["sync"] as? String == "updated", "step 1: updated")
        #expect((a2["result"] as? [String: Any])?["sync"] as? String == "idempotent", "step 2: idempotent")
        #expect((b3["result"] as? [String: Any])?["sync"] as? String == "updated", "step 3: updated after seal and read-back")
        #expect((p4["result"] as? [String: Any])?["code"] as? String == "ok", "step 4: ok (result.code)")
        #expect((p4["result"] as? [String: Any])?["eoa"] as? String == eoaB, "step 4: the active account is B")
        #expect(s5["error"] as? String == "stale_seq", "step 5: an older seq is stale")
        #expect(counting.calls == 5, "every trusted command reached the SDK once")
    }

    @Test func nativeSignatureOfTheActiveAccountMatchesTheIndependentReference() throws {
        // The SDK signs with the native key of the record account only (gate G2: session ready and the account pointer = eoa).
        // Make B the record account through the real engine (seq ledger restarted), then put the session in G2 for B.
        BeamioPwaWalletSync.restartForTests()
        let synced = BeamioPwaWalletSyncEngine.pwaWalletSync(reqId: 900_000_101, seq: 1, eoa: eoaB, phrase: phraseB)
        let sync = (synced["result"] as? [String: Any])?["sync"] as? String
        #expect(sync == "updated" || sync == "idempotent", "B is the record account")
        BeamioConetChatModule.setNativeGateForTests(account: eoaB, sessionReady: true)
        defer { BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false) }
        #expect(BeamioConetChatModule.nativeGate() == .g2, "the session is G2 for B")
        var lines: [String] = []
        for (message, want) in referenceB {
            switch BeamioNativeWallet.signEip191(eoa: eoaB, message: message) {
            case .success(let got):
                #expect(got.lowercased() == want.lowercased(), "EIP-191 signature of a \(message.utf8.count)-byte message")
                lines.append("bytes=\(message.utf8.count) sdk=\(got) ref=\(want) match=\(got.lowercased() == want.lowercased())")
            case .failure(let error):
                Issue.record("BeamioNativeWallet.signEip191 failed: \(error)")
            }
        }
        Attachment.record(lines.joined(separator: "\n"), named: "native-sign-vs-ethers.txt")
    }

    @Test func pgpDecryptOpensTheOpenpgpJsPayloadsForTheStoredAccount() {
        // The X-19 framework must be linked for a real decrypt; the result says so explicitly.
        Attachment.record("BeamioPGPNative.linked = \(BeamioPGPNative.linked)", named: "pgp-linked-decrypt.txt")
        BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
        defer { BeamioChatPgpKeychain.memory = nil }
        let account = "0x1111111111111111111111111111111111111111"
        let stored = BeamioChatPgpKeychain.Secrets(
            privateKeyArmor: pgpPrivateArmored, publicKeyArmor: pgpPublicArmored, pgpKeyId: "", routePublicKeyArmor: "",
            entryDomains: [], siNodes: [], mailboxIp: "", eoa: account)
        #expect(BeamioChatPgpKeychain.save(stored), "the synthetic PGP secrets are stored in the memory records")
        var lines: [String] = []
        for c in pgpCases {
            let result = BeamioNativeWallet.pgpDecrypt(eoa: account, message: Data(c.ciphertext.utf8))
            lines.append("\(c.id) -> \(String(describing: result))")
            #expect(result == .success(Data(c.plaintext.utf8)), "\(c.id) decrypts to its plaintext")
        }
        #expect(BeamioNativeWallet.pgpDecrypt(eoa: "0x2222222222222222222222222222222222222222",
                                              message: Data(pgpCases[0].ciphertext.utf8)) == .failure(.rejected("no_pgp_key")),
                "another account is refused without decrypting")
        Attachment.record(lines.joined(separator: "\n"), named: "pgp-decrypt-results.txt")
    }

    @Test func nativePgpLinkStateIsRecorded() {
        // Answers whether the X-19 OpenPGP framework is linked into this test build (BeamioPGPNative.linked).
        let linked = BeamioPGPNative.linked
        Attachment.record("BeamioPGPNative.linked = \(linked)", named: "pgp-linked.txt")
        #expect(linked == true, "X-19 is linked when the SDK is built with the default X-19 link setting")
    }

    @Test func untrustedAndSubFrameCommandsNeverReachTheSdk() {
        let counting = CountingEngine(PwaWalletSyncSdkEngine())
        let gate = PwaWalletSyncGate(engine: counting)
        let subFrame = PwaWalletSyncTrust.isTrusted(isMainFrame: false, scheme: "cashtrees-local", host: "localhost")
        let remote = PwaWalletSyncTrust.isTrusted(isMainFrame: true, scheme: "https", host: "beamio.ca")
        #expect(!subFrame && !remote)
        for trusted in [subFrame, remote] {
            #expect(ack(run(gate, syncCmd(900_000_011, 9, eoaA, phraseA), trusted: trusted))["error"] as? String == "untrusted_source")
            #expect(ack(run(gate, prereadCmd(900_000_012, 9), trusted: trusted))["error"] as? String == "untrusted_source")
        }
        #expect(counting.calls == 0, "the SDK is not called for a sub-frame or a non-trusted origin")
    }

    @Test func trustedPrereadReachesTheSdkAndReturnsItsAnswerVerbatim() {
        let counting = CountingEngine(PwaWalletSyncSdkEngine())
        let gate = PwaWalletSyncGate(engine: counting)
        let direct = BeamioPwaWalletSyncEngine.nativeMnemonicPreread(reqId: 900_000_021, seq: 21)
        let viaGate = ack(run(gate, prereadCmd(900_000_021, 21), trusted: true))
        #expect(counting.calls == 1)
        #expect(canonical(viaGate) == canonical(direct), "the gate passes the SDK answer unchanged")
    }

    @Test func gateAnswersAreWrappedExactlyOnce() {
        let out = run(PwaWalletSyncGate(engine: PwaWalletSyncSdkEngine()), prereadCmd(900_000_031, 31), trusted: true)
        #expect(out["action"] as? String == "chatModuleEvent")
        #expect((out["event"] as? [String: Any])?["action"] == nil, "no second wrapper")
    }
}
}

private struct SigFailure: Error, CustomStringConvertible {
    let text: String
    var description: String { text }
}
