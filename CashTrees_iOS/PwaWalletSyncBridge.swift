//
//  PwaWalletSyncBridge.swift
//  CashTrees_iOS
//
//  Shell-side trusted gate for the page's `pwaWalletSync` and `nativeMnemonicPreread` commands
//  (spec 59E revision v3.3, section 11; decision order section 59(1)(d)).
//
//  The shell does only what needs no stored state:
//    1. trusted origin (set by the shell from the native frame, never read from the page) -> untrusted_source
//    2. credential fields outside `phrase`                                             -> key_over_bridge_refused
//    3. format of reqId, seq, eoa, phrase                                              -> bad_request
//  Everything after that (stale_seq, same-account idempotency, the overwrite decision, the read-back
//  checks, the persisted reply cache for a repeated reqId/seq) belongs to the chat SDK behind
//  `PwaWalletSyncEngine`. The engine's ack is passed back to the page unchanged.
//
//  Nothing here logs, stores or echoes a phrase. Failure replies carry no data.
//

import Foundation

/// The SDK seam. The chat SDK implements this once its `pwaWalletSync` / `nativeMnemonicPreread` patch is delivered.
/// Each engine call returns one bare ack envelope `{type: "ack", reqId, ok, result? | error?, reason?}`; the gate wraps it
/// for the page and does not change it.
protocol PwaWalletSyncEngine: AnyObject {
    func pwaWalletSync(reqId: Int, seq: Int, eoa: String, phrase: String, reply: @escaping ([String: Any]) -> Void)
    /// M6 method Y (the unlock-sync spec): the page's v3 passcode envelope and, when present, the six-digit
    /// passcode that opens it. The gate has checked their shapes; the SDK decides everything else.
    func pwaWalletSyncCipher(reqId: Int, seq: Int, eoa: String, cipher: [String: Any], passcode: String?, reply: @escaping ([String: Any]) -> Void)
    func nativeMnemonicPreread(reqId: Int, seq: Int, reply: @escaping ([String: Any]) -> Void)
}

/// Used until the SDK seam is wired. Fails closed: a sync answers `write_failed` / `internal_state` (retryable, nothing
/// written) and a preread answers `unknown` (no mnemonic is returned).
final class PwaWalletSyncNotWiredEngine: PwaWalletSyncEngine {
    func pwaWalletSync(reqId: Int, seq: Int, eoa: String, phrase: String, reply: @escaping ([String: Any]) -> Void) {
        reply(["type": "ack", "reqId": reqId, "ok": false, "error": "write_failed", "reason": "internal_state"])
    }

    func pwaWalletSyncCipher(reqId: Int, seq: Int, eoa: String, cipher: [String: Any], passcode: String?, reply: @escaping ([String: Any]) -> Void) {
        reply(["type": "ack", "reqId": reqId, "ok": false, "error": "write_failed", "reason": "internal_state"])
    }

    func nativeMnemonicPreread(reqId: Int, seq: Int, reply: @escaping ([String: Any]) -> Void) {
        reply(["type": "ack", "reqId": reqId, "ok": true, "result": ["code": "read_error"]])
    }
}

enum PwaWalletSyncBridge {
    static let syncCommand = "pwaWalletSync"
    static let prereadCommand = "nativeMnemonicPreread"

    /// Field names that carry credentials, compared lowercased and as whole names (spec 59(1)(c)).
    /// `phrase` is the one credential field the sync request carries, so it is not listed.
    static let forbiddenCredentialFields: Set<String> = [
        "privatekey", "privatekeyhex", "privkey", "mnemonic", "mnemonics", "seed", "seedphrase",
        "recoverycode", "pin", "password", "passphrase", "secret", "secretkey", "keystore",
    ]

    /// The only word counts a BIP-39 English phrase can have (checksum and wordlist are the SDK's job).
    static let validPhraseWordCounts: Set<Int> = [12, 15, 18, 21, 24]

    /// True for the two commands this gate owns. Other commands keep their existing path.
    static func handles(_ command: [String: Any]) -> Bool {
        guard let type = command["type"] as? String else { return false }
        return type == syncCommand || type == prereadCommand
    }

    /// A JSON integer within `minimum ... 2^53-1`. Booleans, strings, fractions, negatives below `minimum`, and
    /// anything missing are nil. `reqId` needs at least 1; `seq` has lower bound 0 (errata E3).
    static func strictInteger(_ value: Any?, minimum: Int) -> Int? {
        guard let number = value as? NSNumber else { return nil }
        // JSON true/false arrive as NSNumber too; they are not integers here.
        if CFGetTypeID(number) == CFBooleanGetTypeID() { return nil }
        let d = number.doubleValue
        guard d.isFinite, d >= Double(minimum), d == d.rounded(.towardZero), d <= 9_007_199_254_740_991 else { return nil }
        return Int(d)
    }

    /// The command object of a page message. The shell's injected bridge nests it under `command`; a flat body is also
    /// accepted, so the wallet-sync check cannot be bypassed by sending the fields at the top level.
    /// Returns the wallet-sync command found in either shape, nested first, or nil when the message is not one.
    static func walletSyncCommand(in body: [String: Any]) -> [String: Any]? {
        if let nested = body["command"] as? [String: Any], handles(nested) { return nested }
        if handles(body) { return body }
        return nil
    }

    /// `0x` followed by 40 lowercase hex digits (spec: "0x<40 位小写十六进制>").
    static func isLowercaseAddress(_ value: String) -> Bool {
        guard value.count == 42, value.hasPrefix("0x") else { return false }
        return value.dropFirst(2).allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
    }

    /// English BIP-39 shape: 12/15/18/21/24 lowercase ASCII words, single spaces, no leading or trailing space.
    static func isWellFormedPhrase(_ value: String) -> Bool {
        let words = value.split(separator: " ", omittingEmptySubsequences: false)
        guard validPhraseWordCounts.contains(words.count) else { return false }
        return words.allSatisfy { word in
            !word.isEmpty && word.allSatisfy { ("a"..."z").contains($0) }
        }
    }

    /// A request carries a credential when a listed name appears. `phrase` is allowed only in pwaWalletSync; in
    /// nativeMnemonicPreread it is refused too (errata E1: the exception covers the answer, never the request).
    ///
    /// M6 method Y (gateCases MG-03, MG-04, MG-05, MG-08): in pwaWalletSync `passcode` is allowed only together with `cipher`;
    /// `cipher` together with `phrase` is refused (ambiguous); in nativeMnemonicPreread `cipher` and `passcode` are refused like `phrase`.
    /// Names are compared lowercased, so a case variant (`Passcode`, `CIPHER`) is judged like the name itself.
    static func hasForbiddenField(_ command: [String: Any]) -> Bool {
        let type = command["type"] as? String ?? ""
        let names = Set(command.keys.filter { $0 != "trustedOrigin" }.map { $0.lowercased() })
        // A page-sent trustedOrigin is invalid and ignored (the shell sets it), so it is not a credential here.
        if !names.isDisjoint(with: forbiddenCredentialFields) { return true }
        if type == prereadCommand {
            return !names.isDisjoint(with: ["phrase", "cipher", "passcode"])
        }
        // pwaWalletSync. The exact names are the only accepted spellings; a case variant of a credential name is refused.
        for credential in ["phrase", "cipher", "passcode"] where names.contains(credential) && command[credential] == nil {
            return true
        }
        if names.contains("passcode") && !names.contains("cipher") { return true }
        if names.contains("cipher") && names.contains("phrase") { return true }
        return false
    }

    /// Exactly six ASCII digits, as a string (M6: the passcode the page just took).
    static func isSixDigitPasscode(_ value: Any?) -> Bool {
        guard let text = value as? String, text.utf8.count == 6 else { return false }
        return text.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
    }

    /// A v3 passcode envelope object (M6 MG-07): a JSON object with integer `v` 3 and `mode` "passcode". The full field, size and
    /// address checks are the SDK's (they answer verify_failed there); the gate refuses only what is not such an envelope at all.
    static func isV3PasscodeEnvelope(_ value: Any?) -> Bool {
        guard let object = value as? [String: Any], let v = object["v"] as? NSNumber else { return false }
        if CFGetTypeID(v) == CFBooleanGetTypeID() { return false }
        return v.doubleValue == 3 && object["mode"] as? String == "passcode"
    }

    /// The closed set of preread result codes (the interface specification).
    static let prereadCodes: Set<String> = ["ok", "confirmed_missing", "read_error", "not_ready"]
    /// The keys a `code: ok` answer may carry. Only `ok` carries material.
    static let prereadOkKeys: Set<String> = ["code", "mnemonic", "eoa", "cipher"]

    /// Preread restricted return, aligned to `result.code` (interface specification):
    /// - `ok`: only `code`, `mnemonic`, `eoa` and `cipher` pass, unchanged; any other key is dropped.
    /// - `confirmed_missing`, `read_error`, `not_ready`: reduced to `{code}`; a mnemonic, eoa or cipher never leaves with them.
    /// - any other code, or none: `{code: "read_error"}` (the page treats it as unknown and keeps its data).
    /// An ack without a `result` object (an error answer) passes unchanged: it carries no material by construction.
    static func restrictPrereadAnswer(_ ack: [String: Any]) -> [String: Any] {
        guard let result = ack["result"] as? [String: Any] else { return ack }
        let code = result["code"] as? String ?? ""
        var out = ack
        if code == "ok" {
            out["result"] = result.filter { prereadOkKeys.contains($0.key) }
        } else if prereadCodes.contains(code) {
            out["result"] = ["code": code]
        } else {
            out["result"] = ["code": "read_error"]
        }
        return out
    }

    /// The wire form the page reads: the chat module event wrapper around the bare ack (the same wrapper the SDK emits).
    static func wrapForPage(_ ack: [String: Any]) -> [String: Any] {
        ["action": "chatModuleEvent", "event": ack]
    }

    static func failure(reqId: Any, error: String, reason: String? = nil) -> [String: Any] {
        var ack: [String: Any] = ["type": "ack", "reqId": reqId, "ok": false, "error": error]
        if let reason { ack["reason"] = reason }
        return ack
    }
}

/// Decides `trustedOrigin` from the native frame that sent the message. True only for the main frame of the embedded
/// local PWA (`cashtrees-local://localhost`). Sub-frames, remote pages and in-app browser pages are not trusted.
enum PwaWalletSyncTrust {
    static func isTrusted(isMainFrame: Bool, scheme: String, host: String) -> Bool {
        isMainFrame
            && scheme.lowercased() == CashTreesPWAScheme.scheme
            && host.lowercased() == CashTreesPWAScheme.host
    }
}

/// Runs the gate for one page command. Replies are given to `reply` already wrapped for the page.
final class PwaWalletSyncGate {
    private let engine: PwaWalletSyncEngine

    init(engine: PwaWalletSyncEngine) {
        self.engine = engine
    }

    /// `command` must satisfy `PwaWalletSyncBridge.handles`. `trustedOrigin` is decided by the shell, never by the page.
    func handle(command: [String: Any], trustedOrigin: Bool, reply: @escaping ([String: Any]) -> Void) {
        let type = command["type"] as? String ?? ""
        let reqId = PwaWalletSyncBridge.strictInteger(command["reqId"], minimum: 1)
        let reqIdValue: Any = reqId ?? NSNull()

        func answer(_ ack: [String: Any]) {
            reply(PwaWalletSyncBridge.wrapForPage(ack))
        }

        // 1. Trust comes before everything: nothing is read or written for an untrusted source.
        guard trustedOrigin else {
            answer(PwaWalletSyncBridge.failure(reqId: reqIdValue, error: "untrusted_source"))
            return
        }
        // 2. Credential fields are refused without echoing their values.
        if PwaWalletSyncBridge.hasForbiddenField(command) {
            answer(PwaWalletSyncBridge.failure(reqId: reqIdValue, error: "key_over_bridge_refused"))
            return
        }
        // 3. Format. Only the fields the contract names are passed on; anything else is dropped here.
        // seq: lower bound 0 (errata E3). Staleness against the highest accepted seq is the SDK's decision.
        guard let reqId, let seq = PwaWalletSyncBridge.strictInteger(command["seq"], minimum: 0) else {
            answer(PwaWalletSyncBridge.failure(reqId: reqIdValue, error: "bad_request"))
            return
        }
        switch type {
        case PwaWalletSyncBridge.syncCommand where command["cipher"] != nil:
            // M6 method Y (MG-01, MG-02, MG-06, MG-07): eoa, a v3 passcode envelope and, when present, a six-digit passcode string.
            // Not gated by wallet.passcode.v1 (that capability gates only the passcode commands).
            guard
                let eoa = command["eoa"] as? String, PwaWalletSyncBridge.isLowercaseAddress(eoa),
                PwaWalletSyncBridge.isV3PasscodeEnvelope(command["cipher"]), let cipher = command["cipher"] as? [String: Any]
            else {
                answer(PwaWalletSyncBridge.failure(reqId: reqId, error: "bad_request"))
                return
            }
            var passcode: String?
            if command.keys.contains("passcode") {
                guard PwaWalletSyncBridge.isSixDigitPasscode(command["passcode"]) else {
                    answer(PwaWalletSyncBridge.failure(reqId: reqId, error: "bad_request"))
                    return
                }
                passcode = command["passcode"] as? String
            }
            engine.pwaWalletSyncCipher(reqId: reqId, seq: seq, eoa: eoa, cipher: cipher, passcode: passcode) { ack in
                answer(ack)
            }
        case PwaWalletSyncBridge.syncCommand:
            guard
                let eoa = command["eoa"] as? String, PwaWalletSyncBridge.isLowercaseAddress(eoa),
                let phrase = command["phrase"] as? String, PwaWalletSyncBridge.isWellFormedPhrase(phrase)
            else {
                answer(PwaWalletSyncBridge.failure(reqId: reqId, error: "bad_request"))
                return
            }
            // 4 and 5 (stale_seq, overwrite) are decided by the SDK; its ack is passed on unchanged.
            engine.pwaWalletSync(reqId: reqId, seq: seq, eoa: eoa, phrase: phrase) { ack in
                answer(ack)
            }
        case PwaWalletSyncBridge.prereadCommand:
            engine.nativeMnemonicPreread(reqId: reqId, seq: seq) { ack in
                answer(PwaWalletSyncBridge.restrictPrereadAnswer(ack))
            }
        default:
            answer(PwaWalletSyncBridge.failure(reqId: reqId, error: "bad_request"))
        }
    }
}
