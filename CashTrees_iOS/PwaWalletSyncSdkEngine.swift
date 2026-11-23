//
//  PwaWalletSyncSdkEngine.swift
//  CashTrees_iOS
//
//  Forwards the trusted gate's checked requests to the chat SDK engine (BeamioPwaWalletSyncEngine). The SDK
//  returns a bare ack, which is passed back unchanged; the gate wraps it once for the page. No key material
//  crosses this boundary: the SDK reads its own native snapshot and decides the overwrite, the read-back and
//  the preread state.
//

import ConetChatSDK
import Foundation

final class PwaWalletSyncSdkEngine: PwaWalletSyncEngine {
    func pwaWalletSync(reqId: Int, seq: Int, eoa: String, phrase: String, reply: @escaping ([String: Any]) -> Void) {
        // pwaWalletSync r3 (SPEC-pwaWalletSync-request-and-reply-r3, section two and three): the shell judges the passcode lock.
        // A locked account answers `locked` and nothing is written; the phrase is not kept. The PWA does not read the lock.
        if BeamioPasscodeSession.shared.isLocked(eoa: eoa.lowercased()) {
            reply(["type": "ack", "reqId": reqId, "ok": false, "error": "locked"])
            return
        }
        reply(BeamioPwaWalletSyncEngine.pwaWalletSync(reqId: reqId, seq: seq, eoa: eoa, phrase: phrase))
    }

    /// M6 method Y: forwarded to the chat SDK's public cipher entry. No isLocked pre-check here: this path is the unlock
    /// itself. The SDK answers ok {decrypted true|false}, unlock_failed, verify_failed, bad_request, or write_failed / internal_state;
    /// the passcode stays in memory and is never logged (SC-04).
    func pwaWalletSyncCipher(reqId: Int, seq: Int, eoa: String, cipher: [String: Any], passcode: String?, reply: @escaping ([String: Any]) -> Void) {
        reply(BeamioPwaWalletSyncEngine.pwaWalletSync(reqId: reqId, seq: seq, eoa: eoa, cipher: cipher, passcode: passcode))
    }

    func nativeMnemonicPreread(reqId: Int, seq: Int, reply: @escaping ([String: Any]) -> Void) {
        reply(BeamioPwaWalletSyncEngine.nativeMnemonicPreread(reqId: reqId, seq: seq))
    }
}
