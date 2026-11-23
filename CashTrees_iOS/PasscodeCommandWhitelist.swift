import Foundation

/// The per-command field whitelist of the passcode commands (frozen passcode protocol v1, section one, item 6). Applied on the
/// native side after the trust gate, so a page that skips the injected functions is still refused. A command outside the table
/// that carries any passcode credential field is refused as well.
enum PasscodeCommandWhitelist {
    /// The allowed fields of each passcode command, including the envelope fields `type` and `reqId`.
    static let fieldsByCommand: [String: Set<String>] = [
        "passcodeProvision": ["type", "reqId", "eoa", "phrase", "passcode"],
        "passcodeUnlock": ["type", "reqId", "eoa", "passcode"],
        "passcodeChange": ["type", "reqId", "eoa", "oldPasscode", "newPasscode"],
        "passcodeDisable": ["type", "reqId", "eoa", "passcode"],
        "nativeRepairProvide": ["type", "reqId", "eoa", "phrase", "passcode", "requestReqId"],
        "passcodeStatus": ["type", "reqId", "eoa"],
        // Same-identity check after a UI unlock: answers {match}; only the eoa is read.
        "nativeIdentityCheck": ["type", "reqId", "eoa"],
        // Page -> native: the UI lock. Only `locked: true` acts (BeamioPasscodeSession.uiLock), nothing else.
        "uiLockState": ["type", "reqId", "locked"],
    ]

    /// The credential fields of the passcode protocol. They are refused in any command outside `fieldsByCommand`.
    static let credentialFields: Set<String> = ["phrase", "passcode", "oldPasscode", "newPasscode"]

    /// nil when the command may pass this check. Otherwise the error code to answer with (`bad_request`). Only the names of the
    /// fields are ever used here, never a value.
    static func refusal(for command: [String: Any]) -> String? {
        let keys = Set(command.keys)
        if let type = command["type"] as? String, let allowed = fieldsByCommand[type] {
            return keys.isSubset(of: allowed) ? nil : "bad_request"
        }
        return keys.isDisjoint(with: credentialFields) ? nil : "bad_request"
    }
}
