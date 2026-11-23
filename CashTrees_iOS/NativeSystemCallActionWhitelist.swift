import Foundation

/// The page -> shell system-call actions (dispatchNativeSystemCallAction channel), kept apart from the passcode command
/// whitelist (v48 §54.3). Only the names and fields listed here are accepted; anything else is refused.
enum NativeSystemCallActionWhitelist {
    static let fieldsByAction: [String: Set<String>] = [
        "dismissIncomingSystemCall": ["type", "reqId", "callId", "sessionId"],
        // Page -> shell: a local CallKit end of an unanswered incoming call; never an uplink (v64 §71).
        "endSystemCall": ["type", "reqId", "callId", "sessionId"],
    ]

    /// nil when the action may pass. Otherwise the error code to answer with (`bad_request`).
    static func refusal(for command: [String: Any]) -> String? {
        guard let type = command["type"] as? String, let allowed = fieldsByAction[type] else { return "bad_request" }
        return Set(command.keys).isSubset(of: allowed) ? nil : "bad_request"
    }
}
