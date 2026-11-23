import Foundation

/// The page-facing `nativeCallHangup` event (v66 §73): a local hang-up reported to the page, which then sends the one
/// voice_end_v1. The event is in the event whitelist and never in the command whitelist.
enum NativeCallHangupEvent {
    static let type = "nativeCallHangup"
    static let reason = "local_hangup"

    static func payload(callId: String, sessionId: String, atMs: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) -> [String: Any] {
        ["type": type, "callId": callId, "sessionId": sessionId, "reason": reason, "at": atMs]
    }
}
