import ConetChatSDK
import Foundation

/// v68 §75 / v54 §61: a voice_ chat line drives a call action only after its outer envelope is verified:
/// EIP-191 recovery over envelope.text == envelope.from == the line sender == the inner offer's from.
/// Verification is asynchronous (the OpenPGP host's ethers.verifyMessage). Anything that does not verify is dropped.
enum VoiceLineVerifier {
    struct Envelope: Equatable {
        let text: String
        let signMessage: String
        let from: String
    }

    /// The chat envelope (text, signMessage, from). Nil for anything else, including a bare signal (it has `type`).
    static func envelope(_ line: String) -> Envelope? {
        guard let data = line.data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              obj["type"] == nil,
              let text = obj["text"] as? String,
              let signMessage = obj["signMessage"] as? String,
              let from = obj["from"] as? String
        else { return nil }
        return Envelope(text: text, signMessage: signMessage, from: from)
    }

    /// The inner signal's callId and sessionId, for the strict ended-record check. Nil when either is missing.
    static func innerIdentity(_ line: String) -> (callId: String, sessionId: String)? {
        guard let env = envelope(line),
              let data = env.text.data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let c = obj["callId"] as? String, let s = obj["sessionId"] as? String,
              !c.isEmpty, !s.isEmpty
        else { return nil }
        return (c, s)
    }

    /// The inner signal's own `from` (lower-cased), or nil when it is missing.
    static func innerFrom(_ text: String) -> String? {
        guard let data = text.data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let from = obj["from"] as? String
        else { return nil }
        let trimmed = from.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Freshness of the inner signal (replay guard): `expiresAt` must not have passed; without it, `timestamp` or
    /// `createdAt` must be within `freshWindowMs` of now. A signature that is valid but stale is not fresh.
    static let freshWindowMs: Double = 15 * 60 * 1000

    static func isFresh(_ text: String, nowMs: Double) -> Bool {
        guard let data = text.data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return false }
        func ms(_ raw: Any?) -> Double? {
            let v: Double? = (raw as? Double) ?? (raw as? NSNumber)?.doubleValue ?? Double((raw as? String) ?? "")
            guard let v, v > 0, v.isFinite else { return nil }
            return v < 100_000_000_000 ? v * 1000 : v
        }
        if let exp = ms(obj["expiresAt"]) { return nowMs <= exp }
        if let t = ms(obj["timestamp"]) ?? ms(obj["createdAt"]) { return nowMs - t <= freshWindowMs && nowMs - t >= -300_000 }
        return false
    }

    /// Verifies the line. `completion(true)` only when the outer signer, envelope.from, the line sender, the inner
    /// from all agree and the inner signal is fresh. Any failure is `false`.
    static func verify(
        line: String,
        lineFrom: String,
        nowMs: Double = Date().timeIntervalSince1970 * 1000,
        completion: @escaping (Bool) -> Void
    ) {
        let sender = lineFrom.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard let env = envelope(line),
              env.from.lowercased() == sender,
              let inner = innerFrom(env.text),
              inner == sender,
              isFresh(env.text, nowMs: nowMs)
        else {
            completion(false)
            return
        }
        BeamioOpenPgpHost.shared.verifyMessage(text: env.text, signature: env.signMessage) { result in
            switch result {
            case .success(let recovered):
                completion(recovered.lowercased() == sender)
            case .failure:
                completion(false)
            }
        }
    }
}
