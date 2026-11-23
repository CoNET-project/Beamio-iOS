import ConetChatSDK
import CryptoKit
import Foundation

/// offer v4 (v108 §108.2–108.4, §108.7 part 1). Parallel to v3: v3 stays the live parser until the project decides the
/// hard switch (v109 (b)). Not wired into a call yet: this is an intermediate state, not a callable candidate.
/// Armor-bearing channels fail closed until the SDK provides the OpenPGP fingerprint (v109 (a)).
enum OfferV4Verifier {
    struct Channel: Equatable {
        let role: String          // cv | cV
        let sid: String
        let key: String
        let wk: String
        let temp: String          // lower-case temp wallet address
        let tempPgpFpr: String    // 40 lower-case hex, or empty
        let tempPgpArmor: String? // nil when absent
        let authFrom: String
        let authValidUntil: Double
        let authSig: String
    }

    /// The only top-level keys v4 accepts. `cv_pay` / `cV_pay` (v122 §141) are not in this set yet: no pay parser exists
    /// in the shell, so an offer carrying them is refused (fail closed) until the parser lands.
    static let topLevelKeys: Set<String> = [
        "proto", "callId", "sessionId", "from", "to", "createdAt", "expiresAt", "timestamp", "codec", "cv", "cV", "sig",
    ]

    /// The only keys one channel object accepts.
    static let channelKeys: Set<String> = ["sid", "key", "wk", "temp", "tempPgpFpr", "tempPgpArmor", "auth"]

    /// v113 §130: key and wk are standard base64 (RFC 4648 alphabet with padding), non-empty, and decode.
    static func isStandardBase64(_ s: String) -> Bool {
        guard !s.isEmpty, s.range(of: "^[A-Za-z0-9+/]+={0,2}$", options: .regularExpression) != nil,
              s.count % 4 == 0 else { return false }
        return Data(base64Encoded: s) != nil
    }

    static func sha256Hex(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    /// §108.3: one line per channel, fields joined by spaces, lines by \n, no trailing newline.
    static func chansDigest(_ chans: [Channel]) -> String {
        let lines = chans.map { c in
            "role:\(c.role) sid:\(c.sid) key:\(c.key) wk:\(c.wk) temp:\(c.temp) tempPgpFpr:\(c.tempPgpFpr) armorSha256:\(c.tempPgpArmor.map { sha256Hex($0) } ?? "")"
        }
        return sha256Hex(lines.joined(separator: "\n"))
    }

    /// §108.4 offer canonical (UTF-8, \n separated, from/to lower-case).
    static func offerCanonical(
        callId: String, sessionId: String, from: String, to: String,
        createdAt: Double, expiresAt: Double, codec: String, chansDigest: String
    ) -> String {
        [
            "CoNET voice_call_offer_v4",
            "callId:\(callId)",
            "sessionId:\(sessionId)",
            "from:\(from.lowercased())",
            "to:\(to.lowercased())",
            "createdAt:\(Int64(createdAt))",
            "expiresAt:\(Int64(expiresAt))",
            "timestamp:\(Int64(createdAt))",
            "codec:\(codec)",
            "chansDigest:\(chansDigest)",
        ].joined(separator: "\n")
    }

    /// §96.1 voice_pgp_auth_v1 canonical for one channel (tempPgpFpr empty when there is no user PGP).
    static func authCanonical(callId: String, sessionId: String, channel: Channel) -> String {
        [
            "CoNET voice_pgp_auth_v1",
            "callId:\(callId)",
            "sessionId:\(sessionId)",
            "channel:\(channel.role)",
            "temp:\(channel.temp.lowercased())",
            "tempPgpFpr:\(channel.tempPgpFpr.lowercased())",
            "from:\(channel.authFrom.lowercased())",
            "validUntil:\(Int64(channel.authValidUntil))",
        ].joined(separator: "\n")
    }

    /// Folds the per-channel auth results into one verdict. Thread-safe; returns the verdict exactly once, on the last result.
    final class AuthGate {
        private let lock = NSLock()
        private var pending: Int
        private var allOk = true
        private var fired = false

        init(count: Int) { pending = count }

        func record(ok: Bool) -> Bool? {
            lock.lock()
            defer { lock.unlock() }
            if !ok { allOk = false }
            pending -= 1
            guard pending == 0, !fired else { return nil }
            fired = true
            return allOk
        }
    }

    /// Parses one channel object (offer cv/cV). Nil when a required field is missing or malformed.
    /// v111 §128: auth carries exactly {from, validUntil, sig}; any other key is refused. tempPgpFpr is read only from
    /// the channel's top level and must be empty or strict lower-case 40-hex.
    static func channel(role: String, _ obj: Any?) -> Channel? {
        guard let d = obj as? [String: Any], Set(d.keys).isSubset(of: channelKeys),
              let sid = d["sid"] as? String, let key = d["key"] as? String, let wk = d["wk"] as? String,
              isStandardBase64(key), isStandardBase64(wk),
              let temp = d["temp"] as? String, let fpr = d["tempPgpFpr"] as? String,
              fpr.isEmpty || fpr.range(of: "^[0-9a-f]{40}$", options: .regularExpression) != nil,
              let auth = d["auth"] as? [String: Any],
              Set(auth.keys) == ["from", "validUntil", "sig"],
              let from = auth["from"] as? String, let sig = auth["sig"] as? String,
              let validUntil = (auth["validUntil"] as? NSNumber)?.doubleValue
        else { return nil }
        return Channel(
            role: role, sid: sid, key: key, wk: wk, temp: temp.lowercased(), tempPgpFpr: fpr.lowercased(),
            tempPgpArmor: d["tempPgpArmor"] as? String, authFrom: from.lowercased(),
            authValidUntil: validUntil, authSig: sig
        )
    }

    /// Offer-level checks that need no fingerprint (§108.7 part 1). Calls back true only when every check passes.
    /// Armor-bearing channels fail closed here (v109 (a)).
    static func verify(
        offer d: [String: Any], localEoa: String, nowMs: Double,
        completion: @escaping (Bool) -> Void
    ) {
        // v122 §141: v4 refuses any undefined key. callerTag is not kept in v4; the display is the verified from's short.
        guard Set(d.keys).isSubset(of: topLevelKeys) else { completion(false); return }
        guard (d["proto"] as? NSNumber)?.intValue == 4, let callId = d["callId"] as? String,
              let sessionId = d["sessionId"] as? String, let from = (d["from"] as? String)?.lowercased(),
              let to = (d["to"] as? String)?.lowercased(), to == localEoa.lowercased(),
              let createdAt = (d["createdAt"] as? NSNumber)?.doubleValue,
              let expiresAt = (d["expiresAt"] as? NSNumber)?.doubleValue,
              (d["timestamp"] as? NSNumber)?.doubleValue == createdAt,
              nowMs <= expiresAt,
              let codec = d["codec"] as? String, let sig = d["sig"] as? String,
              let cvObj = channel(role: "cv", d["cv"]), let cVObj = channel(role: "cV", d["cV"])
        else { completion(false); return }
        // Fail closed: an armor needs the fingerprint check, which is not available until the SDK provides it.
        if cvObj.tempPgpArmor != nil || cVObj.tempPgpArmor != nil { completion(false); return }
        let digest = chansDigest([cvObj, cVObj])
        let canonical = offerCanonical(
            callId: callId, sessionId: sessionId, from: from, to: to,
            createdAt: createdAt, expiresAt: expiresAt, codec: codec, chansDigest: digest
        )
        let chans = [cvObj, cVObj]
        BeamioOpenPgpHost.shared.verifyMessage(text: canonical, signature: sig) { result in
            guard case .success(let recovered) = result, recovered.lowercased() == from else { completion(false); return }
            // Each channel's auth: signer == from, the channel's own fields, validity inside the offer's lifetime.
            // The per-channel results arrive on callback threads; they are folded through one lock so the verdict is
            // computed once, from all results, and the completion fires exactly once.
            let gate = AuthGate(count: chans.count)
            for c in chans {
                let text = authCanonical(callId: callId, sessionId: sessionId, channel: c)
                let fieldsOk = c.authFrom == from && nowMs <= c.authValidUntil && c.authValidUntil <= expiresAt
                guard fieldsOk else {
                    if let verdict = gate.record(ok: false) { completion(verdict) }
                    continue
                }
                BeamioOpenPgpHost.shared.verifyMessage(text: text, signature: c.authSig) { r in
                    var ok = false
                    if case .success(let a) = r, a.lowercased() == from { ok = true }
                    if let verdict = gate.record(ok: ok) { completion(verdict) }
                }
            }
        }
    }
}
