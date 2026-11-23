import Foundation

/// Offer dedupe ledger (chat interface spec, three platforms alike).
/// One record per key `JSON.stringify([callId, sessionId])`, recorded only after the offer passed verification.
/// R is the recovered signer (`callerEoa`), never an unverified field.
/// Quota: 50 unexpired records per R, 1000 unexpired records in total. Expired records (now > expiresAt) are purged
/// first. Over quota: the new offer is refused (fail closed) and nothing unexpired is evicted.
struct BeamioOfferDedupeLedger {
    static let perCallerLimit = 50
    static let globalLimit = 1000

    struct Entry: Equatable {
        var callerEoa: String
        var expiresAtMs: Double
    }

    enum Admission: Equatable {
        case admitted
        case rejectedCallerQuota
        case rejectedGlobalQuota
    }

    private(set) var entries: [String: Entry]

    init(entries: [String: Entry] = [:]) {
        self.entries = entries
    }

    /// `JSON.stringify([callId, sessionId])`: a two-element array of quoted strings, no spaces.
    static func key(callId: String, sessionId: String) -> String {
        func quoted(_ value: String) -> String {
            "\"" + value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        return "[" + quoted(callId) + "," + quoted(sessionId) + "]"
    }

    /// Purges expired records, then admits the offer unless a quota is reached. An existing key is admitted without
    /// a second record (a replay of an already-recorded offer is not a quota event).
    mutating func admit(
        callId: String,
        sessionId: String,
        callerEoa: String,
        expiresAtMs: Double,
        nowMs: Double
    ) -> Admission {
        entries = entries.filter { $0.value.expiresAtMs >= nowMs }
        let k = Self.key(callId: callId, sessionId: sessionId)
        if entries[k] != nil { return .admitted }
        let r = callerEoa.lowercased()
        if entries.values.filter({ $0.callerEoa == r }).count >= Self.perCallerLimit { return .rejectedCallerQuota }
        if entries.count >= Self.globalLimit { return .rejectedGlobalQuota }
        entries[k] = Entry(callerEoa: r, expiresAtMs: expiresAtMs)
        return .admitted
    }
}

/// Persisted ledger shared by the offer path. UserDefaults holds only the key, the R and the expiry (no secrets).
enum BeamioOfferDedupeStore {
    private static let storageKey = "beamio.voice.offerDedupe"
    private static let lock = NSLock()

    static func admit(
        callId: String,
        sessionId: String,
        callerEoa: String,
        expiresAtMs: Double,
        nowMs: Double = Date().timeIntervalSince1970 * 1000
    ) -> BeamioOfferDedupeLedger.Admission {
        lock.lock()
        defer { lock.unlock() }
        var ledger = BeamioOfferDedupeLedger(entries: load())
        let result = ledger.admit(
            callId: callId,
            sessionId: sessionId,
            callerEoa: callerEoa,
            expiresAtMs: expiresAtMs,
            nowMs: nowMs
        )
        save(ledger.entries)
        return result
    }

    private static func load() -> [String: BeamioOfferDedupeLedger.Entry] {
        let raw = UserDefaults.standard.dictionary(forKey: storageKey) as? [String: [String: Any]] ?? [:]
        var out: [String: BeamioOfferDedupeLedger.Entry] = [:]
        for (k, v) in raw {
            guard let r = v["r"] as? String, let exp = v["exp"] as? Double else { continue }
            out[k] = BeamioOfferDedupeLedger.Entry(callerEoa: r, expiresAtMs: exp)
        }
        return out
    }

    private static func save(_ entries: [String: BeamioOfferDedupeLedger.Entry]) {
        let raw: [String: [String: Any]] = entries.mapValues { ["r": $0.callerEoa, "exp": $0.expiresAtMs] }
        UserDefaults.standard.set(raw, forKey: storageKey)
    }
}
