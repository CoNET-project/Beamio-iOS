import ConetChatSDK
import Foundation

/// Resolve CallKit / Incoming identity for a killed-app VoIP wake:
/// opaque push → `voice_offer_fetch` encrypted to mailbox route PGP →
/// `POST http://{entryIp}/post` (shell picks an IP ≠ mailbox B) → decrypt with
/// Keychain user PGP → EIP-191 `callerSignature` → exact-address BeamioTag.
/// Observable decrypt-failure states of the incoming call (SPEC-incoming-call-decrypt-failure-states-r2-2026-11-20, PWA is the UI basis).
/// The native triggers are provisional until the iOS SDK confirms them (spec section five).
enum BeamioDecryptFailureState: String, Equatable {
    case x19Unlinked = "x19_unlinked"
    case keyMissing = "key_missing"
    case passcodeLocked = "passcode_locked"
    case dataCorrupt = "data_corrupt"
    case decryptTimeout = "decrypt_timeout"
    case decryptUnknown = "decrypt_unknown"

    /// The reason code of a failure. `dataCorrupt` carries `key_corrupt` or `cipher_corrupt`; the other states carry their own name.
    enum Reason: String, Equatable {
        case x19NotLinked = "x19_not_linked"
        case keyMissing = "key_missing"
        case passcodeLocked = "passcode_locked"
        case keyCorrupt = "key_corrupt"
        case cipherCorrupt = "cipher_corrupt"
        case decryptTimeout = "decrypt_timeout"
        case decryptUnknown = "decrypt_unknown"
    }

    /// Upper bound of the wait for a decrypt answer. r2 section three gives 10 seconds; whether it applies to decrypt
    /// requests is pending confirmation by the iOS SDK, so the value is held here until that answer.
    static let decryptTimeoutSeconds: TimeInterval = 10

    /// The state and reason of one native pgpDecrypt failure (provisional mapping, see the note above).
    /// Read failures are unknown, retryable, and delete nothing (r2 principles).
    static func of(_ failure: BeamioNativeWallet.Failure) -> (state: BeamioDecryptFailureState, reason: Reason) {
        switch failure {
        case .pending: return (.x19Unlinked, .x19NotLinked)
        case .locked: return (.passcodeLocked, .passcodeLocked)
        case .walletKeyMissing, .rejected("no_pgp_key"): return (.keyMissing, .keyMissing)
        case .rejected("decrypt_failed"), .rejected("pgp_message_shape"): return (.dataCorrupt, .cipherCorrupt)
        case .storageUnreadable, .signFailed, .rejected: return (.decryptUnknown, .decryptUnknown)
        }
    }
}

enum BeamioVoiceOfferIdentity {
	/// Plain value; compared off the main thread while an answer waits for its offer.
	struct OfferEnvelope: Equatable {
		let text: String
		let signMessage: String
		let from: String
	}

	nonisolated struct Resolved: Equatable {
		var callerEoa: String
		var beamioTag: String
		var shortAddress: String
		var callId: String
		/// Ring ID of the call (offer index, push handle; not a channel).
		var sessionId: String
		/// Offer `to` (local callee EOA when present).
		var to: String
		/// Voice protocol v3 (the callee creates the paid channels on Answer).
		var proto: Int = 0
		/// Caller's user-PGP public key and mailbox route key (armored), signed in the offer.
		var callerPgpArmored: String = ""
		var callerRouteArmored: String = ""
		/// Signed `expiresAt` of the offer in epoch ms (0 = absent). A late offer past it is refused.
		var signedExpiresAtMs: Double = 0

		/// Enough to answer or decline: a v3 offer with the caller's keys.
		var answerable: Bool {
			proto == 3
				&& callerPgpArmored.contains("BEGIN PGP PUBLIC KEY")
				&& callerRouteArmored.contains("BEGIN PGP PUBLIC KEY")
		}

		/// base64 armored public key → armor, or "".
		static func decodeArmor(_ raw: String) -> String {
			let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
			guard !t.isEmpty, let data = Data(base64Encoded: t, options: .ignoreUnknownCharacters),
			      let armor = String(data: data, encoding: .utf8),
			      armor.contains("BEGIN PGP PUBLIC KEY")
			else { return "" }
			return armor
		}
	}

	/// Best-effort; failures leave CallKit on opaque "Beamio".
	/// One observable decrypt failure: the state, the reason code, and a log line without any secret, ciphertext or plaintext.
	private static func reportDecryptFailure(
		_ state: BeamioDecryptFailureState,
		reason: BeamioDecryptFailureState.Reason,
		callId: String,
		failure: ((BeamioDecryptFailureState, String) -> Void)?
	) {
		NSLog("[BeamioVoiceOffer] decrypt failure state=%@ reason=%@ %@", state.rawValue, reason.rawValue, redactedCallId(callId))
		failure?(state, reason.rawValue)
	}

	/// The log form of a callId: its length only, never its value.
	static func redactedCallId(_ callId: String) -> String {
		"callId=<redacted len=\(callId.count)>"
	}

	static func resolve(
		callId: String,
		sessionId: String,
		failure: ((BeamioDecryptFailureState, String) -> Void)? = nil,
		completion: @escaping (Resolved?) -> Void
	) {
		// A callId or sessionId that does not fit the format is an input error, not a decrypt state. It is refused here, logged
		// without the values, and not reported through `failure`.
		guard !callId.isEmpty, sessionId.count >= 16 else {
			NSLog("[BeamioVoiceOffer] refused resolve — callId or sessionId does not fit the format (%@)", redactedCallId(callId))
			completion(nil)
			return
		}
		let pointer = BeamioNativeAccountPointer.get()
		// The record is judged first (project rule, r2): a missing PGP record is key_missing; a record that cannot be read is
		// decrypt_unknown, which is retryable. Neither is deleted or overwritten here, and both are reported through `failure`.
		switch BeamioChatPgpKeychain.recordState(eoa: pointer) {
		case .absent:
			reportDecryptFailure(.keyMissing, reason: .keyMissing, callId: callId, failure: failure)
			completion(nil)
			return
		case .unreadable:
			reportDecryptFailure(.decryptUnknown, reason: .decryptUnknown, callId: callId, failure: failure)
			completion(nil)
			return
		case .present:
			break
		}
		guard let secrets = BeamioChatPgpKeychain.load(eoa: pointer),
		      secrets.hasUserPrivate,
		      secrets.hasRoutePublic,
		      !Self.roster(from: secrets).isEmpty
		else {
			// The record is present but cannot be used (restore incomplete, route key or roster missing). It is never skipped
			// silently and never deleted: it is reported as decrypt_unknown, which is retryable.
			reportDecryptFailure(.decryptUnknown, reason: .decryptUnknown, callId: callId, failure: failure)
			completion(nil)
			return
		}

		fetchOfferArmor(callId: callId, sessionId: sessionId, secrets: secrets) { armor in
			guard let armor, armor.contains("BEGIN PGP MESSAGE") else {
				// Retrieving the ciphertext failed: a retryable unknown. Nothing is deleted or overwritten.
				reportDecryptFailure(.decryptUnknown, reason: .decryptUnknown, callId: callId, failure: failure)
				completion(nil)
				return
			}
			// PGP decrypt is native-only (BeamioNativeWallet.pgpDecrypt). The reviewed X-19 build
			// decrypts in process; the offer is parsed and verified below without returning its plaintext to the page.
			switch BeamioNativeWallet.pgpDecrypt(eoa: secrets.eoa, message: Data(armor.utf8)) {
			case .failure(let err):
				let mapped = BeamioDecryptFailureState.of(err)
				NSLog("[BeamioVoiceOffer] decrypt failure state=%@ reason=%@ %@", mapped.state.rawValue, mapped.reason.rawValue, redactedCallId(callId))
				failure?(mapped.state, mapped.reason.rawValue)
				completion(nil)
			case .success(let plain):
				parseAndVerify(plaintext: String(decoding: plain, as: UTF8.self), callId: callId, sessionId: sessionId, completion: completion)
			}
		}
	}

	/// Live chat inbound (already decrypted + outer EIP-191 `from` recovered by
	/// the chat module). Same offer verify + BeamioTag path as mailbox fetch —
	/// used when VoIP wake already painted opaque "Beamio" and the offer
	/// arrives as a normal chat line before / instead of voice_offer_fetch.
	static func resolveFromInboundChatLine(
		line: String,
		from: String,
		completion: @escaping (Resolved?) -> Void
	) {
		// v49 §55: only the chat envelope (text, signMessage, from) is accepted. A bare voice_call_offer JSON is refused:
		// it does not ring, show, register or answer.
		guard let envelope = parseEnvelope(line) else {
			NSLog("[BeamioVoiceOffer] refused: not a chat envelope")
			completion(nil)
			return
		}
		let claimed = from.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		guard claimed.hasPrefix("0x"), claimed.count == 42, envelope.from.lowercased() == claimed else {
			NSLog("[BeamioVoiceOffer] refused: envelope from does not match the line sender")
			completion(nil)
			return
		}
		// Outer envelope signature (EIP-191 over text): the recovered address must equal envelope.from.
		BeamioOpenPgpHost.shared.verifyMessage(text: envelope.text, signature: envelope.signMessage) { verifyResult in
			switch verifyResult {
			case .failure(let err):
				NSLog("[BeamioVoiceOffer] envelope signature failed %@", err.localizedDescription)
				completion(nil)
			case .success(let recovered):
				let signer = recovered.lowercased()
				guard signer == claimed else {
					NSLog("[BeamioVoiceOffer] refused: envelope signer %@ != from", signer)
					completion(nil)
					return
				}
				// The inner offer (its own callerSignature and from) is verified as before.
				parseAndVerify(
					plaintext: envelope.text,
					callId: "",
					sessionId: "",
					expectedCallerEoa: signer,
					completion: completion
				)
			}
		}
	}

	/// The chat envelope (v49 §55): a JSON object with `text`, `signMessage` and `from`. Nil for anything else,
	/// including a bare offer (which has `type` and no envelope fields).
	static func parseEnvelope(_ line: String) -> OfferEnvelope? {
		guard let data = line.data(using: .utf8),
		      let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
		      obj["type"] == nil,
		      let text = obj["text"] as? String,
		      let signMessage = obj["signMessage"] as? String,
		      let from = obj["from"] as? String
		else { return nil }
		return OfferEnvelope(text: text, signMessage: signMessage, from: from)
	}

	// MARK: - Fetch

#if BEAMIO_TEST_HOOKS
	/// Test-only: answers the ciphertext retrieval instead of the network (a nil armor is a failed retrieval). Nil restores the real one.
	static var fetchOfferArmorOverrideForTests: ((@escaping (String?) -> Void) -> Void)?
#endif

	private static func fetchOfferArmor(
		callId: String,
		sessionId: String,
		secrets: BeamioChatPgpKeychain.Secrets,
		completion: @escaping (String?) -> Void
	) {
#if BEAMIO_TEST_HOOKS
		if let answer = fetchOfferArmorOverrideForTests {
			answer(completion)
			return
		}
#endif
		let command: [String: Any] = [
			"command": "voice_offer_fetch",
			"callId": callId,
			"sessionId": sessionId,
			"timestamp": Int(Date().timeIntervalSince1970),
		]
		guard let cmdData = try? JSONSerialization.data(withJSONObject: command),
		      let cmdJson = String(data: cmdData, encoding: .utf8)
		else {
			completion(nil)
			return
		}
		// SI peel: JSON.parse(Buffer.from(decrypted, 'base64')) — encrypt base64(JSON), not raw JSON.
		let opaque = Data(cmdJson.utf8).base64EncodedString()
		BeamioOpenPgpHost.shared.encrypt(plaintext: opaque, publicKeyArmor: secrets.routePublicKeyArmor) { enc in
			switch enc {
			case .failure(let err):
				NSLog("[BeamioVoiceOffer] encrypt fetch cmd failed %@", err.localizedDescription)
				completion(nil)
			case .success(let armor):
				DispatchQueue.global(qos: .utility).async {
					var exclude: Set<String> = []
					if let ip = BeamioSiCipherPost.normalizeIp(secrets.mailboxIp) {
						exclude.insert(ip)
					}
					// Keep wall-clock under CallKit identity bg-task (~18s):
					// 3 entries × 5s timeout. Default 4×12s was cancelled mid-POST
					// (status=0) when chrome suspended at 3.5s → banner stayed "Beamio".
					let result = BeamioSiCipherPost.post(
						armor: armor,
						nodes: Self.roster(from: secrets),
						excludeIps: exclude,
						maxAttempts: 3,
						timeout: 5
					)
					if !result.ok {
						NSLog(
							"[BeamioVoiceOffer] SiPost failed status=%d err=%@",
							result.status,
							result.error.isEmpty ? "-" : result.error
						)
					}
					let offer = Self.extractOfferArmor(result.body)
					DispatchQueue.main.async { completion(offer) }
				}
			}
		}
	}

	private static func roster(from secrets: BeamioChatPgpKeychain.Secrets) -> [BeamioChatPgpKeychain.SiNode] {
		if !secrets.siNodes.isEmpty { return secrets.siNodes }
		return secrets.entryDomains.compactMap { raw in
			guard let ip = BeamioSiCipherPost.normalizeIp(raw) else { return nil }
			return BeamioChatPgpKeychain.SiNode(ip: ip, domain: "", region: "")
		}
	}

	private static func extractOfferArmor(_ text: String) -> String? {
		guard !text.isEmpty else { return nil }
		func fromObject(_ obj: [String: Any]) -> String? {
			guard obj["ok"] as? Bool == true,
			      let offer = obj["offerArmor"] as? String,
			      offer.contains("BEGIN PGP MESSAGE")
			else { return nil }
			return offer
		}
		if let data = text.data(using: .utf8),
		   let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
		   let offer = fromObject(obj)
		{
			return offer
		}
		if let rangeStart = text.range(of: "{"),
		   let rangeEnd = text.range(of: "}", options: .backwards),
		   rangeStart.lowerBound < rangeEnd.upperBound
		{
			let slice = String(text[rangeStart.lowerBound..<rangeEnd.upperBound])
			if let sliceData = slice.data(using: .utf8),
			   let obj = try? JSONSerialization.jsonObject(with: sliceData) as? [String: Any],
			   let offer = fromObject(obj)
			{
				return offer
			}
		}
		return nil
	}

	// MARK: - Verify

	private static func parseAndVerify(
		plaintext: String,
		callId: String,
		sessionId: String,
		expectedCallerEoa: String? = nil,
		completion: @escaping (Resolved?) -> Void
	) {
		// Outer chat envelope may wrap the offer; walk nested `text` / flatten.
		guard let offer = extractVoiceOffer(from: plaintext) else {
			NSLog("[BeamioVoiceOffer] no voice_call_offer_v1 in plaintext")
			completion(nil)
			return
		}
		let claimedFrom = (offer["from"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
		let callerSig = (offer["callerSignature"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
		let canonical = buildCallerCanonicalText(offer: offer)
		guard !callerSig.isEmpty, !canonical.isEmpty else {
			NSLog("[BeamioVoiceOffer] missing callerSignature")
			completion(nil)
			return
		}
		BeamioOpenPgpHost.shared.verifyMessage(text: canonical, signature: callerSig) { verifyResult in
			switch verifyResult {
			case .failure(let err):
				NSLog("[BeamioVoiceOffer] verifyMessage failed %@", err.localizedDescription)
				completion(nil)
			case .success(let recovered):
				let eoa = recovered.trimmingCharacters(in: .whitespacesAndNewlines)
				guard eoa.lowercased().hasPrefix("0x"), eoa.count == 42 else {
					completion(nil)
					return
				}
				if let expected = expectedCallerEoa?.lowercased(), !expected.isEmpty,
				   expected != eoa.lowercased()
				{
					NSLog(
						"[BeamioVoiceOffer] outer signer=%@ != callerSignature=%@",
						expected,
						eoa
					)
					completion(nil)
					return
				}
				if !claimedFrom.isEmpty, claimedFrom.lowercased() != eoa.lowercased() {
					NSLog(
						"[BeamioVoiceOffer] claimed from=%@ != recovered=%@ (rejected)",
						claimedFrom,
						eoa
					)
					completion(nil)
					return
				}
				let toField = (offer["to"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
				let offerCallId = (offer["callId"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
				let offerSessionId = (offer["sessionId"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
				// Dedupe record after verification (v38 §42): quota per recovered R, fail closed when over.
				let dedupCallId = (offerCallId?.isEmpty == false ? offerCallId! : callId)
				let dedupSessionId = (offerSessionId?.isEmpty == false ? offerSessionId! : sessionId)
				let expiresMs = expiresAtMs(of: offer)
				let admission = expiresMs > 0
					? BeamioOfferDedupeStore.admit(callId: dedupCallId, sessionId: dedupSessionId, callerEoa: eoa, expiresAtMs: expiresMs, nowMs: nowMs())
					: BeamioOfferDedupeLedger.Admission.rejectedCallerQuota
				guard admission == .admitted else {
					NSLog("[BeamioVoiceOffer] WARNING dedupe refused (%@) callId=%@", "\(admission)", redactedCallId(dedupCallId))
					completion(nil)
					return
				}
				BeamioTagAddressLookup.fetchExactTag(for: eoa) { tag in
					let resolved = Resolved(
						callerEoa: eoa,
						beamioTag: tag ?? "",
						shortAddress: BeamioIncomingAddressFormat.short(eoa),
						callId: (offerCallId?.isEmpty == false ? offerCallId! : callId),
						sessionId: (offerSessionId?.isEmpty == false ? offerSessionId! : sessionId),
						to: toField,
						proto: Self.protoOf(offer),
						callerPgpArmored: Resolved.decodeArmor((offer["callerPgp"] as? String) ?? ""),
						callerRouteArmored: Resolved.decodeArmor((offer["callerRoute"] as? String) ?? ""),
						signedExpiresAtMs: expiresAtMs(of: offer)
					)
					BeamioNativeVoiceSignaling.rememberOffer(resolved)
					NSLog(
						"[BeamioVoiceOffer] resolved callId=%@ tag=%@ short=%@ v3=%@",
						resolved.callId.isEmpty ? callId : resolved.callId,
						resolved.beamioTag.isEmpty ? "-" : resolved.beamioTag,
						resolved.shortAddress,
						resolved.answerable ? "yes" : "no"
					)
					completion(resolved)
				}
			}
		}
	}

	/// The signed `expiresAt` in epoch ms (seconds are scaled up); 0 when absent or unreadable.
	static func expiresAtMs(of offer: [String: Any]) -> Double {
		let v: Double = (offer["expiresAt"] as? Double) ?? (offer["expiresAt"] as? NSNumber)?.doubleValue
			?? Double((offer["expiresAt"] as? String) ?? "") ?? 0
		guard v > 0, v.isFinite else { return 0 }
		return v < 100_000_000_000 ? v * 1000 : v
	}

	/// Late-offer rule (v37 §41): an offer is applied only while `now` has not passed its signed expiresAt.
	/// The clock of the offer path. Production reads the system time; a test build may pin it (BEAMIO_TEST_HOOKS only).
	static func nowMs() -> Double {
		#if BEAMIO_TEST_HOOKS
		if let pinned = nowMsForTests { return pinned }
		#endif
		return Date().timeIntervalSince1970 * 1000
	}

	#if BEAMIO_TEST_HOOKS
	/// Test only: pins the offer path clock. nil restores the system clock.
	static var nowMsForTests: Double?
	#endif

	static func withinSignedExpiry(_ offer: Resolved, nowMs: Double = BeamioVoiceOfferIdentity.nowMs()) -> Bool {
		offer.signedExpiresAtMs > 0 && nowMs <= offer.signedExpiresAtMs
	}

	static func extractVoiceOffer(from plaintext: String) -> [String: Any]? {
		func walk(_ value: Any, depth: Int) -> [String: Any]? {
			guard depth < 8 else { return nil }
			if let dict = value as? [String: Any] {
				if let type = dict["type"] as? String, type == "voice_call_offer_v1" {
					return dict
				}
				if let text = dict["text"] as? String,
				   let nested = parseJsonObject(text)
				{
					if let hit = walk(nested, depth: depth + 1) { return hit }
				}
				for (_, v) in dict {
					if let hit = walk(v, depth: depth + 1) { return hit }
				}
			}
			if let s = value as? String, let nested = parseJsonObject(s) {
				return walk(nested, depth: depth + 1)
			}
			return nil
		}
		if let root = parseJsonObject(plaintext) {
			return walk(root, depth: 0)
		}
		// The offer armor is a Chat envelope: the PGP literal is base64(UTF-8 JSON),
		// exactly like every other Chat message (web worker and PWA both encode it
		// so). Decoding it here was missing, so a fetched offer never parsed and the
		// killed-app call stayed anonymous.
		let compact = plaintext.trimmingCharacters(in: .whitespacesAndNewlines)
		if let data = Data(base64Encoded: compact, options: [.ignoreUnknownCharacters])
			?? BeamioLenientBase64.decode(compact),
		   let text = String(data: data, encoding: .utf8),
		   let root = parseJsonObject(text)
		{
			return walk(root, depth: 0)
		}
		return nil
	}

	private static func parseJsonObject(_ s: String) -> [String: Any]? {
		guard let data = s.data(using: .utf8),
		      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
		else { return nil }
		return obj
	}

	static func protoOf(_ offer: [String: Any]) -> Int {
		if let i = offer["proto"] as? Int { return i }
		if let n = offer["proto"] as? NSNumber { return n.intValue }
		return 0
	}

	/// Canonical text for `callerSignature` (no from / tag / signature itself).
	static func buildCallerCanonicalText(offer: [String: Any]) -> String {
		func s(_ key: String) -> String {
			if let v = offer[key] as? String { return v }
			if let n = offer[key] as? NSNumber { return n.stringValue }
			return ""
		}
		func n(_ key: String) -> String {
			if let i = offer[key] as? Int { return String(i) }
			if let d = offer[key] as? Double { return String(Int(d)) }
			if let num = offer[key] as? NSNumber { return num.stringValue }
			if let str = offer[key] as? String { return str }
			return ""
		}
		// Voice protocol v3 only: no channel material in the offer (the callee
		// creates it on Answer). Older offers do not verify.
		guard protoOf(offer) == 3 else { return "" }
		return [
			"CoNET voice_call_offer_v3",
			"callId:\(s("callId"))",
			"sessionId:\(s("sessionId"))",
			"to:\(s("to").lowercased())",
			"createdAt:\(n("createdAt"))",
			"expiresAt:\(n("expiresAt"))",
			"timestamp:\(n("timestamp"))",
			"codec:\(s("codec"))",
			"callerPgp:\(s("callerPgp"))",
			"callerRoute:\(s("callerRoute"))",
		].joined(separator: "\n")
	}
}

#if BEAMIO_TEST_HOOKS
extension BeamioVoiceOfferIdentity {
	/// Test-only entry to the production parse-and-verify path (BEAMIO_TEST_HOOKS builds only; absent from release).
	static func parseAndVerifyForTests(
		plaintext: String,
		callId: String,
		sessionId: String,
		completion: @escaping (Resolved?) -> Void
	) {
		parseAndVerify(plaintext: plaintext, callId: callId, sessionId: sessionId, completion: completion)
	}
}
#endif
