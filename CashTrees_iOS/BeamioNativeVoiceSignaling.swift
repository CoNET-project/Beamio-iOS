import ConetChatSDK
import Foundation
import Security
import UIKit

/// Native voice signaling over entry nodes (`BeamioSiCipherPost`) — no PWA.
/// Decline / Accept: AES-GCM control body → `voice_uplink` encrypted to **caller mailbox route PGP**.
/// Dialer: native `voice_listen` on offer.sessionId to receive accept/reject + media.
enum BeamioNativeVoiceSignaling {
	enum Role: String {
		case callee
		case dialer
	}

	/// Active native temporary-relay call (callee after Answer, or dialer after startSystemCall).
	struct ActiveCall: Equatable {
		var role: Role
		var offer: BeamioVoiceOfferIdentity.Resolved
		/// Local `voice_listen` sessionId.
		var listenSessionId: String
		/// Peer listen session for uplink `targetSessionId` (dialer: empty until accept).
		var peerMediaSessionId: String
		/// Encrypt-to / uplink `to` (callee→caller EOA, dialer→callee EOA).
		var peerEoa: String
		var localEoa: String
		/// Dialer starts listen-only until remote accept enables PCM.
		var mediaEnabled: Bool
		/// Voice protocol v3: the call's four paid channels (nil for older calls).
		var v3: BeamioVoiceV3.Call? = nil

		/// Callee accept listen id (compat alias).
		var acceptSessionId: String { listenSessionId }
	}

	private static let lock = NSLock()
	private static var cacheByCallId: [String: BeamioVoiceOfferIdentity.Resolved] = [:]
	private static var inFlightDecline: Set<String> = []
	private static var inFlightAccept: Set<String> = []
	/// Callee calls whose accept already started (Answer, or the didActivate fallback).
	private static var acceptStarted: Set<String> = []
	/// Callee calls whose CallKit audio session is active (media may start).
	private static var calleeAudioReady: Set<String> = []
	/// Bound calls whose accept waits for the unlock (locked answer): callId -> sessionId.
	private static var awaitingUnlockAccepts: [String: String] = [:]
	private static var activeCall: ActiveCall?
	/// Busy rejects: sent at once when the second call's offer is resolved (its
	/// decrypt already loaded `BeamioOpenPgpHost`, which the dialer cancel also
	/// uses during a live call). Only an unresolved offer waits, because
	/// resolving it here would boot the host's WKWebView and SpringBoard used to
	/// drop the live banner (v68 decline stage).
	private static var busyRejects = BeamioBusyRejectQueue<BeamioVoiceOfferIdentity.Resolved>()

	// MARK: - Caller cancel / hang-up seen by the shell

	/// Calls the caller has already ended, keyed by callId and by sessionId. A VoIP
	/// push makes iOS report the call at once, so the caller's cancel can arrive
	/// before the report exists (the app is still waking up). Remembering it lets
	/// the report be ended as soon as it is made.
	/// Persisted: a push can wake a new process for the next call, and the chat
	/// backlog then replays the earlier, already-cancelled offer; without the mark
	/// that offer would ring CallKit again.
	private static let remoteEndedKey = "beamio.voice.remoteEnded"
	private static let remoteEndedTTL: TimeInterval = 1200

	/// Caller holds `lock`.
	private static func loadRemoteEnded(now: Date) -> [String: TimeInterval] {
		let raw = UserDefaults.standard.dictionary(forKey: remoteEndedKey) as? [String: TimeInterval] ?? [:]
		let cutoff = now.timeIntervalSince1970 - remoteEndedTTL
		return raw.filter { $0.value >= cutoff }
	}

	static func wasRemoteEnded(callId: String, sessionId: String) -> Bool {
		remoteEndedAgeSeconds(callId: callId, sessionId: sessionId) != nil
	}

	/// Seconds since `markRemoteEnded` for this call/session, or `nil` if not marked /
	/// expired. Soft FG uses a short window so history dumps of old ends soft-skip
	/// (no CallKit flash), while a close end-before-offer race (~seconds) can soft-allow.
	static func remoteEndedAgeSeconds(callId: String, sessionId: String) -> TimeInterval? {
		lock.lock()
		defer { lock.unlock() }
		let now = Date()
		let map = loadRemoteEnded(now: now)
		var stamped: TimeInterval?
		if !callId.isEmpty, let d = map[callId] {
			stamped = d
		}
		if !sessionId.isEmpty, let d = map[sessionId] {
			if stamped == nil || d > stamped! { stamped = d }
		}
		guard let stamped else { return nil }
		return max(0, now.timeIntervalSince1970 - stamped)
	}

	/// Documents/voice-qa.log (pull with `devicectl device copy from`). A killed app
	/// woken by a call push has no console to read, so the cancel path leaves a
	/// short trail here too. QA and Debug builds only (like `BeamioQALog`):
	/// Release writes no file, just the system log line.
	static func qaTrail(_ line: String) {
		NSLog("[BeamioVoiceQA] %@", line)
		#if DEBUG || BEAMIO_QA
		writeQaTrailFile(line)
		#endif
	}

	#if DEBUG || BEAMIO_QA
	private static func writeQaTrailFile(_ line: String) {
		guard let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else { return }
		let url = dir.appendingPathComponent("voice-qa.log")
		let data = Data("\(ISO8601DateFormatter().string(from: Date())) \(line)\n".utf8)
		if let handle = try? FileHandle(forWritingTo: url) {
			defer { try? handle.close() }
			_ = try? handle.seekToEnd()
			try? handle.write(contentsOf: data)
		} else {
			try? data.write(to: url, options: .atomic)
		}
	}
	#endif

	private static func markRemoteEnded(callId: String, sessionId: String) {
		markStrictEnded(callId: callId, sessionId: sessionId)
		lock.lock()
		let now = Date()
		var map = loadRemoteEnded(now: now)
		if !callId.isEmpty { map[callId] = now.timeIntervalSince1970 }
		if !sessionId.isEmpty { map[sessionId] = now.timeIntervalSince1970 }
		UserDefaults.standard.set(map, forKey: remoteEndedKey)
		lock.unlock()
	}

	/// Incoming calls this device already declined or hung up, keyed by callId
	/// and sessionId. The PWA or a replayed chat offer can soft-report the same
	/// call again seconds later; that must not ring a call that is over.
	/// Persisted so a relaunch (or a cold start from a push) still knows.
	private static let locallyEndedKey = "beamio.voice.locallyEnded"
	private static let locallyEndedTTL: TimeInterval = 1200

	/// Caller holds `lock`.
	private static func loadLocallyEnded(now: Date) -> [String: TimeInterval] {
		let raw = UserDefaults.standard.dictionary(forKey: locallyEndedKey) as? [String: TimeInterval] ?? [:]
		let cutoff = now.timeIntervalSince1970 - locallyEndedTTL
		return raw.filter { $0.value >= cutoff }
	}

	static func markLocallyEnded(callId: String, sessionId: String) {
		markStrictEnded(callId: callId, sessionId: sessionId)
		lock.lock()
		let now = Date()
		var map = loadLocallyEnded(now: now)
		if !callId.isEmpty { map[callId] = now.timeIntervalSince1970 }
		if !sessionId.isEmpty { map[sessionId] = now.timeIntervalSince1970 }
		UserDefaults.standard.set(map, forKey: locallyEndedKey)
		lock.unlock()
	}

	/// Strict composite-key ended record: key JSON.stringify([callId, sessionId]), written only when both ids are
	/// non-empty. It can only add drops: the existing dual-key checks stay the rule for everything else.
	private static let strictEndedKey = "beamio.voice.strictEnded"
	private static let strictEndedTTL: TimeInterval = 1200

	static func strictEndedKeyString(callId: String, sessionId: String) -> String? {
		let c = callId.trimmingCharacters(in: .whitespacesAndNewlines)
		let s = sessionId.trimmingCharacters(in: .whitespacesAndNewlines)
		guard !c.isEmpty, !s.isEmpty else { return nil }
		func q(_ v: String) -> String {
			"\"" + v.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
		}
		return "[" + q(c) + "," + q(s) + "]"
	}

	static func markStrictEnded(callId: String, sessionId: String) {
		guard let key = strictEndedKeyString(callId: callId, sessionId: sessionId) else { return }
		lock.lock()
		defer { lock.unlock() }
		let now = Date().timeIntervalSince1970
		var map = (UserDefaults.standard.dictionary(forKey: strictEndedKey) as? [String: TimeInterval] ?? [:])
		map = map.filter { now - $0.value <= strictEndedTTL }
		map[key] = now
		UserDefaults.standard.set(map, forKey: strictEndedKey)
	}

	/// True when the strict composite key was ended within its window. Never true for an empty sessionId.
	static func wasStrictEnded(callId: String, sessionId: String) -> Bool {
		guard let key = strictEndedKeyString(callId: callId, sessionId: sessionId) else { return false }
		lock.lock()
		defer { lock.unlock() }
		let now = Date().timeIntervalSince1970
		guard let t = (UserDefaults.standard.dictionary(forKey: strictEndedKey) as? [String: TimeInterval])?[key] else { return false }
		return now - t <= strictEndedTTL
	}

	static func wasLocallyEnded(callId: String, sessionId: String) -> Bool {
		lock.lock()
		defer { lock.unlock() }
		let map = loadLocallyEnded(now: Date())
		return (!callId.isEmpty && map[callId] != nil)
			|| (!sessionId.isEmpty && map[sessionId] != nil)
	}

	// MARK: - Incoming ring time (tells a system timeout from a Decline)

	/// iOS ends an unanswered incoming CallKit call after about 60 s; a Decline
	/// arrives as the same End. A ring at least this long counts as a timeout.
	/// (The ring window is 60 s on every platform; the caller's own timeout
	/// normally arrives first, this covers a lost one.)
	static let systemRingTimeoutSeconds: TimeInterval = 55
	private static var incomingRingStarted: [String: Date] = [:]

	/// First CallKit report of this incoming call (a re-report keeps the first time).
	static func noteIncomingRingStarted(callId: String) {
		guard !callId.isEmpty else { return }
		lock.lock()
		let now = Date()
		incomingRingStarted = incomingRingStarted.filter { now.timeIntervalSince($0.value) < 600 }
		if incomingRingStarted[callId] == nil { incomingRingStarted[callId] = now }
		callKitReportedAtMap = callKitReportedAtMap.filter { now.timeIntervalSince($0.value) < 7 * 24 * 3600 }
		if callKitReportedAtMap[callId] == nil { callKitReportedAtMap[callId] = now }
		lock.unlock()
	}

	/// Seconds this incoming call has rung, then forgets it; nil if unknown.
	static func takeIncomingRingSeconds(callId: String) -> TimeInterval? {
		lock.lock()
		defer { lock.unlock() }
		guard let started = incomingRingStarted.removeValue(forKey: callId) else { return nil }
		return Date().timeIntervalSince(started)
	}

	// MARK: - Busy rejects (on disk, like locallyEnded)

	private static let busyRejectedKey = "beamio.voice.busyRejected"

	/// A second incoming call rejected as busy while in a call: closed on this
	/// device (no later ring) and remembered so the page can record it as
	/// "Missed call · While on another call" when it sees the offer later.
	static func markBusyRejected(callId: String, sessionId: String) {
		markLocallyEnded(callId: callId, sessionId: sessionId)
		lock.lock()
		let now = Date()
		var map = (UserDefaults.standard.dictionary(forKey: busyRejectedKey) as? [String: TimeInterval] ?? [:])
			.filter { now.timeIntervalSince1970 - $0.value < locallyEndedTTL }
		if !callId.isEmpty { map[callId] = now.timeIntervalSince1970 }
		if !sessionId.isEmpty { map[sessionId] = now.timeIntervalSince1970 }
		UserDefaults.standard.set(map, forKey: busyRejectedKey)
		lock.unlock()
	}

	static func wasBusyRejected(callId: String, sessionId: String) -> Bool {
		lock.lock()
		defer { lock.unlock() }
		let now = Date().timeIntervalSince1970
		let map = (UserDefaults.standard.dictionary(forKey: busyRejectedKey) as? [String: TimeInterval] ?? [:])
			.filter { now - $0.value < locallyEndedTTL }
		return (!callId.isEmpty && map[callId] != nil) || (!sessionId.isEmpty && map[sessionId] != nil)
	}



	static func observeChatEvent(_ payload: [String: Any]) {
		guard payload["action"] as? String == "chatModuleEvent",
		      let event = payload["event"] as? [String: Any]
		else { return }
		if let type = event["type"] as? String, type == "event:status" {
			qaTrail("chat status \((event["payload"] as? [String: Any])?["status"] as? String ?? "?")")
		}
		guard event["type"] as? String == "event:message",
		      let body = event["payload"] as? [String: Any],
		      let line = body["line"] as? String,
		      let from = (body["from"] as? String)?.lowercased(),
		      from.hasPrefix("0x"), from.count == 42
		else { return }
		qaTrail("chat message from=…\(from.suffix(6)) len=\(line.count)")

		// v68 §75 / v69 §76: a voice_ chat line drives no call action until its outer envelope is verified
		// (outer EIP-191 signer == envelope.from == line sender == inner from). Unverified: dropped silently.
		if line.contains("voice_") {
			VoiceLineVerifier.verify(line: line, lineFrom: from) { verified in
				guard verified else {
					qaTrail("voice line dropped: not verified")
					return
				}
				// Strict ended record (only adds drops): a call ended under this exact {callId, sessionId} stays ended.
				if let id = VoiceLineVerifier.innerIdentity(line),
				   wasStrictEnded(callId: id.callId, sessionId: id.sessionId) {
					qaTrail("voice line dropped: call already ended (strict key)")
					return
				}
				handleVerifiedChatLine(line: line, from: from)
			}
			return
		}
		handleVerifiedChatLine(line: line, from: from)
	}

	/// The chat-line handling for a line whose voice signals (if any) are verified.
	static func handleVerifiedChatLine(line: String, from: String) {
		// Call control (caller cancel / hang-up) is recognised by the chat module
		// (v72: the SDK peer-control hook is not attached; the chat path above is the only driver.)
		if endSignal(in: line) != nil { return }

		// v3 dialer: the callee's device is ringing (wake receipt).
		if line.contains("voice_call_ringing_v1"),
		   let signal = voiceSignal(in: line, types: ["voice_call_ringing_v1"])
		{
			dialerDidReceiveRinging(callId: (signal["callId"] as? String) ?? "", from: from)
			return
		}

		// v3 dialer: the callee answers (or declines) with a chat message.
		if line.contains("voice_call_accept_v1") || line.contains("voice_call_reject_v1") || line.contains("voice_call_timeout_v1"),
		   let signal = voiceSignal(in: line, types: ["voice_call_accept_v1", "voice_call_reject_v1", "voice_call_timeout_v1"]),
		   BeamioVoiceOfferIdentity.protoOf(signal) == 3 || (signal["type"] as? String) != "voice_call_accept_v1"
		{
			let type = (signal["type"] as? String) ?? ""
			if type == "voice_call_accept_v1" {
				dialerDidReceiveAcceptV3(accept: signal, from: from)
			} else {
				dialerDidReceiveRejectV3(
					type: type,
					callId: (signal["callId"] as? String) ?? "",
					from: from,
					reason: (signal["reason"] as? String) ?? ""
				)
			}
			return
		}

		// Offer path: verify + BeamioTag, then replace opaque CallKit "Beamio".
		guard line.contains("voice_call_offer_v1") || line.contains("callerSignature") else {
			return
		}
		let ringOver = offerRingWindowOver(line: line)
		BeamioVoiceOfferIdentity.resolveFromInboundChatLine(line: line, from: from) { resolved in
			guard let resolved else { return }
			rememberOffer(resolved)
			let pushAlias = BeamioVoipIncomingBootstrap.shared.callKit.lastReportedCallId
			if !pushAlias.isEmpty, pushAlias != resolved.callId {
				aliasOffer(resolved, under: pushAlias)
			}
			let tag = resolved.beamioTag
			let short = resolved.shortAddress
			qaTrail(
				"chat offer → tag=\(tag.isEmpty ? "-" : tag) callId=\(resolved.callId.prefix(8)) push=\(pushAlias.prefix(8))"
			)
			DispatchQueue.main.async {
				let callKit = BeamioVoipIncomingBootstrap.shared.callKit
				let liveSame = callKit.hasLiveIncoming(
					forCallId: resolved.callId,
					sessionId: resolved.sessionId
				)
				// PushKit never reported (empty lastReportedCallId) — soft-report
				// CallKit while SSE/app is alive so FG/BG with mailbox open still rings.
				// Lock-screen wake still requires a working PushKit/APNs path.
				// The caller already ended this call (its end can be replayed before
				// the offer from a cold listen's backlog): never ring it again.
				if wasRemoteEnded(callId: resolved.callId, sessionId: resolved.sessionId) {
					qaTrail("chat offer for an ended call; not reported callId=\(resolved.callId.prefix(8))")
					return
				}
				// A replayed offer whose ring window has passed is over even if its
				// end never reached this device (lost while a push woke the app).
				if ringOver, !liveSame {
					qaTrail("chat offer past its ring window; not reported callId=\(resolved.callId.prefix(8))")
					return
				}
				sendRingingIfNeeded(resolved)
				if pushAlias.isEmpty, !liveSame {
					// v116 §135 (transitional): the name is the verified from's short address. The self-reported tag never
					// names the caller here (no tag is shown as identity; the claimed tag is not a display name).
					let display: String = {
						let verifiedShort = BeamioIncomingAddressFormat.short(resolved.callerEoa)
						return verifiedShort.isEmpty ? "Beamio call" : verifiedShort
					}()
					qaTrail(
						"chat offer empty-push → soft CallKit report callId=\(resolved.callId.prefix(8))"
					)
					NSLog(
						"[BeamioNativeVoice] empty-push chat offer → soft CallKit report callId=%@",
						resolved.callId
					)
					BeamioVoipIncomingBootstrap.shared.reportIncomingCallKit(
						callId: resolved.callId,
						sessionId: resolved.sessionId,
						peerAddress: resolved.callerEoa,
						displayName: display,
						claimedTag: tag,
						claimedAddress: short,
						mustReportForPushKit: false
					)
					return
				}
				callKit.updateVerifiedIdentity(
					callId: resolved.callId,
					sessionId: resolved.sessionId,
					tag: tag,
					shortAddress: short
				)
				if !pushAlias.isEmpty, pushAlias != resolved.callId {
					callKit.updateVerifiedIdentity(
						callId: pushAlias,
						sessionId: resolved.sessionId,
						tag: tag,
						shortAddress: short
					)
				}
			}
		}
	}

	private static func endSignal(in line: String) -> (type: String, callId: String, sessionId: String)? {
		func walk(_ value: Any, depth: Int) -> (String, String, String)? {
			guard depth < 8 else { return nil }
			if let text = value as? String {
				let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
				if let data = trimmed.data(using: .utf8),
				   let parsed = try? JSONSerialization.jsonObject(with: data)
				{
					return walk(parsed, depth: depth + 1)
				}
				// Chat envelopes are often base64(UTF-8 JSON), same as offer armor.
				if let data = Data(base64Encoded: trimmed, options: [.ignoreUnknownCharacters])
					?? BeamioLenientBase64.decode(trimmed),
				   let decoded = String(data: data, encoding: .utf8),
				   let parsed = try? JSONSerialization.jsonObject(with: Data(decoded.utf8))
				{
					return walk(parsed, depth: depth + 1)
				}
				return nil
			}
			guard let obj = value as? [String: Any] else { return nil }
			if let type = obj["type"] as? String,
			   type == "voice_end_v1" || type == "voice_call_timeout_v1"
			{
				let callId = (obj["callId"] as? String) ?? ""
				let sessionId = (obj["sessionId"] as? String) ?? ""
				if callId.isEmpty && sessionId.isEmpty { return nil }
				return (type, callId, sessionId)
			}
			if let inner = obj["text"] as? String, let hit = walk(inner, depth: depth + 1) {
				return hit
			}
			for (_, v) in obj {
				if let hit = walk(v, depth: depth + 1) { return hit }
			}
			return nil
		}
		guard let hit = walk(line, depth: 0) else { return nil }
		return (type: hit.0, callId: hit.1, sessionId: hit.2)
	}

	/// Whether a call is still live on this device (not ended by the remote side or locally). A late-arriving offer may only be
	/// applied to a live call. Test hook: `liveOverrideForTests` (BEAMIO_TEST_HOOKS builds only; not in release).
	/// How long a call stays live after CallKit first reported it. An offer that arrives later than this is for an ended call.
	static let lateOfferCallTTLSeconds: TimeInterval = 600

	/// Whether a call is still live, for applying a late-arriving offer (fail closed):
	/// 1. an end marker (remote or local) means ended; a marker past its own TTL has already been dropped by its store;
	/// 2. a call CallKit reported and no longer holds is ended;
	/// 3. a call older than `lateOfferCallTTLSeconds` since its first CallKit report is ended, so an expired marker cannot revive it;
	/// 4. a call CallKit never reported is live (an offer may arrive before CallKit reports the call).
	static func isCallStillLive(callId: String, sessionId: String) -> Bool {
#if BEAMIO_TEST_HOOKS
		if let override = liveOverrideForTests { return override(callId, sessionId) }
#endif
		if wasRemoteEnded(callId: callId, sessionId: sessionId) || wasLocallyEnded(callId: callId, sessionId: sessionId) {
			return false
		}
		guard let reported = callKitReportedAt(callId: callId) else { return true }
		if !callKitHasCall(callId: callId) { return false }
		return Date().timeIntervalSince(reported) <= lateOfferCallTTLSeconds
	}

	/// First CallKit report time for a call (kept for the late-offer rule; pruned after a week).
	private static var callKitReportedAtMap: [String: Date] = [:]

	static func callKitReportedAt(callId: String) -> Date? {
		lock.lock()
		defer { lock.unlock() }
		return callKitReportedAtMap[callId]
	}

	/// Whether CallKit holds the call now. The test hook answers instead of the bootstrap.
	private static func callKitHasCall(callId: String) -> Bool {
#if BEAMIO_TEST_HOOKS
		if let present = callKitPresentForTests { return present(callId) }
#endif
		return BeamioVoipIncomingBootstrap.shared.callKit.callKitHasCall(callId: callId)
	}

#if BEAMIO_TEST_HOOKS
	/// Test-only: answers whether CallKit holds the call (the bootstrap is not touched by tests). nil restores the real check.
	static var callKitPresentForTests: ((String) -> Bool)?

	/// Test-only: sets the first CallKit report time of a call, to exercise the TTL rule.
	static func setCallKitReportedAtForTests(callId: String, at: Date?) {
		lock.lock()
		defer { lock.unlock() }
		callKitReportedAtMap[callId] = at
	}
#endif

#if BEAMIO_TEST_HOOKS
	/// Test-only: answers `isCallStillLive` instead of the ended-call records. nil restores the real check.
	static var liveOverrideForTests: ((String, String) -> Bool)?
#endif

	/// The decision for an offer that arrives late (after the caller gave up or after the call ended): it is applied (cached,
	/// rung, shown) only when it is answerable and its call is still live. Pure given `isCallStillLive`.
	static func shouldApplyLateOffer(_ offer: BeamioVoiceOfferIdentity.Resolved, callId: String, sessionId: String) -> Bool {
		offer.answerable && BeamioVoiceOfferIdentity.withinSignedExpiry(offer) && isCallStillLive(callId: callId, sessionId: sessionId)
	}

	/// Holds the result of one offer wait. The callback writes only while the wait is open; after the wait is abandoned
	/// (timeout), a late result is dropped, so no thread reads or writes the value without the lock.
	final class OfferWaitBox {
		private let lock = NSLock()
		private var abandoned = false
		private var value: BeamioVoiceOfferIdentity.Resolved?

		func deliver(_ resolved: BeamioVoiceOfferIdentity.Resolved?) {
			lock.lock()
			defer { lock.unlock() }
			if !abandoned { value = resolved }
		}

		/// Ends the wait and returns the value delivered so far (nil if none). Any later delivery is dropped.
		func finish() -> BeamioVoiceOfferIdentity.Resolved? {
			lock.lock()
			defer { lock.unlock() }
			abandoned = true
			return value
		}
	}

	static func rememberOffer(_ incoming: BeamioVoiceOfferIdentity.Resolved) {
		guard !incoming.callId.isEmpty else { return }
		lock.lock()
		// A later copy without the caller keys must not erase them from the
		// shell's own decrypt of the same offer.
		var resolved = incoming
		if !resolved.answerable,
		   let prior = cacheByCallId[resolved.callId],
		   prior.answerable,
		   prior.sessionId == resolved.sessionId
		{
			resolved.proto = prior.proto
			resolved.callerPgpArmored = prior.callerPgpArmored
			resolved.callerRouteArmored = prior.callerRouteArmored
		}
		cacheByCallId[resolved.callId] = resolved
		if !resolved.sessionId.isEmpty {
			cacheByCallId[resolved.sessionId] = resolved
		}
		// A busy reject that waited for this offer goes out now, during our call.
		let waitingBusy = resolved.answerable
			? busyRejects.offerResolved(callId: resolved.callId, sessionId: resolved.sessionId)
			: nil
		lock.unlock()
		if let waitingBusy {
			BeamioQALog.write("busy reject offer resolved; sending callId=\(resolved.callId.prefix(8))")
			DispatchQueue.global(qos: .userInitiated).async {
				sendDeclineUplink(offer: resolved, rejectReason: waitingBusy.reason)
			}
			return
		}
	}

	/// The v3 accept for the callee's four channels (cv, cV, ev, eV), as JSON text.
	private static func acceptText(
		offer: BeamioVoiceOfferIdentity.Resolved,
		localEoa: String,
		made: [BeamioVoiceV3.Own]
	) -> String? {
		guard made.count == 4,
		      let ch = BeamioVoiceV3.acceptChannels(cv: made[0], cV: made[1], ev: made[2], eV: made[3])
		else { return nil }
		let nowMs = Int(Date().timeIntervalSince1970 * 1000)
		let accept: [String: Any] = [
			"type": "voice_call_accept_v1",
			"proto": 3,
			"callId": offer.callId,
			"sessionId": offer.sessionId,
			"from": localEoa,
			"to": offer.callerEoa.lowercased(),
			"createdAt": nowMs,
			"timestamp": nowMs,
			"codec": "audio/pcm;rate=16000",
			"ch": ch,
		]
		return (try? JSONSerialization.data(withJSONObject: accept)).flatMap { String(data: $0, encoding: .utf8) }
	}

	/// Alias PushKit / lastReported callId → same offer so cancel + tag updates
	/// still hit when chat offer `callId` differs from the VoIP registration key.
	static func aliasOffer(_ resolved: BeamioVoiceOfferIdentity.Resolved, under key: String) {
		let alias = key.trimmingCharacters(in: .whitespacesAndNewlines)
		guard !alias.isEmpty else { return }
		lock.lock()
		cacheByCallId[alias] = resolved
		lock.unlock()
	}

	static func cachedOffer(callId: String, sessionId: String) -> BeamioVoiceOfferIdentity.Resolved? {
		lock.lock()
		defer { lock.unlock() }
		if !callId.isEmpty, let hit = cacheByCallId[callId] { return hit }
		if !sessionId.isEmpty, let hit = cacheByCallId[sessionId] { return hit }
		return nil
	}

	static func forgetOffer(callId: String, sessionId: String) {
		lock.lock()
		if !callId.isEmpty { cacheByCallId.removeValue(forKey: callId) }
		if !sessionId.isEmpty { cacheByCallId.removeValue(forKey: sessionId) }
		if activeCall?.offer.callId == callId || activeCall?.offer.sessionId == sessionId {
			wipeAndClearActiveCall()
			dialerCancel = nil
			dialerTimeout = nil
		}
		lock.unlock()
		if !callId.isEmpty { clearPendingDial(callId: callId) }
	}

	static func currentActiveCall() -> ActiveCall? {
		lock.lock()
		defer { lock.unlock() }
		return activeCall
	}

	static func updateActiveCall(_ next: ActiveCall) {
		lock.lock()
		activeCall = next
		lock.unlock()
	}

	/// Ends the active call: zeroes its channel keys (T) first, then drops the call. Keys are memory only.
	private static func wipeAndClearActiveCall() {
		if let call = activeCall, let v3 = call.v3 {
			v3.ownVoice.tk.wipe()
			v3.ownVideo.tk.wipe()
			// The SDK holds this call's channel keys (T) in its own store: drop them with the call.
			BeamioVoiceEphemeral.clearCall(sids: [v3.ownVoice.channel.sid, v3.ownVideo.channel.sid])
		}
		activeCall = nil
	}

	static func clearActiveCall() {
		lock.lock()
		wipeAndClearActiveCall()
		dialerCancel = nil
		dialerTimeout = nil
		lock.unlock()
		clearPendingDial()
		flushBusyRejectsWhenIdle()
	}

	// MARK: - Dialer cancel (built natively while the call rings)

	/// The caller-cancel Chat message for our ringing outgoing call: `voice_end_v1`,
	/// signed with the wallet key the chat SDK keeps and encrypted to the callee's
	/// user PGP key, the same envelope the page's Chat send produces. Built when the
	/// dial starts, rebuilt every couple of seconds while it rings (so its signed
	/// time stays close to the hang-up) and held in memory only; dropped when the call connects, is
	/// rejected, times out or ends. A hang-up before the callee answers posts it
	/// from the CallKit End, so the cancel never waits for the page.
	private struct DialerCancel {
		var callId: String
		var sessionId: String
		var armor: String
		/// Callee mailbox (entry A must not be mailbox B) and our own mailbox.
		var excludeIps: Set<String>
		/// `timestamp` inside the signed signal (ms): the end time the callee records.
		var signedAtMs: Int
		/// How many copies have been built for this call (1 = the dial-time copy).
		var copies: Int
	}

	/// What every copy of one call's cancel needs; looked up once at dial.
	private struct DialerCancelTarget {
		var callId: String
		var sessionId: String
		var localEoa: String
		var peerEoa: String
		var userKeyArmor: String
		var routeKeyArmor: String
		var excludeIps: Set<String>
		/// End of the ring window (offer `createdAt` + 60 s), ms.
		var timeoutAtMs: Int
	}

	private static var dialerCancel: DialerCancel?
	/// Our `voice_call_timeout_v1`, signed once at dial with the end of the ring
	/// window as its time (known in advance). Posted when the window ends unanswered.
	private static var dialerTimeout: DialerCancel?
	/// The call whose cancel was posted; a copy finishing later is not stored.
	private static var dialerCancelSpentCallId = ""

	/// Same lifetime the page puts on a voice signal (`VOICE_CALL_MAX_DURATION_MS`).
	private static let voiceSignalLifetimeMs = 15 * 60 * 1000

	/// The signed `timestamp` is the callee's record end time, and signing plus
	/// encrypting at End takes 0.1–2 s. So the held copy is rebuilt while the call
	/// rings and End posts the newest one at once: its time is at most about this
	/// interval (plus one build) before the hang-up.
	private static let dialerCancelRefreshSeconds: TimeInterval = 2

	private static func dialerCancelStillRinging(_ callId: String) -> Bool {
		lock.lock()
		defer { lock.unlock() }
		guard let cur = activeCall, dialerCancelSpentCallId != callId else { return false }
		return cur.role == .dialer && cur.offer.callId == callId && !cur.mediaEnabled
	}

	/// Callee keys and send exclusions for a dialer signal. Blocking (key lookup); off the main queue.
	private static func makeDialerCancelTarget(
		callId: String, sessionId: String, localEoa: String, peerEoa: String, timeoutAtMs: Int
	) -> DialerCancelTarget? {
		// The cancel is wrapped to the callee's mailbox route key (entry sees
		// only that mailbox's key ID), so both keys are needed.
		guard let keys = BeamioAddressPgp.searchKey(address: peerEoa),
		      keys.userPublicKeyArmored.contains("BEGIN PGP PUBLIC KEY"),
		      keys.routePublicKeyArmored.contains("BEGIN PGP PUBLIC KEY")
		else {
			BeamioQALog.write("dialer cancel not prepared: callee key")
			return nil
		}
		guard let mailbox = BeamioAddressPgp.mailboxIp(
			forRoutePgpKeyID: keys.routePgpKeyID,
			nodes: BeamioChatPgpKeychain.loadSiNodes()
		), let mailboxIp = BeamioSiCipherPost.normalizeIp(mailbox) else {
			// Without the callee mailbox an entry could be mailbox B: the page sends instead.
			BeamioQALog.write("dialer cancel not prepared: callee mailbox")
			return nil
		}
		// Same exclusions as the page send: callee mailbox and our own mailbox.
		var exclude: Set<String> = [mailboxIp]
		if let own = BeamioSiCipherPost.normalizeIp(BeamioChatPgpKeychain.loadMailboxIp()) {
			exclude.insert(own)
		}
		return DialerCancelTarget(
			callId: callId,
			sessionId: sessionId,
			localEoa: localEoa,
			peerEoa: peerEoa,
			userKeyArmor: keys.userPublicKeyArmored,
			routeKeyArmor: keys.routePublicKeyArmored,
			excludeIps: exclude,
			timeoutAtMs: timeoutAtMs
		)
	}

	/// One Chat message to the callee: the signal signed with the SDK wallet key,
	/// encrypted to the callee's user key and wrapped to its mailbox. `nil` on any
	/// failure or once the call stopped ringing.
	private static func sealDialerSignal(
		_ target: DialerCancelTarget,
		type: String,
		stampMs: Int,
		/// False only for the cancel after a relaunch (no live call in memory).
		requireRinging: Bool = true,
		completion: @escaping (String?) -> Void
	) {
		let signal: [String: Any] = [
			"type": type,
			"callId": target.callId,
			"sessionId": target.sessionId,
			"from": target.localEoa,
			"to": target.peerEoa,
			"createdAt": stampMs,
			"expiresAt": stampMs + voiceSignalLifetimeMs,
			"timestamp": stampMs,
		]
		guard let signalData = try? JSONSerialization.data(withJSONObject: signal),
		      let text = String(data: signalData, encoding: .utf8)
		else { return completion(nil) }
		BeamioConetChatSignBroker.requestEip191(message: text, timeout: 10) { signed in
			guard !requireRinging || dialerCancelStillRinging(target.callId), case .success(let signature) = signed else {
				return completion(nil)
			}
			let envelope: [String: Any] = [
				"timestamp": stampMs,
				"text": text,
				"from": target.localEoa,
				"signMessage": signature,
			]
			guard let envData = try? JSONSerialization.data(withJSONObject: envelope) else { return completion(nil) }
			BeamioOpenPgpHost.shared.encrypt(
				plaintext: envData.base64EncodedString(),
				publicKeyArmor: target.userKeyArmor
			) { encrypted in
				guard case .success(let userArmor) = encrypted, userArmor.contains("BEGIN PGP MESSAGE") else {
					return completion(nil)
				}
				BeamioOpenPgpHost.shared.wrapArmorToMailboxWork(
					innerArmor: userArmor,
					mailboxRoutePublicArmor: target.routeKeyArmor,
					noPush: false
				) { wrapped in
					guard case .success(let armor) = wrapped, armor.contains("BEGIN PGP MESSAGE") else {
						return completion(nil)
					}
					completion(armor)
				}
			}
		}
	}

	/// The ring window of our outgoing call ended unanswered: close the call as timed out locally. No uplink is sent
	/// (v67 §74: no voice_call_timeout_v1; the callee expires the ring by expiresAt), then `dialerDidReceiveReject` tells
	/// the page `callTimedOut`, which records `timed_out` without sending its own. Answer, reject or hang-up already
	/// changed the call, so a late timer does nothing.
	private static func dialerRingWindowEnded(callId: String) {
		guard dialerCancelStillRinging(callId) else { return }
		lock.lock()
		let timeout = dialerTimeout?.callId == callId ? dialerTimeout : nil
		dialerTimeout = nil
		dialerCancel = nil
		dialerCancelSpentCallId = callId
		lock.unlock()
		clearPendingDial(callId: callId)
		BeamioQALog.write("dialer ring window ended callId=\(callId.prefix(8)) prepared=\(timeout != nil ? "yes" : "no")")
		if let timeout {
			var bgTask = UIBackgroundTaskIdentifier.invalid
			bgTask = UIApplication.shared.beginBackgroundTask(withName: "beamio.voice.dialer-timeout") {
				if bgTask != .invalid {
					UIApplication.shared.endBackgroundTask(bgTask)
					bgTask = .invalid
				}
			}
			DispatchQueue.global(qos: .userInitiated).async {
				let started = Date()
				var result = BeamioSiCipherPost.post(
					armor: timeout.armor,
					nodes: BeamioChatPgpKeychain.loadSiNodes(),
					excludeIps: timeout.excludeIps,
					maxAttempts: 4,
					timeout: 6,
					hedgeAfter: 0.6
				)
				if !result.ok {
					result = BeamioSiCipherPost.post(
						armor: timeout.armor,
						nodes: BeamioChatPgpKeychain.loadSiNodes(),
						excludeIps: timeout.excludeIps
					)
				}
				BeamioQALog.write(
					"dialer timeout posted callId=\(callId.prefix(8)) ok=\(result.ok ? "yes" : "no") ms=\(Int(Date().timeIntervalSince(started) * 1000))"
				)
				DispatchQueue.main.async {
					if bgTask != .invalid {
						UIApplication.shared.endBackgroundTask(bgTask)
						bgTask = .invalid
					}
				}
			}
		}
		dialerDidReceiveReject(action: "callTimedOut")
	}


	/// Mailbox `voice_listen` accepts `[0-9a-fA-F-]{16,64}` — 32 hex chars.
	static func randomMailboxVoiceSessionId() -> String {
		var bytes = [UInt8](repeating: 0, count: 16)
		_ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
		return bytes.map { String(format: "%02x", $0) }.joined()
	}

	// MARK: - Dialer (outgoing)

	/// Our outgoing call (voice v3): the page already sent the offer to the
	/// callee's mailbox. Nothing opens while ringing; the callee's accept (a
	/// chat message to our mailbox) brings our channels (`dialerDidReceiveAcceptV3`).
	/// Returns false when the dialer could not attach (the page must cancel the offer).
	@discardableResult
	static func attachOutgoingDialer(
		callId: String,
		sessionId: String,
		peerEoa: String,
		/// The offer's `createdAt` (ms) from the page; 0 = now. The ring window starts there.
		offerCreatedAtMs: Int = 0
	) -> Bool {
		let trimmedCall = callId.trimmingCharacters(in: .whitespacesAndNewlines)
		let trimmedSession = sessionId.trimmingCharacters(in: .whitespacesAndNewlines)
		let peer = peerEoa.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		// While it rings: keep the SDK's warm entries fresh for the listens after the accept,
		// and make sure the frame-encryption host is alive.
		BeamioEntryPool.shared.warmNow()
		BeamioVoiceRoutePgp.shared.ensureAlive(reason: "dial start")
		func failed(_ reason: String) -> Bool {
			BeamioQALog.write("dialer attach failed callId=\(trimmedCall.prefix(8)) reason=\(reason) appState=\(appStateLabel())")
			return false
		}
		guard !trimmedSession.isEmpty else { return failed("no-session") }
		guard peer.hasPrefix("0x"), peer.count == 42 else { return failed("bad-peer") }
		guard let secrets = BeamioChatPgpKeychain.load(eoa: BeamioNativeAccountPointer.get()) else { return failed("no-chat-keys") }
		let localEoa = secrets.eoa.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		guard localEoa.hasPrefix("0x"), localEoa.count == 42 else { return failed("no-local-eoa") }
		let offer = BeamioVoiceOfferIdentity.Resolved(
			callerEoa: localEoa,
			beamioTag: "",
			shortAddress: "",
			callId: trimmedCall.isEmpty ? trimmedSession : trimmedCall,
			sessionId: trimmedSession,
			to: peer,
			proto: 3
		)
		rememberOffer(offer)
		let active = ActiveCall(
			role: .dialer,
			offer: offer,
			listenSessionId: trimmedSession,
			peerMediaSessionId: "",
			peerEoa: peer,
			localEoa: localEoa,
			mediaEnabled: false
		)
		lock.lock()
		activeCall = active
		lock.unlock()
		NSLog(
			"[BeamioNativeVoice] dialer attach callId=%@ session=%@ peer=%@",
			offer.callId,
			trimmedSession,
			String(peer.suffix(8))
		)
		// A receipt can beat this attach (the page posts the offer first): keep it.
		lock.lock()
		peerRinging.remove(offer.callId)
		let early = earlyRinging.removeValue(forKey: offer.callId)
		earlyRinging = earlyRinging.filter { Date().timeIntervalSince1970 - $0.value.at < 600 }
		let rangEarly = early.map { $0.from == peer } ?? false
		if rangEarly { peerRinging.insert(offer.callId) }
		lock.unlock()
		if rangEarly {
			qaTrail("ringing receipt received (before attach) callId=\(offer.callId.prefix(8))")
			// After this main-queue block, which also runs beginOutgoing (it resets the screen).
			DispatchQueue.main.async {
				BeamioInCallScreenModel.shared.notePeerWake(callId: offer.callId, .ringing)
			}
		}
		schedulePeerWakeCheck(callId: offer.callId)
		let attachedAt = Int(Date().timeIntervalSince1970 * 1000)
		let createdAt = (1 ... attachedAt).contains(offerCreatedAtMs) ? offerCreatedAtMs : attachedAt
		let timeoutAtMs = createdAt + Int(ringWindowMs)
		// v64 §71: no shell cancel uplink (voice_end_v1 for a ringing dial is the page's only). The callee expires by expiresAt.
		let dialCallId = offer.callId
		// Off the main queue: a busy main thread (UI work) must not push the
		// timeout past the callee's own 60 s backup. The UI part hops to main itself.
		// A strict timer: `asyncAfter` let GCD coalesce this ~60 s wait by about 1 s
		// (RC3: +0.94 / +1.1 s), which ate the margin before the callee's backup.
		let ringTimer = DispatchSource.makeTimerSource(flags: .strict, queue: .global(qos: .userInitiated))
		ringTimer.schedule(deadline: .now() + Double(max(0, timeoutAtMs - attachedAt)) / 1000, leeway: .milliseconds(20))
		ringTimer.setEventHandler {
			ringTimer.cancel()  // One shot; cancelling also releases this handler and the timer.
			dialerRingWindowEnded(callId: dialCallId)
		}
		ringTimer.resume()
		// Five rings without a receipt: Unreachable (main queue: it talks to the page and the screen).
		let unreachableDelay = BeamioDialerReceiptRule.delay(createdAtMs: createdAt, nowMs: attachedAt, afterMs: peerUnreachableMs)
		DispatchQueue.main.asyncAfter(deadline: .now() + unreachableDelay) {
			dialerPeerUnreachable(callId: dialCallId)
		}
		savePendingDial(callId: dialCallId, sessionId: trimmedSession, peerEoa: peer, timeoutAtMs: timeoutAtMs)
		observeAppStateForDialsOnce()
		BeamioQALog.write(
			"dialer attach ok callId=\(dialCallId.prefix(8)) ringLeftMs=\(max(0, timeoutAtMs - attachedAt)) appState=\(appStateLabel())"
		)
		return true
	}

	// MARK: - Dial start failure, lifecycle trail, recovery after a kill

	/// Last app state seen on the main thread (read off-main without blocking).
	private static var cachedAppState = "unknown"

	/// active / inactive / background, for QA lines. Off the main thread it
	/// returns the last state seen there (never waits on a busy main thread).
	static func appStateLabel() -> String {
		guard Thread.isMainThread else {
			lock.lock(); defer { lock.unlock() }
			return cachedAppState
		}
		let label: String
		switch UIApplication.shared.applicationState {
		case .active: label = "active"
		case .inactive: label = "inactive"
		case .background: label = "background"
		@unknown default: label = "unknown"
		}
		lock.lock()
		cachedAppState = label
		lock.unlock()
		return label
	}

	/// CallKit refused our outgoing call (`CXStartCallAction` failed). The offer is
	/// already out, so the callee must hear the cancel now: post the ready native
	/// cancel when there is one, then tell the page (`callDialerFailed`), which
	/// sends its own cancel unless the shell took it, records the call and closes
	/// the screen. Main queue.
	static func dialerStartFailed(callId: String, reason: String) {
		lock.lock()
		let ringing = activeCall.map { $0.role == .dialer && $0.offer.callId == callId && !$0.mediaEnabled } ?? false
		let sessionId = activeCall?.listenSessionId ?? ""
		lock.unlock()
		guard ringing else {
			BeamioQALog.write("dialer start failed callId=\(callId.prefix(8)) reason=\(reason) (no ringing dial)")
			return
		}
		lock.lock()
		if activeCall?.offer.callId == callId {
			wipeAndClearActiveCall()
			dialerCancel = nil
			dialerTimeout = nil
		}
		dialerCancelSpentCallId = callId
		lock.unlock()
		clearPendingDial(callId: callId)
		BeamioQALog.write(
			"dialer start failed callId=\(callId.prefix(8)) reason=\(reason) cancel=none appState=\(appStateLabel())"
		)
		BeamioNativeVoiceChannel.shared.stop()
		BeamioCallTonePlayer.shared.stopRingback(reason: "dial-failed")
		BeamioVoipIncomingBootstrap.shared.emitToWeb("callDialerFailed", callId: callId, sessionId: sessionId)
		BeamioInCallScreenModel.shared.end(callId: callId)
	}

	private static var appStateObserversInstalled = false

	/// QA trail: app state changes while our dial rings (a lock or a kill in the
	/// middle of a dial shows up as the last line before silence).
	private static func observeAppStateForDialsOnce() {
		DispatchQueue.main.async {
			guard !appStateObserversInstalled else { return }
			appStateObserversInstalled = true
			let events: [(Notification.Name, String)] = [
				(UIApplication.willResignActiveNotification, "will-resign-active"),
				(UIApplication.didEnterBackgroundNotification, "did-enter-background"),
				(UIApplication.willEnterForegroundNotification, "will-enter-foreground"),
				(UIApplication.didBecomeActiveNotification, "did-become-active"),
				(UIApplication.protectedDataWillBecomeUnavailableNotification, "device-locking"),
				(UIApplication.protectedDataDidBecomeAvailableNotification, "device-unlocked"),
			]
			for (name, label) in events {
				NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { _ in
					_ = appStateLabel()
					lock.lock()
					let ringing = activeCall.flatMap { $0.role == .dialer && !$0.mediaEnabled ? $0.offer.callId : nil }
					let cancelReady = dialerCancel != nil
					let timeoutReady = dialerTimeout != nil
					lock.unlock()
					guard let ringing else { return }
					BeamioQALog.write(
						"dialer app \(label) callId=\(ringing.prefix(8)) cancelReady=\(cancelReady ? "yes" : "no") timeoutReady=\(timeoutReady ? "yes" : "no")"
					)
				}
			}
		}
	}

	/// Our dial while it rings, kept on disk: if the app is killed mid-ring
	/// (watchdog, memory), the next launch still tells the callee. Ids and the
	/// ring-window end only (no keys).
	private static let pendingDialKey = "beamio.voice.pendingDial"

	private static func savePendingDial(callId: String, sessionId: String, peerEoa: String, timeoutAtMs: Int) {
		UserDefaults.standard.set([
			"callId": callId,
			"sessionId": sessionId,
			"peer": peerEoa,
			"timeoutAtMs": timeoutAtMs,
		], forKey: pendingDialKey)
	}

	/// The dial stopped ringing (answered, cancelled, rejected, timed out).
	static func clearPendingDial(callId: String = "") {
		let defaults = UserDefaults.standard
		guard let saved = defaults.dictionary(forKey: pendingDialKey) else { return }
		if !callId.isEmpty, let savedId = saved["callId"] as? String, savedId != callId { return }
		defaults.removeObject(forKey: pendingDialKey)
	}

	/// At launch: a dial was still ringing when the app last died. Inside its
	/// ring window, send the callee our cancel (`voice_end_v1`); after it, the
	/// callee's own 60 s backup already ended the call. Waits for the chat
	/// module's local signer (set once it starts) until the window ends.
	static func recoverDialAfterRelaunch() {
		let defaults = UserDefaults.standard
		guard let saved = defaults.dictionary(forKey: pendingDialKey) else { return }
		defaults.removeObject(forKey: pendingDialKey)
		let callId = saved["callId"] as? String ?? ""
		let sessionId = saved["sessionId"] as? String ?? ""
		let peer = saved["peer"] as? String ?? ""
		let timeoutAtMs = (saved["timeoutAtMs"] as? Int) ?? Int((saved["timeoutAtMs"] as? Double) ?? 0)
		let nowMs = Int(Date().timeIntervalSince1970 * 1000)
		guard !callId.isEmpty, !sessionId.isEmpty, peer.hasPrefix("0x"), peer.count == 42 else { return }
		guard nowMs < timeoutAtMs - 1_000 else {
			BeamioQALog.write("dialer relaunch: dial callId=\(callId.prefix(8)) died while ringing; window over, callee ends it")
			return
		}
		BeamioQALog.write("dialer relaunch: dial callId=\(callId.prefix(8)) died while ringing; cancel (windowLeftMs=\(timeoutAtMs - nowMs))")
		// v64 §71: no relaunch cancel uplink. The callee expires the ring by expiresAt.
		BeamioQALog.write("dialer relaunch: no cancel uplink callId=\(callId.prefix(8))")
	}

	// MARK: - Wake receipt (`voice_call_ringing_v1`)

	/// Calls this device already told the caller about (callId → time sent).
	private static var ringingSent: [String: TimeInterval] = [:]
	/// Dials whose callee sent the receipt.
	private static var peerRinging: Set<String> = []
	/// Receipts that arrived before `attachOutgoingDialer` (callId → sender, time).
	private static var earlyRinging: [String: (from: String, at: TimeInterval)] = [:]

	/// Callee: tell the caller this device is ringing, once per call. Same path
	/// as Decline / Accept: caller user-PGP, caller mailbox route layer, random
	/// entry; NoPush (the caller is dialing in the foreground). Never for our own
	/// dial or a call that already ended.
	static func sendRingingIfNeeded(_ offer: BeamioVoiceOfferIdentity.Resolved) {
		guard offer.answerable, !offer.callId.isEmpty else { return }
		if wasRemoteEnded(callId: offer.callId, sessionId: offer.sessionId)
			|| wasLocallyEnded(callId: offer.callId, sessionId: offer.sessionId)
		{
			return
		}
		guard let secrets = BeamioChatPgpKeychain.load(eoa: BeamioNativeAccountPointer.get()) else { return }
		let localEoa = secrets.eoa.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		let caller = offer.callerEoa.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		guard localEoa.hasPrefix("0x"), localEoa.count == 42, caller.hasPrefix("0x"), caller != localEoa else { return }
		let now = Date().timeIntervalSince1970
		lock.lock()
		ringingSent = ringingSent.filter { now - $0.value < 600 }
		if ringingSent[offer.callId] != nil {
			lock.unlock()
			return
		}
		ringingSent[offer.callId] = now
		lock.unlock()
		DispatchQueue.global(qos: .userInitiated).async {
			let nowMs = Int(now * 1000)
			let body: [String: Any] = [
				"type": "voice_call_ringing_v1",
				"callId": offer.callId,
				"sessionId": offer.sessionId,
				"from": localEoa,
				"to": caller,
				"createdAt": nowMs,
				"timestamp": nowMs,
			]
			let text = (try? JSONSerialization.data(withJSONObject: body)).flatMap { String(data: $0, encoding: .utf8) } ?? ""
			var ok = false
			var attempt = 0
			while !text.isEmpty, !ok, attempt < 2 {
				if attempt > 0 { Thread.sleep(forTimeInterval: 0.7) }
				ok = BeamioVoiceV3.postChatMessage(
					text: text, localEoa: localEoa,
					peerUserPgp: offer.callerPgpArmored, peerRoute: offer.callerRouteArmored, noPush: true
				)
				attempt += 1
			}
			qaTrail("ringing receipt callId=\(offer.callId.prefix(8)) ok=\(ok ? "yes" : "no")")
			if !ok {
				lock.lock()
				ringingSent.removeValue(forKey: offer.callId)
				lock.unlock()
			}
		}
	}

	/// Caller: no receipt within this time → "Their phone may be restricting Beamio".
	static let peerWakeTimeout: TimeInterval = 8

	private static func schedulePeerWakeCheck(callId: String) {
		DispatchQueue.main.asyncAfter(deadline: .now() + peerWakeTimeout) {
			lock.lock()
			let stillRinging = activeCall.map { $0.role == .dialer && $0.offer.callId == callId && !$0.mediaEnabled } ?? false
			let rang = peerRinging.contains(callId)
			lock.unlock()
			guard stillRinging, !rang else { return }
			qaTrail("no ringing receipt in 8 s callId=\(callId.prefix(8))")
			BeamioInCallScreenModel.shared.notePeerWake(callId: callId, .restricted)
		}
	}

	/// Caller: no receipt after five ringback rings = 25 s from the offer's
	/// `createdAt` (`BeamioDialerReceiptRule`).
	static let peerUnreachableMs: Double = BeamioDialerReceiptRule.unreachableAfterMs

	/// No ringing receipt after five rings: the callee's phone never got the call
	/// (force stopped, switched off, push blocked). Main thread.
	/// - posts the cancel signed at dial, so a late push cannot ring the callee
	///   for a call that is over (the page gets `dialerCancelPosting` first and
	///   sends no cancel of its own; with no cancel ready the page sends one);
	/// - tells the page `callUnreachable` (it records `unreachable`);
	/// - stops the ringback, shows "Unreachable", ends the CallKit call 2 s later.
	/// The 60 s ring-window timer then finds no call and does nothing, and a
	/// receipt that comes later matches no call.
	static func dialerPeerUnreachable(callId: String) {
		lock.lock()
		let still = activeCall.map { $0.role == .dialer && $0.offer.callId == callId && !$0.mediaEnabled } ?? false
		let rang = peerRinging.contains(callId)
		lock.unlock()
		guard BeamioDialerReceiptRule.endsUnreachable(stillRinging: still, rang: rang) else { return }
		lock.lock()
		guard let cur = activeCall, cur.role == .dialer, cur.offer.callId == callId, !cur.mediaEnabled else {
			lock.unlock()
			return
		}
		let sessionId = cur.listenSessionId
		wipeAndClearActiveCall()
		dialerCancel = nil
		dialerTimeout = nil
		dialerCancelSpentCallId = callId
		lock.unlock()
		clearPendingDial(callId: callId)
		qaTrail("dialer unreachable (no ringing receipt in \(Int(peerUnreachableMs / 1000)) s) callId=\(callId.prefix(8)) cancel=none")
		NSLog("[BeamioNativeVoice] dialer callUnreachable callId=%@", callId)
		BeamioNativeVoiceChannel.shared.stop()
		BeamioVoipIncomingBootstrap.shared.emitToWeb("callUnreachable", callId: callId, sessionId: sessionId)
		BeamioCallTonePlayer.shared.stopRingback(reason: "unreachable")
		BeamioInCallScreenModel.shared.showUnreachable(callId: callId)
		DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
			BeamioVoipIncomingBootstrap.shared.callKit.end(callId: callId, sessionId: sessionId)
		}
	}

	/// Caller: the callee's device sent `voice_call_ringing_v1` for our dial.
	static func dialerDidReceiveRinging(callId: String, from: String) {
		lock.lock()
		let match = activeCall.map {
			$0.role == .dialer && $0.offer.callId == callId && $0.peerEoa == from.lowercased()
		} ?? false
		if match {
			peerRinging.insert(callId)
		} else if !callId.isEmpty {
			// Not attached yet (or an older call is still active): attachOutgoingDialer checks this.
			earlyRinging[callId] = (from: from.lowercased(), at: Date().timeIntervalSince1970)
		}
		lock.unlock()
		guard match else { return }
		qaTrail("ringing receipt received callId=\(callId.prefix(8))")
		DispatchQueue.main.async {
			BeamioInCallScreenModel.shared.notePeerWake(callId: callId, .ringing)
		}
	}

	/// The channel learned the peer's relays (or moved ours): keep the call copy in step.
	static func updateV3Call(callId: String, v3: BeamioVoiceV3.Call) {
		lock.lock()
		if var cur = activeCall, cur.offer.callId == callId {
			cur.v3 = v3
			activeCall = cur
		}
		lock.unlock()
	}


	/// v3 dialer: the callee's accept arrived on our mailbox (chat message, signer
	/// recovered as `from`). Pick our relays, open our two channels, start media.
	static func dialerDidReceiveAcceptV3(accept: [String: Any], from: String) {
		let callId = (accept["callId"] as? String) ?? ""
		let ringId = (accept["sessionId"] as? String) ?? ""
		lock.lock()
		guard let cur = activeCall, cur.role == .dialer, cur.offer.proto == 3,
		      cur.offer.callId == callId, cur.offer.sessionId == ringId,
		      cur.peerEoa == from.lowercased(), !cur.mediaEnabled, cur.v3 == nil,
		      !inFlightAccept.contains("v3:\(callId)")
		else {
			lock.unlock()
			return
		}
		inFlightAccept.insert("v3:\(callId)")
		lock.unlock()
		clearPendingDial(callId: callId)
		BeamioCallTiming.mark("accept-rx")
		qaTrail("v3 accept rx callId=\(callId.prefix(8))")
		DispatchQueue.global(qos: .userInitiated).async {
			defer {
				lock.lock()
				inFlightAccept.remove("v3:\(callId)")
				lock.unlock()
			}
			guard let ch = accept["ch"] as? [String: Any],
			      var call = BeamioVoiceV3.callFromAccept(callId: callId, ch: ch)
			else {
				qaTrail("v3 accept unusable callId=\(callId.prefix(8))")
				return
			}
			var exclude: Set<String> = []
			if let mailbox = BeamioSiCipherPost.normalizeIp(BeamioChatPgpKeychain.loadMailboxIp()) { exclude.insert(mailbox) }
			let calleeRoute = BeamioAddressPgp.searchKey(address: cur.peerEoa)?.routePublicKeyArmored ?? ""
			let avoid = [BeamioChatPgpKeychain.loadRoutePublicArmor(eoa: BeamioNativeAccountPointer.get()), calleeRoute]
			guard let voiceRelay = BeamioVoiceV3.RelayNodes.pick(excludeIps: exclude, excludeArmors: avoid),
			      let videoRelay = BeamioVoiceV3.RelayNodes.pick(excludeIps: exclude, excludeArmors: avoid)
			else {
				qaTrail("v3 accept: no relay nodes cached")
				return
			}
			call.ownVoice.relay = voiceRelay
			call.ownVideo.relay = videoRelay
			lock.lock()
			guard var live = activeCall, live.role == .dialer, live.offer.callId == callId, !live.mediaEnabled else {
				lock.unlock()
				return
			}
			live.v3 = call
			live.peerMediaSessionId = call.peerVoice.channel.sid
			live.mediaEnabled = true
			activeCall = live
			dialerCancel = nil
			dialerTimeout = nil
			let snapshot = live
			lock.unlock()
			// The callee's relays came with its accept: build our Hang Up now.
				NSLog("[BeamioNativeVoice] v3 dialer accept callId=%@", callId)
			BeamioNativeVoiceChannel.shared.start(active: snapshot)
			DispatchQueue.main.async {
				BeamioVoipIncomingBootstrap.shared.callKit.markOutgoingConnected(
					callId: snapshot.offer.callId,
					sessionId: snapshot.listenSessionId
				)
				BeamioInCallScreenModel.shared.markConnected(callId: snapshot.offer.callId)
				BeamioVoipIncomingBootstrap.shared.emitToWeb(
					"callAnswered",
					callId: snapshot.offer.callId,
					sessionId: snapshot.listenSessionId
				)
			}
		}
	}

	/// v3 dialer: the callee declined or timed out (chat message to our mailbox).
	static func dialerDidReceiveRejectV3(type: String, callId: String, from: String, reason: String = "") {
		lock.lock()
		let match = activeCall.map {
			$0.role == .dialer && $0.offer.proto == 3 && $0.offer.callId == callId && $0.peerEoa == from.lowercased() && !$0.mediaEnabled
		} ?? false
		lock.unlock()
		guard match else { return }
		// Only the verified callee (signer == the peer we dialed) can say "busy".
		if type == "voice_call_reject_v1" && reason == "busy" {
			dialerDidReceiveBusy()
			return
		}
		dialerDidReceiveReject(action: type == "voice_call_timeout_v1" ? "callTimedOut" : "callRejected")
	}

	/// The callee is in another call: the page records "busy", the screen says
	/// so, the busy tone plays on the call's audio session (about 3 s), then
	/// CallKit ends the call.
	static func dialerDidReceiveBusy() {
		lock.lock()
		guard let cur = activeCall, cur.role == .dialer else {
			lock.unlock()
			return
		}
		let callId = cur.offer.callId
		let sessionId = cur.listenSessionId
		wipeAndClearActiveCall()
		dialerCancel = nil
		dialerTimeout = nil
		lock.unlock()
		clearPendingDial(callId: callId)
		qaTrail("dialer busy callId=\(callId.prefix(8))")
		NSLog("[BeamioNativeVoice] dialer callBusy callId=%@", callId)
		BeamioNativeVoiceChannel.shared.stop()
		DispatchQueue.main.async {
			BeamioVoipIncomingBootstrap.shared.emitToWeb("callBusy", callId: callId, sessionId: sessionId)
			BeamioInCallScreenModel.shared.showBusy(callId: callId)
			BeamioCallTonePlayer.shared.playBusy {
				BeamioVoipIncomingBootstrap.shared.callKit.end(callId: callId, sessionId: sessionId)
			}
		}
	}

	/// Ring window for every call (PWA `INCOMING_CALL_RING_TIMEOUT_MS`, Android
	/// `INCOMING_RING_TIMEOUT_MS`): 60 s from the offer's `createdAt`.
	static let ringWindowMs: Double = 60_000

	/// The offer can no longer be ringing — the page's `isVoiceCallOfferRinging`
	/// rule: its `expiresAt` has passed, or it was created (`createdAt`, else
	/// `timestamp`) more than the ring window plus 15 s ago. Seconds or ms.
	/// Missing fields → false.
	/// Whether an inbound offer line is past its ring window (signed expiry or the window since createdAt). Uses the offer clock.
	static func offerRingWindowOver(line: String) -> Bool {
		guard let offer = BeamioVoiceOfferIdentity.extractVoiceOffer(from: line) else { return false }
		func ms(_ raw: Any?) -> Double {
			let v: Double = (raw as? Double) ?? (raw as? NSNumber)?.doubleValue
				?? Double((raw as? String) ?? "") ?? 0
			guard v > 0, v.isFinite else { return 0 }
			return v < 100_000_000_000 ? v * 1000 : v
		}
		let now = BeamioVoiceOfferIdentity.nowMs()
		let expires = ms(offer["expiresAt"])
		if expires > 0, expires <= now { return true }
		let created = ms(offer["createdAt"]) > 0 ? ms(offer["createdAt"]) : ms(offer["timestamp"])
		guard created > 0 else { return false }
		return now - created > ringWindowMs + 15_000
	}

	/// A voice signal object inside a chat line (nested `text`, base64 envelopes).
	private static func voiceSignal(in line: String, types: Set<String>) -> [String: Any]? {
		func walk(_ value: Any, depth: Int) -> [String: Any]? {
			guard depth < 8 else { return nil }
			if let text = value as? String {
				let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
				if let data = trimmed.data(using: .utf8), let parsed = try? JSONSerialization.jsonObject(with: data) {
					return walk(parsed, depth: depth + 1)
				}
				if let data = Data(base64Encoded: trimmed, options: [.ignoreUnknownCharacters]) ?? BeamioLenientBase64.decode(trimmed),
				   let decoded = String(data: data, encoding: .utf8),
				   let parsed = try? JSONSerialization.jsonObject(with: Data(decoded.utf8))
				{
					return walk(parsed, depth: depth + 1)
				}
				return nil
			}
			guard let obj = value as? [String: Any] else { return nil }
			if let type = obj["type"] as? String, types.contains(type) { return obj }
			if let inner = obj["text"] { return walk(inner, depth: depth + 1) }
			return nil
		}
		return walk(line, depth: 0)
	}

	/// The callee declined or timed out (chat message to our mailbox).
	static func dialerDidReceiveReject(action: String) {
		lock.lock()
		guard let cur = activeCall, cur.role == .dialer else {
			lock.unlock()
			return
		}
		let callId = cur.offer.callId
		let sessionId = cur.listenSessionId
		wipeAndClearActiveCall()
		dialerCancel = nil
		dialerTimeout = nil
		lock.unlock()
		clearPendingDial(callId: callId)
		let webAction = action == "callTimedOut" ? "callTimedOut" : "callRejected"
		NSLog("[BeamioNativeVoice] dialer %@ callId=%@", webAction, callId)
		BeamioNativeVoiceChannel.shared.stop()
		DispatchQueue.main.async {
			BeamioVoipIncomingBootstrap.shared.emitToWeb(webAction, callId: callId, sessionId: sessionId)
			BeamioVoipIncomingBootstrap.shared.callKit.end(callId: callId, sessionId: sessionId)
		}
	}

	// MARK: - Callee Decline / Accept

	/// CallKit Decline / Telecom reject — fire-and-forget on a background queue.
	/// Uses a UIBackgroundTask so VoIP process suspension cannot cancel the
	/// resolve+AES+voice_uplink before the dialer receives `voice_call_reject_v1`.
	/// - Parameter reason: `"declined"` (user Decline) or `"busy"` (single-call
	///   gate while another call is ringing / connected). Dialer ends on either.
	static func sendDecline(
		callId: String,
		sessionId: String,
		reason: String = "declined",
		protectStickyChrome: Bool = false
	) {
		let rejectReason: String = {
			let t = reason.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
			if t == "busy" { return "busy" }
			if t == "timeout" { return "timeout" }
			return "declined"
		}()
		let key = "\(callId)|\(sessionId)|\(rejectReason)"
		lock.lock()
		if inFlightDecline.contains(key) {
			lock.unlock()
			return
		}
		inFlightDecline.insert(key)
		lock.unlock()

		// Busy (we are in a call, or another call rings here): tell the new
		// caller now, so it hears the busy tone while it dials. A resolved offer
		// is sealed with the OpenPGP host its decrypt already loaded. v69: never
		// resolveOfferSync here — booting the hidden WKWebView during a live
		// call dropped the Incoming banner (v68) — so an unresolved offer waits
		// for its resolve (`rememberOffer`) or for our call to end.
		if protectStickyChrome {
			let resolved = cachedOffer(callId: callId, sessionId: sessionId).flatMap { $0.answerable ? $0 : nil }
			lock.lock()
			let decision = busyRejects.busyCallArrived(
				callId: callId, sessionId: sessionId, reason: rejectReason, resolved: resolved
			)
			inFlightDecline.remove(key)
			lock.unlock()
			switch decision {
			case .sendNow(let now):
				BeamioQALog.write("busy reject now callId=\(now.callId.prefix(8))")
				DispatchQueue.global(qos: .userInitiated).async {
					sendDeclineUplink(offer: now, rejectReason: rejectReason)
				}
				return
			case .alreadySent:
				// Same call seen again (chat offer, then its VoIP push): one reject is enough.
				BeamioQALog.write("busy reject already sent callId=\(callId.prefix(8))")
				return
			case .wait:
				break
			}
			BeamioQALog.write("busy reject waits for the offer callId=\(callId.prefix(8))")
			DispatchQueue.main.async {
				BeamioVoipIncomingBootstrap.shared.callKit.noteBusyDeclineDeferredNoWebView(callId: callId)
			}
			return
		}

		// v66: a missing offer used to begin+end `beamio.voice.decline` while
		// CallKit Incoming was up in Background (v65 self-probe). That end
		// drops the banner. Skip the task unless the app is active and the
		// caller did not ask to protect sticky chrome.
		let useBackgroundTask = !protectStickyChrome
			&& UIApplication.shared.applicationState == .active

		DispatchQueue.global(qos: .userInitiated).async {
			defer {
				lock.lock()
				inFlightDecline.remove(key)
				lock.unlock()
			}
			guard let offer = resolveOfferSync(callId: callId, sessionId: sessionId) else {
				NSLog(
					"[BeamioNativeVoice] decline skip — no v3 offer callId=%@ sessionId=%@ reason=%@ (no bg task)",
					callId,
					sessionId,
					rejectReason
				)
				return
			}
			if useBackgroundTask {
				var bgTask = UIBackgroundTaskIdentifier.invalid
				bgTask = UIApplication.shared.beginBackgroundTask(withName: "beamio.voice.decline") {
					if bgTask != .invalid {
						UIApplication.shared.endBackgroundTask(bgTask)
						bgTask = .invalid
					}
				}
				defer {
					DispatchQueue.main.async {
						if bgTask != .invalid {
							UIApplication.shared.endBackgroundTask(bgTask)
							bgTask = .invalid
						}
					}
				}
				sendDeclineUplink(offer: offer, rejectReason: rejectReason)
				return
			}
			sendDeclineUplink(offer: offer, rejectReason: rejectReason)
		}
	}

	/// Busy rejects whose offer never resolved during our call. Call only after
	/// the sticky Incoming call is gone: resolving may boot the OpenPGP WebView.
	static func flushDeferredStickyDeclines() {
		lock.lock()
		let pending = busyRejects.ownCallEnded()
		lock.unlock()
		guard !pending.isEmpty else { return }
		BeamioQALog.write("busy reject after our call ended count=\(pending.count)")
		DispatchQueue.global(qos: .userInitiated).async {
			for item in pending {
				guard let offer = resolveOfferSync(callId: item.callId, sessionId: item.sessionId) else {
					BeamioQALog.write("busy reject skipped: no offer callId=\(item.callId.prefix(8))")
					continue
				}
				sendDeclineUplink(offer: offer, rejectReason: item.reason)
			}
		}
	}

	/// Our call ended by either side (a remote end runs no CXEndCallAction):
	/// send busy rejects still waiting for their offer once no CallKit call is live.
	private static func flushBusyRejectsWhenIdle() {
		lock.lock()
		let any = !busyRejects.waiting.isEmpty
		lock.unlock()
		guard any else { return }
		for delay in [0.0, 1.5] {
			DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
				guard !BeamioVoipIncomingBootstrap.shared.callKit.hasLiveCallKitCall() else { return }
				flushDeferredStickyDeclines()
			}
		}
	}

	private static func sendDeclineUplink(
		offer: BeamioVoiceOfferIdentity.Resolved,
		rejectReason: String
	) {
		// v67 §74: a timeout is never uplinked (no voice_call_timeout_v1); it is handled locally.
		if rejectReason == "timeout" {
			BeamioQALog.write("callee timeout: local only, no uplink callId=\(offer.callId.prefix(8))")
			forgetOffer(callId: offer.callId, sessionId: offer.sessionId)
			return
		}
		guard let secrets = BeamioChatPgpKeychain.load(eoa: BeamioNativeAccountPointer.get()) else {
			NSLog("[BeamioNativeVoice] decline — missing Chat PGP secrets in Keychain")
			return
		}
		let localEoa = secrets.eoa.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		guard localEoa.hasPrefix("0x"), localEoa.count == 42 else {
			NSLog("[BeamioNativeVoice] decline — missing local eoa in Keychain")
			return
		}
		let nowMs = Int(Date().timeIntervalSince1970 * 1000)
		let body: [String: Any] = [
			// An unanswered ring is a timeout for the caller, not a Decline.
			"type": "voice_call_reject_v1",  // a timeout returns before this point (v67 §74): no timeout type is built
			"callId": offer.callId,
			"sessionId": offer.sessionId,
			"from": localEoa,
			"to": offer.callerEoa.lowercased(),
			"reason": rejectReason,
			"createdAt": nowMs,
			"timestamp": nowMs,
		]
		// To the caller's mailbox: the caller has no channel while ringing.
		let text = (try? JSONSerialization.data(withJSONObject: body)).flatMap { String(data: $0, encoding: .utf8) } ?? ""
		let started = Date()
		let ok = !text.isEmpty && BeamioVoiceV3.postChatMessage(
			text: text, localEoa: localEoa,
			peerUserPgp: offer.callerPgpArmored, peerRoute: offer.callerRouteArmored, noPush: false
		)
		BeamioQALog.write(
			"decline posted callId=\(offer.callId.prefix(8)) reason=\(rejectReason) ok=\(ok ? "yes" : "no") ms=\(Int(Date().timeIntervalSince(started) * 1000))"
		)
		NSLog(
			"[BeamioNativeVoice] decline uplink callId=%@ reason=%@ ok=%@",
			offer.callId,
			rejectReason,
			ok ? "yes" : "no"
		)
		forgetOffer(callId: offer.callId, sessionId: offer.sessionId)
	}

	// MARK: - Hang Up

	/// Native hang up (v66 §73, v67 §74): the shell builds and sends no voice_end_v1. It reports the hang-up to the page
	/// as `nativeCallHangup`; the page sends the one voice_end_v1. A page that is not running gets nothing (local end only).
	static func sendHangup(callId: String) {
		lock.lock()
		let snapshot = activeCall
		lock.unlock()
		guard let call = snapshot, call.offer.callId == callId, call.mediaEnabled else { return }
		BeamioQALog.write("native hangup reported callId=\(callId.prefix(8))")
		BeamioVoipIncomingBootstrap.shared.emitNativeHangupIfPageRunning(callId: callId, sessionId: call.offer.sessionId)
	}

	/// CallKit Answer: voice v3 accept to the caller's mailbox; starts our channels.
	/// `mediaDeferred`: sent at Answer, before CallKit activates the audio session;
	/// capture starts in [calleeAudioActivated]. Network work does not wait for audio.
	/// Strict bind for a tapped answer: the account must read
	/// as a value; anything else, or a refused bind, is false (the caller ends the call).
	static func bindAnsweredCall(callId: String) -> Bool {
		guard case .value(let eoa) = BeamioNativeAccountPointer.read() else { return false }
		return BeamioPasscodeSession.shared.bindIncomingCall(callId: callId, eoa: eoa)
	}

	/// The accept starts only when the SDK authorizes it. Locked: the
	/// accept waits for the unlock (resumeAwaitingAccepts). Any other refusal ends the
	/// call as cancelled. Nothing is signed here.
	static func acceptWhenAuthorized(
		callId: String,
		sessionId: String,
		mediaDeferred: Bool = true,
		completion: ((String) -> Void)? = nil
	) {
		switch BeamioPasscodeSession.shared.incomingCallAuthorizeAnswer(callId: callId) {
		case .allow:
			lock.lock()
			awaitingUnlockAccepts.removeValue(forKey: callId)
			lock.unlock()
			sendAccept(callId: callId, sessionId: sessionId, mediaDeferred: mediaDeferred, completion: completion)
		case .deny:
			// TEMPORARY FAIL-CLOSED: a locked answer ends as cancelled. The wait for
			// the PWA entry unlock is re-enabled only after the entry and the T_load/T_in measurement land.
			qaTrail("accept refused callId=\(callId.prefix(8)) cancelled (locked: temporary fail-closed)")
			DispatchQueue.main.async {
				BeamioVoipIncomingBootstrap.shared.callKit.end(callId: callId, sessionId: sessionId)
			}
			completion?("")
		}
	}

	/// After a successful unlock: start the accepts that were waiting for it.
	static func resumeAwaitingAccepts() {
		lock.lock()
		let waiting = awaitingUnlockAccepts
		lock.unlock()
		for (callId, sessionId) in waiting {
			acceptWhenAuthorized(callId: callId, sessionId: sessionId)
		}
	}

	/// The call ended: it no longer waits for an unlock.
	static func dropAwaitingUnlock(callId: String) {
		lock.lock()
		awaitingUnlockAccepts.removeValue(forKey: callId)
		lock.unlock()
	}

	static func sendAccept(
		callId: String,
		sessionId: String,
		mediaDeferred: Bool = false,
		completion: ((String) -> Void)? = nil
	) {
		let key = "\(callId)|\(sessionId)"
		lock.lock()
		if inFlightAccept.contains(key) || acceptStarted.contains(callId) {
			lock.unlock()
			completion?("")
			return
		}
		inFlightAccept.insert(key)
		if acceptStarted.count > 32 { acceptStarted.removeAll() }
		acceptStarted.insert(callId)
		if !mediaDeferred { calleeAudioReady.insert(callId) }
		lock.unlock()
		BeamioQALog.write("accept start callId=\(callId.prefix(8)) session=\(sessionId.prefix(8))")

		DispatchQueue.global(qos: .userInitiated).async {
			defer {
				lock.lock()
				inFlightAccept.remove(key)
				lock.unlock()
			}
			// The offer can still be on its way: right after a push the native chat
			// listen may be reconnecting, and it delivers the offer once it is back.
			var resolvedOffer = resolveOfferSync(callId: callId, sessionId: sessionId)
			if resolvedOffer == nil {
				BeamioQALog.write("accept waiting for offer callId=\(callId.prefix(8))")
				for tick in 0..<20 {
					// The first fetch came back empty (offer not stored yet, or the
					// entry or mailbox was briefly down): fetch again every second
					// instead of only waiting for the chat listen to deliver it.
					if tick % 2 == 0 {
						BeamioVoiceOfferIdentity.resolve(callId: callId, sessionId: sessionId) { resolved in
							if let resolved, resolved.answerable { rememberOffer(resolved) }
						}
					}
					Thread.sleep(forTimeInterval: 0.5)
					if let hit = cachedOffer(callId: callId, sessionId: sessionId), hit.answerable {
						resolvedOffer = hit
						break
					}
				}
			}
			guard let offer = resolvedOffer else {
				BeamioQALog.write("accept skip: no v3 offer callId=\(callId.prefix(8)); ending local call")
				NSLog(
					"[BeamioNativeVoice] accept skip — no v3 offer callId=%@ sessionId=%@",
					callId,
					sessionId
				)
				// Without the offer no accept can be sent, so the caller keeps
				// ringing. Do not leave a connected CallKit call and a running call
				// timer here with nothing behind them (same as a failed uplink).
				DispatchQueue.main.async {
					BeamioInCallScreenModel.shared.end(callId: callId)
					BeamioVoipIncomingBootstrap.shared.callKit.end(callId: callId, sessionId: sessionId)
					completion?("")
				}
				return
			}
			guard let secrets = BeamioChatPgpKeychain.load(eoa: BeamioNativeAccountPointer.get()) else {
				NSLog("[BeamioNativeVoice] accept — missing Chat PGP secrets in Keychain")
				DispatchQueue.main.async { completion?("") }
				return
			}
			let localEoa = secrets.eoa.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
			guard localEoa.hasPrefix("0x"), localEoa.count == 42 else {
				NSLog("[BeamioNativeVoice] accept — missing local eoa in Keychain")
				DispatchQueue.main.async { completion?("") }
				return
			}
			sendAcceptV3(offer: offer, localEoa: localEoa, completion: completion)
		}
	}

	/// CallKit activated the call's audio session: start capture and playout on
	/// the callee call. If the accept never started (no Answer seen), start it now.
	static func calleeAudioActivated(callId: String, sessionId: String, completion: ((String) -> Void)? = nil) {
		lock.lock()
		calleeAudioReady.insert(callId)
		if calleeAudioReady.count > 32 { calleeAudioReady = [callId] }
		let started = acceptStarted.contains(callId)
		var enable: ActiveCall?
		if var cur = activeCall, cur.role == .callee, cur.offer.callId == callId, !cur.mediaEnabled {
			cur.mediaEnabled = true
			activeCall = cur
			enable = cur
		}
		lock.unlock()
		if let enable {
			qaTrail("callee media on audio activate callId=\(callId.prefix(8))")
			BeamioNativeVoiceChannel.shared.enableMedia(active: enable)
			return
		}
		if !started {
			acceptWhenAuthorized(callId: callId, sessionId: sessionId, completion: completion)
		}
		// Started and still building: sendAcceptV3 reads calleeAudioReady when it creates the call.
	}

	/// v3 Answer: create the four paid channels (our wallet pays), open our two
	/// on relays we pick, and send the accept to the caller's mailbox as a chat
	/// message (recipient PGP + mailbox route layer, random entry). Runs off main.
	private static func sendAcceptV3(
		offer: BeamioVoiceOfferIdentity.Resolved,
		localEoa: String,
		completion: ((String) -> Void)?
	) {
		func fail(_ why: String) {
			qaTrail("v3 accept failed: \(why) callId=\(offer.callId.prefix(8))")
			lock.lock()
			acceptStarted.remove(offer.callId)
			lock.unlock()
			DispatchQueue.main.async {
				BeamioInCallScreenModel.shared.end(callId: offer.callId)
				BeamioVoipIncomingBootstrap.shared.callKit.end(callId: offer.callId, sessionId: offer.sessionId)
				completion?("")
			}
		}
		// Native authorization before any signature: the SDK judges the
		// call, the account and gen0. Anything but allow ends the call as cancelled.
		guard BeamioPasscodeSession.shared.incomingCallAuthorizeAnswer(callId: offer.callId) == .allow else {
			return fail("incoming answer not authorized")
		}
		guard BeamioChatWalletKeychain.hasKey(eoa: localEoa) else {
			return fail("no stored wallet key")
		}
		BeamioCallTiming.mark("accept-v3-start")
		var made: [BeamioVoiceV3.Own] = []
		let sealedAccept: String? = nil  // built after authorize; nothing is pre-sealed
		do {
			for _ in 0 ..< 4 {
				guard let own = BeamioVoiceV3.newPaidChannel(payerEoa: localEoa) else {
					return fail("sign")
				}
				made.append(own)
			}
			var exclude: Set<String> = []
			if let mailbox = BeamioSiCipherPost.normalizeIp(BeamioChatPgpKeychain.loadMailboxIp()) { exclude.insert(mailbox) }
			let avoid = [BeamioChatPgpKeychain.loadRoutePublicArmor(eoa: BeamioNativeAccountPointer.get()), offer.callerRouteArmored]
			guard let voiceRelay = BeamioVoiceV3.RelayNodes.pick(excludeIps: exclude, excludeArmors: avoid),
			      let videoRelay = BeamioVoiceV3.RelayNodes.pick(excludeIps: exclude, excludeArmors: avoid)
			else { return fail("no relay nodes cached") }
			made[2].relay = voiceRelay
			made[3].relay = videoRelay
		}
		let cv = made[0], cV = made[1]
		let ev = made[2], eV = made[3]
		// Sealed while ringing: Answer only posts it (native HTTP, no crypto WebView).
		let text: String
		if sealedAccept != nil {
			text = ""
		} else {
			guard let built = acceptText(offer: offer, localEoa: localEoa, made: made) else { return fail("encode") }
			text = built
		}
		let call = BeamioVoiceV3.Call(
			callId: offer.callId,
			ownVoice: ev,
			ownVideo: eV,
			peerVoice: .init(channel: cv.channel, relay: nil),
			peerVideo: .init(channel: cV.channel, relay: nil)
		)
		lock.lock()
		// Media only once CallKit's audio session is up; the listens and the accept go now.
		let active = ActiveCall(
			role: .callee,
			offer: offer,
			listenSessionId: ev.channel.sid,
			peerMediaSessionId: cv.channel.sid,
			peerEoa: offer.callerEoa.lowercased(),
			localEoa: localEoa,
			mediaEnabled: calleeAudioReady.contains(offer.callId),
			v3: call
		)
		activeCall = active
		lock.unlock()
		// Our listens open beside the accept post; the caller's media waits for them anyway.
		BeamioNativeVoiceChannel.shared.start(active: active)
		var ok = false
		for attempt in 0 ..< 3 {
			if let sealed = sealedAccept {
				ok = BeamioVoiceV3.postSealedChatMessage(armor: sealed, peerRoute: offer.callerRouteArmored)
			} else {
				ok = BeamioVoiceV3.postChatMessage(
					text: text, localEoa: localEoa,
					peerUserPgp: offer.callerPgpArmored, peerRoute: offer.callerRouteArmored, noPush: true
				)
			}
			BeamioQALog.write("v3 accept post attempt=\(attempt + 1) ok=\(ok ? "yes" : "no") sealed=\(sealedAccept == nil ? "no" : "yes")")
			if ok { break }
			Thread.sleep(forTimeInterval: 0.6 * Double(attempt + 1))
		}
		BeamioCallTiming.mark("accept-v3-sent")
		guard ok else {
			BeamioNativeVoiceChannel.shared.stop()
			lock.lock()
			if activeCall?.offer.callId == offer.callId { wipeAndClearActiveCall() }
			lock.unlock()
			return fail("post")
		}
		let answered = offer
		DispatchQueue.main.async {
			BeamioInCallScreenModel.shared.begin(
				callId: answered.callId,
				sessionId: answered.sessionId,
				tag: answered.beamioTag,
				address: answered.callerEoa
			)
			completion?(ev.channel.sid)
		}
	}

	// MARK: - Resolve + uplink

	private static func resolveOfferSync(
		callId: String,
		sessionId: String
	) -> BeamioVoiceOfferIdentity.Resolved? {
		if let hit = cachedOffer(callId: callId, sessionId: sessionId), hit.answerable {
			return hit
		}
		let sem = DispatchSemaphore(value: 0)
		let box = OfferWaitBox()
		BeamioVoiceOfferIdentity.resolve(callId: callId, sessionId: sessionId) { resolved in
			box.deliver(resolved)
			sem.signal()
		}
		_ = sem.wait(timeout: .now() + 20)
		// A late result is dropped (box.finish), and an offer for a call that is no longer live is never cached.
		guard let hit = box.finish(), hit.answerable,
		      BeamioVoiceOfferIdentity.withinSignedExpiry(hit),
		      isCallStillLive(callId: callId, sessionId: sessionId)
		else { return nil }
		rememberOffer(hit)
		return hit
	}

}
