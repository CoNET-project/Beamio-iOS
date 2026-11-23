import Foundation
import Testing
@testable import CashTrees_iOS
@testable import ConetChatSDK

// PWA envelope sample v2 (fixture only; no key material). The envelope text is
// signed by envelopeFrom with EIP-191; the outer check recovers from exactly this text.
// Nested in the serialized SdkStateSuite parent: this suite verifies through the SDK's shared OpenPGP host, and the suites
// there that switch accounts or restore end the session, which tears that host down (BeamioPasscodeSession, reason ends call resources).
// Run one after another, a verification never meets a teardown from a parallel suite (evidence: 12 rounds, all failures -8 torn down).
extension SdkStateSuite {
@Suite(.serialized)
struct BeamioEnvelopeSampleTests {
	static let envelopeText = """
{"type":"voice_call_offer_v1","proto":3,"callId":"vt-env2-call-0001","sessionId":"vt-env2-session-0001","from":"0x5EAC5064D7BA0CcCf2Cb1B055A865e5b776CFd77","to":"0x000000000000000000000000000000000000dEaD","codec":"audio/pcm;rate=16000","callerPgp":"VEVTVC1GSVhUVVJFLVBHUC1BUk1PUi1OT1QtQS1SRUFMLUtFWQ==","callerRoute":"VEVTVC1GSVhUVVJFLVJPVVRFLU5PVC1BLVJFQUwtS0VZ","callerTag":"vt_caller","expiresAt":1795222709258,"createdAt":1795221809258,"timestamp":1795221809258,"callerSignature":"0xd44faafe5a615211e8e132e7391f51969e2a607bbecde628c56116698a61662c1b39c7731f1787939a0260f47f8cf851d9011675bc696dc13c63e84a0a7859261b"}
"""
	static let signMessage = "0x2c05f7978d5ff9ea16d97c275dde953a5ca7e095c609e68c80941d96b3d9e0d61320d7def566ca415cbbed947415c5f14cc951c5df00ed59b4edf75eb2819d831b"
	static let envelopeFrom = "0x5EAC5064D7BA0CcCf2Cb1B055A865e5b776CFd77"

	static func line(text: String = envelopeText, signature: String = signMessage, from: String = envelopeFrom) -> String {
		let obj: [String: Any] = ["text": text, "signMessage": signature, "from": from]
		return String(decoding: try! JSONSerialization.data(withJSONObject: obj), as: UTF8.self)
	}

	static func resolve(_ line: String, from: String) async -> BeamioVoiceOfferIdentity.Resolved? {
		await withCheckedContinuation { cont in
			BeamioVoiceOfferIdentity.resolveFromInboundChatLine(line: line, from: from) { cont.resume(returning: $0) }
		}
	}

	@Test func acceptsThePlainEnvelopeFromTheSample() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		// No network: the tag lookup is stubbed (BEAMIO_TEST_HOOKS). The assertions are the sample's own facts.
		BeamioTagAddressLookup.testOverride = { _ in nil }
		defer { BeamioTagAddressLookup.testOverride = nil }
		let resolved = await Self.resolve(Self.line(), from: Self.envelopeFrom)
		if resolved == nil { await TestSupportSdkState.recordHostFailure("acceptsThePlainEnvelopeFromTheSample") }
		#expect(resolved != nil)
		#expect(resolved?.callerEoa.lowercased() == Self.envelopeFrom.lowercased())
		#expect(resolved?.callId == "vt-env2-call-0001")
	}

	@Test func acceptsTheSampleInsideItsSignedWindow() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		// createdAt 1795221809258 < pinned clock < expiresAt 1795222709258: the sample's own facts, no system clock.
		BeamioTagAddressLookup.testOverride = { _ in nil }
		BeamioVoiceOfferIdentity.nowMsForTests = 1_795_222_000_000
		defer { BeamioTagAddressLookup.testOverride = nil; BeamioVoiceOfferIdentity.nowMsForTests = nil }
		let resolved = await Self.resolve(Self.line(), from: Self.envelopeFrom)
		if resolved == nil { await TestSupportSdkState.recordHostFailure("acceptsTheSampleInsideItsSignedWindow") }
		#expect(resolved != nil)
	}

	@Test func expiredOfferIsNotRungEndToEndTheRingGate() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		// Inbound path: resolve, then the ring gate of BeamioNativeVoiceSignaling. Past expiresAt the offer is not rung or reported.
		BeamioTagAddressLookup.testOverride = { _ in nil }
		defer { BeamioTagAddressLookup.testOverride = nil; BeamioVoiceOfferIdentity.nowMsForTests = nil }
		BeamioVoiceOfferIdentity.nowMsForTests = 1_795_222_709_259
		#expect(BeamioNativeVoiceSignaling.offerRingWindowOver(line: Self.line()) == true)
		// Inside the ring window (createdAt 1795221809258 + 10 s) and before expiresAt: rung.
		BeamioVoiceOfferIdentity.nowMsForTests = 1_795_221_819_258
		#expect(BeamioNativeVoiceSignaling.offerRingWindowOver(line: Self.line()) == false)
	}

	@Test func refusesTheSampleAfterItsSignedExpiry() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		// The signature resolves; the late-offer rule (withinSignedExpiry) refuses it once the clock passes expiresAt (fail closed).
		BeamioTagAddressLookup.testOverride = { _ in nil }
		defer { BeamioTagAddressLookup.testOverride = nil }
		let resolved = await Self.resolve(Self.line(), from: Self.envelopeFrom)
		if resolved == nil { await TestSupportSdkState.recordHostFailure("refusesTheSampleAfterItsSignedExpiry") }
		guard let offer = resolved else { Issue.record("sample did not resolve"); return }
		#expect(BeamioVoiceOfferIdentity.withinSignedExpiry(offer, nowMs: 1_795_222_709_259) == false)
		#expect(BeamioVoiceOfferIdentity.withinSignedExpiry(offer, nowMs: 1_795_222_000_000) == true)
	}

	@Test func refusesAValidSignatureOfAnotherText() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		// The same real signature over a changed text recovers another address: it must not equal envelopeFrom.
		let changed = Self.envelopeText + " "
		let resolved = await Self.resolve(Self.line(text: changed), from: Self.envelopeFrom)
		#expect(resolved == nil)
	}

	@Test func refusesAnEnvelopeWhenTheLineSenderDiffers() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		let resolved = await Self.resolve(Self.line(), from: "0x1111111111111111111111111111111111111111")
		#expect(resolved == nil)
	}
}
}
