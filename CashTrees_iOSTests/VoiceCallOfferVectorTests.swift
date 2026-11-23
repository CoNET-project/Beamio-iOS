import Foundation
import Testing
@testable import CashTrees_iOS
@testable import ConetChatSDK

// PWA voice_call_offer_v1 rev2 vector, public values only: no keys, no secrets.
// Exercises the shell's own canonical builder (BeamioVoiceOfferIdentity.buildCallerCanonicalText) and the
// OpenPGP host's ethers.verifyMessage path that parseAndVerify uses for the caller signature.
// Nested in the serialized SdkStateSuite parent: this suite verifies through the SDK's shared OpenPGP host, and the suites
// there that switch accounts or restore end the session, which tears that host down (BeamioPasscodeSession, reason ends call resources).
// Run one after another, a verification never meets a teardown from a parallel suite (evidence: 12 rounds, all failures -8 torn down).
extension SdkStateSuite {
@Suite(.serialized)
struct VoiceCallOfferVectorTests {
	static let signer = "0x660fc041ffe39750ef53149debb5cf2df32c5b0f"
	static let signature = "0xf814f04f44d3342c013041364877442c7f0de864e092ca16c72dd30a4531422328b05dc310274b8e05c23e247c3437d912db10eb2af05a11c1b2899375a51d8c1c"
	static let signText = "CoNET voice_call_offer_v3\ncallId:vt-call-0001\nsessionId:vt-session-0001\nto:0x000000000000000000000000000000000000dead\ncreatedAt:1795217195851\nexpiresAt:1795218095851\ntimestamp:1795217195851\ncodec:audio/pcm;rate=16000\ncallerPgp:VEVTVC1GSVhUVVJFLVBHUC1BUk1PUi1OT1QtQS1SRUFMLUtFWQ==\ncallerRoute:VEVTVC1GSVhUVVJFLVJPVVRFLU5PVC1BLVJFQUwtS0VZ"
	static let vectorFrom = "0x660fC041FFE39750eF53149debB5cF2dF32C5B0f"

	static func offer(callId: String = "vt-call-0001", from: String = vectorFrom) -> [String: Any] {
		[
			"type": "voice_call_offer_v1",
			"proto": 3,
			"callId": callId,
			"sessionId": "vt-session-0001",
			"from": from,
			"to": "0x000000000000000000000000000000000000dEaD",
			"codec": "audio/pcm;rate=16000",
			"callerPgp": "VEVTVC1GSVhUVVJFLVBHUC1BUk1PUi1OT1QtQS1SRUFMLUtFWQ==",
			"callerRoute": "VEVTVC1GSVhUVVJFLVJPVVRFLU5PVC1BLVJFQUwtS0VZ",
			"createdAt": 1795217195851,
			"expiresAt": 1795218095851,
			"timestamp": 1795217195851,
			"callerSignature": "0xf814f04f44d3342c013041364877442c7f0de864e092ca16c72dd30a4531422328b05dc310274b8e05c23e247c3437d912db10eb2af05a11c1b2899375a51d8c1c",
		]
	}

	nonisolated(unsafe) static var lastError: Error?
	static func recover(text: String, signature: String) async -> String? {
		lastError = nil
		return await withCheckedContinuation { (cont: CheckedContinuation<String?, Never>) in
			BeamioOpenPgpHost.shared.verifyMessage(text: text, signature: signature) { result in
				switch result {
				case .success(let address): cont.resume(returning: address.lowercased())
				case .failure(let e): lastError = e; cont.resume(returning: nil)
				}
			}
		}
	}

	@Test func canonicalTextIsByteIdenticalToThePwaSignText() {
		let text = BeamioVoiceOfferIdentity.buildCallerCanonicalText(offer: Self.offer())
		#expect(text == Self.signText)
	}

	@Test func positiveVectorRecoversTheSigner() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		let text = BeamioVoiceOfferIdentity.buildCallerCanonicalText(offer: Self.offer())
		let recovered = await Self.recover(text: text, signature: Self.signature)
		if recovered == nil { await TestSupportSdkState.recordHostFailure("positiveVectorRecoversTheSigner", error: Self.lastError) }
		#expect(recovered == Self.signer)
	}

	@Test func negativeOneByteChangedCallIdDoesNotRecoverTheSigner() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		let text = BeamioVoiceOfferIdentity.buildCallerCanonicalText(offer: Self.offer(callId: "vt-call-0002"))
		let recovered = await Self.recover(text: text, signature: Self.signature)
		#expect(recovered != Self.signer)
	}

	@Test func negativeFromReplacedKeepsSignatureValidButClaimMismatches() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		// from is not in the signed text: the signature still recovers the signer, so the shell must
		// reject on claimed from != recovered (parseAndVerify). This test pins the vector's facts.
		let text = BeamioVoiceOfferIdentity.buildCallerCanonicalText(offer: Self.offer(from: "0x1111111111111111111111111111111111111111"))
		let recovered = await Self.recover(text: text, signature: Self.signature)
		if recovered == nil { await TestSupportSdkState.recordHostFailure("negativeFromReplacedKeepsSignatureValidButClaimMismatches", error: Self.lastError) }
		#expect(recovered == Self.signer)
		#expect("0x1111111111111111111111111111111111111111" != recovered)
	}

	@Test func fromReplacedIsRejectedByTheProductionParseAndVerify() async throws {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		// Production path (parseAndVerify): claimed from != recovered signer must yield nil.
		let data = try JSONSerialization.data(withJSONObject: Self.offer(from: "0x1111111111111111111111111111111111111111"))
		let plaintext = String(decoding: data, as: UTF8.self)
		let result: BeamioVoiceOfferIdentity.Resolved? = await withCheckedContinuation { cont in
			BeamioVoiceOfferIdentity.parseAndVerifyForTests(plaintext: plaintext, callId: "vt-call-0001", sessionId: "vt-session-0001") { cont.resume(returning: $0) }
		}
		#expect(result == nil)
	}
}
}
