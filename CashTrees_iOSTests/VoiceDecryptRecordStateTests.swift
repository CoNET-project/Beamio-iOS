#if BEAMIO_TEST_HOOKS
import Foundation
import Testing
@testable import CashTrees_iOS
@testable import ConetChatSDK

/// The incoming-call decrypt, through BeamioVoiceOfferIdentity.resolve (the real path, before any network fetch).
/// A missing PGP record reports key_missing; an unreadable record reports decrypt_unknown; neither deletes nor overwrites.
/// Synthetic values only. The PGP record store and the account pointer are process-wide: the suite is nested in the serialized
/// SdkStateSuite parent, so it never runs alongside the other suites that replace them.
extension SdkStateSuite {
@Suite(.serialized)
struct VoiceDecryptRecordStateTests {
    private let account = "0x3333333333333333333333333333333333333333"
    private let callId = "push-call-0002"
    private let sessionId = "push-session-0002-synthetic"

    /// Captures what resolve reports through its failure callback and its completion.
    private final class Outcome {
        var failureState: BeamioDecryptFailureState?
        var failureReason: String?
        var completed = false
        var resolvedWasNil = false
    }

    /// The SDK keeps the pointer under this key (private there). It is read raw, so that a value with capitals is restored as it was.
    private static let pointerKey = "beamio.native.account.v1"

    /// Restores the records and the account pointer exactly as they were before the case, capitals included.
    private func run(_ body: () -> Void) {
        let savedRecords = BeamioChatPgpKeychain.memory
        let savedRawPointer = BeamioNativeAccountPointer.defaults.string(forKey: Self.pointerKey)
        BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
        BeamioNativeAccountPointer.set(account)
        defer {
            if let raw = savedRawPointer {
                // set() lower-cases, so it refreshes the key snapshot; the raw value is then written back unchanged.
                BeamioNativeAccountPointer.set(raw)
                BeamioNativeAccountPointer.defaults.set(raw, forKey: Self.pointerKey)
            } else {
                BeamioNativeAccountPointer.clear()
            }
            BeamioChatPgpKeychain.memory = savedRecords
        }
        body()
    }

    private func resolve(_ outcome: Outcome) {
        BeamioVoiceOfferIdentity.resolve(
            callId: callId,
            sessionId: sessionId,
            failure: { state, reason in
                outcome.failureState = state
                outcome.failureReason = reason
            },
            completion: { resolved in
                outcome.completed = true
                outcome.resolvedWasNil = (resolved == nil)
            }
        )
    }

    @Test func unreadableRecordReportsDecryptUnknownAndKeepsTheRecord() {
        run {
            // Store a private key, then damage the stored armor (drop its BEGIN marker, keep the item): an unreadable record.
            let secrets = BeamioChatPgpKeychain.Secrets(
                privateKeyArmor: "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic\n-----END PGP PRIVATE KEY BLOCK-----",
                publicKeyArmor: "", pgpKeyId: "", routePublicKeyArmor: "",
                entryDomains: [], siNodes: [], mailboxIp: "", eoa: account)
            #expect(BeamioChatPgpKeychain.save(secrets), "fixture: the record is stored")
            if let records = BeamioChatPgpKeychain.memory {
                for key in records.values.keys where records.values[key]?.contains("BEGIN PGP PRIVATE KEY") == true {
                    records.values[key] = "not-a-pgp-private-key"
                }
            }
            #expect(BeamioChatPgpKeychain.recordState(eoa: account) == .unreadable, "precondition: the record is unreadable")
            let before = BeamioChatPgpKeychain.memory?.values ?? [:]

            let outcome = Outcome()
            resolve(outcome)

            #expect(outcome.completed && outcome.resolvedWasNil, "resolve completes with no identity")
            #expect(outcome.failureState == .decryptUnknown, "an unreadable record is decrypt_unknown")
            #expect(outcome.failureReason == "decrypt_unknown", "the reason code is decrypt_unknown")
            #expect(BeamioChatPgpKeychain.recordState(eoa: account) == .unreadable, "the record is not deleted or changed")
            #expect((BeamioChatPgpKeychain.memory?.values ?? [:]) == before, "nothing is written")
        }
    }

    @Test func missingRecordReportsKeyMissing() {
        run {
            #expect(BeamioChatPgpKeychain.recordState(eoa: account) == .absent, "precondition: no record")
            let outcome = Outcome()
            resolve(outcome)
            #expect(outcome.completed && outcome.resolvedWasNil, "resolve completes with no identity")
            #expect(outcome.failureState == .keyMissing, "a missing record is key_missing")
            #expect(outcome.failureReason == "key_missing", "the reason code is key_missing")
        }
    }

    @Test func restoreIncompleteRecordReportsDecryptUnknownAndIsNotDeleted() {
        run {
            let secrets = BeamioChatPgpKeychain.Secrets(
                privateKeyArmor: "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic\n-----END PGP PRIVATE KEY BLOCK-----",
                publicKeyArmor: "", pgpKeyId: "", routePublicKeyArmor: "synthetic-route",
                entryDomains: [], siNodes: [BeamioChatPgpKeychain.SiNode(ip: "203.0.113.10", domain: "", region: "")],
                mailboxIp: "", eoa: account)
            #expect(BeamioChatPgpKeychain.save(secrets), "fixture: the record is stored")
            #expect(BeamioChatPgpKeychain.markRestoreIncomplete(eoa: account), "fixture: the restore-incomplete mark is written")
            #expect(BeamioChatPgpKeychain.recordState(eoa: account) == .present, "precondition: the record is present")
            #expect(BeamioChatPgpKeychain.load(eoa: account) == nil, "precondition: load refuses an incomplete restore")
            let before = BeamioChatPgpKeychain.memory?.values ?? [:]

            let outcome = Outcome()
            resolve(outcome)

            #expect(outcome.completed && outcome.resolvedWasNil, "resolve completes with no identity")
            #expect(outcome.failureState == .decryptUnknown, "a present record that cannot be loaded is decrypt_unknown, not skipped")
            #expect(outcome.failureReason == "decrypt_unknown", "the reason code is decrypt_unknown")
            #expect(BeamioChatPgpKeychain.recordState(eoa: account) == .present, "the record is not deleted")
            #expect((BeamioChatPgpKeychain.memory?.values ?? [:]) == before, "nothing is written")
        }
    }

    @Test func presentRecordWithoutRouteKeyReportsDecryptUnknown() {
        run {
            let secrets = BeamioChatPgpKeychain.Secrets(
                privateKeyArmor: "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic\n-----END PGP PRIVATE KEY BLOCK-----",
                publicKeyArmor: "", pgpKeyId: "", routePublicKeyArmor: "",
                entryDomains: [], siNodes: [BeamioChatPgpKeychain.SiNode(ip: "203.0.113.10", domain: "", region: "")],
                mailboxIp: "", eoa: account)
            #expect(BeamioChatPgpKeychain.save(secrets), "fixture: the record is stored without a route key")
            #expect(BeamioChatPgpKeychain.recordState(eoa: account) == .present, "precondition: the record is present")

            let outcome = Outcome()
            resolve(outcome)

            #expect(outcome.completed && outcome.resolvedWasNil, "resolve completes with no identity")
            #expect(outcome.failureState == .decryptUnknown, "a present record without its route key is decrypt_unknown")
            #expect(BeamioChatPgpKeychain.recordState(eoa: account) == .present, "the record is not deleted")
        }
    }

    @Test func presentRecordWithEmptyRosterReportsDecryptUnknown() {
        run {
            let secrets = BeamioChatPgpKeychain.Secrets(
                privateKeyArmor: "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic\n-----END PGP PRIVATE KEY BLOCK-----",
                publicKeyArmor: "", pgpKeyId: "", routePublicKeyArmor: "synthetic-route",
                entryDomains: [], siNodes: [], mailboxIp: "", eoa: account)
            #expect(BeamioChatPgpKeychain.save(secrets), "fixture: the record is stored with an empty roster")
            #expect(BeamioChatPgpKeychain.recordState(eoa: account) == .present, "precondition: the record is present")

            let outcome = Outcome()
            resolve(outcome)

            #expect(outcome.completed && outcome.resolvedWasNil, "resolve completes with no identity")
            #expect(outcome.failureState == .decryptUnknown, "a present record with an empty roster is decrypt_unknown")
            #expect(BeamioChatPgpKeychain.recordState(eoa: account) == .present, "the record is not deleted")
        }
    }

    @Test func aFailedCiphertextRetrievalReportsDecryptUnknownAndKeepsTheRecord() {
        run {
            let secrets = BeamioChatPgpKeychain.Secrets(
                privateKeyArmor: "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic\n-----END PGP PRIVATE KEY BLOCK-----",
                publicKeyArmor: "", pgpKeyId: "",
                routePublicKeyArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic\n-----END PGP PUBLIC KEY BLOCK-----",
                entryDomains: [], siNodes: [BeamioChatPgpKeychain.SiNode(ip: "203.0.113.10", domain: "", region: "")],
                mailboxIp: "", eoa: account)
            #expect(BeamioChatPgpKeychain.save(secrets), "fixture: a complete record is stored")
            #expect(BeamioChatPgpKeychain.recordState(eoa: account) == .present, "precondition: the record is present")
            let before = BeamioChatPgpKeychain.memory?.values ?? [:]

            // The ciphertext retrieval fails (no network in a test): the answer is nil.
            BeamioVoiceOfferIdentity.fetchOfferArmorOverrideForTests = { answer in answer(nil) }
            defer { BeamioVoiceOfferIdentity.fetchOfferArmorOverrideForTests = nil }

            let outcome = Outcome()
            resolve(outcome)

            #expect(outcome.completed && outcome.resolvedWasNil, "resolve completes with no identity")
            #expect(outcome.failureState == .decryptUnknown, "a failed ciphertext retrieval is decrypt_unknown (retryable)")
            #expect(outcome.failureReason == "decrypt_unknown", "the reason code is decrypt_unknown")
            #expect(BeamioChatPgpKeychain.recordState(eoa: account) == .present, "the record is not deleted")
            #expect((BeamioChatPgpKeychain.memory?.values ?? [:]) == before, "nothing is written")
        }
    }

    @Test func aPointerWithCapitalsIsRestoredAsItWas() {
        let raw = "0xABCDEF0123456789ABCDEF0123456789ABCDEF01"
        let savedRaw = BeamioNativeAccountPointer.defaults.string(forKey: Self.pointerKey)
        defer {
            if let savedRaw { BeamioNativeAccountPointer.defaults.set(savedRaw, forKey: Self.pointerKey) } else { BeamioNativeAccountPointer.clear() }
        }
        BeamioNativeAccountPointer.defaults.set(raw, forKey: Self.pointerKey)
        run {
            #expect(BeamioNativeAccountPointer.defaults.string(forKey: Self.pointerKey) == account, "inside the case the pointer is the account")
        }
        #expect(BeamioNativeAccountPointer.defaults.string(forKey: Self.pointerKey) == raw, "after the case the capitals are back as they were")
    }
}
}
#endif
