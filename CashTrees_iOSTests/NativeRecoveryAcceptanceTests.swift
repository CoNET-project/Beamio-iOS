import Foundation
import Testing
@testable import ConetChatSDK

// Acceptance of the two formal recovery entries: BeamioTag plus password, and the recovery code.
// Synthetic only: the registry records are the shared synthetic fixtures (native-recovery-vectors.v1.json, SHA256
// 817957b9bb63fd31de9bb82f739405260ca998752b3fe7afc660601604c12b80); the recovery code, the password and the account
// name are synthetic values from the same vectors; the phrase is the public BIP-39 test phrase. The KDF is the
// production one (argon2id through X-19, not a stand-in). The registry is the fixture, not the chain: the chain read
// is not exercised here.
private let syntheticAccount = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
private let syntheticCode = "3kRz8mQ2vLpN7wXy1sTcFh"
private let syntheticName = "syn_recover_0001"
private let syntheticPassword = "SYN-pin-2026"
// Registry record for keccak256(code) (path A) and for the account name (path B), from the fixtures.
private let fixturePathA = "eyJzdG9yZWQiOnsiYWxnbyI6ImFyZ29uMmlkIiwidiI6MTksIm0iOjMyNzY4LCJ0IjozLCJwIjoxLCJzYWx0IjoiVTFsT0xWTkJURlF0TURBd01EQXdNUT09IiwiaGFzaCI6Ik41Sm5zRFJVRUppQmxmWlVYaENRK09EV2ZzaVJCOVE0MXpCb0l6SG1xZ2M9In0sImltZyI6IlUxbE9TVll0TURBd01EQXh4VVpZbnl5a0RsSm84eHI1L1g5OFArQVRBK3dFeW10WEZDZVlmZThjTlYvTnE2QVI4U3BBc2pWUUIxRDNtckd1Y1NNRlhTVG1qcGxHczYvbk5xRVBXLzdaWDkrQitsODBpbk0vamhWREpoS0hMRlBGUU9KTHkwVlNlSUFJZ2xOSENvMzViMFU3MFNHeVRnbEpnRG1ibmdmWmlhYlprTFlLYmNMbzE2VTUwdStiWVdkZ2VpUFU0blZxWE53PSJ9"
private let fixturePathB = "eyJzdG9yZWQiOnsiYWxnbyI6ImFyZ29uMmlkIiwidiI6MTksIm0iOjMyNzY4LCJ0IjozLCJwIjoxLCJzYWx0IjoiVTFsT0xWTkJURlF0TURBd01EQXdNUT09IiwiaGFzaCI6Ik41Sm5zRFJVRUppQmxmWlVYaENRK09EV2ZzaVJCOVE0MXpCb0l6SG1xZ2M9In0sImltZyI6IlUxbE9TVll0TURBd01EQXgvOFBHRUR1b1FPK0FBVEo0MWRwZC9EL2pZbU5WOTNYNnpqeHBUM0g0QTlibTRzTE1UL1dyL2RzUXYzNnlQR3QvTmxtbDB2Zk1senhRWXg3d0p4MjdwdXZ2QzNrZDBsZHBkQXJQNk9WQzV1QmlSTWdHNVI5UFVaNThnN21DZUU5WndrMnN0N0FYNDUzd1M3UnpxQlVYeDR0T2xDOHpBZlFKallrQ21LRnlyOXd4N2xjZEtGQ0JpdHUya3FvPSJ9"

private struct FixtureRegistry: BeamioRecoveryRegistryReading {
    func recordByNameHash(_ nameHash: [UInt8]) -> Result<String, Error> {
        let hex = "0x" + nameHash.map { String(format: "%02x", $0) }.joined()
        return hex == "0xc994c0e53eb8fa2986fd8ef845c5cf46067a6440b22e0fb2e3554a421b6ef173" ? .success(fixturePathA) : .success("")
    }
    func recordByAccountName(_ name: String) -> Result<String, Error> {
        name == syntheticName ? .success(fixturePathB) : .success("")
    }
    func legacyRecordByAccountName(_ name: String) -> Result<String, Error> { .success("") }
}

private final class MemoryPinAttempts: BeamioNativeRecovery.PinAttemptStoring {
    private var failures = 0
    private var last: Date?
    func load() -> (failures: Int, lastFailure: Date?) { (failures, last) }
    func save(failures: Int, lastFailure: Date?) { self.failures = failures; self.last = lastFailure }
}

extension SdkStateSuite {
@Suite(.serialized)
struct NativeRecoveryAcceptanceTests {
    /// Runs one recovery with a clean device state for the synthetic account, then restores the globals.
    private func withCleanDevice(_ body: () -> Void) {
        let savedStore = BeamioNativeWallet.keyStore
        let savedRegistry = BeamioNativeRecovery.registry
        let savedAttempts = BeamioNativeRecovery.attempts
        defer {
            BeamioNativeWallet.keyStore = savedStore
            BeamioNativeRecovery.registry = savedRegistry
            BeamioNativeRecovery.attempts = savedAttempts
        }
        // A clean test memory for the wallet items (mnemonic, key, intent, commit): the saved items come back at the end.
        let savedItems = BeamioChatWalletTestMemory.items
        BeamioChatWalletTestMemory.items = [:]
        defer { BeamioChatWalletTestMemory.items = savedItems }
        // the product store (BeamioPasscodeWalletStore): an account restored with its mnemonic is the no-passcode set and its key is
        // derived from the set on read (iOS SDK behaviour). The raw store holds no key record for it.
        let store = BeamioPasscodeWalletStore.standard
        BeamioNativeWallet.keyStore = store
        BeamioNativeRecovery.registry = FixtureRegistry()
        BeamioNativeRecovery.attempts = MemoryPinAttempts()
        BeamioNativeAccountPointer.clear()
        BeamioNativeKeySnapshot.invalidate()
        store.delete(eoa: syntheticAccount)
        body()
    }

    @Test func beamioTagAndPasswordRecoveryDerivesTheOriginalAccount() {
        #expect(BeamioPGPNative.linked, "the production KDF needs X-19 linked in this build")
        withCleanDevice {
            let outcome = BeamioNativeRecovery.restore(.account(name: syntheticName, password: Array(syntheticPassword.utf8)))
            Attachment.record("entry=beamiotag+password outcome=\(String(describing: outcome))", named: "recovery-path-b.txt")
            #expect(outcome == .ok(eoa: syntheticAccount), "BeamioTag plus password restores the original account")
            #expect(BeamioNativeWallet.keyStore.read(eoa: syntheticAccount)?.count == 32, "the restored key is readable for the derived account through the product store")
        }
    }

    @Test func recoveryCodeRecoveryDerivesTheOriginalAccount() {
        #expect(BeamioPGPNative.linked, "the production KDF needs X-19 linked in this build")
        withCleanDevice {
            let outcome = BeamioNativeRecovery.restore(.recoveryCode(syntheticCode))
            Attachment.record("entry=recovery-code outcome=\(String(describing: outcome))", named: "recovery-path-a.txt")
            #expect(outcome == .ok(eoa: syntheticAccount), "the recovery code restores the original account")
            #expect(BeamioNativeWallet.keyStore.read(eoa: syntheticAccount)?.count == 32, "the restored key is readable for the derived account through the product store")
        }
    }

    @Test func wrongPasswordDoesNotRestoreAnAccount() {
        withCleanDevice {
            let outcome = BeamioNativeRecovery.restore(.account(name: syntheticName, password: Array("wrong-password".utf8)))
            #expect(outcome != .ok(eoa: syntheticAccount), "a wrong password restores nothing")
            #expect(BeamioNativeWallet.keyStore.read(eoa: syntheticAccount) == nil, "nothing is stored after a failed attempt")
        }
    }
}
}
