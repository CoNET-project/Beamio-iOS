import CryptoKit
import Foundation

/// Runtime source gate for every page-to-native command. The trusted identity is the embedded build's
/// `BeamioPWABuild.json` (written at build time, before signing): nothing is hard-coded here.
/// A missing or unreadable sidecar, or an active tree that differs from it, fails closed (`untrusted_source`).
enum NativeBridgeTrust {
    struct Identity: Equatable {
        let version: String
        let zipSHA256: String
        let treeSHA256: String
    }

    /// Pure: the identity from the build sidecar facts, or nil (fail closed) when any field is missing or empty.
    static func identity(from facts: (ver: String, zipSha256: String, treeDigest: String)?) -> Identity? {
        guard let facts, !facts.ver.isEmpty, !facts.zipSha256.isEmpty, !facts.treeDigest.isEmpty else { return nil }
        return Identity(version: facts.ver, zipSHA256: facts.zipSha256.lowercased(), treeSHA256: facts.treeDigest.lowercased())
    }

    /// Read once from the app bundle. nil logs and fails closed.
    static let embeddedIdentity: Identity? = {
        let id = identity(from: CashTreesPWABundleStore.embeddedBuildFacts())
        if id == nil { print("[NativeBridgeTrust] embedded identity unavailable (BeamioPWABuild.json missing or invalid): fail closed") }
        return id
    }()

    /// An empty value never equals a real digest, so a missing identity denies every check.
    static var expectedPwaVersion: String { embeddedIdentity?.version ?? "" }
    static var expectedEmbeddedZipSHA256: String { embeddedIdentity?.zipSHA256 ?? "" }
    static var expectedActiveTreeSHA256: String { embeddedIdentity?.treeSHA256 ?? "" }

    /// Error code for a command whose SOURCE does not match (the untrusted-source gate). v164 §184.1–184.2 and
    /// §25.52Y.44 item 4: a source or frame mismatch is origin_refused for every command. Only the legacy commands
    /// (pwaWalletSync, nativeMnemonicPreread) keep untrusted_source.
    static func untrustedSourceErrorCode(forCommand type: String) -> String {
        switch type {
        case "shellRecordRead", "shellRecordWrite", "walletCredential": return "origin_refused"
        default: return "untrusted_source"
        }
    }

    static func allowsPageCommand(_ type: String) -> Bool {
        // This operation accepts arbitrary page-supplied armor and returns plaintext. PGP
        // decrypt is performed by native mailbox/voice paths after their own provenance checks.
        type != "pgpDecryptInbound"
    }

    static func documentGenerationMatches(capturedAtNavigation: String?, currentActive: String?) -> Bool {
        guard let capturedAtNavigation, let currentActive else { return false }
        return capturedAtNavigation == expectedActiveTreeSHA256
            && currentActive == expectedActiveTreeSHA256
            && capturedAtNavigation == currentActive
    }

    static func isTrusted(
        isMainFrame: Bool,
        scheme: String,
        host: String,
        port: Int,
        activeVersion: String,
        embeddedZipSHA256: String,
        activeTreeSHA256: String
    ) -> Bool {
        isMainFrame
            && scheme.lowercased() == CashTreesPWAScheme.scheme
            && host.lowercased() == CashTreesPWAScheme.host
            && port == 0
            && activeVersion == expectedPwaVersion
            && embeddedZipSHA256.lowercased() == expectedEmbeddedZipSHA256
            && activeTreeSHA256.lowercased() == expectedActiveTreeSHA256
    }

    static func currentBundleIsTrusted(
        isMainFrame: Bool,
        scheme: String,
        host: String,
        port: Int,
        documentTreeSHA256: String?,
        frameDocumentURL: URL?,
        committedDocumentURL: URL?
    ) -> Bool {
        // This generation is captured by the native navigation delegate before
        // the document commits. A page cannot self-assert a newer URL/token after
        // an OTA promotion to inherit trust from the newly active tree.
        bundleTrusted(
            isMainFrame: isMainFrame,
            scheme: scheme,
            host: host,
            port: port,
            frameDocumentURL: frameDocumentURL,
            committedDocumentURL: committedDocumentURL,
            generationMatches: documentGenerationMatches(
                capturedAtNavigation: documentTreeSHA256,
                currentActive: CashTreesPWABundleStore.shared.activeTreeSHA256(digest: treeDigestOfActive(_:))
            ),
            zipMatches: embeddedZipMatches(),
            activeBundleMatches: CashTreesPWABundleStore.shared.activeBundleMatches(
                expectedVersion: expectedPwaVersion,
                expectedTreeSHA256: expectedActiveTreeSHA256,
                digest: treeDigestOfActive(_:)
            )
        )
    }

    /// The runtime decision, with its evidence given as values. Each piece is evaluated only when the order reaches it: the zip
    /// digest is costly and is not computed when the generation already failed. Tests drive this with synthetic evidence to show
    /// that each axis (frame, scheme, host, port, document) is decided by `isTrusted`, not by the missing bundle.
    static func bundleTrusted(
        isMainFrame: Bool,
        scheme: String,
        host: String,
        port: Int,
        frameDocumentURL: URL?,
        committedDocumentURL: URL?,
        generationMatches: @autoclosure () -> Bool,
        zipMatches: @autoclosure () -> Bool,
        activeBundleMatches: @autoclosure () -> Bool
    ) -> Bool {
        guard frameDocumentURL != nil,
              frameDocumentURL?.absoluteString == committedDocumentURL?.absoluteString,
              generationMatches()
        else { return false }
        guard zipMatches() else { return false }
        return activeBundleMatches() && isTrusted(
            isMainFrame: isMainFrame,
            scheme: scheme,
            host: host,
            port: port,
            activeVersion: expectedPwaVersion,
            embeddedZipSHA256: expectedEmbeddedZipSHA256,
            activeTreeSHA256: expectedActiveTreeSHA256
        )
    }

    /// The embedded SilentPassUI.zip matches the pinned digest.
    static func embeddedZipMatches() -> Bool {
        guard let zip = Bundle.main.url(forResource: "SilentPassUI", withExtension: "zip"),
              let zipData = try? Data(contentsOf: zip, options: .mappedIfSafe)
        else { return false }
        return digest(zipData) == expectedEmbeddedZipSHA256
    }

    /// The gate's tree digest is the build algorithm itself: one implementation, no second copy.
    nonisolated static func treeDigestOfActive(_ root: URL) -> String? {
        CashTreesPWASameVersionRule.treeDigest(at: root)
    }

    nonisolated static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
