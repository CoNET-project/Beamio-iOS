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
        /// "embedded" (BeamioPWABuild.json) or "ota" (signed OTA identity verified with a compiled-in key).
        var origin: String = "embedded"
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

    static func documentGenerationMatches(
        capturedAtNavigation: String?, currentActive: String?, expectedTree: String = expectedActiveTreeSHA256
    ) -> Bool {
        guard let capturedAtNavigation, let currentActive, !expectedTree.isEmpty else { return false }
        return capturedAtNavigation == expectedTree
            && currentActive == expectedTree
            && capturedAtNavigation == currentActive
    }

    static func isTrusted(
        isMainFrame: Bool,
        scheme: String,
        host: String,
        port: Int,
        activeVersion: String,
        embeddedZipSHA256: String,
        activeTreeSHA256: String,
        expected: Identity? = embeddedIdentity
    ) -> Bool {
        guard let expected, !expected.treeSHA256.isEmpty else { return false }
        return isMainFrame
            && scheme.lowercased() == CashTreesPWAScheme.scheme
            && host.lowercased() == CashTreesPWAScheme.host
            && port == 0
            && activeVersion == expected.version
            && embeddedZipSHA256.lowercased() == expectedEmbeddedZipSHA256
            && activeTreeSHA256.lowercased() == expected.treeSHA256
    }

    /// The identity the active bundle resolves to right now: the embedded build, or a signed OTA identity (compiled-in
    /// public key, payload contentDigest equal to the full active digest). Records, version claims and status files are
    /// never consulted. nil = no trusted identity (every command fails closed).
    static func resolvedIdentity() -> Identity? {
        guard let resolved = CashTreesPWABundleStore.shared.activeResolvedIdentity(
            embeddedVersion: expectedPwaVersion,
            embeddedTree: expectedActiveTreeSHA256,
            digest: treeDigestOfActive(_:)
        ) else { return nil }
        return Identity(version: resolved.version, zipSHA256: expectedEmbeddedZipSHA256, treeSHA256: resolved.tree,
                        origin: resolved.origin)
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
        let resolved = resolvedIdentity()
        return bundleTrusted(
            isMainFrame: isMainFrame,
            scheme: scheme,
            host: host,
            port: port,
            frameDocumentURL: frameDocumentURL,
            committedDocumentURL: committedDocumentURL,
            generationMatches: documentGenerationMatches(
                capturedAtNavigation: documentTreeSHA256,
                currentActive: CashTreesPWABundleStore.shared.activeTreeSHA256(digest: treeDigestOfActive(_:)),
                expectedTree: resolved?.treeSHA256 ?? ""
            ),
            zipMatches: embeddedZipMatches(),
            activeBundleMatches: resolved != nil,
            expected: resolved
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
        activeBundleMatches: @autoclosure () -> Bool,
        expected: Identity? = embeddedIdentity
    ) -> Bool {
        guard sameDocument(frameDocumentURL, committedDocumentURL),
              generationMatches()
        else { return false }
        guard zipMatches() else { return false }
        guard let expected else { return false }
        return activeBundleMatches() && isTrusted(
            isMainFrame: isMainFrame,
            scheme: scheme,
            host: host,
            port: port,
            activeVersion: expected.version,
            embeddedZipSHA256: expectedEmbeddedZipSHA256,
            activeTreeSHA256: expected.treeSHA256,
            expected: expected
        )
    }

    /// The frame's document is the committed document: both present and equal in everything but the fragment (scheme, user,
    /// host, port, path, query). The fragment carries the page's client-side route (HashRouter, for example `#/chat`) and does
    /// not change the document. A URL that cannot be split into components is never the same document.
    static func sameDocument(_ frame: URL?, _ committed: URL?) -> Bool {
        guard let frame, let committed,
              var a = URLComponents(url: frame, resolvingAgainstBaseURL: false),
              var b = URLComponents(url: committed, resolvingAgainstBaseURL: false)
        else { return false }
        a.fragment = nil
        b.fragment = nil
        guard let ua = a.url?.absoluteString, let ub = b.url?.absoluteString else { return false }
        return ua == ub
    }

    /// The embedded SilentPassUI.zip matches the pinned digest.
    /// The app bundle is read-only and sealed by the code signature, so the embedded ZIP is hashed once per process
    ///: the first call is a full SHA-256, later calls reuse that result.
    static func embeddedZipMatches() -> Bool {
        embeddedZipMatchesOnce
    }

    private static let embeddedZipMatchesOnce: Bool = {
        guard let zip = Bundle.main.url(forResource: "SilentPassUI", withExtension: "zip"),
              let zipData = try? Data(contentsOf: zip, options: .mappedIfSafe)
        else { return false }
        return digest(zipData) == expectedEmbeddedZipSHA256
    }()

    /// The gate's tree digest is the build algorithm itself: one implementation, no second copy.
    nonisolated static func treeDigestOfActive(_ root: URL) -> String? {
        CashTreesPWASameVersionRule.treeDigest(at: root)
    }

    nonisolated static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
