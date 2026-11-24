import Foundation
import UIKit

/// External links from the page (`CashTreesIOS.openURL({ url })`).
///
/// The `openURL` action is not gated by the bundle trust check (`NativeBridgeTrust`): the page's client-side routes
/// (HashRouter fragments such as `#/chat`) do not change the document, and an external link is handed to the system
/// as-is. Only the URL rules below apply: a non-empty URL with a scheme on the allowlist. Every other bridge action
/// keeps the trust check unchanged (`BeamioBridgeRoute`).
enum BeamioExternalURL {
    /// http(s)/mailto/tel, plus catalog wallet schemes. Native opens the page URL as-is; no package or scheme URL is invented.
    static let allowedSchemes: Set<String> = [
        "http", "https", "mailto", "tel",
        // EIP-681 (`ethereum:0x…@8453/transfer?…`) for Coinbase Wallet / system wallet handoff.
        "ethereum",
        "metamask", "cbwallet", "coinbase", "base",
        "okx", "okex", "tpdapp", "tpoutside", "phantom", "trust",
    ]

    /// The URL to open for a raw page value, or nil when it is empty, unparsable, has no scheme or a scheme off the allowlist.
    static func urlToOpen(_ raw: String?) -> URL? {
        let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !trimmed.isEmpty, let url = URL(string: trimmed), let scheme = url.scheme?.lowercased() else { return nil }
        guard allowedSchemes.contains(scheme) else { return nil }
        return url
    }

    /// Opens the raw page value through `opener` when `urlToOpen` accepts it. Returns whether `opener` was called.
    @discardableResult
    static func open(_ raw: String?, opener: (URL) -> Void) -> Bool {
        guard let url = urlToOpen(raw) else { return false }
        opener(url)
        return true
    }

    /// The system opener used by the shell.
    static let systemOpener: (URL) -> Void = { url in
        UIApplication.shared.open(url, options: [:], completionHandler: nil)
    }
}

/// How the bridge handles one page action given the bundle trust result.
enum BeamioBridgeRoute: Equatable {
    /// `openURL`: handed to `BeamioExternalURL` whatever the trust result.
    case openExternal
    /// A trusted action: the normal dispatch.
    case dispatch
    /// An untrusted action other than `openURL`: refused (as before).
    case refuse

    static func route(action: String, trusted: Bool) -> BeamioBridgeRoute {
        if action == "openURL" { return .openExternal }
        return trusted ? .dispatch : .refuse
    }
}
