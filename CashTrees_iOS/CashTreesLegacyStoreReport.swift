import Combine
import ConetChatSDK
import Foundation
import WebKit

/// Reports the legacy store (the old PWA data kept by WebKit for the old origin) to the SDK, and holds the WebView until the
/// report is written. The SDK does not read the legacy store (§25.52PY.15); the shell judges it (§25.52K.2).
///
/// Judgement by origin, without reading any content (WKWebsiteDataStore.fetchDataRecords, no file paths):
/// - a record whose display name is `beamio.app` (the old origin https://beamio.app) → `unreadable`. The reader that would
///   read it is not implemented yet, so the state is unknown and retried; nothing is onboarded and nothing is written.
/// - no such record → `absent`. The current PWA (cashtrees-local://localhost, display name `localhost`) never counts.
/// - the callback does not arrive within the timeout → `unreadable` (read failure).
/// `found` is never reported here: it needs a verified wallet record.
@MainActor
final class CashTreesLegacyStoreGate: ObservableObject {
	static let shared = CashTreesLegacyStoreGate()

	/// The old origin's display name, as WebKit lists it (the host of https://beamio.app).
	static let legacyDisplayName = "beamio.app"
	/// Upper bound for the callback. A timeout is a read failure (unknown), never absence.
	static let timeoutSeconds: TimeInterval = 5

	enum Kind: String {
		case absent
		case unreadable
	}

	/// The judgement from the display names of the website data records. Pure: no store access.
	static func judge(displayNames: [String]) -> Kind {
		displayNames.contains { $0.lowercased() == legacyDisplayName } ? .unreadable : .absent
	}

	/// True once the report is written (or failed). The WebView is created only after this.
	@Published private(set) var isReady = false
	private var started = false
	private var finished = false

	/// Starts the report once. Called from the SwiftUI body; the callback runs on the main thread.
	func start() {
		guard !started else { return }
		started = true
		let types: Set<String> = [
			WKWebsiteDataTypeIndexedDBDatabases,
			WKWebsiteDataTypeWebSQLDatabases,
			WKWebsiteDataTypeLocalStorage,
		]
		WKWebsiteDataStore.default().fetchDataRecords(ofTypes: types) { [weak self] records in
			let names = records.map { $0.displayName }
			self?.finish(kind: Self.judge(displayNames: names), recordCount: names.count)
		}
		DispatchQueue.main.asyncAfter(deadline: .now() + Self.timeoutSeconds) { [weak self] in
			self?.finish(kind: .unreadable, recordCount: -1)
		}
	}

	private func finish(kind: Kind, recordCount: Int) {
		guard !finished else { return }
		finished = true
		let result: BeamioShellRecord.LegacyReportResult
		switch kind {
		case .absent: result = BeamioShellRecord.reportLegacyStore(.absent)
		case .unreadable: result = BeamioShellRecord.reportLegacyStore(.unreadable)
		}
		// Counts and the kind only: no display names, no content.
		NSLog("[LegacyStoreReport] reported=%@ result=%@ records=%d", kind.rawValue, result.rawValue, recordCount)
		isReady = true
	}
}
