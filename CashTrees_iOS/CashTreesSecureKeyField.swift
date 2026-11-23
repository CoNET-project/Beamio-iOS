import UIKit

/// Secure input for key material on the native import screen.
///
/// UIKit's standard paste into a text field posts an accessibility announcement carrying the pasted text ("<text>, paste",
/// notification 1008) whenever an accessibility client is active (VoiceOver, Switch Control, UI automation). It does so
/// even with `isSecureTextEntry`, and `com.apple.Accessibility` writes that announcement to the unified log at Info level,
/// so a pasted private key ended up in the system log in plain text.
///
/// This field never lets UIKit run its paste path:
/// - `paste(_:)` reads the pasteboard itself, clears the pasteboard at once, writes the text into the field without any
///   announcement, and posts only a neutral announcement ("Pasted").
/// - The paste-configuration route (`paste(itemProviders:)`) and text drag-and-drop are off.
/// - `accessibilityValue` is a mask, never the text.
final class CashTreesSecureKeyField: UITextField, UITextDropDelegate {
    /// Neutral announcement after a paste. Never contains the text.
    var pastedAnnouncement = "Pasted"

    /// Where the pasted text comes from and how it is cleared. Tests use a private pasteboard.
    var pasteboard: UIPasteboard = .general

    /// Accessibility notification hook (tests record it instead of posting).
    var announce: (String) -> Void = { UIAccessibility.post(notification: .announcement, argument: $0) }

    override init(frame: CGRect) {
        super.init(frame: frame)
        configure()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        configure()
    }

    private func configure() {
        isSecureTextEntry = true
        autocapitalizationType = .none
        autocorrectionType = .no
        spellCheckingType = .no
        smartQuotesType = .no
        smartDashesType = .no
        smartInsertDeleteType = .no
        textContentType = nil
        pasteConfiguration = nil
        textDragInteraction?.isEnabled = false
        textDropDelegate = self
    }

    // MARK: Paste

    override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool {
        if action == #selector(paste(_:)) { return pasteboard.hasStrings }
        // No copy, cut, select, look up, share or replace on key material.
        return false
    }

    override func paste(_ sender: Any?) {
        guard let raw = pasteboard.string, !raw.isEmpty else { return }
        clearPasteboard()
        insertWithoutAnnouncement(raw)
        announce(pastedAnnouncement)
    }

    /// The UIPasteConfiguration route is turned off; nothing is pasted this way.
    override func paste(itemProviders: [NSItemProvider]) {}

    /// Clears the pasteboard right after the read. The shell never writes key material to the pasteboard itself.
    func clearPasteboard() {
        pasteboard.items = []
    }

    /// Replaces the selection (or appends) by setting `text` directly: a programmatic change posts no announcement.
    private func insertWithoutAnnouncement(_ s: String) {
        let current = text ?? ""
        if let range = selectedTextRange {
            let start = offset(from: beginningOfDocument, to: range.start)
            let end = offset(from: beginningOfDocument, to: range.end)
            let ns = current as NSString
            if start >= 0, end >= start, end <= ns.length {
                text = ns.replacingCharacters(in: NSRange(location: start, length: end - start), with: s)
                if let pos = position(from: beginningOfDocument, offset: start + (s as NSString).length) {
                    selectedTextRange = textRange(from: pos, to: pos)
                }
                sendActions(for: .editingChanged)
                return
            }
        }
        text = current + s
        sendActions(for: .editingChanged)
    }

    // MARK: Accessibility

    /// A mask instead of the text (one bullet per character, at most 8, so the length is not read out exactly).
    override var accessibilityValue: String? {
        get {
            let n = (text ?? "").count
            return n == 0 ? nil : String(repeating: "•", count: min(n, 8))
        }
        set {}
    }

    // MARK: Drop

    func textDroppableView(_ textDroppableView: UIView & UITextDroppable,
                           proposalForDrop drop: UITextDropRequest) -> UITextDropProposal {
        UITextDropProposal(operation: .forbidden)
    }
}
