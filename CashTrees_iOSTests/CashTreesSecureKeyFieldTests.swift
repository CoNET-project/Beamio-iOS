//
//  CashTreesSecureKeyFieldTests.swift
//  CashTrees_iOSTests
//
//  The secure key field (kept after the native recovery page was removed; no screen uses it now): the paste-leak fix and its regression tests: the pasted text goes into the field, the pasteboard is
//  cleared at once, the only announcement is the neutral one, and the accessibility value is a mask.
//  Synthetic text only (never a real key). Uses a private named pasteboard, not the general one.
//

import Testing
import UIKit
@testable import CashTrees_iOS

@MainActor
struct CashTreesSecureKeyFieldTests {
    private static let synthetic = String(repeating: "ab", count: 32)  // 64 hex characters, synthetic

    private func makeField() -> (CashTreesSecureKeyField, UIPasteboard, [String]) {
        let board = UIPasteboard(name: UIPasteboard.Name("qa-secure-key-field-\(UUID().uuidString)"), create: true)!
        let field = CashTreesSecureKeyField(frame: .zero)
        field.pasteboard = board
        return (field, board, [])
    }

    @Test func pasteWritesTheTextClearsThePasteboardAndAnnouncesOnlyTheNeutralText() {
        let (field, board, _) = makeField()
        var announced: [String] = []
        field.announce = { announced.append($0) }
        field.pastedAnnouncement = "Pasted"
        board.string = Self.synthetic

        #expect(field.canPerformAction(#selector(UIResponderStandardEditActions.paste(_:)), withSender: nil))
        field.paste(nil)

        #expect(field.text == Self.synthetic)
        #expect(!board.hasStrings, "pasteboard cleared right after the read")
        #expect(announced == ["Pasted"])
        #expect(!announced.joined().contains(Self.synthetic))
        UIPasteboard.remove(withName: board.name)
    }

    @Test func pasteWithAnEmptyPasteboardDoesNothing() {
        let (field, board, _) = makeField()
        var announced: [String] = []
        field.announce = { announced.append($0) }
        #expect(!field.canPerformAction(#selector(UIResponderStandardEditActions.paste(_:)), withSender: nil))
        field.paste(nil)
        #expect((field.text ?? "").isEmpty)
        #expect(announced.isEmpty)
        UIPasteboard.remove(withName: board.name)
    }

    @Test func accessibilityValueIsAMask() {
        let (field, board, _) = makeField()
        #expect(field.accessibilityValue == nil)
        field.text = Self.synthetic
        let v = field.accessibilityValue ?? ""
        #expect(!v.contains("ab"))
        #expect(v == String(repeating: "•", count: 8))
        field.text = "abc"
        #expect(field.accessibilityValue == "•••")
        UIPasteboard.remove(withName: board.name)
    }

    @Test func noOtherEditActionsAndNoDropOrPasteConfiguration() {
        let (field, board, _) = makeField()
        field.text = Self.synthetic
        for action in [#selector(UIResponderStandardEditActions.copy(_:)), #selector(UIResponderStandardEditActions.cut(_:)),
                       #selector(UIResponderStandardEditActions.select(_:)), #selector(UIResponderStandardEditActions.selectAll(_:))] {
            #expect(!field.canPerformAction(action, withSender: nil), "\(action)")
        }
        #expect(field.isSecureTextEntry)
        #expect(field.textContentType == nil)
        #expect(field.autocorrectionType == .no)
        #expect(field.pasteConfiguration == nil)
        #expect(field.textDropDelegate === field)
        UIPasteboard.remove(withName: board.name)
    }
}
