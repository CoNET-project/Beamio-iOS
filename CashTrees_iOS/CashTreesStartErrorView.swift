//
//  CashTreesStartErrorView.swift
//  CashTrees_iOS
//
//  Shown when the local PWA bundle could not be prepared at start, or when the background content check found a
//  bundle that is not the embedded build. A clear error and a retry control. Platform UI; no user data is shown.
//

import SwiftUI

enum CashTreesStartErrorKind: Equatable {
    case startFailed
    case contentCheckFailed
}

struct CashTreesStartErrorCopy: Equatable {
    let title: String
    let body: String
    let retry: String

    static func forLanguages(_ preferred: [String], kind: CashTreesStartErrorKind) -> CashTreesStartErrorCopy {
        let lang = (preferred.first ?? "").lowercased()
        let checkFailed = kind == .contentCheckFailed
        if lang.hasPrefix("zh") {
            return .init(
                title: checkFailed ? "应用内容校验未通过" : "Beamio 无法启动",
                body: checkFailed ? "应用内容需要修复。你的钱包和聊天不受影响。请点“重试”修复。"
                    : "应用内容未能准备好。你的钱包和聊天不受影响。",
                retry: "重试")
        }
        if lang.hasPrefix("ja") {
            return .init(
                title: checkFailed ? "アプリの内容を確認できませんでした" : "Beamio を起動できません",
                body: checkFailed ? "アプリの内容の修復が必要です。ウォレットとチャットには影響ありません。「再試行」をタップして修復してください。"
                    : "アプリの内容を準備できませんでした。ウォレットとチャットには影響ありません。",
                retry: "再試行")
        }
        return .init(
            title: checkFailed ? "App content check failed" : "Beamio couldn't start",
            body: checkFailed ? "The app content needs to be repaired. Your wallet and chats are not affected. Tap Try again to repair."
                : "The app content could not be prepared. Your wallet and chats are not affected.",
            retry: "Try again")
    }
}

struct CashTreesStartErrorView: View {
    let kind: CashTreesStartErrorKind
    let detail: String
    let onRetry: () -> Void

    var body: some View {
        let copy = CashTreesStartErrorCopy.forLanguages(Locale.preferredLanguages, kind: kind)
        VStack(spacing: 16) {
            Text(copy.title)
                .font(.title3.weight(.semibold))
                .foregroundStyle(.white)
                .multilineTextAlignment(.center)
            Text(copy.body)
                .font(.subheadline)
                .multilineTextAlignment(.center)
                .foregroundStyle(.white.opacity(0.8))
            Text(detail)
                .font(.footnote.monospaced())
                .multilineTextAlignment(.center)
                .foregroundStyle(.white.opacity(0.5))
                .lineLimit(3)
            Button(action: onRetry) {
                Text(copy.retry)
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("pwa-start-retry")
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(red: 0, green: 4 / 255, blue: 20 / 255).ignoresSafeArea())
    }
}
