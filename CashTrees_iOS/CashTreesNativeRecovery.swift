import ConetChatSDK
import UIKit

/// Native recovery page (spec v1.1-r3u §25.42.4). Two paths: A, the recovery code; B, account name and password.
/// The shell only hosts the page. It checks the input format, hands the secret to the SDK recovery engine as bytes it
/// then wipes, and shows the result code. It never parses, decrypts or derives anything and calls no HTTP API.
///
/// Wired to the SDK: `BeamioNativeRecovery.onRecoveryRequired` presents the page and returns whether it is
/// open (§25.41.3); each attempt runs `BeamioNativeRecovery.restore` off the main queue and reports with `finish`.
/// Without X-19 the engine answers `not_supported`, shown as "not available on this device".

/// Result codes of `nativeRecoveryResult` (§25.42.8).
enum CashTreesRecoveryCode: String, CaseIterable {
    case ok, cancelled
    case invalidFormat = "invalid_format"
    case badPin = "bad_pin"
    case backoff
    case notFound = "not_found"
    case networkError = "network_error"
    case alreadyExists = "already_exists"
    case recordInvalid = "record_invalid"
    case writeFailed = "write_failed"
    case readbackFailed = "readback_failed"
    case legacyRecord = "legacy_record"
    case notSupported = "not_supported"
}

/// What the page hands to the engine. The secret is bytes the engine wipes after use; the page wipes its own copy.
enum CashTreesRecoveryRequest {
    case code(secret: [UInt8])
    case account(name: String, password: [UInt8])
}

/// The engine seam: `CashTreesSdkRecoveryEngine` in the app, a fake in tests.
protocol CashTreesRecoveryEngine: AnyObject {
    /// One submit; `done` is called on the main queue with the code and, for `backoff`, the remaining seconds.
    func submit(_ request: CashTreesRecoveryRequest, done: @escaping (CashTreesRecoveryCode, Int?) -> Void)
    /// The page closed. `hadResult` false means the SDK sends `cancelled` (§25.42.8).
    func pageClosed(hadResult: Bool)
}

/// The SDK engine (BeamioNativeRecovery, spec 25.42.5). `restore` reads the chain, so it runs off the main queue.
/// Each outcome goes to the open page and to the bridge (`finish`); closing before any result sends `cancelled`.
final class CashTreesSdkRecoveryEngine: CashTreesRecoveryEngine {
    func submit(_ request: CashTreesRecoveryRequest, done: @escaping (CashTreesRecoveryCode, Int?) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            let outcome: BeamioNativeRecovery.RestoreOutcome
            switch request {
            case .code(var bytes):
                // The SDK takes the code as a String (recorded limit: Swift strings cannot be wiped, §25.42.9).
                let code = String(decoding: bytes, as: UTF8.self)
                for i in bytes.indices { bytes[i] = 0 }
                outcome = BeamioNativeRecovery.restore(.recoveryCode(code))
            case .account(let name, var password):
                outcome = BeamioNativeRecovery.restore(.account(name: name, password: password))
                for i in password.indices { password[i] = 0 }
            }
            let (code, eoa, cooldown) = Self.map(outcome)
            DispatchQueue.main.async {
                BeamioNativeRecovery.finish(code, eoa: eoa, cooldownSec: cooldown)
                done(CashTreesRecoveryCode(rawValue: code.rawValue) ?? .notSupported, cooldown)
            }
        }
    }

    func pageClosed(hadResult: Bool) {
        if !hadResult { BeamioNativeRecovery.finish(.cancelled) }
    }

    static func map(_ o: BeamioNativeRecovery.RestoreOutcome) -> (BeamioNativeRecovery.ResultCode, String?, Int?) {
        switch o {
        case .ok(let eoa): return (.ok, eoa, nil)
        case .backoff(let s): return (.backoff, nil, s)
        case .failed(let c): return (c, nil, nil)
        }
    }
}

/// Presents the page for the SDK (`onRecoveryRequired`).
enum CashTreesNativeRecoveryRoute {
    static let recoveredNotification = Notification.Name("CashTreesNativeRecovered")
    private static let lock = NSLock()
    private static var installed = false

    static func installOnce() {
        lock.lock()
        defer { lock.unlock() }
        guard !installed else { return }
        installed = true
        BeamioNativeRecovery.onRecoveryRequired = { _ in
            if Thread.isMainThread { return present() }
            return DispatchQueue.main.sync { present() }
        }
    }

    /// True when the page is (or already was) on screen.
    @discardableResult
    static func present(engine: CashTreesRecoveryEngine = CashTreesSdkRecoveryEngine()) -> Bool {
        guard Thread.isMainThread else { return DispatchQueue.main.sync { present(engine: engine) } }
        let windows = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.flatMap { $0.windows }
        var top = (windows.first(where: { $0.isKeyWindow }) ?? windows.first)?.rootViewController
        while let p = top?.presentedViewController { top = p }
        guard let host = top else { return false }
        if host is CashTreesNativeRecoveryViewController { return true }
        BeamioQALog.write("native recovery page presented")
        let vc = CashTreesNativeRecoveryViewController(copy: .forLanguages(Locale.preferredLanguages), engine: engine)
        vc.modalPresentationStyle = .fullScreen
        vc.onFinished = { code in
            if code == .ok { NotificationCenter.default.post(name: recoveredNotification, object: nil) }
        }
        host.present(vc, animated: true)
        return true
    }
}

/// Input checks done on the page before anything reaches the engine (§25.42.4).
enum CashTreesNativeRecoveryInput {
    /// ASCII whitespace trimmed from both ends of the recovery code.
    private static let asciiSpace = CharacterSet(charactersIn: " \t\n\r\u{0B}\u{0C}")
    private static let alnum = CharacterSet(charactersIn: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

    /// Path A: 22 characters of [0-9A-Za-z] after trimming ASCII whitespace. Nil means `invalid_format`.
    static func normalizedCode(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: asciiSpace)
        guard s.unicodeScalars.count == 22, s.unicodeScalars.allSatisfy({ alnum.contains($0) }) else { return nil }
        return s
    }

    /// Path B, the BeamioTag rule of the PWA (beamio-UI `normalizeBeamioTagInput`, then `BEAMIO_TAG_PATTERN`): every "@" removed,
    /// trimmed, NFKC, zero-width characters (U+200B to U+200D, U+FEFF) removed; then 3 to 26 characters of [a-zA-Z0-9_.].
    /// Case is kept (the registry key is case-sensitive). Nil means the name is not a BeamioTag: no query is made.
    static func beamioTagName(_ raw: String) -> String? {
        let noAt = raw.replacingOccurrences(of: "@", with: "")
        let trimmed = noAt.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalised = trimmed.precomposedStringWithCompatibilityMapping
        var stripped = String.UnicodeScalarView()
        stripped.append(contentsOf: normalised.unicodeScalars.filter { !((0x200B ... 0x200D).contains($0.value) || $0.value == 0xFEFF) })
        let name = String(stripped)
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.")
        guard (3 ... 26).contains(name.unicodeScalars.count), name.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return nil }
        return name
    }

    /// Path B: the BeamioTag (see `beamioTagName`) and the password as typed. Nil means no query is made.
    static func account(name: String, password: String) -> (name: String, password: String)? {
        guard let tag = beamioTagName(name), !password.isEmpty else { return nil }
        return (tag, password)
    }

    static func wipe(_ request: CashTreesRecoveryRequest) {
        switch request {
        case .code(var s): for i in s.indices { s[i] = 0 }
        case .account(_, var p): for i in p.indices { p[i] = 0 }
        }
    }
}

/// Page copy, English and Chinese by system language (same rule as the import page).
struct CashTreesNativeRecoveryCopy: Equatable {
    let title, choose, pathCode, pathAccount, codePlaceholder, namePlaceholder, passwordPlaceholder: String
    let submit, back, cancel, working, pasted: String
    let messages: [String: String]

    static let en = CashTreesNativeRecoveryCopy(
        title: "Restore wallet", choose: "How do you want to restore?",
        pathCode: "Recovery code", pathAccount: "Account name and password",
        codePlaceholder: "Recovery code (22 characters)", namePlaceholder: "Account name", passwordPlaceholder: "Password",
        submit: "Restore", back: "Back", cancel: "Cancel", working: "Restoring…", pasted: "Pasted",
        messages: [
            "ok": "Restored", "invalid_format": "Check the input and try again.", "tag_format": "Use 3–26 letters, numbers, dots, or underscores", "bad_pin": "The password is not correct.",
            "backoff": "Too many attempts. Try again in %d seconds.", "not_found": "No record was found.",
            "network_error": "Could not connect. Try again later.",
            "already_exists": "This device already has a wallet key. Nothing was changed.",
            "record_invalid": "The record could not be read.", "write_failed": "Could not save. Try again.",
            "readback_failed": "Could not save. Try again.",
            "legacy_record": "This account uses an older record that this version cannot restore yet.",
            "not_supported": "Restore is not available on this device.",
        ])

    static let zh = CashTreesNativeRecoveryCopy(
        title: "恢复钱包", choose: "选择恢复方式",
        pathCode: "恢复码", pathAccount: "账号名与密码",
        codePlaceholder: "恢复码（22 位）", namePlaceholder: "账号名", passwordPlaceholder: "密码",
        submit: "恢复", back: "返回", cancel: "取消", working: "正在恢复…", pasted: "已粘贴",
        messages: [
            "ok": "已恢复", "invalid_format": "请检查输入后重试。", "tag_format": "请使用 3–26 个字母、数字、点或下划线", "bad_pin": "密码不正确。",
            "backoff": "尝试次数过多，请 %d 秒后再试。", "not_found": "未找到记录。",
            "network_error": "无法连接，请稍后重试。", "already_exists": "本设备已有钱包密钥，未做任何改动。",
            "record_invalid": "记录无法读取。", "write_failed": "保存失败，请重试。", "readback_failed": "保存失败，请重试。",
            "legacy_record": "该账号使用旧版记录，本版本暂不支持恢复。",
            "not_supported": "本设备暂不支持恢复。",
        ])

    static func forLanguages(_ preferred: [String]) -> CashTreesNativeRecoveryCopy {
        (preferred.first ?? "").lowercased().hasPrefix("zh") ? zh : en
    }

    /// The text for a code; `cancelled` has none.
    func message(for code: CashTreesRecoveryCode, cooldownSec: Int? = nil) -> String? {
        guard code != .cancelled, let m = messages[code.rawValue] else { return nil }
        return code == .backoff ? String(format: m, cooldownSec ?? 0) : m
    }
}

/// The page. First screen: choose the path. Then one form. Failures keep the page open; `ok` closes it.
final class CashTreesNativeRecoveryViewController: UIViewController {
    private let copy: CashTreesNativeRecoveryCopy
    private let engine: CashTreesRecoveryEngine
    private(set) var hadResult = false
    var onFinished: ((CashTreesRecoveryCode?) -> Void)?

    private let codeField = CashTreesSecureKeyField()
    private let nameField = UITextField()
    private let passwordField = CashTreesSecureKeyField()
    private let statusLabel = UILabel()
    private let submitButton = UIButton(type: .system)
    private let chooser = UIStackView()
    private let form = UIStackView()
    private var path: Character = "A"
    private var busy = false
    private var shield: UIView?

    init(copy: CashTreesNativeRecoveryCopy, engine: CashTreesRecoveryEngine) {
        self.copy = copy
        self.engine = engine
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { nil }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(red: 7 / 255, green: 17 / 255, blue: 38 / 255, alpha: 1)
        let title = label(copy.title, size: 20, weight: .semibold)
        title.accessibilityTraits = .header

        chooser.axis = .vertical
        chooser.spacing = 12
        chooser.addArrangedSubview(label(copy.choose, size: 14, weight: .regular))
        chooser.addArrangedSubview(button(copy.pathCode, id: "nativeRecovery.pathCode") { [weak self] in self?.show(path: "A") })
        chooser.addArrangedSubview(button(copy.pathAccount, id: "nativeRecovery.pathAccount") { [weak self] in self?.show(path: "B") })

        for f in [codeField, passwordField] {
            f.pastedAnnouncement = copy.pasted
            f.keyboardType = .asciiCapable
            styleField(f)
        }
        codeField.placeholder = copy.codePlaceholder
        codeField.accessibilityLabel = copy.codePlaceholder
        codeField.accessibilityIdentifier = "nativeRecovery.code"
        passwordField.placeholder = copy.passwordPlaceholder
        passwordField.accessibilityLabel = copy.passwordPlaceholder
        passwordField.accessibilityIdentifier = "nativeRecovery.password"
        nameField.placeholder = copy.namePlaceholder
        nameField.autocorrectionType = .no
        nameField.autocapitalizationType = .none
        nameField.spellCheckingType = .no
        nameField.smartQuotesType = .no
        nameField.smartDashesType = .no
        nameField.textContentType = nil
        nameField.accessibilityIdentifier = "nativeRecovery.name"
        styleField(nameField)

        statusLabel.font = .systemFont(ofSize: 14)
        statusLabel.textColor = UIColor(red: 253 / 255, green: 230 / 255, blue: 138 / 255, alpha: 1)
        statusLabel.numberOfLines = 0
        statusLabel.textAlignment = .center
        statusLabel.isHidden = true
        statusLabel.accessibilityIdentifier = "nativeRecovery.status"

        var pill = UIButton.Configuration.filled()
        pill.baseBackgroundColor = .white
        pill.baseForegroundColor = view.backgroundColor
        pill.cornerStyle = .capsule
        pill.title = copy.submit
        submitButton.configuration = pill
        submitButton.accessibilityIdentifier = "nativeRecovery.submit"
        submitButton.addTarget(self, action: #selector(submit), for: .touchUpInside)

        form.axis = .vertical
        form.spacing = 12
        form.isHidden = true
        [codeField, nameField, passwordField, statusLabel, submitButton].forEach { form.addArrangedSubview($0) }
        form.addArrangedSubview(button(copy.back, id: "nativeRecovery.back") { [weak self] in self?.showChooser() })

        let cancel = button(copy.cancel, id: "nativeRecovery.cancel") { [weak self] in self?.close(nil) }
        let stack = UIStackView(arrangedSubviews: [title, chooser, form, cancel])
        stack.axis = .vertical
        stack.spacing = 20
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -24),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: view.keyboardLayoutGuide.topAnchor, constant: -16),
            codeField.heightAnchor.constraint(equalToConstant: 44),
            nameField.heightAnchor.constraint(equalToConstant: 44),
            passwordField.heightAnchor.constraint(equalToConstant: 44),
        ])

        // §25.42.4 item 9: cover the page while the app is in the background (app switcher snapshot).
        let nc = NotificationCenter.default
        nc.addObserver(self, selector: #selector(coverContent), name: UIApplication.willResignActiveNotification, object: nil)
        nc.addObserver(self, selector: #selector(uncoverContent), name: UIApplication.didBecomeActiveNotification, object: nil)
    }

    // MARK: - Paths

    func show(path p: Character) {
        path = p
        chooser.isHidden = true
        form.isHidden = false
        codeField.isHidden = p != "A"
        nameField.isHidden = p != "B"
        passwordField.isHidden = p != "B"
        statusLabel.isHidden = true
        (p == "A" ? codeField : nameField).becomeFirstResponder()
    }

    private func showChooser() {
        clearInputs()
        form.isHidden = true
        chooser.isHidden = false
    }

    // MARK: - Submit

    @objc func submit() {
        guard !busy else { return }  // §25.42.4 item 5: no double submit
        let request: CashTreesRecoveryRequest
        if path == "A" {
            let raw = codeField.text ?? ""
            codeField.text = ""
            guard let code = CashTreesNativeRecoveryInput.normalizedCode(raw) else { return show(.invalidFormat, nil) }
            request = .code(secret: Array(code.utf8))
        } else {
            let pw = passwordField.text ?? ""
            passwordField.text = ""
            guard let tag = CashTreesNativeRecoveryInput.beamioTagName(nameField.text ?? "") else {
                return showFormatMessage(copy.messages["tag_format"] ?? "")  // the PWA message; no query is made
            }
            guard let acc = CashTreesNativeRecoveryInput.account(name: tag, password: pw) else {
                return show(.invalidFormat, nil)
            }
            request = .account(name: acc.name, password: Array(acc.password.utf8))
        }
        busy = true
        submitButton.isEnabled = false
        statusLabel.text = copy.working
        statusLabel.isHidden = false
        engine.submit(request) { [weak self] code, cooldown in self?.show(code, cooldown) }
    }

    /// Shows a format message on the page (no SDK call, the form stays usable).
    private func showFormatMessage(_ text: String) {
        busy = false
        submitButton.isEnabled = true
        statusLabel.text = text
        statusLabel.isHidden = text.isEmpty
    }

    private func show(_ code: CashTreesRecoveryCode, _ cooldown: Int?) {
        hadResult = true
        busy = false
        submitButton.isEnabled = true
        let message = copy.message(for: code, cooldownSec: cooldown) ?? ""
        statusLabel.text = message
        statusLabel.isHidden = message.isEmpty
        BeamioQALog.write("native recovery result \(code.rawValue)")  // code only, never the input
        UIAccessibility.post(notification: .announcement, argument: message)
        if code == .ok {
            submitButton.isEnabled = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) { [weak self] in self?.close(.ok) }
        }
    }

    private func close(_ code: CashTreesRecoveryCode?) {
        clearInputs()
        engine.pageClosed(hadResult: hadResult)
        dismiss(animated: true) { [weak self] in self?.onFinished?(code) }
    }

    private func clearInputs() {
        codeField.text = ""
        passwordField.text = ""
        nameField.text = ""
    }

    // MARK: - Background shield

    @objc private func coverContent() {
        guard shield == nil else { return }
        let v = UIView(frame: view.bounds)
        v.backgroundColor = view.backgroundColor
        v.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        v.accessibilityIdentifier = "nativeRecovery.shield"
        view.addSubview(v)
        shield = v
    }

    @objc private func uncoverContent() {
        shield?.removeFromSuperview()
        shield = nil
    }

    var isShielded: Bool { shield != nil }

    // MARK: - Small helpers

    private func label(_ text: String, size: CGFloat, weight: UIFont.Weight) -> UILabel {
        let l = UILabel()
        l.text = text
        l.font = .systemFont(ofSize: size, weight: weight)
        l.textColor = .white
        l.textAlignment = .center
        l.numberOfLines = 0
        return l
    }

    private func button(_ title: String, id: String, action: @escaping () -> Void) -> UIButton {
        let b = UIButton(type: .system, primaryAction: UIAction { _ in action() })
        b.setTitle(title, for: .normal)
        b.setTitleColor(.white, for: .normal)
        b.accessibilityIdentifier = id
        return b
    }

    private func styleField(_ f: UITextField) {
        f.borderStyle = .roundedRect
        f.backgroundColor = .white
        f.textColor = UIColor(red: 7 / 255, green: 17 / 255, blue: 38 / 255, alpha: 1)
    }
}
