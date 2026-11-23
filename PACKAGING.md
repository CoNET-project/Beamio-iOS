# iOS 打包说明（Beamio 壳）

## 唯一允许的出包路径

所有 iOS QA 候选与正式包，只能由 `build-qa-adhoc.sh`（或经同一门禁的正式打包脚本）产出。
IDE 的 Archive、Xcode 直接导出等其他路径产出的包，**不得用于验收、真机、上传或发布**。

## 运行

```bash
export BEAMIO_SHELL_GATE=/绝对路径/verify-shell-pwa-version.sh   # 权威门禁（与 verify-delegated-freeze.py、verify-ios-single-zip.sh 同目录）
export BEAMIO_PWA_FROZEN_MANIFEST=/绝对路径/冻结清单（第一行为 ZIP sha256）
./build-qa-adhoc.sh <输出目录>
```

脚本顺序：

1. 校验门禁钉住哈希（已审门禁版本）：
   - `verify-shell-pwa-version.sh` `407b6dd922f0fd265d936215457d1daed24f7e5ca8b2b9f21e86b05971100390`
   - `verify-delegated-freeze.py` `26a43f7f19c3557bb673215815ffdf2a905aed70db2a2c560b4fe5e8c555b270`
   - `verify-ios-single-zip.sh` `990cb82bbc69949d5fb5606722e6c5e3f32d3d22015f011aad0606ed1bbb3a6a`
   不符即停止。
2. `ios-prebuild`（xcodebuild 之前，沙盒外）：退出码 0 为正式，4 为仅 QA（QA-ONLY-NOT-FROZEN），其他失败即停止。
3. `xcodebuild archive` 与 `-exportArchive`（Release，`BEAMIO_PWA_EXPECTED_ZIP_SHA256` 由冻结清单导出）。
4. `ios-artifact` 对 `.xcarchive`，并把 `.ipa` 解到临时目录后对 `Payload/*.app` 运行同一门禁。两者都须通过（0 或 4）。
5. 写回执：产物名、`.ipa` sha256、两次退出码、期望 ZIP sha256。exit 4 时产物名加 `QA-ONLY-NOT-FROZEN-` 前缀，不进验收发布。

## 回执必附

- 完整命令与环境变量（不含口令或凭据）。
- 三个门禁文件的哈希比对结果。
- `ios-prebuild` 与 `ios-artifact`（`.xcarchive` 及解包 `.ipa`）的退出码。
- 扫描路径清单（门禁报告的路径）。
- 产物哈希（`.ipa` sha256，以及 `.xcarchive` 中 `SilentPassUI.zip` 的 sha256）。

## 当前状态

- 门禁对 iOS 根目录做仓库身份校验：根目录必须是登记的 iOS 仓库或其工作树的顶层，且工作区干净（未跟踪文件也算）；不满足即拒绝，本脚本不会出包。
- 0.53.42 冻结已作废（VOID 8d90212c…），不得用于验收。
