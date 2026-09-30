# Changelog / 更新说明

本文件记录 ios_auto_test 工具链（`ios_auto_test.py` + `ios_utils.py`）的重要变更。

## [2026-09-29] 重签流程修复与安装失败自动重试

### 背景

在一台 iOS 26.5.2 设备（iPhone13）上对 TuSDK 涂图 Demo IPA 执行完整流程时出现两类失败：

1. **安装阶段**：`MismatchedApplicationIdentifierEntitlement — rejecting upgrade`
2. **启动阶段**：安装成功但 app 无法启动，devicectl 报
   `Launchd job spawn failed (NSPOSIXErrorDomain error 88 "Malformed Mach-o file")`

两个问题都已修复，并在 iPhone13（iOS 26.5.2）与 iPhone15（iOS 26.5）双机回归通过（`TEST RESULT: SUCCESS`）。

---

### 修复 1：安装失败自动重试（ios_auto_test.py）

**问题**

设备上存在旧安装记录时，新签名 IPA 安装报：

```
ERROR: Install failed. Got error "MismatchedApplicationIdentifierEntitlement"
with code 0x00000000: Upgrade's application-identifier entitlement string
(JMD2JV9294.*) does not match installed application's application-identifier
string (JMD2JV9294.org.lasque.TuSDKDemo); rejecting upgrade.
```

关键在于：该残留记录**不会出现在** `ideviceinstaller list --user` 里，导致脚本
的 `--reinstall` 分支（先卸载再装）判断"应用未安装"而跳过卸载，直接安装失败。

**修复**

- `SIGNING_PATTERNS` 新增 `MismatchedApplicationIdentifierEntitlement → mismatched_identifier` 分类
- `install_app()` 拆出单次安装辅助 `_install_ipa_once()`；当失败输出命中
  `mismatched_identifier` 时，自动对目标 bundle 执行 uninstall 清除残留记录后重试一次
- 失败信息中 exit code 统一展示（ideviceinstaller 无 stderr 细分场景）

**效果**

换签名身份/换描述文件重装同一 bundle id 时不再需要手动卸载。

---

### 修复 2：启动失败 EBADMACHO —— 重签流程三处修正（ios_utils.py）

**问题现象**

重签 IPA 安装成功，但 SpringBoard/launchd 拒绝拉起进程：

```
runningboardd: Launch failed with Error Domain=NSPOSIXErrorDomain Code=88
"Malformed Mach-o file" UserInfo={NSLocalizedDescription=Launchd job spawn failed}
```

主二进制 Mach-O 结构、codesign 验签、amfid 校验全部正常，错误极具迷惑性。

**定位过程**

通过约 20 次真机 A/B 实验（同一 IPA、不同重签参数组合，iPhone13/iPhone15 双机验证）二分定位，确认三个独立叠加缺陷：

| # | 缺陷 | 触发概率 |
|---|------|---------|
| 1 | entitlements 全量拷贝 profile 的 24 个键，包含 `com.apple.security.hardened-process.*` 系列 | 主因，稳定复现 |
| 2 | framework 只签了 `.framework` 内层二进制而非 framework bundle 本身 | 部分场景（`0xe800801c No code signature found`） |
| 3 | 重签后未对 `.app` bundle 整体重签，`_CodeSignature/CodeResources` 仍是原 IPA 的旧 hash | 部分场景 |

**修复内容**

1. **最小授权集**：`auto_sign_ipa` 不再全量拷贝 profile entitlements，只保留
   5 个基础键（application-identifier / team-identifier / get-task-allow /
   keychain-access-groups / default-data-protection），其余以
   `Skipped N non-essential profile entitlements` 提示跳过。
   实测 `platform-restrictions-string: *` 等 hardened-process 键会让内核在
   spawn 阶段直接拒绝（错误 88/22），且失败对键集**非单调**（单键通过、组合失败），
   黑名单方式不可靠，故收敛为白名单。

2. **framework 整体签名**：`.framework` 与 `.appex` 现在直接对 bundle 目录执行
   `codesign -f -s`，与 Apple 官方嵌套签名规范一致；不再解析内层二进制路径。

3. **重建 CodeResources**：全部组件签完后，对 `.app` bundle 执行一次
   `codesign -f -s ... <App>.app`，使 `_CodeSignature/CodeResources` 与新二进制
   hash 匹配。

4. **校验增强**：打包前校验从 `codesign -v <主二进制>` 升级为
   `codesign -v --deep --strict <App>.app`，覆盖全部嵌套组件。

**附带修复**

- `sign_binary()` 的 `-f`（force）参数拼接顺序修正（原先放在末尾，等价但易碎）

**验证结论**

| 变体 | entitlements | framework 签名方式 | bundle 重签 | restore-symbol | 结果 |
|------|-------------|-------------------|------------|----------------|------|
| 原脚本产物 | profile 全量 24 键 | 内层二进制 | 无 | 全部 16 个 | spawn 失败 (88) |
| 最小集 + 正确签名 | 5 基础键 | framework bundle | 有 | 主二进制 | ✅ 启动成功 |
| 最小集 + 正确签名 | 5 基础键 | framework bundle | 有 | 全部 16 个 | ✅ 启动成功 |
| 全量 - 2 个 platform-restrictions | 22 键 | framework bundle | 有 | 主二进制 | ❌ spawn 失败 (88) |

最终修复 = 最小授权集 + framework bundle 签名 + bundle 重签 + deep 校验；
`restore-symbol` 全量处理与启动失败无关，`--restore-stripped-symbols` 可放心使用。

---

### 升级注意事项

- **行为变化**：`--auto-sign` 产出的 IPA entitlements 不再包含 profile 中的
  hardened-process / network-extension / siri / iCloud 等扩展权限。如需这些能力，
  请自行在 `ios_utils.py` 的 `BASE_KEYS` 之外追加所需键（注意上表的内核校验风险）。
- 旧的 `*_resigned.ipa` 产物为缺陷版本生成，请删除后用新脚本重新生成。
- 多设备环境建议显式传 `--udid`（脚本在多设备时默认取第一台并告警）。

---

## [2026-09-29 v2] 日志采集增强：spawn 错误识别 + 新旧崩溃报告区分 + SUCCESS 复查

### 背景

用户问了一个关键问题：`idevicecrashreport -e` 能否抓到 error 88？答案是不能——
**spawn 阶段被拒绝的进程没有 pid，永远不会生成 crash report**。这暴露了脚本的
三个盲区：

1. error 88/22 在 `syslog_analysis` 中没有任何分类，只能人工翻 syslog
2. `idevicecrashreport` 拉回的历史报告（包括其他 app、其他年份的）会被误归为
   本次测试的发现——此前一次运行因此把 2025 年 SecureUtilityPlusDemo 的报告
   当成了本次结果，导致错误分类
3. CODESIGNING Invalid Page 类崩溃发生在启动后 ~100ms，30s 监控窗口内进程
   "出现过"即判 SUCCESS，起来即死会被误报成功

### 新增 1：spawn 阶段错误识别（ios_auto_test.py）

- 新增 `SPAWN_ERROR_PATTERNS`：识别 `NSPOSIXErrorDomain Code=88/22`、
  `EBADMACHO`、`EINVAL`、`Launchd job spawn failed`、`Malformed Mach-o file`
- `classify_from_syslog` 输出新增 `spawn_errors` 字段（写入 `syslog_analysis.json`）
- `classify_status` 中 spawn 错误优先于泛化 debugger 错误：devicectl 表面只报
  通用错误链，syslog 里的内核/launchd 原因才是可执行信息（debugserver 未挂载
  这类工具故障仍保持原优先级）
- LAUNCH_FAILURE 的 summary 现在直接给出真因与排查方向，不再只显示
  "app process never started"

### 新增 2：崩溃报告新旧自动区分

- `collect_crash_reports` 记录测试开始时间戳（`test_start_epoch`）
- 新增 `separate_crash_reports()`：按 .ips 的 mtime 与测试开始时间比较
  - mtime ≥ 测试开始 → **本次新增**，参与状态判定与符号化
  - mtime < 测试开始 → 自动移入 `crash_reports/Retired/`，不计入结果
- `test_result.json` 的 `crash_reports` 只包含本次新增报告

### 新增 3：SUCCESS 复查窗口（settle window）

- 状态为 SUCCESS 时，等待 8 秒后再次拉取 crash report
- 发现本次新增的 .ips → 状态降级为 `LAUNCH_CRASH`，summary 标注
  `Downgraded from SUCCESS` 并提取 termination 指示（如 CODESIGNING Invalid Page）
- 无新增报告 → 输出 `SUCCESS confirmed`

### 真机回归结果（iPhone13, iOS 26.5.2）

- 10 份 2025 年历史报告（SecureUtilityPlusDemo 等）自动退役 → `Retired/`
- 1 份本次窗口内生成的 `TuSDKDemo-2026-09-29-182123.ips`（CODESIGNING Invalid
  Page，runtime 119ms）被正确捕获 → 状态从 SUCCESS 降级为 LAUNCH_CRASH，
  summary 明确指出 `Downgraded from SUCCESS: process died shortly after launch`
- 单元测试：spawn 错误识别（88/22）、分类优先级、debugserver 例外、Retired 归
  档逻辑全部通过

### 排障流程变化

```
旧：test_result.json summary（可能误报）→ 人工翻 syslog
新：syslog_analysis.spawn_errors 非空？
    ├─ 是 → spawn 阶段拒绝（entitlements/CodeResources 问题），看 debugger_output.log 错误链
    └─ 否 → 看 crash_reports/ 本次新增的 .ips（运行期崩溃），symbolicated/ 已符号化
```

## [2026-09-30] 文档补充：多 Git 服务器身份配置

README 新增「开发环境多 Git 服务器身份配置」章节：

- SSH 别名分流（github / BangcleGitLab），强调 SSH `User` 字段必须为 `git`
  （Git 服务器固定用 git 用户登录，账号身份由密钥决定——写账号用户名会被拒绝）
- `includeIf hasconfig:remote.*.url` 按 remote URL 自动切换 commit 身份
  （git >= 2.36），配合 gitdir 目录规则双兜底
- GitHub noreply 邮箱正确格式说明
