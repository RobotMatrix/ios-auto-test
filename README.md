# iOS App Automation Test Tool

iOS 真机自动化测试工具：一键完成 **IPA 重签 → 安装 → 启动监控 → 状态分类 → 日志/崩溃收集 → 崩溃符号化** 的完整闭环。

适配 iOS 26.x 设备，支持未脱壳/重签场景的 Objective-C 符号恢复与 JIT 权限注入。

## 功能概览

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ 1. 设备检测   │ → │ 2. 自动重签   │ → │ 3. 安装+启动  │ → │ 4. 状态分类   │
│  (多设备选择) │   │ (restore-sym │   │  (syslog 实时 │   │  (6种状态)    │
│              │   │ + codesign)  │   │   捕获)       │   │              │
└──────────────┘   └──────────────┘   └──────────────┘   └──────┬───────┘
                                                                │
                                                 ┌──────────────▼───────┐
                                                 │ 5. 收集: syslog /     │
                                                 │    crash reports /   │
                                                 │    logarchive        │
                                                 └──────────────┬───────┘
                                                 ┌──────────────▼───────┐
                                                 │ 6. lldb 符号化崩溃报告 │
                                                 └──────────────────────┘
```

### 测试状态分类

| 状态 | 含义 |
|------|------|
| `SUCCESS` | 应用启动并正常运行 |
| `LAUNCH_CRASH` | 启动阶段崩溃（launch window 内） |
| `LAUNCH_TIMEOUT` | 启动超时被系统 watchdog 杀死 |
| `RUNTIME_CRASH` | 运行一段时间后崩溃 |
| `LAUNCH_FAILURE` | 启动失败（签名/权限/依赖缺失等） |
| `NO_PROCESS` | 进程始终未出现 |

## 环境依赖

```bash
# libimobiledevice 套件（设备通信）
brew install libimobiledevice

# ios-deploy（可选，备用启动通道）
brew install ios-deploy

# restore-symbol（可选，恢复被 strip 的 ObjC 方法符号）
# https://github.com/tobefuturer/restore-symbol
brew install restore-symbol   # 或源码编译安装

# Xcode 命令行工具（devicectl / lldb / codesign）
xcode-select --install
```

**设备要求**：
- iPhone 已通过 USB 连接 Mac
- 首次使用需在设备上点击「信任此电脑」，并完成一次 `xcrun devicectl manage pair --device <UDID>`
- 开发者证书需在设备上受信任：设置 → 通用 → VPN与设备管理 → 信任对应证书

## 快速开始

### 基本用法（自动重签 + 全流程测试）

```bash
python3 ios_auto_test.py \
    --ipa "/path/to/app.ipa" \
    --auto-sign \
    --restore-stripped-symbols --restore-symbols \
    --reinstall \
    --provision-profile ./vendor_wildcard.mobileprovision
```

> **注意**：路径含空格/括号/中文时，只需**一层**引号包裹。`--ipa "'/path/app.ipa'"` 这种嵌套引号会把引号字符传进路径导致文件找不到。

### 常用参数组合

```bash
# 多设备环境指定设备
python3 ios_auto_test.py --ipa app.ipa --udid 00008110-XXXXXXXXXXXX --auto-sign ...

# 跳过安装，直接测试已安装应用
python3 ios_auto_test.py --bundle-id org.lasque.TuSDKDemo --no-install

# lldb 实时附加，捕获崩溃时的完整回溯/寄存器
python3 ios_auto_test.py --ipa app.ipa --auto-sign --lldb-debug

# 自定义启动超时与监控时长
python3 ios_auto_test.py --ipa app.ipa --auto-sign --launch-timeout 30 --monitor-time 60
```

### 全部参数

| 参数 | 说明 |
|------|------|
| `--ipa PATH` | 待安装的 .ipa 路径 |
| `--bundle-id ID` | Bundle identifier（缺省时自动从 IPA 读取） |
| `--udid UDID` | 目标设备 UDID（缺省时自动检测；多设备时建议显式指定） |
| `--no-install` | 跳过安装，测试已安装的应用 |
| `--reinstall` | 已安装时先卸载再重装 |
| `--launch-timeout N` | 启动等待上限秒数（默认 20） |
| `--monitor-time N` | 启动成功后的监控时长秒数（默认 30） |
| `--output-dir DIR` | 输出目录（默认 `./ios_test_output`） |
| `--auto-sign` | 安装前自动重签 IPA |
| `--sign-entitlements LIST` | 逗号分隔的额外 entitlements（默认 JIT/内存/调试三件套） |
| `--restore-stripped-symbols` | 重签前对全部 Mach-O 运行 restore-symbol 恢复 ObjC 符号 |
| `--restore-symbols` | 测试后用 lldb 对崩溃报告符号化 |
| `--provision-profile PATH` | 用于重签的 .mobileprovision 文件 |
| `--lldb-debug` | lldb 附加启动，实时捕获崩溃回溯 |

## 重签流程（`--auto-sign`）

`auto_sign_ipa` 执行以下步骤，每一步都对应一个历史踩坑点：

```
1. 解压 IPA
2. [可选] restore-symbol 处理全部 Mach-O（恢复被 strip 的 ObjC 方法名）
3. 构造 entitlements —— ★ 使用最小授权集（见下）
4. 重签全部嵌入组件：
   - .framework  → codesign 签 framework bundle 本身（不是内层二进制）
   - .dylib      → codesign 签文件
   - .appex      → codesign 签 appex bundle
   - 主二进制     → codesign 签文件
5. ★ 对 .app bundle 整体重签，重建 _CodeSignature/CodeResources
6. 重新打包为 IPA
7. codesign -v --deep --strict 全量校验
```

### ★ 最小授权集（关键设计）

重签时 **不会** 把 provisioning profile 里的全部 entitlements 拷贝进来，只保留 5 个基础键：

```
application-identifier
com.apple.developer.team-identifier
get-task-allow
keychain-access-groups
com.apple.developer.default-data-protection
```

**原因**：iOS 26 内核在进程 spawn 阶段会对部分 `com.apple.security.hardened-process.*` 权限（如 `platform-restrictions-string: *`）做强校验。开发证书签名下，这些键的取值或组合不合法时，launchd 直接拒绝 spawn，报出极具误导性的：

```
Launch failed: NSPOSIXErrorDomain error 88 "Malformed Mach-o file" (Launchd job spawn failed)
```

该失败**对键集非单调**（单个键能过、组合会挂），逐键黑名单不可靠，因此默认只保留基础键。

### 常见错误速查

| 错误 | 真实原因 | 处理 |
|------|---------|------|
| `MismatchedApplicationIdentifierEntitlement ... rejecting upgrade` | 设备上有旧安装记录，其 entitlement 前缀与新签名不一致；该记录对 `ideviceinstaller list --user` 不可见 | 脚本已自动处理：检测到此错误会先 uninstall 再重试。手动处理：`ideviceinstaller -u <UDID> uninstall <bundle-id>` |
| `error 88 "Malformed Mach-o file"` (spawn 阶段) | ① entitlements 含 hardened-process 系列键（已由最小授权集规避）② CodeResources 未随重签更新（已修复） | 升级到修复版脚本 |
| `error 22 EINVAL` (spawn 阶段) | 同上，entitlements 组合不合法的另一种表现 | 同上 |
| `ApplicationVerificationFailed 0xe8008017` | 重签后未重建 CodeResources | 已修复（bundle 重签步骤） |
| `No code signature found 0xe800801c` | 只签了外层 bundle，漏签嵌套 framework | 已修复（framework 整体签名） |
| `profile has not been explicitly trusted` | 设备未信任开发者证书 | 设置 → 通用 → VPN与设备管理 → 信任 |
| `The device must be paired` | CoreDevice(Xcode) 未配对 | `xcrun devicectl manage pair --device <UDID>` |

## 日志采集与自动区分

工具同时采集两类日志，并自动区分归属：

### 两类错误的采集通道

| 错误类别 | 发生阶段 | 采集通道 | 识别特征 |
|---------|---------|---------|---------|
| **spawn 阶段拒绝**（error 88 EBADMACHO / error 22 EINVAL） | launchd 拉起进程前，进程没有 pid | **syslog**（唯一证据来源，不产生任何 crash report） | runningboardd 记录 `Launchd job spawn failed` |
| **运行期崩溃**（Invalid Page / EXC_BAD_ACCESS / SIGABRT 等） | 进程已启动并运行 | **crash report**（`idevicecrashreport` 拉取 .ips） | bug_type 309/282 等 |

这就是为什么 `test_result.json` 的 `syslog_analysis.spawn_errors` 字段为空或非空，
直接指示该看 syslog 还是看 crash report。

### 新旧报告自动区分

设备上会积累大量历史崩溃报告（可能属于其他 app、其他年份）。脚本以**测试开始
时间戳**为界，把拉取到的 .ips 分为：

- **本次新增**：mtime ≥ 测试开始时间 → 进入 `crash_reports/`，参与状态判定与符号化
- **历史遗留**：mtime < 测试开始时间 → 自动移入 `crash_reports/Retired/`，不污染结论

### SUCCESS 复查窗口

进程启动成功 ≠ 测试通过。CODESIGNING Invalid Page 这类崩溃常在启动后 ~100ms
才触发，纯看监控窗口会把"起来即死"误判为 SUCCESS。因此 SUCCESS 结果会进入
**8 秒 settle 窗口**：再次拉取 crash report，若发现本次新增的崩溃报告（如
`CODESIGNING Invalid Page`），状态自动降级为 `LAUNCH_CRASH` 并在 summary 中注明
`Downgraded from SUCCESS`。

### 输出目录结构

```
ios_test_output/
├── test_result.json                 # 测试结果汇总（状态/耗时/错误分类）
├── syslog_org.xxx.<bundle>.log      # 全量设备 syslog（本次测试窗口）
├── syslog_org.xxx.<bundle>_process.log  # 按进程名过滤的 syslog
├── debugger_output.log              # devicectl/lldb 启动通道输出（启动失败时看这里）
├── syslog_analysis.json             # syslog 自动分析
│                                    #   spawn_errors: spawn 阶段错误（error 88/22）
│                                    #   crashes / signing_errors / jetsam_events ...
├── entitlements.json                # 重签后主二进制的 entitlements
├── logarchive.tar                   # OSLog 归档（含 hang/freeze 数据）
├── lldb_load_symbols.txt            # lldb 符号加载脚本（手动调试用）
├── crash_reports/                   # 本次测试新增的 .ips 崩溃报告
│   └── Retired/                     # 测试前已存在的历史报告（自动隔离）
└── symbolicated/                    # 符号化后的崩溃报告
```

**排障第一入口**：`test_result.json` 的 `summary` 只是初步分类，启动失败时优先看 `debugger_output.log` 里的完整错误链（devicectl 的报错会层层给出根因，如 spawn 阶段的 error 88）。

## 项目结构

```
ios_auto_test.py   # 主流程：设备检测/安装/启动/监控/状态分类/输出
ios_utils.py       # 工具库：restore-symbol 集成、auto_sign_ipa 重签、崩溃符号化
vendor_wildcard.mobileprovision  # 通配符描述文件（需替换为自己的）
```

## 已知限制

- `--provision-profile` 使用通配符 profile 时，签名后的 app 无推送等特殊权限；如需测试远程推送请使用带推送权限的 profile 并保留对应 entitlement
- 安装失败重试只针对 `MismatchedApplicationIdentifierEntitlement` 一类；其他错误需按上表人工处理
- `logarchive.tar` 体积可能超过 1GB（受 `--monitor-time` 影响），注意磁盘空间
