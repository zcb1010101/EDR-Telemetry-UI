# EDR Telemetry UI

> 面向 Windows 的 EDR 遥测采集、真伪校验与离线比对一体化平台。纯 PowerShell 引擎 + 调用Windows原生API + 本地 Web 界面，
> 无需接入 EDR 后台 API，所有输入输出均为本机文件。

![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![Web](https://img.shields.io/badge/Web-Node.js-green)
![Language](https://img.shields.io/badge/Language-PowerShell%20%2F%20JavaScript-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 目录

- [项目简介](#项目简介)
- [功能特性](#功能特性)
- [技术架构](#技术架构)
- [目录结构](#目录结构)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [使用指南](#使用指南)
- [离线比对与安全基线](#离线比对与安全基线)
- [威胁评级体系](#威胁评级体系)
- [配置说明](#配置说明)
- [扩展新场景](#扩展新场景)
- [安全说明](#安全说明)
- [常见问题](#常见问题)
- [许可证](#许可证)

---

## 项目简介

EDR Telemetry UI 是一套用于验证 Windows EDR（终端检测与响应）产品遥测完整性的离线工具链，
包含三个核心能力：

1. **遥测采集**：通过 68 个独立场景脚本，在本机模拟进程、文件、网络、注册表、服务、驱动、WMI 等 53 场景；
   16 类安全相关行为，并输出结构化 JSONL 事件日志；
2. **真伪校验**：每个场景内置独立校验逻辑，行为执行后自动断言系统真实状态（进程是否创建、注册表
   键值是否写入、服务是否注册等），区分「行为已执行」与「行为真实生效」；
3. **离线比对**：将本地采集到的行为事件与厂商 EDR 控制台导出的日志进行确定性关联比对，生成
   PASS / PARTIAL / FAIL / INCONCLUSIVE 四档判定结论，评估 EDR 遥测覆盖能力。

项目提供**纯 PowerShell 终端模式**与 **Web 平台模式**两种使用入口，核心引擎完全复用，适合在隔离的测试机上进行 EDR 产品能力验证与回归测试。

---

## 功能特性

### 遥测采集引擎

- **16 个遥测分类、53 个场景、68 个独立脚本**，可单独调用、可按分类调用、可批量串行执行；
- 每个场景内置：行为执行 → 独立真伪校验 → 精确清理 → 标准化 JSONL 日志，全流程闭环；
- 行为对象使用随机 nonce 标识，支持并发轮次区分与结果追溯；
- LV0–LV3 四级威胁评级，管理员场景自动跳过并标记 `ADMINISTRATOR_REQUIRED`；
- 网络行为默认使用 `127.0.0.1` 回环地址，不访问公网；
- 服务、驱动、计划任务等高风险行为采证后立即清理，不残留系统状态。

### 离线比对引擎

- 厂商日志统一字段转换（Normalizer），内置 Tencent iOA EDR 与 Generic 两套映射，可自由扩展；
- 确定性字段键关联（correlation keys）+ 时间窗口候选召回，无锚点加权打分；
- 10 种断言操作符：`present / absent / equals / not_equals / contains / regex / one_of / range / cidr / timestamp_between`；
- 四级判定汇总：`PASS / PARTIAL / FAIL / INCONCLUSIVE`，自动生成中文 Markdown 结论报告。

### Web 平台

- 三大功能视图：**场景运行**、**日志对比**、**结果输出**；
- 场景运行支持单场景 / 分场景类 / 全场景三种模式，实时统计与运行日志滚动输出；
- 日志对比支持本地日志与厂商日志上传、基础校验、可选标准化与离线比对；
- 结果输出支持导入/选择最近比对结果，查看通过率与达标率，导出 JSON / Markdown / HTML；
- 服务仅监听 `127.0.0.1`，全部为本地文件操作。

### 工程化配套

- 安全基线管理：基线初始化 / 查看 / 导入 / 覆盖校验；
- 一键启停脚本（PowerShell 与 CMD 双入口）、环境自检、空闲端口自动选择；
- 场景脚本与基线生成器，支持声明式扩展新场景；
- 编码修复工具，解决 Windows PowerShell 5.1 中文乱码问题。

---
## 技术架构

```text
┌────────────────────────────────────────────────────────────────────┐
│                        使用入口（两种模式）                        │
│                                                                  │
│  ① 终端模式                   ② Web 平台模式                      │
│  Run-EDRTelemetry.ps1         start-platform.ps1 / .bat          │
│  Start-TelemetrySuite.ps1        │                               │
│  Compare-OfflineLogs.ps1         ▼                               │
│  Convert-VendorLogs.ps1      server/server.js (Node.js HTTP)     │
│  Initialize-SecurityBaseline    │ 仅监听 127.0.0.1               │
│                                ▼                                 │
│                        web/ 前端（原生 HTML/CSS/JS）              │
│                   场景运行 · 日志对比 · 结果输出                   │
└──────────────────────────────┬─────────────────────────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────────────┐
│                 PowerShell 核心引擎（core/，PS 5.1）               │
│                                                                  │
│  EdrTelemetry.Common.ps1      配置 / 日志 / 评级 / 公共工具        │
│  EdrTelemetry.Behaviors.ps1   68 种遥测行为实现（含原生 API 调用） │
│  EdrTelemetry.SerialRunner.ps1 串行执行器（单/分类/全量）          │
│  EdrTelemetry.Normalizer.ps1  厂商字段统一转换                    │
│  EdrTelemetry.Baseline.ps1    安全基线解析与断言                  │
│  EdrTelemetry.Comparator.ps1  离线比对引擎                        │
└──────────────────────────────┬─────────────────────────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────────────┐
│  配置文件（config/）           产物目录（自动生成）                 │
│  project.json                  runs/   轮次事件日志与摘要          │
│  scenario-catalog.csv          import/  导入的厂商日志             │
│  threat-levels.json            reports/ 比对结果 JSON / Markdown  │
│  vendors.json                  logs/    运行日志                  │
│  baseline-templates.json       baselines/ 16 类安全基线           │
└────────────────────────────────────────────────────────────────────┘
```

## 目录结构

```text
EDR-Telemetry-UI/
├── Run-EDRTelemetry.ps1             # 终端主入口（交互式菜单）
├── Start-TelemetrySuite.ps1         # 命令行批量串行执行入口
├── Compare-OfflineLogs.ps1          # 离线比对入口
├── Convert-VendorLogs.ps1           # 厂商日志标准化入口
├── Initialize-SecurityBaseline.ps1  # 安全基线初始化/查看/导入/校验
├── start-platform.ps1 / .bat        # Web 平台一键启动
├── stop-platform.ps1 / .bat         # Web 平台一键停止
│
├── core/                            # PowerShell 核心引擎
│   ├── EdrTelemetry.Common.ps1      #   配置、日志、评级、工具
│   ├── EdrTelemetry.Behaviors.ps1   #   68 种遥测行为实现
│   ├── EdrTelemetry.SerialRunner.ps1#   串行执行器
│   ├── EdrTelemetry.Normalizer.ps1  #   厂商字段统一转换
│   ├── EdrTelemetry.Baseline.ps1    #   基线解析与断言
│   └── EdrTelemetry.Comparator.ps1  #   离线比对引擎
│
├── config/                          # 配置文件
│   ├── project.json                 #   项目参数（目录、窗口、时长）
│   ├── scenario-catalog.csv         #   68 场景元数据目录
│   ├── threat-levels.json           #   LV0-LV3 威胁评级定义
│   ├── vendors.json                 #   厂商字段映射与路由规则
│   └── baseline-templates.json      #   基线生成模板
│
├── scenarios/                       # 16 个分类目录、68 个 Invoke-*.ps1
├── baselines/                       # 16 个分类安全基线（*.baseline.json）
├── server/                          # Web 后端
│   ├── server.js                    #   Node.js HTTP 服务（127.0.0.1）
│   └── scripts/                     #   运行/标准化/比对的桥接脚本
├── web/                             # Web 前端
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── tools/                           # 工程工具
│   ├── Fix-FileEncoding.ps1         #   UTF-8 BOM 编码修复
│   └── Generate-ScenarioScripts.ps1 #   场景脚本与基线生成器
│
├── runs/                            # 轮次事件日志与摘要（自动生成）
├── import/                          # 用户导入的厂商日志（自动生成）
├── reports/                         # 离线比对结果（自动生成）
└── logs/                            # 运行日志（自动生成）
```

---

## 环境要求

| 依赖 | 版本/说明 | 是否必需 |
| --- | --- | --- |
| Windows | 10 / 11 或 Windows Server，x64 | 必需 |
| Windows PowerShell | 5.1（系统自带） | 必需 |
| Node.js + npm | Web 平台模式需要 | 仅 Web 模式 |
| Python + pefile | 仅 `win.hash.imphash` 场景 | 可选 |
| 管理员权限 | 用户账号、服务、驱动、组策略、WMI 等场景 | 部分场景 |

> 建议始终以 `powershell -NoProfile -ExecutionPolicy Bypass` 方式运行脚本；
> 缺少 Python 时 IMPHASH 场景会跳过，其余场景不受影响。

---

## 快速开始

### 1. 编码修复（复制/迁移后首次运行必做）

若项目从其他位置复制/移动后出现“输入字符串的格式不正确”或中文乱码，请先执行一次编码修复：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\Fix-FileEncoding.ps1
```

Windows PowerShell 5.1 读取无 BOM 的 UTF-8 中文脚本时会按系统 ANSI 解码，导致格式字符串被破坏；
该工具会一次性将项目内全部 `.ps1 / .json / .csv / .md` 文件修复为 UTF-8 BOM 编码。

### 2. 终端模式启动

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Run-EDRTelemetry.ps1
```

主菜单支持：查看能力目录、运行单个场景、按分类运行、运行全部场景、批量运行、厂商日志导入、
离线比对、安全基线管理。

### 3. Web 平台模式启动

```powershell
.\start-platform.ps1            # 一键启动（自动自检 + 选端口 + 开浏览器）
.\start-platform.ps1 -NoBrowser # 仅启动服务，不打开浏览器
```

```cmd
start-platform.bat              # CMD 环境一键启动
```

停止平台：

```powershell
.\stop-platform.ps1
```

```cmd
stop-platform.bat
```

> 启动脚本会依次检查 Node.js、npm、PowerShell、Python（可选）、核心脚本、配置与 Web 文件，

> 自动选择空闲端口（默认 8787，候选 8787–8790），后台启动服务并打开浏览器；

> 停止脚本会终止平台进程树、清理占用端口并删除 `.platform` 下的 PID/日志文件；

> 可右键 .bat 选择管理员身份运行。注意以管理员身份启动的平台就需要以管理员身份停止。

---

## 使用指南

### 一、CLI 终端模式

#### 1.1 运行单个场景

所有场景脚本参数统一，以文件创建为例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scenarios\FileManipulation\Invoke-FileCreation.ps1
```

通用参数：

| 参数 | 说明 | 默认值 |
| --- | --- | --- |
| `-RunId` | 轮次 ID | 自动生成 |
| `-Nonce` | 本轮标记 | 自动生成 |
| `-OutputLog` | 事件日志路径 | `runs/<日期>/<RunId>/events.jsonl` |
| `-ThreatLevel` | LV0-LV3，覆盖默认评级 | 目录默认 |
| `-IntervalSeconds` | 执行后等待秒数 | 3 |
| `-SkipCleanup` | 跳过清理（排查用） | - |
| `-ServiceName` | EDR 代理服务名（SysOps 场景） | - |
| `-UsbWaitSeconds` | USB 等待秒数 | 60 |
| `-ConfirmManual` | 人工场景确认 | - |

#### 1.2 批量串行执行

```powershell
# 按场景 ID
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-TelemetrySuite.ps1 `
  -ScenarioIds win.file.create,win.registry.create,win.hash.md5 `
  -IntervalSeconds 3

# 按分类
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-TelemetrySuite.ps1 `
  -Categories "Process Activity","File Manipulation"

# 全部场景
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-TelemetrySuite.ps1 -All
```

Runner 按目录顺序串行执行，每个场景写入同一份 `events.jsonl`，完成后生成 `suite-summary.json`。

#### 1.3 厂商日志标准化

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Convert-VendorLogs.ps1 `
  -VendorId tencent -InputPath .\import\cloud.json -OutputPath .\import\normalized.json
```

目前支持的厂商 ID：`tencent`、`generic`。字段映射维护在 `config/vendors.json`。

#### 1.4 离线比对

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Compare-OfflineLogs.ps1 `
  -LocalLog .\runs\20260816\smoke-001\events.jsonl `
  -Cloud .\import\cloud.json `
  -VendorId tencent `
  -OutputPath .\reports\validation-result.json `
  -CloudManifest .\import\cloud-export-manifest.json
```

输出 `validation-result.json` 与同目录 `validation-conclusion.md`。兼容参数：

| 参数 | 说明 |
| --- | --- |
| `-StrongCorrelationTimeMs` | 兼容保留，当前不参与判定 |
| `-CandidateTimeLimitMs` | 兼容保留，当前不参与判定 |
| `-BaselineDirectory` | 基线目录 |
| `-CloudManifest` | 厂商导出清单（可选） |

#### 1.5 安全基线管理

```powershell
# 重新生成并列出基线
powershell -NoProfile -ExecutionPolicy Bypass -File .\Initialize-SecurityBaseline.ps1

# 查看并导出指定场景基线
powershell -NoProfile -ExecutionPolicy Bypass -File .\Initialize-SecurityBaseline.ps1 -Show win.process.create

# 导入自定义基线
powershell -NoProfile -ExecutionPolicy Bypass -File .\Initialize-SecurityBaseline.ps1 -ImportPath custom.json

# 校验场景覆盖
powershell -NoProfile -ExecutionPolicy Bypass -File .\Initialize-SecurityBaseline.ps1 -Validate
```

---

### 二、Web 平台模式

#### 2.1 功能入口

| 视图 | 功能 | 说明 |
| --- | --- | --- |
| 场景运行 | 单场景 / 分场景类 / 全场景 | 实时统计（总数/待运行/运行中/已完成/成功率）、滚动运行日志、可中途停止 |
| 日志对比 | 本地日志 + 厂商日志导入 | 基础校验、可选标准化、离线比对，可查看比对状态 |
| 结果输出 | 比对结果查看与导出 | 占比与达标率展示，导出 JSON / Markdown / HTML |

#### 2.2 注意事项

- 服务只监听 `127.0.0.1`，所有运行、导入、比对均为本机文件操作，不访问外网；
- Agent 安装/卸载/异常、驱动加载/修改/卸载、账号注销等场景暂未开放，前端会置灰提示；
- 需管理员场景在普通权限下会由 Runner 记录为跳过，不中断批次。

#### 2.3 后端 API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/health` | 健康检查 |
| GET | `/api/catalog` | 场景目录 |
| GET | `/api/runs/recent` | 最近运行批次摘要 |
| POST | `/api/run` | 启动运行批次 |
| GET | `/api/run/:id` | 批次状态 |
| GET | `/api/run/:id/events` | 批次实时事件流 |
| POST | `/api/run/cancel?id=` | 停止运行批次 |
| POST | `/api/import/local` | 上传本地事件日志 |
| POST | `/api/import/vendor` | 上传厂商原始日志 |
| POST | `/api/compare` | 发起离线比对 |
| GET | `/api/reports` | 比对报告列表 |
| GET | `/api/report/content` | 报告内容 |
| POST | `/api/report/import` | 导入外部报告 |

---

## 离线比对与安全基线

### 比对流程

1. 读取本地 `events.jsonl`，按 `scenario_id` 选择版本匹配的基线；
2. 厂商原始日志按映射路由标准化为 Canonical 字段，保留原始记录与来源字段；
3. 以本地行为时间为基准，在 `time_before_seconds` 与 `time_after_seconds` 窗口内召回候选；
4. `correlation.keys` 对本地字段与 Canonical 字段做确定性全等匹配，不做锚点加权打分；
5. 事件类型与动作必须匹配，且时间差不超过基线配置的最大时间差；
6. 排序去重后输出候选，未命中全部关联键的候选仅展示、不参与判定；
7. 断言支持 `present/absent/equals/not_equals/contains/regex/one_of/range/cidr/timestamp_between`；
8. `required` 失败为 FAIL、未评估为 INCONCLUSIVE；`recommended` 失败为 PARTIAL；
9. 汇总规则：有 FAIL 则 FAIL，有 INCONCLUSIVE/未比较则 INCONCLUSIVE，有 PARTIAL 则 PARTIAL，
   否则 PASS；同时输出中文 Markdown 结论。

### 安全基线

每个遥测分类对应一份 `baselines/*.baseline.json`，定义：

- 事件类型与动作（`event_type` / `event_actions`）；
- 关联键（`correlation.keys`：本地字段 ↔ 云字段，可带归一化器）；
- 断言列表（字段、操作符、期望来源、严重级别）；
- 时间窗口（`time_before_seconds` / `time_after_seconds` / `max_time_difference_ms`）。

基线支持通过 `Initialize-SecurityBaseline.ps1` 重新生成、按场景导出、导入自定义基线并校验覆盖。

---

## 威胁评级体系

| 级别 | 中文名称 | 说明 | 颜色 |
| --- | --- | --- | --- |
| LV0 | 无风险 | 信息采集与只读行为，不修改系统状态 | 绿 |
| LV1 | 低风险 | 常规应用行为，清理后无残留，需要记录与确认 | 黄 |
| LV2 | 中风险 | 持久化或系统修改行为，需要管理员权限与精确清理 | 洋红 |
| LV3 | 高风险 | 注入、篡改、WMI 持久化等高风险行为，仅允许在隔离测试机执行 | 红 |

评级规则：

- `admin_required`：场景 `RequiresAdmin=true` 且当前进程非管理员时，状态为 `SKIPPED / ADMINISTRATOR_REQUIRED`；
- `cleanup_failed`：清理失败时状态为 `CLEANUP_ERROR`，并停止后续高危场景；
- `threat_override`：调用方可通过 `-ThreatLevel` 覆盖目录默认评级。

---

## 配置说明

### config/project.json（项目参数）

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `schema_version` | `2.0` | 配置结构版本 |
| `default_run_dir` | `runs` | 运行产物目录 |
| `default_log_dir` | `logs` | 运行日志目录 |
| `default_import_dir` | `import` | 导入目录 |
| `default_report_dir` | `reports` | 报告目录 |
| `default_interval_seconds` | `3` | 场景间默认间隔（秒） |
| `min_interval_seconds` / `max_interval_seconds` | `0` / `300` | 间隔上下限 |
| `default_vendor` | `tencent` | 默认厂商 ID |
| `time_before_seconds` | `60` | 候选召回前置窗口 |
| `time_after_seconds` | `300` | 候选召回后置窗口 |
| `default_max_time_difference_ms` | `3000` | 默认最大时间差 |
| `max_displayed_candidates` | `50` | 候选展示上限 |
| `cleanup_timeout_seconds` | `30` | 清理超时 |
| `usb_wait_seconds` | `60` | USB 场景等待时间 |
| `file_behavior_hold_ms` | `2000` | 文件行为保持时长 |

### config/scenario-catalog.csv（场景目录）

每行定义一个场景：分类、目录、场景 ID、场景名、行为类型、威胁评级、是否需要管理员、操作类型。

### config/vendors.json（厂商映射）

按厂商定义输入容器（JSON 数组 / JSONL）、记录选择器、事件/主机字段来源，以及「路由条件 → Canonical
字段」的映射规则（支持常量、字段来源、值变换与空值策略）。新增厂商只需追加一个 `vendors` 节点。

---

## 扩展新场景

1. 在 `config/scenario-catalog.csv` 增加一行（分类、目录、ID、名称、行为类型、评级、权限）；
2. 在 `core/EdrTelemetry.Behaviors.ps1` 实现对应 `BehaviorKind` 的行为函数（执行、校验、清理）；
3. 在 `config/baseline-templates.json` 确认分类模板，或为场景增加专属断言；
4. 运行生成器，自动产出独立场景脚本与分类基线：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\Generate-ScenarioScripts.ps1
```

新增厂商日志映射：

1. 在 `config/vendors.json` 的 `vendors` 节点下新增厂商定义；
2. 按业务事件类型编写 `routes` 路由规则（`when` 匹配条件 + `canonical` 字段映射）；
3. 使用 `Convert-VendorLogs.ps1` 验证映射结果。

---

## 安全说明

- 网络场景默认全部使用 `127.0.0.1` 回环，不访问公网；
- 注册表场景只操作 `HKCU\Software\EdrTelemetry\Runs\<nonce>` 隔离位置；
- 服务、驱动、计划任务均使用含 nonce 的唯一名称，从不启动真实服务/驱动，采证后立即删除；
- 停止 EDR 代理必须显式指定 `-ServiceName` 且加 `-ConfirmManual`；
- 用户账号、WMI、组策略场景应只在隔离测试机运行；
- 所有临时目录位于 `%TEMP%\EdrTelemetry\<RunId>\`，默认自动清理；
- Web 服务仅监听 `127.0.0.1`，不对外网开放；
- 本项目不接入任何 EDR 后台 API，所有输入输出均为本机文件。

---

## 常见问题

**Q1：运行脚本报“输入字符串的格式不正确”或中文乱码？**

A：Windows PowerShell 5.1 读取无 BOM 的 UTF-8 中文脚本会按 ANSI 解码。先运行
`tools\Fix-FileEncoding.ps1` 将全部脚本修复为 UTF-8 BOM 编码。

**Q2：Web 平台启动失败或端口被占用？**

A：先运行 `stop-platform.ps1` 清理残留进程与端口；若 8787–8790 均被占用，请释放端口后重试。
也可查看 `.platform\server.out.log` 与 `server.err.log` 定位问题。

**Q3：IMPHASH 场景被跳过？**

A：该场景依赖 Python 与 pefile 库。安装 Python 并执行 `pip install pefile` 后重新运行；
缺失时仅该场景跳过，不影响其他场景。

**Q4：部分场景显示 `ADMINISTRATOR_REQUIRED`？**

A：用户账号、服务、驱动、组策略、WMI 等场景需要管理员权限。请以管理员身份运行
PowerShell；普通权限下 Runner 会记录为跳过，不中断批次。

**Q5：离线比对结果大量 INCONCLUSIVE？**

A：说明本地行为事件在时间窗口内未召回匹配候选，或厂商日志中缺少对应事件。请确认：
厂商日志已按正确 `-VendorId` 标准化、导出时间窗口覆盖行为执行时间、基线与映射配置正确。

---

## 许可证

---

*EDR Telemetry UI · Windows EDR 遥测采集、真伪校验与离线比对一体化平台*
