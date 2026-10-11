# 回归恢复记录（2026-10-11）

本轮范围：保存现状、核对成功基线、复现失败、最小修复和真实 Public 验证。新增功能、重构与通用性优化暂停。失败日志不清理。

## 可恢复的起始版本

- 起始提交：`9e65e045436a5c850b35f45d3b9c70a86daa47b0`；工作树干净，未提交补丁为空。
- 快照分支：`snapshot/regression-20261011-start`。
- 镜像：`scan-agent:regression-snapshot-20261011`，ID `sha256:53dc3f07b6ae98350b6c4bc63a189b20026d6b918c5f2c9f5d27388ba63d3fde`。
- 私有快照目录：`outputs/regression-20261011/snapshot-start/`，包含完整 `repository.bundle`、工作树 tar、本地配置、原提交包和三轮平台结果原件。Git bundle 已验证；原文件保留。含密钥的文件没有提交 Git。
- 恢复说明：上述目录中的 `RESTORE.md`。先保存恢复前的工作，再使用快照分支或在新目录从 bundle 建仓，不自动覆盖当前目录。

## 平台成功基线与版本对应

最近一份已提供的真实平台 11 成功、0 失败结果对应 `6ffa306b6c14b173a6877263bb102dc8a53dcf11`，总运行时间 1721.33 秒。30/30 个运行源文件与 Git、原提交包和平台预测包逐字节相同。

原提交包：`outputs/mapping-fix-20261009/submission-package/submission.zip`，SHA256 `190c95d400d8384ac4495fc4e1c816299ebc7aa6d0901b4b6297df210506f537`。

平台 build.log 仅记录短镜像 ID `0ac36f7d2883`、标签 `participant-agent:d00220ef2412`，不能恢复平台完整镜像 ID。本地对应原包镜像为 `scan-agent:regression-baseline-20261011`，ID `sha256:aec8b8e3b6f2bfd6ca1dbd50abff145c4f60c6b30835e527144e0dfeae7d3cb1`。这是本地包镜像，不冒充平台镜像。

本轮读取的最新 `(2).zip` 是平台 9/11、2284.89 秒，Task 1 case2、case6 失败；36/36 个运行源文件对应起始 `9e65e04`。此前 `(1).zip` 是 `3730719` 的 6/11。不同轮次分别保留，没有混用。

基线的 11/11 是打榜阶段运行和格式检查，旧产物已有 Wrapper 数量、例外排除和局部回替等语义漏项证据。本轮没有通过撤回这些验收恢复表面成功。

详细证据：`outputs/regression-20261011/baseline-provenance.json`、`latest9of11-evidence/source-provenance.json`、`change-impact.md`。早期证据中“最新结果待提供”的字样是当时状态；本节记录后续已完成的归档核对。

## 已验证原因与尚未证明的归因

### Task 1 case6

最新平台首个模型响应逐项展开扫描段，达到 7000 completion tokens，`finish_reason=length`，109.196 秒后得到未闭合 JSON。预检拒绝，纠正请求超时，没有执行 EDA。匹配环境的起始版本再次出现同样截断，随后重请求才通过，耗时 144.11 秒。

### Task 1 case2

最新平台 R1 的七条使能声明使用 `usage scan`，实际产生 1653 条 DFTR9。模型修复中对重复的 `se_serdes`、`se_ctrl` 行使用非唯一 old span，严格编辑预检拒绝，随后请求超时。同环境起始版本复现失败：错误的时钟关联和 `replace false` 候选导致最终零条链，140.89 秒未通过。

单变量 EDA 实验仅把平台 R1 的七个 `usage scan` 改为 `usage all`（另有必要的输出路径重定位），得到 14 条链、最长 281、正确分区与使能，仅剩任务明确允许的 DFTR10。该实验不是自主 Agent 验证。

基线与当前匹配环境使用相同输入、本地新 Key 配置、`deepseek-v4-pro`、jobs=1、Python 3.12.3、OpenAI SDK 3.24.0、相同原生工具 SHA256；不挂载 Golden。基线 case2/case6 分别在 67.76/50.10 秒通过统一实体检查。

**未证明**：基线以后新增的某一句提示直接造成全部退步。上下文和模型候选不同，模型随机性未消除；多个错误编辑路径原本就在基线中。源码差异中的潜在影响与已证实日志触发点分列于 `change-impact.md`，没有把所有变化都认定为原因。

## 最小修改与检查边界

1. `f49f34f0383eed981740184b6b6cc82cb2e1bfb7`：只收紧已有扫描段提示，要求模型省略运行时负责生成的段声明，返回紧凑 Dofile。已有输入派生段编译、实际映射和验收不变。受影响 case6 实跑 37.29 秒通过，实际执行 R1/R2 两次工具调用；两次模型响应完整，280 段和原 280 个 SFF 使能连接得到实际证明。
2. `8939ec00f43fa1f697f9c0fac066ddac40797413`：只把已有门控分区提示中的“usually needs usage all”改为明确配置 `usage all`。受影响 case2 实跑 120.15 秒，三次工具调用后通过。首轮仍使用 scan，第二轮发生重复编辑拒绝和错误时钟关联，最终模型改正。因此本次通过不证明提示已经消除所有坏候选。

新增一个小型 mock 回归测试检查提示和原扫描段编译证据。625 项 unittest 通过，Ruff 通过。验收、唯一编辑检查、预算、网表保护、Golden 隔离、报告真实性和正证检查没有放宽。

两个修改保留为单独 Git 提交，修复分支 `regression/20261011-repair`。本次诊断完整批次镜像固定为 `scan-agent:regression-fix2`，ID `sha256:0b34c159e3f5af0bcf35c84535f2926155bf4a214809464741ca1823dd5a1ac2`。

### 完整批次新发现的 case3 问题

case3 在 141.65 秒后失败。原生日志没有 ERROR，DRC 为 0，实际 I55/W15 正确；但任务要求排除的 27 个 FF 全部仍为 scannable。

R1 试图把 `cluster_foreach` 中 `puts` 输出作为返回集合。R2–R5 又用 `lappend` 把单元素集合句柄拼成普通 Tcl 列表，再交给 `set_scan_element`，原生日志出现 `COM-2003 Nothing matched for _dbColl...`。这不是 `get_obj_insts` API 错误；镜像帮助说明 `get_cells` 是它的别名。此前成功 Dofile 使用单个 include/exception filter，直接传返回集合。

第三个最小修改 `837733316a742a7e690501d1fed2f89b7767b23e`：只在已有子树选择提示后增加“同一查询包含例外条件，直接传返回集合，不拼句柄列表或捕获打印名称”。验收仍要求实际 27 个排除、16 个 mintthresh 例外保留；没有自动按 case 名修改候选。

625 项测试和 Ruff 通过。候选镜像 `scan-agent:regression-fix3`，ID `sha256:a93c25a1924c0f2479e9f28c1cd7b01340662e62b61571120983c0adaaa737b4`。**真实 Agent case3 尚未验证，完整 11 例尚未验证**，因为模型账户欠费。集合操作单变量原生实验另存 `case3-collection-proof/`：实际 27 个排除、16 个例外保留，I55/W15，内部最长 86；三条长 128 的 Wrapper 链均有真实不可拆分 CTL 段，DRC0，输出齐全。该实验不能代替模型生成验证。

## 完整 11 例验证

批次：`outputs/public-live-20261011T012325828028Z`。同一 fix2 镜像、当前本地配置、jobs=1，不暴露 Golden。此批未通过，原 summary 和失败日志全部保留；不能拼接其他镜像/单例结果称 11/11。

| Case | 本批结果 | 外部墙钟秒 | 实际核对 |
|---|---|---:|---|
| Task1 case1 | 通过已记录检查 | 31.69 | ICG 目标 68 / 保留 156；外部 2651 SFF 保留，PLL 76 DFF；最终文件与执行轮次字节相同 |
| Task1 case2 | 通过已记录检查 | 104.21 | 14 链，最长 281；七分区数量/成员/使能 all；仅授权 DFTR10；3 次工具、4 次模型请求 |
| Task1 case3 | 失败 | 141.65 | I55/W15、DRC0；27 个应排除 FF 未排除，不放宽检查 |
| Task1 case4 | 通过已记录检查 | 32.89 | 局部连接/替换/回替结构及输出一致，范围外状态保留 |
| Task1 case5 | 模型服务拒绝 | 47.57 | HTTP400 `Arrearage`；零 EDA，不作为代码失败或通过 |
| Task1 case6 | 中断，未完成 | — | 控制台亦有 `Arrearage`；runner 未记录完成，不计入本批通过数 |
| Task2 case1 | 未运行 | — | 模型账户阻塞，待新批完整验证 |
| Task2 case2 | 未运行 | — | 同上 |
| Task2 case3 | 未运行 | — | 同上 |
| Task2 case4 | 未运行 | — | 同上 |
| Task2 case5 | 未运行 | — | 同上 |

独立检查：`full-independent-task1.json/md`、`fixed-full-independent-references.json`。原生实体/文件/行号字节核对与复用生产语义 helper 的交叉核对明确区分；后者不是独立算法或完整功能等价证明。

**外部阻塞**：case5、case6 控制台记录 HTTP400 `Arrearage`。阿里云官方错误说明将其归为账户欠费/余额不足；没有查看账户后台或推断具体欠款额。已请用户恢复本地 Key 所属账户服务。没有更换指定模型、密钥写入源码或循环无效重试。

恢复后顺序：先最小模型连通检查，再同一 fix3 镜像真实 Agent case3，核对实际排除/例外/链数/CTL/报告与证据；如通过，再新建完整 11 例批次并逐例独立审核。前一批成功项不会代替新镜像完整验证。尚未完成这些步骤，因此不声明恢复稳定。

## 任务要求漏项与剩余边界

人工需求映射复核另存 `fixed-full-task1-mapping-coverage.json/md`：case2 只有一条映射，没有覆盖七分区、链数/最长、使能归属、隔离和 lockup 等关键条款；case3 缺少 CTL/库/顶层和输出映射；case4 对保留范围、不插链和输出条款未单独映射。实际配置与结构可以正确，但映射覆盖并不等于达标，不能声称官方 >=90% 或正式评分已证明。

相关非空映射提示/定位检查在成功基线已存在，不是本轮新增算法造成的已证实回归。为遵守本轮暂停新增功能/通用优化，记录具体漏项，没有新增泛化的覆盖率解析器，也没有用删映射或放宽验收掩盖它们。后续需要针对明确漏项单独修复并验证，才可声称完整满足要求。

`main` 与默认开发镜像保留起始版本。修复分支保存三个逐项可恢复检查点，GitHub 发布对应的树应逐字节相等，App 发布 SHA 与本地原提交 SHA 分开记录。完整验证完成前不替换已交付包或以新包声称 11/11。

GitHub 修复分支已发布：`regression/20261011-repair`，三个已核对相同源码树的发布检查点分别为 `ffb13c92`、`57f68dcc`、`cbc434de`。本地原提交保留 `f49f34f`、`8939ec0`、`8377333`；App 使用不同提交元数据，所以 SHA 不同，源码树相同。对应表在 `outputs/regression-20261011/publication-checkpoints.json`。`main` 仍为 `9e65e04`。

## 证据边界

本轮本地结果不等于新平台成绩，也不证明 Hidden case 或正式功能分数。模型生成的 requirement_mapping 数量不能证明覆盖所有自然语言要求；最终报告将列出实际核对项与仍需官方解释的边界。没有提交到评测平台。
