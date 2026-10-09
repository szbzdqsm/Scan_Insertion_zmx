# 本地提交包格式

依据正式 Word §5.2、官方 `reference_submission/README.md` 的“文件结构”“打包提交”，以及已读取的主办方 Q13/A14、Q21。材料已明确 ZIP 格式，无需另选格式。

```text
submission.zip
├── .env                    # 空 Key 占位，运行时配置
├── .dockerignore           # .env 不进入 Docker 构建上下文
├── Dockerfile
├── README.md
├── SOURCE_MANIFEST.json    # 逐文件 SHA；入口权限保存在 ZIP 中
└── submission/
    ├── agent_system        # ZIP 中保留可执行权限
    ├── agent_runner.py
    ├── scan_agent.py
    ├── requirements.txt
    └── …                   # Dockerfile 明确使用的运行模块
```

平台入口为 `/submission/agent_system -input <case> -output <output>`，使用 `docker run`。打包脚本按实际 Dockerfile 的 COPY 清单选择运行文件，并将构建源路径适配为 `submission/<file>`。

运行 `.venv/bin/python scripts/package_submission.py --output-dir <新的输出目录>` 创建 staging 和 ZIP；已有目录不覆盖。包内 `.env` 新建空 `LLM_API_KEY`，不读取私人 `agent/.env`。正式使用 Key 应在私有副本或运行环境配置。Public 输入/答案、生成产物、测试、旧日志、Git 与虚拟环境均不进入包。

已有材料未要求另外提交 Docker 镜像 tar、技术报告 PDF 或 Word；本地 ZIP 打包也不表示已上传评测平台。

2026-10-09 仅验证映射修复的小范围测试及 Task 2 case3；此前完整 Public 11/11 是 v56，不能当作本次修改版的完整验证结果。实际小测试和包核对结果见 [LIVE_VALIDATION.md](LIVE_VALIDATION.md) 的最新记录。

已生成：`outputs/mapping-fix-20261009/submission-package/submission.zip`。35 文件、137,527 字节；SHA-256 `1c7212586711a638447bc05a5cc7991a83022d54a1f44b0cb25bb5315c44e116`。该 ZIP 的目录内容已实际构建为 `scan-agent:submission-v57`，单跑 Task 2 case3 与独立引用复核通过，入口及私人配置排除检查通过。
