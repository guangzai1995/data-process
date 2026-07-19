# Synthetic Training Samples 实现计划

> **面向 AI 代理的工作者：** 必需子技能：使用 superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans 逐任务实现此计划。步骤使用复选框（`- [ ]`）语法来跟踪进度。

**目标：** 构建一个安全的 DeepSeek 纯合成训练样例生成器，不读取真实 audit 数据，可一键启动、中断后恢复。

**架构：** 新增独立合成器脚本读取本地 `.env`，调用 OpenAI-compatible DeepSeek API 生成纯合成 JSON 样例。输出按 JSONL 逐条 flush 到 `audit_training/synthetic_samples/`，同时维护 `state.json` 和 sample_id 去重以支持恢复。

**技术栈：** Python 3 标准库（`argparse`、`json`、`hashlib`、`datetime`、`pathlib`、`urllib.request`、`unittest`），shell 一键入口，DeepSeek OpenAI-compatible API。

---

## 文件结构

- 创建：`scripts/synthesize_training_samples.py`
  - 负责 `.env` 解析、DeepSeek 请求、模型响应解析、样例标准化、JSONL 写入和 state 恢复。
- 创建：`scripts/run_synthetic_samples.sh`
  - 一键入口，默认读取 `.env`，支持传递 CLI 参数，Ctrl+C 后保留进度。
- 创建：`.env.example`
  - 只记录变量名和示例值，不包含真实密钥。
- 修改：`.gitignore`
  - 明确忽略 `.env`，允许 `.env.example` 入库。
- 修改：`audit_training/README.md`
  - 记录安全合成运行方式、恢复机制和输出位置。
- 创建：`tests/test_synthesize_training_samples.py`
  - 覆盖 `.env` 解析、模型样例解析、拒绝 audit-like 字段、恢复去重。

## 任务 1：TDD 测试骨架

**文件：**
- 创建：`tests/test_synthesize_training_samples.py`

- [x] **步骤 1：编写失败的测试**

新增测试覆盖：
- `.env` 解析
- `parse_model_samples()` 支持 `sft`、`router`、`tool_use_sft`
- 拒绝 `request_id`、`file_path` 等 audit-like 字段
- `run_synthesis()` 从已有 JSONL 恢复并去重

- [x] **步骤 2：运行测试验证失败**

运行：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/test_synthesize_training_samples.py -v
```

预期：FAIL，错误包含 `FileNotFoundError`，因为 `scripts/synthesize_training_samples.py` 尚未创建。

## 任务 2：实现合成器

**文件：**
- 创建：`scripts/synthesize_training_samples.py`

- [ ] **步骤 1：实现 `.env` 与配置加载**

实现 `load_env_file()`、`load_config()`，默认：

```text
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash
DEEPSEEK_TIMEOUT=30
```

- [ ] **步骤 2：实现模型调用与解析**

实现 `generate_batch()` 调用 `/chat/completions`，提示词只包含纯合成任务要求，不包含真实 audit 内容。

- [ ] **步骤 3：实现断点续跑**

实现 `run_synthesis()`：
- 读取已有 `samples.jsonl` 的 `sample_id`
- 每写入一条就 flush 并更新 `state.json`
- 下次运行从已完成数继续

- [ ] **步骤 4：运行测试验证通过**

运行：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests/test_synthesize_training_samples.py -v
```

预期：PASS。

## 任务 3：一键脚本与文档

**文件：**
- 创建：`scripts/run_synthetic_samples.sh`
- 创建：`.env.example`
- 修改：`.gitignore`
- 修改：`audit_training/README.md`

- [ ] **步骤 1：新增一键脚本**

脚本执行：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/synthesize_training_samples.py --env-file .env "$@"
```

收到中断时提示进度已保存在 `audit_training/synthetic_samples/state.json`。

- [ ] **步骤 2：更新 env 和文档**

`.env.example` 包含：

```text
DEEPSEEK_API_KEY=
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash
DEEPSEEK_TIMEOUT=30
```

README 说明不读取真实 audit，不发送真实数据到 DeepSeek。

## 任务 4：验证与 smoke

**文件：**
- 无新增文件，生成物保持忽略。

- [ ] **步骤 1：完整测试**

运行：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_synthesize_training_samples.py -v
git diff --check -- scripts/synthesize_training_samples.py scripts/run_synthetic_samples.sh tests/test_synthesize_training_samples.py audit_training/README.md .gitignore .env.example
find scripts tests -type d -name __pycache__ -print
```

- [ ] **步骤 2：安全 DeepSeek smoke**

本地 `.env` 写入真实 key 后运行：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/synthesize_training_samples.py --env-file .env --target-count 1 --batch-size 1
```

预期：输出 `samples.jsonl` 一条纯合成记录，`state.json` completed 为 1，`git status --short` 不出现生成数据或 `.env`。
