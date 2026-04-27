<!-- 文件说明：源码目录说明文档。用于说明当前复现流程、阶段产物、测试方法和运行约定。 -->

# DeepReproduction

## 环境配置

```bash
cd DeepReproduction/source
pdm install
```

如果外网访问依赖本地代理，在运行需要联网的命令前显式添加：

```bash
HTTP_PROXY=http://127.0.0.1:7897 \
HTTPS_PROXY=http://127.0.0.1:7897 \
http_proxy=http://127.0.0.1:7897 \
https_proxy=http://127.0.0.1:7897
```

## 当前复现流程

当前主流程是：

```text
knowledge -> build -> poc -> verify
```

目前已经真正实现并验证到的阶段是：

- `knowledge`
- `build`

其中：

- `knowledge` 在宿主机执行，负责外部漏洞知识采集与结构化整理
- `build` 在宿主机准备 workspace、clone 仓库、收集本地证据，但真实构建通过 Docker 完成
- `poc` 和 `verify` 仍处于骨架阶段，架构上也要求在 Docker 中执行

## 文件流转

### 1. Knowledge 阶段

输入：

- `CVE ID`
- OSV 和参考链接
- 外部网页、补丁、PoC 线索

输出到 `Dataset/<CVE>/`：

- `vuln_yaml/task.yaml`
  - 任务基础信息
  - `repo_url`
  - `vulnerable_ref`
  - `fixed_ref`
- `vuln_yaml/knowledge.yaml`
  - `summary`
  - `affected_files`
  - `reproduction_hints`
  - `expected_error_patterns`
  - 候选 build 线索
- `vuln_yaml/knowledge_sources.yaml`
  - 参考链接筛选结果
- `vuln_yaml/runtime_state.yaml`
  - 阶段状态和 LLM 状态
- `vuln_data/vuln_diffs/patch.diff`
  - 后续 `build/poc/verify` 直接消费的补丁 diff
- `vuln_data/knowledge_sources/*`
  - 清洗后的网页、原始附件和解压内容

### 2. Build 阶段

输入：

- `Dataset/<CVE>/vuln_yaml/knowledge.yaml`
- `Dataset/<CVE>/vuln_yaml/task.yaml`
- `Dataset/<CVE>/vuln_data/vuln_diffs/patch.diff`

工作区：

- `workspaces/<CVE>/repo`
  - clone 下来的目标仓库
- `workspaces/<CVE>/artifacts/build`
  - build 阶段的所有动态产物

build 阶段当前会做：

1. clone 仓库到 `workspaces/<CVE>/repo`
2. 比较多个候选 ref
   - `knowledge.vulnerable_ref`
   - `knowledge.fixed_ref`
   - `fixed_ref^`
3. 读取真实源码中的构建证据
   - `Makefile`
   - `CMakeLists.txt`
   - `README`
   - CI 配置
   - patch 涉及文件
4. 生成 `build_context.yaml`
5. 由模型和规则共同生成 `build_plan.yaml`
6. 生成 `Dockerfile` 和 `build.sh`
7. 通过 `docker build` 和 `docker run` 执行真实构建
8. 落盘 `build.log` 和 `build_artifact.yaml`

输出到 `workspaces/<CVE>/artifacts/build/`：

- `build_context.yaml`
  - 本地证据汇总
  - 多个 ref 的 build 文件、README、patch 相关片段
- `build_plan.yaml`
  - 选中的 vulnerable/fixed ref
  - `build_system`
  - `install_packages`
  - `build_commands`
  - 可选 `dockerfile_override`
  - 可选 `build_script_override`
- `Dockerfile`
  - 本次 build 用的镜像定义
- `build.sh`
  - 容器内执行的构建脚本
- `build.log`
  - `docker build` 与 `container run` 的执行日志
- `build_artifact.yaml`
  - 最终构建产物和确认后的构建事实

### 3. 后续阶段约定

- `poc` 未来消费：
  - `knowledge.yaml`
  - `build_artifact.yaml`
  - `workspace/repo`
- `verify` 未来消费：
  - `knowledge.yaml`
  - `build_artifact.yaml`
  - `poc_artifact.yaml`

两者的真实执行都约定在 Docker 容器中完成。

## 运行依赖

- 项目使用 `pdm` 管理依赖
- 运行前需要准备 `.env`
- 已接入阶段相关的关键变量包括：
  - `KNOWLEDGE_AGENT_MODEL`
  - `KNOWLEDGE_AGENT_API_KEY`
  - `KNOWLEDGE_AGENT_BASE_URL`
  - `BUILD_AGENT_MODEL`
  - `BUILD_AGENT_API_KEY`
  - `BUILD_AGENT_BASE_URL`
  - `KNOWLEDGE_ENABLE_LLM_CURATION`
  - `KNOWLEDGE_MAX_REFERENCE_DEPTH`
  - `KNOWLEDGE_MAX_FETCH_COUNT`
  - `KNOWLEDGE_FETCH_TIMEOUT_SECONDS`
  - `LLM_TIMEOUT_SECONDS`

## Knowledge 阶段测试方法

当前最稳定的测试入口是：

```bash
pdm run python scripts/run_knowledge.py CVE-2022-28805 --dataset-root ../Dataset
```

如果外网访问依赖本地代理，使用：

```bash
HTTP_PROXY=http://127.0.0.1:7897 \
HTTPS_PROXY=http://127.0.0.1:7897 \
http_proxy=http://127.0.0.1:7897 \
https_proxy=http://127.0.0.1:7897 \
pdm run python scripts/run_knowledge.py CVE-2022-28805 --dataset-root ../Dataset
```

测试前如需清空旧产物，可删除对应 CVE 目录：

```bash
rm -rf ../Dataset/CVE-2022-28805
```

知识阶段成功后，重点检查：

1. 命令成功退出，并打印 `Knowledge stage completed`
2. `../Dataset/<CVE>/vuln_yaml/runtime_state.yaml` 中：
   - `final_status: success`
   - `last_error: null`
3. `../Dataset/<CVE>/vuln_yaml/task.yaml` 中：
   - `repo_url`、`vulnerable_ref`、`fixed_ref` 不为空
4. `../Dataset/<CVE>/vuln_data/knowledge_sources/cleaned/` 中：
   - 至少存在若干抓取后的清洗文件
5. `../Dataset/<CVE>/vuln_data/vuln_diffs/patch.diff`：
   - 文件非空
6. `../Dataset/<CVE>/vuln_yaml/knowledge.yaml`：
   - `summary` 不为空
   - `affected_files` 有值时说明补丁解析成功

## Build 阶段测试方法

当前 build 阶段的独立测试入口是：

```bash
pdm run python scripts/run_build.py CVE-2022-28805 --dataset-root ../Dataset --workspace-root workspaces
```

如果需要通过本地代理联网 clone 目标仓库，使用：

```bash
HTTP_PROXY=http://127.0.0.1:7897 \
HTTPS_PROXY=http://127.0.0.1:7897 \
http_proxy=http://127.0.0.1:7897 \
https_proxy=http://127.0.0.1:7897 \
pdm run python scripts/run_build.py CVE-2022-28805 --dataset-root ../Dataset --workspace-root workspaces
```

该命令会：

1. 从 `../Dataset/<CVE>/vuln_yaml/knowledge.yaml` 读取知识阶段结果
2. clone 目标仓库到 `workspaces/<CVE>/repo`
3. 读取真实 `Makefile/README/patch.diff`
4. 生成 `build_context.yaml` 和 `build_plan.yaml`
5. 生成 `artifacts/build/Dockerfile` 和 `build.sh`
6. 执行 `docker build`
7. 执行 `docker run ... /workspace/artifacts/build/build.sh`

测试前如需清空旧工作区，可删除：

```bash
rm -rf workspaces/CVE-2022-28805
```

Build 阶段成功后，重点检查：

1. 命令成功退出，并打印 `Build stage completed`
2. `workspaces/<CVE>/repo/` 已生成
3. `workspaces/<CVE>/artifacts/build/build_context.yaml`
   - 含有多个候选 ref 的源码快照
4. `workspaces/<CVE>/artifacts/build/build_plan.yaml`
   - 含有 `chosen_vulnerable_ref`
   - 含有 `build_system`
   - 含有 `install_packages` 与 `build_commands`
5. `workspaces/<CVE>/artifacts/build/Dockerfile`
   - 用于真实构建的镜像定义
6. `workspaces/<CVE>/artifacts/build/build.sh`
   - 容器内执行的构建脚本
7. `workspaces/<CVE>/artifacts/build/build.log`
   - 含有 `image_build_success=...`
   - 若镜像构建成功，还应含有 `container_run_success=...`
8. `workspaces/<CVE>/artifacts/build/build_artifact.yaml`
   - 记录最终构建状态和确认后的构建事实

## Verify 阶段测试方法

前提：

- knowledge 阶段已经跑过：`../Dataset/<CVE>/vuln_yaml/knowledge.yaml` 已存在
- build 阶段已经跑过：`workspaces/<CVE>/artifacts/build/build_artifact.yaml` 已存在，且对应的 Docker 镜像已构建（镜像 tag 即 `BuildArtifact.docker_image_tag`）
- poc 阶段已经跑过：`workspaces/<CVE>/artifacts/poc/poc_artifact.yaml` 已存在；如果还产出了 `run_verify.yaml`，verify 阶段会读取其中的 `eligible_for_verify` 做短路判断

当前 verify 阶段的独立测试入口是：

```bash
pdm run python scripts/run_verify.py CVE-2022-28805 --dataset-root ../Dataset --workspace-root workspaces
```

该命令会：

1. 从前序阶段的产物读取 `KnowledgeModel` / `BuildArtifact` / `PoCArtifact`
2. 短路检查：如果 `run_verify.yaml.eligible_for_verify` 为 false，或 patch.diff 找不到，或 image tag 缺失 → 直接判 `inconclusive`，不跑 docker
3. 渲染 `verify.Dockerfile`、`verify_run.sh`，把 patch.diff 拷贝到 `workspaces/<CVE>/artifacts/verify/patch.diff`
4. 执行两次独立的 docker run（环境变量 `PATCH_MODE=pre|post`），共用同一镜像
5. 解析两次执行的日志，比较 pre/post 行为
6. 落盘 `verify_result.yaml`

Verify 阶段成功后，重点检查 `workspaces/<CVE>/artifacts/verify/` 下：

1. `verify_context.yaml` — 收集到的本地证据
2. `verify_plan.yaml` — 渲染前的执行计划
3. `Dockerfile`、`verify_run.sh`、`patch.diff` — 实际执行用的产物
4. `pre_patch.log`、`post_patch.log` — 两次容器运行的完整日志
5. `verify_result.yaml` — 最终判定结果

`verify_result.yaml` 关键字段：

- `verdict`：`success` | `failed` | `inconclusive`
- `confidence`：`high` | `medium` | `low`
- `pre_patch_triggered` / `post_patch_clean`：核心比对结论
- `patch_apply_success`：post 模式下 `git apply` 是否成功

三态语义：

- `success`：pre 触发 + post 不触发，复现闭环
- `failed`：`pre_not_triggered`（PoC 在漏洞态没打到目标行为）或 `post_still_triggered`（patch 没修复）
- `inconclusive`：`patch_apply_failed`（patch 在镜像里打不上）/ `log_not_well_formed`（脚本输出不完整）/ `poc_run_verify_ineligible`（PoC 自己说不合格）/ `stage_exception`（verify 本身异常）

## 如何判断大模型是否生效

查看：

- `../Dataset/<CVE>/vuln_yaml/runtime_state.yaml`
- `workspaces/<CVE>/artifacts/build/build_plan.yaml`

重点字段：

- `llm_status: success`
  - 表示模型成功返回并被系统接受

- `llm_status: failed`
  - 表示模型调用失败，系统回退到规则化知识生成

- `llm_status: unexpected_response`
  - 表示模型返回了非预期 JSON

- `llm_status: disabled`
  - 表示当前关闭了知识阶段大模型整理

当 `llm_status: success` 时，`knowledge.yaml` 中通常会看到更紧凑的：

- `summary`
- `vulnerability_type`
- `reproduction_hints`
- `expected_error_patterns`

当 build 阶段模型生效时，`build_plan.yaml` 中通常会看到：

- 更具体的 `install_packages`
- 更贴近目标仓库的 `build_commands`
- 失败后修正过的 `rationale`
- 必要时出现 `dockerfile_override` 或 `build_script_override`

## 当前已验证能力

当前知识阶段已经验证可运行的能力包括：

- OSV 引导任务信息
- 保留 OSV `references[].type`
- `FIX` / `EVIDENCE` 参考链接按高优先级抓取
- 网页抓取与清洗
- GitHub commit 和 `.diff` 抓取
- 标准 `patch.diff` 落盘
- LLM JSON 输出解析
- LLM 状态显式记录
- LLM 辅助识别并落盘 PoC

当前 build 阶段已经验证可运行的能力包括：

- 消费 `knowledge.yaml` 和 `patch.diff`
- clone 目标仓库
- 对 `vulnerable_ref`、`fixed_ref`、`fixed_ref^` 做本地源码快照
- 读取真实 `Makefile/README`
- 生成 `build_context.yaml`
- 模型参与生成 `build_plan.yaml`
- 生成 `Dockerfile` 和 `build.sh`
- 通过 Docker 执行 build
- 区分 `docker_build` 与 `container_run` 两类失败
- 失败后按失败类型重规划
