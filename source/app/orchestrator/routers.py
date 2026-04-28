"""文件说明：阶段路由规则。

这个文件负责回答一个问题：
“某个阶段执行完之后，流程下一步应该去哪里？”

这里不关心阶段内部细节，只依据共享状态中的结果字段做判断。
这样可以把“阶段实现”和“流程跳转”明确分开，方便后续单独调整重试策略。
"""

MAX_BUILD_RETRY = 2
MAX_POC_RETRY = 2


def route_after_build(state):
    """构建阶段后的路由规则。

    返回值语义：
    - `poc`：构建成功，进入 PoC 阶段。
    - `build`：构建失败但仍可重试。
    - `failed`：构建失败且达到重试上限，结束流程。
    """

    build = state.get("build")
    retry_count = state.get("retry_count", {})

    if build and build.build_success:
        return "poc"

    if retry_count.get("build", 0) < MAX_BUILD_RETRY:
        return "build"

    return "failed"


def route_after_poc(state):
    """PoC 阶段后的路由规则。

    设计决定（任务 0 H5）：闸门用 execution_success 而不是 reproducer_verified。
    理由：reproducer_verified=False 也应该有机会进入 verify 阶段，让 verify 在
    隔离的 docker 环境里做独立差分判定——可能 PoC 的 pattern matching 太严，
    但 verify 用 pre/post 差分能看出真实情况。

    即"脚本跑通但没打到目标行为"也推进到 verify；仅当脚本根本没跑通才走重试或失败。
    """

    poc = state.get("poc")
    retry_count = state.get("retry_count", {})

    if poc and poc.execution_success:
        return "verify"

    if retry_count.get("poc", 0) < MAX_POC_RETRY:
        return "poc"

    return "failed"


def route_after_verify(state):
    """验证阶段后的路由规则。

    返回值语义：
    - `success`：复现闭环（pre 触发 + post 不触发）
    - `failed`：复现失败（pre 未触发 或 post 仍触发）
    - `inconclusive`：无法判定（patch 打不上 / log 不完整 / 阶段异常）

    当前三个出口都接到 END。`inconclusive` 出口保留给未来人工复核或重试。
    """

    verify = state.get("verify")
    if verify is None:
        return "failed"
    if verify.verdict == "success":
        return "success"
    if verify.verdict == "inconclusive":
        return "inconclusive"
    return "failed"
