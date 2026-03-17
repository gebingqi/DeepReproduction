"""计划功能：定义主流程阶段路由规则，决定构建、PoC 与验证阶段的重试和流转方向。"""
MAX_BUILD_RETRY = 2
MAX_POC_RETRY = 2


def route_after_build(state):
    build = state.get("build")
    retry_count = state.get("retry_count", {})

    if build and build.build_success:
        return "poc"

    current = retry_count.get("build", 0)
    if current < MAX_BUILD_RETRY:
        return "build"

    return "failed"


def route_after_poc(state):
    poc = state.get("poc")
    retry_count = state.get("retry_count", {})

    if poc and poc.execution_success:
        return "verify"

    current = retry_count.get("poc", 0)
    if current < MAX_POC_RETRY:
        return "poc"

    return "failed"


def route_after_verify(state):
    verify = state.get("verify")
    if verify and verify.verdict == "success":
        return "success"
    return "failed"
