#pragma once

#if DBG
#define KS_TRACE_INFO(Format, ...) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
        "KernelScope: " Format "\n", __VA_ARGS__))
#define KS_TRACE_ERROR(Format, ...) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
        "KernelScope: " Format "\n", __VA_ARGS__))
#else
#define KS_TRACE_INFO(...) ((void)0)
#define KS_TRACE_ERROR(...) ((void)0)
#endif

