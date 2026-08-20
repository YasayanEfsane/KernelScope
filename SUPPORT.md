# Support

KernelScope is an educational project and currently has no commercial or
production support commitment. Community support is best effort.

## Supported requests

- Building the user-mode projects with Visual Studio 2022.
- Building the driver with a compatible Windows SDK and WDK.
- Understanding the documented protocol and JSONL schema.
- Reproducing offline test failures.
- Diagnosing installation in an isolated, test-signed VM.
- Interpreting PE-analysis findings and Authenticode result categories.
- Defensive feature proposals that preserve the security boundary.

## Unsupported requests

- Production deployment approval or operational guarantees.
- Malware development, offensive tradecraft, or evasion.
- Hooking, patching, hiding, stealth, persistence, or credential collection.
- PatchGuard, HVCI, DSE, Secure Boot, signature, anti-cheat, or EDR bypasses.
- Arbitrary kernel/process memory access.
- Analysis of proprietary binaries that the reporter is not authorized to share.
- Debugging on a machine without a tested recovery path or disposable snapshot.

## Before opening an issue

1. Read `README.md` and the relevant document under `docs/`.
2. Rebuild the driver and user-mode tools from the same commit.
3. Run the offline tests.
4. Confirm the exact Windows, Visual Studio, SDK, WDK, and KMDF versions.
5. Record whether HVCI/Memory Integrity, Secure Boot, and test signing are enabled.
6. Reduce the problem to the smallest safe reproduction in an isolated VM.
7. Remove credentials, keys, unrelated memory, proprietary data, and personal information.

## Useful diagnostic information

- Exact commit or source archive hash.
- Windows edition, version, and build number.
- Visual Studio, SDK, and WDK versions.
- Build configuration and complete warning/error text.
- Collector command and exit code.
- Driver service state from `sc.exe query KernelScopeDriver`.
- Minimal sanitized protocol trace, stack trace, or debugger output.
- Whether the issue reproduces with HVCI/Memory Integrity enabled.

Do not upload complete crash dumps publicly. They can contain credentials,
tokens, private data, unrelated process memory, and proprietary code.

## Security issues

Do not use a public support issue for a vulnerability. Follow
[`SECURITY.md`](SECURITY.md) and use GitHub's private vulnerability-reporting
workflow.

## Response expectations

There is no guaranteed response time. Maintainers may close reports that lack a
reproduction, fall outside the defensive scope, duplicate an existing report,
or require unsafe testing on a non-disposable system.

