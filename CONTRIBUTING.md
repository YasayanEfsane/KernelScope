# Contributing to KernelScope

Thank you for helping improve KernelScope. Contributions must preserve the
project's defensive purpose, documented-API policy, narrow kernel trust
boundary, and honest validation standards.

By participating, you agree to follow [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
Security vulnerabilities must use the private process in
[`SECURITY.md`](SECURITY.md), not a public issue or pull request.

## Scope gate

A proposal is eligible only when all of these statements are true:

- It serves authorized defensive research, engineering, reliability, or education.
- It uses documented and supported Microsoft APIs or documented file formats.
- It does not require hooking, patching, bypasses, hiding, stealth, persistence,
  credential access, arbitrary memory access, anti-cheat bypass, or EDR evasion.
- Kernel-mode work is necessary, minimal, bounded, and explainable.
- Trust-boundary, failure-mode, compatibility, and test impacts can be documented.

Maintainers will reject a change that violates this gate even if its code is
technically correct.

## Before starting

1. Search existing issues and pull requests.
2. Read `README.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, and
   `docs/PROTOCOL.md` when the change touches a boundary.
3. Open a defensive feature request for a significant change.
4. Explain why kernel mode is required for any new driver behavior.
5. Agree on protocol-version and compatibility handling before changing the ABI.

Small documentation fixes and isolated test corrections can go directly to a
pull request.

## Development environment

- Windows 10 or Windows 11 x64.
- Visual Studio 2022 or newer.
- Desktop development with C++ workload.
- A mutually compatible Windows SDK and WDK.
- A disposable VM snapshot for every driver runtime test.

Do not load development drivers on a workstation, production host, or machine
containing sensitive data.

## Branches and commits

- Create a focused branch from the current default branch.
- Keep commits small enough to review and bisect.
- Use imperative commit subjects such as `parser: reject overlapping raw ranges`.
- Separate mechanical formatting from behavior changes.
- Do not rewrite unrelated code or generated project metadata.
- Never commit build outputs, dumps, secrets, certificates, or third-party binaries.

## Engineering standards

### All code

- Keep source, comments, logs, errors, UI strings, tests, and documentation in English.
- Treat warnings as errors and keep `/W4` clean.
- Check every relevant system, framework, and cryptographic return value.
- Use explicit bounds and checked arithmetic at every untrusted-data boundary.
- Prefer deterministic behavior and fail-closed validation.
- Do not claim that code is vulnerability-free.

### Kernel mode

- Use C, KMDF, SAL annotations, and documented WDK APIs.
- Notification callbacks must perform minimal, bounded work.
- Do not allocate, hash, scan files, verify signatures, parse PE files, or
  serialize JSON in a notification callback.
- Use non-executable pool and preserve HVCI-compatible design principles.
- Document IRQL, locking, ownership, initialization, rollback, and unload behavior.
- Unregister every callback before its code or storage can be released.
- Complete failed IOCTLs with zero output bytes.

### User mode

- Use modern C++17 or newer and RAII for owned resources.
- Do not allow exceptions to cross system or protocol boundaries.
- Validate every driver response independently.
- Preserve meaningful Win32 errors and stable exit codes.
- Treat file bytes, paths, trust results, and protocol responses as untrusted input.

### Protocol changes

- Use fixed-width Windows integer types only.
- Do not add pointers, handles, `size_t`, flexible arrays, bitfields, or native enums.
- Add compile-time size and offset assertions.
- Define and reject unknown flags, message types, and nonzero reserved fields.
- Update `docs/PROTOCOL.md`, offline tests, negative integration tests, and the
  collector's independent validation.
- Use a new protocol version for an incompatible ABI or semantic change.

### Parser changes

- Do not trust memory-mapped image semantics.
- Validate addition, multiplication, offsets, sizes, counts, RVAs, and terminators.
- Add a synthetic non-executable regression case for each bug.
- Do not add malware, proprietary drivers, or redistributability-unclear samples.

## Tests

At minimum, a pull request should run:

```powershell
msbuild .\collector\KernelScopeCollector.vcxproj /m `
  /p:Configuration=Release /p:Platform=x64

.\tools\run-tests.ps1 -Configuration Release
```

Kernel changes additionally require a WDK build and the relevant isolated-VM
integration cases. Record:

- Windows build;
- Visual Studio, SDK, and WDK versions;
- HVCI/Memory Integrity state;
- build configuration;
- offline and integration results;
- Driver Verifier use, if any;
- known warnings, limitations, or skipped cases.

Driver Verifier is manual and VM-only. Never add a script that enables it
automatically.

## Documentation

Update documentation in the same pull request when behavior, commands, output,
security assumptions, protocol fields, findings, tests, or limitations change.
All links and examples must be valid and must not contain secrets or fictional
claims of completed testing.

## Pull request checklist

- Complete `.github/pull_request_template.md`.
- Describe purpose, design, alternatives, trust-boundary impact, and failure modes.
- Link the relevant issue when one exists.
- Include regression tests and exact validation results.
- State whether the protocol, SDDL, IOCTL access, IRQL, allocation, or signing
  behavior changed.
- Keep the pull request free of unrelated changes.

## Review criteria

Reviewers prioritize:

1. defensive scope and documented API usage;
2. kernel safety and lifecycle correctness;
3. trust-boundary validation;
4. compatibility and protocol stability;
5. deterministic offline regression coverage;
6. honest limitations and documentation;
7. maintainability and clarity.

A pull request may be closed when its safety model is unclear, its tests cannot
be reproduced, or its requested behavior is outside project scope.

## Licensing and provenance

Contributions are submitted under the repository's MIT License. Submit only code
and documentation that you have the right to license. Identify third-party
inspiration or specifications when required, and do not copy proprietary or
license-incompatible material.

