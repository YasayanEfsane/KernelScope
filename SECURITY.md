# Security policy

KernelScope is an educational kernel project with a security-sensitive parser
and protocol. Responsible private reporting is essential.

## Supported versions

| Version | Security support |
| --- | --- |
| Current default branch | Best-effort fixes |
| Latest source release | Best-effort fixes when reproducible |
| Older commits or educational snapshots | Not supported |
| Modified forks and unsigned third-party builds | Not supported |

There is currently no production-supported release, guaranteed response time,
or backport commitment.

## Report a vulnerability privately

Use GitHub's **Security** tab and **Report a vulnerability** workflow. Do not
open a public issue, discussion, or pull request for an undisclosed security
problem.

Include as much of the following as is safe:

- affected commit, tag, or source archive hash;
- Windows edition, version, and build;
- Visual Studio, Windows SDK, WDK, and KMDF versions;
- whether HVCI/Memory Integrity, Secure Boot, and test signing were enabled;
- affected component and trust boundary;
- minimal reproduction steps in an isolated VM;
- expected and observed behavior;
- sanitized stack trace, NTSTATUS/Win32 code, or parser input construction;
- confidentiality, integrity, and availability impact;
- whether the issue is reliably reproducible;
- suggested mitigation, if known.

## Do not submit

- Private keys, `.pfx`, `.pvk`, passwords, tokens, credentials, or HSM material.
- Complete public crash dumps or unrelated process/kernel memory.
- Proprietary drivers or binaries without redistribution authorization.
- Malware samples, exploit kits, or offensive tooling.
- Personal information or data belonging to another person.
- A public proof of concept before coordinated disclosure.

Prefer a small synthetic reproduction. If a dump is essential, agree on a
private transfer and sanitization process before sharing it.

## In-scope security areas

- Kernel memory safety and ring-buffer bounds.
- Callback registration, rollback, synchronization, cleanup, and unload.
- Device SDDL and IOCTL access control.
- Protocol size, version, flag, message, reserved-field, and output validation.
- Sequence/drop accounting errors that cause unsafe behavior or false integrity claims.
- PE parser out-of-bounds access, overflow, denial of service, or trust confusion.
- SHA-256 or Authenticode result misclassification.
- JSON escaping or output handling that creates a security boundary failure.
- Build/release behavior that exposes secrets or misrepresents signed artifacts.

## Out-of-scope requests

- Hooking, kernel patching, or executable-memory modification.
- PatchGuard, HVCI, DSE, Secure Boot, signature, anti-cheat, or EDR bypasses.
- Arbitrary kernel/process memory reading or writing.
- Hiding, credential collection, persistence, stealth, or offensive evasion.
- Vulnerabilities in Windows, KMDF, CNG, WinTrust, GitHub Actions, or third-party
  tools that do not arise from KernelScope's own code or configuration.
- Testing on systems the reporter is not authorized to use.

## Response process

Maintainers will make a best-effort attempt to:

1. acknowledge the report privately;
2. verify scope and request missing safe details;
3. reproduce in an isolated environment;
4. assess severity and affected versions;
5. prepare a fix and regression test;
6. validate user-mode and kernel changes at the appropriate level;
7. coordinate disclosure and release notes;
8. credit the reporter when requested and appropriate.

Timelines depend on severity, reproducibility, maintainer availability, and the
need for Windows/WDK/VM validation. Silence is not permission to disclose
sensitive details prematurely.

## Coordinated disclosure

Please allow a reasonable opportunity to investigate and release a correction.
Once remediation is available, disclosure should describe impact, affected
versions, and mitigation without unnecessarily enabling abuse.

## Safe-harbor intent

Good-faith research is welcome when it:

- targets only systems and files the researcher is authorized to test;
- follows this policy and avoids privacy violations or service disruption;
- uses the minimum data and access necessary;
- reports findings privately and allows coordinated remediation;
- does not use KernelScope to develop offensive, stealth, or bypass capability.

This statement expresses project intent and is not legal advice or authorization
to test third-party systems.

## Operational safety

Reproduce kernel issues only in a disposable, snapshotted VM with a tested
recovery path. Driver Verifier may intentionally crash or boot-loop the VM and
must never be enabled automatically. Follow `docs/TESTING.md`.

