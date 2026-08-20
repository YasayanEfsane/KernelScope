# Threat model

## Assets

- Kernel stability and memory integrity.
- Authenticity and ordering of telemetry delivered by the driver.
- Availability of the fixed ring and collector output.
- Integrity of analyzed file bytes and reported hash/signature status.
- Confidentiality of local filesystem paths present in telemetry or PE debug data.

## Trust assumptions

KernelScope trusts the Windows kernel, KMDF, I/O manager ACL enforcement,
supported notification APIs, CNG, WinTrust, configured certificate stores, and
the administrator boundary. It assumes the driver binary loaded by the OS is
the reviewed build. LocalSystem and Administrators are trusted operators.

KernelScope does not protect against a compromised kernel, a malicious
administrator, vulnerable third-party kernel code, offline output tampering,
or signing-root compromise. It is a sensor and analysis aid, not a policy
enforcement mechanism.

## Adversary-controlled inputs

- Process IDs, parent IDs, image paths, image bases, and image sizes reported to
  documented callbacks.
- IOCTL input buffers and lengths from an ACL-authorized caller.
- Every byte, offset, RVA, count, and string in a PE/COFF file.
- Output paths and command-line values selected by the operator.
- Certificate/trust data exposed by the configured Windows trust providers.

## Controls

- `SDDL_DEVOBJ_SYS_ALL_ADM_ALL` plus `FILE_DEVICE_SECURE_OPEN`.
- `FILE_READ_DATA` for query/collection and `FILE_WRITE_DATA` for reset.
- `METHOD_BUFFERED` only; exact sizes; version/type/flag/reserved validation.
- Fixed records, fixed ring capacity, `NonPagedPoolNx`, and no callback allocation.
- Saturating arithmetic and checked ring indices.
- Callback unregistration before secure ring cleanup.
- Independent user-mode validation of every response and event.
- File-byte parsing with checked addition, multiplication, ranges, and RVA mapping.
- Cache-only WinTrust revocation policy with a distinct inconclusive status.
- No binary payloads, arbitrary memory, credentials, or private keys in telemetry.

## Abuse cases and residual risk

| Abuse case | Control | Residual risk |
| --- | --- | --- |
| Unprivileged process opens device | SDDL and I/O manager access checks | Misconfigured host security can undermine ACLs |
| Authorized caller submits malformed protocol | Exact validation and zero-byte failures | Logic defect in a future protocol version |
| Event storm exhausts storage | Fixed ring, drops, gap/statistics reporting | Telemetry loss is intentional under overload |
| Malformed PE targets parser | No mapping; checked offsets/RVAs/arithmetic | Parser defects require fuzzing and review |
| Invalid signature appears valid | WinTrust result mapping; unknown is distinct | Local trust-store compromise or policy mismatch |
| Output reveals sensitive path | Only bounded metadata; operator controls output ACL | Paths/PDB strings may still contain user names |
| Administrator resets counters | Write access and admin-only SDDL | Admin is inside the trust boundary |
| Collector crashes/stops | Ring remains bounded and drop-aware | Events may be lost before restart |

## Out of scope by design

There is no hooking, patching, executable-memory modification, security-feature
bypass, arbitrary memory inspection, hiding, credential capture, stealth,
persistence, unsupported API, kernel filesystem scanning, or network monitoring.
Feature requests that require any of those behaviors must be rejected.

