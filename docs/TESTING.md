# Testing and debugging

## Offline tests

Offline tests require Visual Studio C++ and a Windows SDK, but do not require
administrator rights or a loaded driver:

```powershell
.\tools\run-tests.ps1 -Configuration Release
```

The executable returns nonzero on any failed case. Tests construct PE byte
arrays in memory and do not download or execute a corpus.

## Optional isolated-VM integration matrix

Take a snapshot, build and test-sign the driver, install it, then run the basic
script from an elevated PowerShell:

```powershell
msbuild .\tests\Integration\KernelScopeIntegration.vcxproj /m /p:Configuration=Release /p:Platform=x64
.\tests\Integration\DriverIntegration.Tests.ps1 `
  -CollectorPath .\collector\x64\Release\KernelScopeCollector.exe `
  -NegativeClientPath .\tests\Integration\x64\Release\KernelScopeIntegration.exe `
  -DriverPath .\driver\x64\Debug\KernelScopeDriver.sys `
  -AllowTestSigned
```

Omit `-DriverPath` when the driver is already loaded. Add `-ExerciseOverflow`
only when the VM snapshot is disposable; it creates many short-lived processes.

Complete this manual matrix before a release candidate:

| Case | Expected result |
| --- | --- |
| Driver load/unload | Device appears; callbacks are removed; unload succeeds |
| Protocol negotiation | v1 capabilities and bounds are exact |
| Invalid IOCTL | Fails with zero returned bytes |
| Undersized/oversized fixed buffers | `STATUS_INFO_LENGTH_MISMATCH`, zero bytes |
| Zero/65-event batch | Rejected; 1 and 64 accepted |
| Unsupported version | Rejected with zero bytes |
| Nonzero reserved/unknown flag/type | Rejected with zero bytes |
| Repeated open/close | No handle/object growth |
| Ring overflow | Dropped total grows; later sequence gap/drop record appears |
| Process and image generation | Bounded create/exit and image records appear |
| Collector termination during requests | Handle closes; driver remains usable |
| Unload after activity | No callbacks execute after unload |
| Reset through read-only handle | I/O manager denies access |
| Reset through authorized write handle | Counters reset; sequence does not reset |

Malformed IOCTL cases should be implemented in a dedicated, reviewed user-mode
negative-test client that imports `Protocol.h`. Never use a generic arbitrary
kernel IOCTL fuzzer. Fuzz only this project's documented protocol and only in a
disposable VM.

## Driver Verifier — manual only

> **DANGER:** Driver Verifier intentionally stresses kernel drivers and may
> crash or boot-loop the test machine. Never run these commands on a workstation
> or production system. Use a disposable VM, take a snapshot, enable recovery,
> and know how to enter Safe Mode before continuing. No KernelScope script
> enables Driver Verifier automatically.

From an elevated terminal in the isolated VM:

```powershell
verifier.exe /standard /driver KernelScopeDriver.sys
verifier.exe /querysettings
```

Reboot, exercise the integration matrix, collect any crash dump, then disable:

```powershell
verifier.exe /reset
```

If the VM cannot boot, enter Safe Mode or Windows Recovery and run the reset
command. Revert the snapshot if recovery is uncertain.

## WinDbg

Configure kernel debugging between two isolated VMs or a host/test VM according
to Microsoft's current documentation. Use public symbols and a private symbol
path for the matching KernelScope build:

```text
.symfix
.sympath+ C:\Symbols\KernelScope
.reload /f
lm m KernelScopeDriver
bp KernelScopeDriver!KsEvtIoDeviceControl
bp KernelScopeDriver!KsRingPush
!wdfkd.wdfldr
```

Do not log complete protocol buffers, file contents, certificate private data,
or unrelated process memory. Useful observations are NTSTATUS values, ring
indices/counts, event types, sequence numbers, and callback registration flags.

## Fuzzing strategy

- Expose `PeParser::ParseBytes` to a coverage-guided harness.
- Seed only tiny, redistributable synthetic PE structures.
- Assert termination, bounded memory use, and no sanitizer finding.
- Add every minimized crash as a non-executable regression byte array.
- For the driver protocol, generate only structures defined by `Protocol.h` and
  mutate lengths, versions, types, flags, reserved fields, counts, and output
  sizes in the isolated VM.
- Never fuzz unrelated device objects, Windows itself, third-party drivers, or
  undocumented interfaces.
