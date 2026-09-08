# Validation record

## Driver-specific CodeQL policy

The dedicated `driver-codeql.yml` workflow uses CodeQL CLI 2.25.5,
`microsoft/windows-drivers` 1.10.0, and `microsoft/cpp-queries` 0.0.5, pinned to
Microsoft's current general-use combination for driver analysis. The captured x64 Release KMDF build continues
to use the repository's WDK/SDK 10.0.26100.6584 packages. The workflow runs both
the recommended and must-fix driver suites, publishes the recommended SARIF to
GitHub code scanning, and fails when the must-fix suite reports a result.

Only SARIF and text evidence are uploaded. The workflow never installs, starts,
signs, or uploads the driver binary and does not use signing credentials. This
is static source analysis; it is not driver runtime validation, a Driver
Verification Log, HLK completion, WHCP certification, or proof of kernel safety.

Microsoft identifies CodeQL as the primary static-analysis direction for
Windows drivers and documents that Static Driver Verifier is unavailable in
WDKs newer than build 26017:

- [CodeQL analysis for Windows driver code](https://learn.microsoft.com/windows-hardware/drivers/devtest/static-tools-and-codeql)
- [Static Driver Verifier support status](https://learn.microsoft.com/windows-hardware/drivers/devtest/static-driver-verifier)

## 2026-09-04 hosted Windows/WDK validation

Pull request [#7](https://github.com/YasayanEfsane/KernelScope/pull/7)
introduced a real WDK validation job. The first complete proof was
[wdk-driver-ci run 4](https://github.com/YasayanEfsane/KernelScope/actions/runs/33869017695)
for source commit `7c9ace873b9d59d6e38bdfe3f252623fc3b7ba8f`.

| Component | Observed value |
| --- | --- |
| Runner | Windows Server 2022 Datacenter, build 20348 |
| Runner image | `windows-2022`, image `20260830.290.1` |
| Visual Studio | Enterprise 2022, `17.14.37614.0` |
| MSBuild | x64 `17.14.51.32402` |
| WDK and SDK NuGet packages | `10.0.26100.6584` |
| Driver target | x64, KMDF 1.15, Universal |
| Configurations | Debug and Release |

The successful job:

- restored exact Microsoft WDK and matching SDK package versions;
- selected Visual Studio 2022/MSBuild 17 explicitly instead of a floating
  Visual Studio major version;
- rebuilt every driver C source in Debug and Release with `/W4`, warnings as
  errors, SDL checks, Spectre mitigations, and `/INTEGRITYCHECK`;
- linked the documented `Wdmsec.lib` dependency used by the secure device SDDL;
- produced both x64 driver images without compiler or linker diagnostics;
- ran `InfVerif /u` successfully;
- confirmed that the Release image was `NotSigned`; and
- uploaded only text logs and manifests after rejecting binary and signing
  material from the evidence directory.

The proof-run Release image was 13,824 bytes with SHA-256
`15056a78aaceb8326f8a7fa4b1a3fec55ce04a3604dd5015a761ee9be23a2542`.
This hash identifies ephemeral unsigned CI output; it is not a release artifact.
The current workflow validates the stamped Release INF, records its exit code,
and still does not upload the driver binary.

## 2026-08-20 source-delivery validation

The generation environment was Linux and did not contain Visual Studio, MSVC,
the Windows SDK, the WDK, KMDF libraries, PowerShell, or a Windows kernel. No
claim was made at that time that the driver or complete Windows executables had
been built there.

Checks completed in that environment:

- `Protocol.h` and `ProtocolValidation.h` compiled as strict C11.
- The protocol offline test executable compiled as C++17 with `-Wall -Wextra
  -Werror -pedantic`; all 5 cases passed.
- The PE parser and its synthetic tests compiled against temporary validation
  definitions of the documented PE structures; all 4 cases passed. Those
  temporary definitions are not part of the repository.
- Sequence-gap and JSON-escaping tests compiled with temporary Win32 function
  declarations; both cases passed. The temporary declarations are not part of
  the repository.
- `JsonWriter.cpp` compiled as C++17 with warnings as errors.
- Every `.vcxproj` and MSBuild property file parsed as XML.
- Every GitHub workflow and issue-template YAML file parsed successfully.
- `CITATION.cff` and the Dependabot configuration parsed successfully as YAML.
- All 32 local Markdown links resolved to files inside the repository.
- Repository-wide scans found no placeholder domains or authoring markers, no
  trailing whitespace, and no non-English Turkish characters.
- Source scanning found no `METHOD_NEITHER`, direct I/O method, arbitrary-memory
  primitive, forbidden hook/patch primitive, compiled binary, certificate, or
  private-key artifact.
- The source archive passed a complete ZIP integrity check.

## Validation still required before a driver release

Hosted compilation is a package-quality gate, not kernel runtime validation.
A release candidate still requires:

1. Review and disposition every driver-specific CodeQL result; generate and
   validate a DVL separately if a future release pursues WHCP certification.
2. Build and sign only in an organization-controlled release environment.
3. Load the signed package only in a snapshotted isolated VM.
4. Run `KernelScopeIntegration.exe`, the PowerShell integration workflow, and
   the complete manual negative matrix in `TESTING.md`.
5. Exercise HVCI/Memory Integrity compatibility and run Driver Verifier only
   under the explicit manual safety procedure.
6. Record Windows build numbers, toolchain versions, hashes, logs, signing
   provenance, and every deviation before assigning a release tag.
