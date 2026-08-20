# Validation record

## 2026-08-20 source-delivery validation

The generation environment was Linux and did not contain Visual Studio, MSVC,
the Windows SDK, the WDK, KMDF libraries, PowerShell, or a Windows kernel. No
claim is made that the driver or complete Windows executables were built here.

Checks completed in the available environment:

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
- The final source archive passed a complete ZIP integrity check after all
  documentation, governance, and repository metadata updates.

Required Windows release validation remains:

1. Build all relevant projects with Visual Studio 2022, the paired current
   Windows SDK/WDK, `/W4`, warnings as errors, and WDK Code Analysis.
2. Run `KernelScopeTests.exe` on Windows to exercise BCrypt SHA-256 and the real
   SDK PE definitions.
3. Sign and load only in a snapshotted isolated VM.
4. Run `KernelScopeIntegration.exe`, the PowerShell integration workflow, and
   the complete manual negative matrix in `TESTING.md`.
5. Run Driver Verifier only under the explicit manual safety procedure.
6. Record Windows build numbers, SDK/WDK versions, HVCI state, hashes, logs, and
   any deviations before assigning a release tag.
