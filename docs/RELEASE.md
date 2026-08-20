# Release process

## Release posture

KernelScope is currently a pre-1.0 educational project. A source snapshot is not
a production-supported driver release. Release readiness requires both source
quality and Windows-specific evidence.

## Versioning

Repository releases use semantic versioning:

- `MAJOR`: incompatible public user-mode behavior or a deliberately redesigned
  supported interface;
- `MINOR`: backward-compatible capability or analysis additions;
- `PATCH`: backward-compatible correctness, documentation, or security fixes.

The kernel/user protocol has its own integer version. Repository version changes
do not automatically change the protocol version. Any ABI or semantic protocol
change must follow the compatibility rules in `PROTOCOL.md`.

## Required release evidence

Record all of the following before creating a tag:

- exact source commit;
- Windows editions, versions, and build numbers tested;
- Visual Studio, Windows SDK, WDK, and KMDF versions;
- Debug and Release build logs with warnings treated as errors;
- offline test results;
- isolated-VM integration results;
- HVCI/Memory Integrity state and compatibility results;
- manual Driver Verifier configuration and outcome, if performed;
- CodeQL and static-analysis results;
- source archive SHA-256;
- known limitations, accepted risks, and deferred findings.

Do not claim a Windows or WDK combination was tested without retaining its
build and test evidence.

## Signing separation

Signing is an external release operation. The repository and ordinary CI must
never contain or expose:

- private certificate keys;
- `.pfx`, `.pvk`, HSM credentials, tokens, or PINs;
- reusable signing secrets;
- unsigned or test-signed kernel binaries presented as production artifacts.

An organization-controlled signing job may consume an approved source/build
input after review. Release provenance should identify the exact source commit,
toolchain, and resulting hashes without exposing secret material.

## Release checklist

1. Freeze the intended scope and review all changes since the previous tag.
2. Confirm the defensive-scope and documented-API policies still hold.
3. Review `Protocol.h`, ABI assertions, IOCTL access bits, and SDDL changes.
4. Run formatting, source scans, XML/YAML validation, and static analysis.
5. Build user-mode Debug and Release targets on Windows.
6. Run all offline tests.
7. Build the WDK project with the recorded toolchain.
8. Test-sign only in a disposable VM and run the integration matrix.
9. Review callback cleanup, unload, ring-overflow, cancellation, and failure paths.
10. Complete the production-hardening checklist or document every exception.
11. Update `CHANGELOG.md`, `README.md`, and version metadata.
12. Create a signed source tag and a source archive.
13. Publish hashes, evidence summary, limitations, and upgrade notes.
14. Monitor private vulnerability reports and regression feedback.

## Source archive contents

A source release may contain source code, project files, documentation, scripts,
synthetic test data, and CI configuration. It must not contain compiled drivers,
executables, catalogs, private keys, certificates, dumps, credentials, malware,
or proprietary third-party binaries.

## Security releases

Security fixes should use the private reporting and coordinated disclosure
process in `SECURITY.md`. The release notes should describe affected versions,
impact, remediation, and validation without publishing exploit-enabling detail
before users have a reasonable opportunity to update.

## Rollback

If a release causes instability or a security regression:

1. stop distribution and mark the release as affected;
2. preserve source, build, and test evidence;
3. advise users to stop and remove the driver through the documented process;
4. restore a known-good source/tag rather than bypassing platform protections;
5. issue a corrected release with a new version and complete evidence;
6. document root cause and new regression coverage.

