## Summary

Describe the defensive purpose and implementation.

## Design and boundaries

Describe alternatives considered, kernel/user responsibility, untrusted inputs,
IRQL, locking, ownership, failure modes, and compatibility impact.

## Security and compatibility

- [ ] Uses only documented Windows/WDK APIs.
- [ ] Adds no hooks, patches, bypasses, hiding, arbitrary memory access, stealth, or persistence.
- [ ] Kernel callback work remains fixed, bounded, and allocation-free.
- [ ] Protocol ABI changes include a version decision and size/offset assertions.
- [ ] SDDL, IOCTL access bits, output-size behavior, and reserved fields were reviewed.
- [ ] Threat model and failure modes were reviewed.
- [ ] No binary, key, secret, dump, malware, or third-party driver was added.

## Validation

- [ ] User-mode Release build is warning-free.
- [ ] Offline tests pass.
- [ ] WDK build result and exact environment are recorded, if kernel code changed.
- [ ] Optional integration/Verifier testing occurred only in an isolated snapshot VM.
- [ ] README, protocol, security, testing, and changelog documentation are updated.

## Evidence

List the exact commands, Windows build, Visual Studio/SDK/WDK versions, HVCI
state, test results, and any skipped checks or remaining limitations.
