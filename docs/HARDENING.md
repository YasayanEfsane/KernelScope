# Production-hardening checklist

KernelScope is educational. Before any controlled deployment beyond a lab,
complete and record every applicable item:

- [ ] Independent kernel and user-mode security review completed.
- [ ] WDK Code Analysis, PREfast for Drivers, current MSVC analysis, and CodeQL clean.
- [ ] Offline tests and the full isolated-VM integration matrix pass on each
  supported Windows build.
- [ ] Driver Verifier was run manually in a disposable VM and every finding triaged.
- [ ] HVCI/Memory Integrity compatibility tested without disabling protections.
- [ ] EV/attestation or WHQL signing workflow is organization-controlled; no
  private key or signing secret is present in source control or CI artifacts.
- [ ] Release hashes and reproducible provenance are published.
- [ ] Device SDDL and IOCTL access bits remain least privilege.
- [ ] Protocol changes increment the version and preserve strict downgrade rules.
- [ ] Pool tags, object lifetimes, callback removal, and failure unwind paths reviewed.
- [ ] Event storms, multi-reader behavior, sequence exhaustion, and disk-full
  behavior have operational runbooks.
- [ ] JSONL directory has explicit restrictive ACLs, retention, and rotation policy.
- [ ] PDB paths and image paths are treated as potentially sensitive metadata.
- [ ] Trust/revocation policy is documented; unknown revocation is never called valid.
- [ ] Parser fuzzing runs continuously with ASan in user mode where supported.
- [ ] No feature added hooking, patching, arbitrary memory access, hiding,
  persistence, bypasses, executable pool, or undocumented APIs.
- [ ] Incident response covers safe service stop, evidence preservation, dump
  collection, and rollback.
- [ ] A support owner, update cadence, vulnerability intake, and end-of-life plan exist.

Any unchecked item is a documented deployment risk, not an implicit exception.

