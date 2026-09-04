# GitHub repository setup

This guide turns the source package into a maintainable GitHub repository. The
exact names of GitHub settings can change over time; use the current equivalent
when the interface differs.

## 1. Prepare the source tree

Extract the source package and publish the contents of the `KernelScope`
directory, not the outer ZIP file. Confirm that the tree contains no build
outputs, signing material, dumps, credentials, or third-party binaries.

From a terminal in the repository root:

```powershell
git init
git add .
git commit -m "Initial defensive KernelScope source release"
git branch -M main

$RepositoryUrl = Read-Host 'Enter the new Git repository URL'
git remote add origin $RepositoryUrl
git push -u origin main
```

Review the staged file list before the first commit:

```powershell
git status --short
git ls-files
```

Do not override `.gitignore` to add `.sys`, `.exe`, `.dll`, `.pfx`, `.pvk`,
`.cer`, `.cat`, dumps, or build directories.

## 2. Repository identity

Recommended description:

> Defensive Windows KMDF telemetry, PE/COFF analysis, SHA-256, Authenticode,
> JSONL reporting, and hardened kernel/user protocol validation.

Recommended topics:

- `windows`
- `windows-kernel`
- `kmdf`
- `driver-development`
- `defensive-security`
- `kernel-telemetry`
- `pe-coff`
- `authenticode`
- `cpp17`
- `cybersecurity-education`

Set the license to MIT and keep Releases, Issues, and Security visible. Enable
Discussions only when there is capacity to moderate them.

## 3. Default branch and ruleset

Use `main` as the default branch. Create a branch ruleset or protection rule
that:

- requires pull requests before merging;
- prevents force pushes and branch deletion;
- requires at least one approving review when collaborators are present;
- dismisses stale approvals after new commits;
- requires conversation resolution;
- requires the user-mode CI, WDK driver CI, and CodeQL checks observed on pull requests;
- requires the branch to be current before merge when practical;
- restricts direct pushes to maintainers or uses the same pull-request path for everyone.

Do not guess required check names before the workflows have run once. Select the
exact checks GitHub reports for `.github/workflows/ci.yml`,
`.github/workflows/wdk-driver.yml`, and `.github/workflows/codeql.yml`.

Avoid allowing administrators to bypass the ruleset for ordinary changes. Keep
an emergency path documented and auditable.

## 4. Actions permissions

The workflows request minimal repository permissions. In repository settings:

- allow only the actions needed by the checked-in workflows;
- prefer actions from GitHub and verified publishers;
- keep the default workflow token read-only unless a workflow explicitly needs more;
- require approval for workflows from first-time outside contributors;
- do not place signing keys or reusable driver-signing credentials in ordinary Actions secrets.

Dependabot is configured for monthly GitHub Actions update pull requests. Review
action updates like code changes; do not merge them blindly.

## 5. Security settings

Enable the security features available for the repository and account plan:

- dependency graph;
- Dependabot alerts;
- Dependabot security updates;
- CodeQL/code scanning;
- secret scanning and push protection;
- private vulnerability reporting;
- security advisories.

Confirm that the **Report a vulnerability** flow is available before directing
external researchers to it. If the repository is transferred or made private,
recheck these settings.

Never configure a workflow that test-signs or loads the kernel driver on a
hosted runner.

## 6. Issue management

The repository includes structured forms for bugs, defensive features, and
questions. Blank issues are disabled.

Recommended labels:

| Label | Purpose |
| --- | --- |
| `bug` | Reproducible defect |
| `enhancement` | Defensive feature proposal |
| `question` | Build, protocol, usage, or analysis question |
| `security` | Public tracking only after coordinated disclosure |
| `protocol` | ABI or validation change |
| `driver` | KMDF and Ring 0 code |
| `collector` | Device client, JSONL, or CLI |
| `analyzer` | PE, hash, signature, or findings |
| `tests` | Offline or integration coverage |
| `documentation` | Documentation-only work |
| `dependencies` | Automated dependency update |
| `github-actions` | Workflow dependency or behavior |
| `needs-reproduction` | Missing safe reproduction |
| `out-of-scope` | Violates defensive scope or support policy |

Do not use public issues for undisclosed vulnerabilities.

## 7. Pull requests

The pull-request template requires security-boundary analysis and exact test
evidence. Reviewers should verify:

- defensive scope and documented API use;
- kernel callback bounds and allocation behavior;
- SDDL and IOCTL access bits;
- protocol sizes, offsets, versioning, flags, and reserved fields;
- cleanup, rollback, unload, IRQL, and locking;
- parser arithmetic and range checks;
- regression tests and documentation;
- absence of binaries, keys, dumps, and secrets.

Use squash merging for small focused changes or preserve commits when they form
a meaningful reviewable history. Keep the chosen convention consistent.

## 8. Releases

Follow `docs/RELEASE.md`. For the initial publication:

1. keep the project marked pre-1.0;
2. publish source only;
3. attach the source archive hash and validation summary;
4. attach the hosted WDK compile/INF evidence and state that isolated-VM runtime
   testing is still required;
5. do not attach unsigned, test-signed, or privately signed driver binaries;
6. do not claim production support or vulnerability-free status.

Use annotated or signed Git tags when possible. A release tag must point to the
exact reviewed commit.

## 9. Signing infrastructure

Production driver signing should be a separate, organization-controlled system
with access review, hardware-backed key protection where appropriate, audit
logs, and explicit artifact approval. Ordinary repository maintainers and
hosted CI should not automatically receive signing authority.

Test certificates belong only in the isolated lab trust store. Never commit a
test certificate's private key.

## 10. Post-publication checks

After the first push:

- verify README badges and every local documentation link;
- confirm the MIT license is detected;
- confirm issue forms render correctly;
- run user-mode CI, WDK driver CI, and CodeQL once;
- select the observed status checks in the branch ruleset;
- verify private vulnerability reporting;
- verify Dependabot configuration;
- inspect the repository for accidentally uploaded binaries or secrets;
- clone into a clean directory and repeat the user-mode build instructions.

Repeat the repository-security review after transfers, visibility changes,
workflow changes, or maintainer changes.

