# Product Vulnerability Handling Portfolio

Oliver Dozier · CISSP, OSCP, CCNP Security

Hands-on work samples for product vulnerability management: moving from raw scanner output to decisions about exploitability to published, machine-readable disclosures. The target is a widely used open-source LLM web interface, chosen because AI/ML software is where dependency risk is growing fastest.

| Project | What it demonstrates | Standards |
|---|---|---|
| [01: SBOM, triage, and VEX](#project-1-sbom-vulnerability-triage-and-vex) | Generating an SBOM, scanning it, and triaging 65 advisories by real reachability in the product's code, not severity score alone | CycloneDX, OpenVEX, CVSS |
| [02: CSAF advisory and bulletin](#project-2-csaf-20-advisory-and-security-bulletin) | Turning the top finding into a schema-valid CSAF 2.0 advisory and a customer-facing security bulletin | CSAF 2.0, CWE, CVSS v3.1 |
| 03: Threat model of an LLM inference service | *In progress* | STRIDE, CWE |
| 04: AI-assisted VEX justification drafting | *In progress* | OpenVEX, LLM tooling |

## Files in this repo

| File | What it is |
|---|---|
| `requirements-pinned.txt` | Project 1 input: the exact dependency versions analyzed |
| `sbom.cdx.json` | Project 1: CycloneDX 1.6 SBOM |
| `scan-results.pip-audit.json` | Project 1: raw scanner output |
| `vex.openvex.json` | Project 1: triage decisions in OpenVEX format |
| `OD-SA-2026-001.csaf.json` | Project 2: CSAF 2.0 security advisory |
| `security-bulletin.md` | Project 2: customer-facing security bulletin |

## Tooling and approach

Built with `cyclonedx-py`, `pip-audit`, and direct source review of the target. AI assistance (Claude) was used to speed up drafting and tooling. Every triage decision is tied to specific evidence in the target's source code so it can be checked independently.

---

## Project 1: SBOM, Vulnerability Triage, and VEX

**Target:** [text-generation-webui](https://github.com/oobabooga/text-generation-webui) v1.8 (June 2024), a widely used open-source interface for running large language models locally.
**Scope:** the 13 version-pinned dependencies in `requirements_nowheels.txt`, resolved to exact versions in `requirements-pinned.txt`. Unpinned dependencies are out of scope for this pass.
**Scan date:** October 23, 2026

### What this shows

A scanner gives you a list of CVEs. It doesn't tell you which ones matter to this product. The work here is the step in between: checking each finding against how the application actually uses the vulnerable code, then publishing that decision in a machine-readable form (VEX) so downstream users don't have to repeat the analysis.

### Method

1. **SBOM:** generated a CycloneDX 1.6 SBOM with `cyclonedx-py` → `sbom.cdx.json`
2. **Scan:** ran `pip-audit` against OSV/PyPI advisory data → `scan-results.pip-audit.json`
3. **Triage:** for a representative set of findings across every affected package, read the advisory's exploit preconditions and checked the application's source to see whether those preconditions can be met
4. **VEX:** recorded each decision in OpenVEX format with a standard justification → `vex.openvex.json`

### Results

- **65 unique advisories** across 4 packages (gradio 33, transformers 26, jinja2 5, accelerate 1). The raw scan reports 115 because several advisory feeds list the same issue.
- **13 triaged in depth:** 5 affected, 6 not affected, 2 under investigation.

### Key finding

**Jinja2 sandbox breakout via model-supplied chat templates (CVE-2025-27516) is the top priority.** The app renders chat templates in Jinja's sandbox and loads those templates from the model file's metadata. That means anyone who publishes a model controls template content, which is exactly the precondition the advisory requires. A user who downloads a malicious model could have arbitrary Python code executed on their machine. The fix is one version bump (jinja2 3.1.6).

The same package also shows why severity scores alone mislead. **CVE-2024-56326** is rated high (CVSS 7.8) and sits in the same sandbox, but it requires a custom filter that the application never registers. It is not exploitable here.

### Triage table

| CVE | Package | Status | Priority | Rationale |
|---|---|---|---|---|
| CVE-2025-27516 | jinja2 3.1.2 | affected | P1 | Chat and instruction templates are rendered in an ImmutableSandboxedEnvironment (modules/chat.py), and template content is loaded from model metadata (tokenizer.chat_template, modules/models_settings.py). A downloaded model can therefore supply attacker-controlled template content, which is the precondition for this sandbox breakout via the built-in `\|attr` filter. |
| CVE-2024-56326 | jinja2 3.1.2 | not_affected — vulnerable_code_not_in_execute_path | None | Exploitation requires an application-defined custom filter that invokes a callable passed into it. The application registers no custom filters or globals on its Jinja environment (only from_string calls in modules/chat.py), so the indirect str.format path cannot be reached. Remediated anyway by the jinja2 3.1.6 upgrade. |
| CVE-2024-56201 | jinja2 3.1.2 | not_affected — vulnerable_code_cannot_be_controlled_by_adversary | None | Exploitation requires control of both template content and template filename. Templates are compiled with from_string, which takes no adversary-controlled filename. |
| CVE-2024-22195 | jinja2 3.1.2 | not_affected — vulnerable_code_not_in_execute_path | None | The xmlattr filter injection affects HTML output. Rendered templates here become a text prompt sent to the model, not HTML returned to a browser, so the injected attributes have no sink. |
| CVE-2024-34064 | jinja2 3.1.2 | not_affected — vulnerable_code_not_in_execute_path | None | Same analysis as CVE-2024-22195: rendered template output is a model prompt, not HTML. |
| CVE-2024-4941 | gradio 4.26.0 | affected | P1 (if exposed) | The UI instantiates a gr.JSON component (modules/ui_chat.py), the component named in the local file inclusion advisory. Exposure depends on deployment: default binding is localhost, but --listen or --share makes the UI reachable by others. |
| CVE-2024-47867 | gradio 4.26.0 | affected | P2 (only with --share) | Affects the public share tunnel, which the application exposes through its --share flag. Reachable only when a user enables sharing. |
| CVE-2024-12217 | gradio 4.26.0 | affected | P2 (Windows only) | Path traversal on Windows hosts. The project ships Windows launchers (cmd_windows.bat), so Windows deployments are in scope; Linux and macOS deployments are not. |
| CVE-2024-4253 | gradio 4.26.0 | not_affected — vulnerable_code_not_present | None | The advisory describes command injection in a repository CI workflow (test-functions), not in the published package. That code is not present in the installed wheel. |
| CVE-2025-2099 | transformers 4.41.2 | not_affected — vulnerable_code_not_in_execute_path | None | The ReDoS is in transformers.testing_utils, a test helper. The application never imports it (no references in the codebase). |
| CVE-2025-14926 | transformers 4.41.2 | not_affected — vulnerable_code_not_in_execute_path | None | Code injection in the SEW convert_config checkpoint-conversion utility. The application loads models through standard loaders and never invokes upstream conversion scripts. |
| CVE-2026-1839 | transformers 4.41.2 | under_investigation | Open | The advisory concerns the Trainer class. The application's training tab instantiates transformers.Trainer (modules/training.py). Reachability depends on whether attacker-supplied checkpoints reach the vulnerable path; analysis open. |
| CVE-2026-69112 | accelerate 0.30.1 | under_investigation | Open | Path traversal in load_checkpoint_in_model. Model loading uses accelerate for device placement, so a malicious model repository may reach this path. Confirming whether the application's loader invokes the vulnerable function. |

### Recommended remediation, in order

1. Upgrade jinja2 to 3.1.6 or later. This closes all five jinja2 advisories in one low-risk change.
2. Upgrade gradio. This is a major-version jump with breaking changes, so until it lands: keep the default localhost binding, avoid `--share`, and require `--gradio-auth` wherever the UI is exposed.
3. Upgrade transformers and accelerate, and resolve the two open investigations.

### Limitations

This is a dependency-level analysis of one release. It does not include dynamic testing or exploit validation, and it covers only the pinned dependency set.

---

## Project 2: CSAF 2.0 Advisory and Security Bulletin

Takes the top finding from Project 1 (CVE-2025-27516 as it applies to text-generation-webui v1.8) and publishes it two ways, the way a product security team would:

- **`OD-SA-2026-001.csaf.json`:** a machine-readable CSAF 2.0 security advisory with the product tree, package URL, CWE, CVSS v3.1 vector, product status, and remediations. It validates against the OASIS CSAF 2.0 JSON schema.
- **`security-bulletin.md`:** the customer-facing version, structured like a vendor security bulletin: summary, details table, affected products, remediation, related non-affecting findings, acknowledgements, and revision history.

### Decisions worth noting

- **Score source:** uses the NVD base score (8.8) rather than inventing one, and notes where an environmental re-score could reasonably differ. Red Hat scores the same CVE at 7.3 by treating user interaction as required, which is a fair read for this product's attack path.
- **Product-specific impact:** the bulletin explains *why this product* is affected (model-supplied chat templates), not just that a dependency has a CVE.
- **Non-affecting findings:** included so customers whose scanners flag them get an answer without opening a support ticket.

---

## Disclaimer

Independent portfolio work. Not affiliated with or endorsed by the text-generation-webui project, Pallets, or Hugging Face. All vulnerabilities referenced are already public.
