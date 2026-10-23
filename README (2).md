# Product Vulnerability Handling Portfolio

Oliver Dozier · CISSP, OSCP, CCNP Security

Hands-on work samples for product vulnerability management: moving from raw scanner output to decisions about exploitability to published, machine-readable disclosures. The target is a widely used open-source LLM web interface, chosen because AI/ML software is where dependency risk is growing fastest.

| Project | What it demonstrates | Standards |
|---|---|---|
| [01: SBOM, triage, and VEX](01-sbom-vex/) | Generating an SBOM, scanning it, and triaging 65 advisories by real reachability in the product's code, not severity score alone | CycloneDX, OpenVEX, CVSS |
| [02: CSAF advisory and bulletin](02-csaf-advisory/) | Turning the top finding into a schema-valid CSAF 2.0 advisory and a customer-facing security bulletin | CSAF 2.0, CWE, CVSS v3.1 |
| 03: Threat model of an LLM inference service | *In progress* | STRIDE, CWE |
| 04: AI-assisted VEX justification drafting | *In progress* | OpenVEX, LLM tooling |

## Tooling and approach

Built with `cyclonedx-py`, `pip-audit`, and direct source review of the target. AI assistance (Claude) was used to speed up drafting and tooling. Every triage decision is tied to specific evidence in the target's source code so it can be checked independently.

## Disclaimer

Independent portfolio work. Not affiliated with or endorsed by the text-generation-webui project, Pallets, or Hugging Face. All vulnerabilities referenced are already public.
