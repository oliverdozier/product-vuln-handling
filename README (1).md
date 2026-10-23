# Project 2: CSAF 2.0 Advisory and Human-Readable Security Bulletin

Takes the top finding from Project 1 (CVE-2025-27516 as it applies to text-generation-webui v1.8) and publishes it two ways, the way a product security team would:

- **`OD-SA-2026-001.csaf.json`:** a machine-readable CSAF 2.0 security advisory with the product tree, package URL, CWE, CVSS v3.1 vector, product status, and remediations. It validates against the OASIS CSAF 2.0 JSON schema.
- **`security-bulletin.md`:** the customer-facing version, structured like a vendor security bulletin: summary, details table, affected products, remediation, related non-affecting findings, acknowledgements, and revision history.

## Decisions worth noting

- **Score source:** uses the NVD base score (8.8) rather than inventing one, and notes where an environmental re-score could reasonably differ. Red Hat scores the same CVE at 7.3 by treating user interaction as required, which is a fair read for this product's attack path.
- **Product-specific impact:** the bulletin explains *why this product* is affected (model-supplied chat templates), not just that a dependency has a CVE.
- **Non-affecting findings:** included so customers whose scanners flag them get an answer without opening a support ticket.
