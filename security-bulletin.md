# Security Bulletin: text-generation-webui, October 2026

*Portfolio exercise. This is not an official bulletin from the text-generation-webui project or Pallets.*

**Advisory ID:** OD-SA-2026-001 · **Published:** October 23, 2026 · **Severity:** High

## Summary

text-generation-webui v1.8 includes a version of the Jinja2 template library with a sandbox breakout. Because the application renders chat templates supplied by model files, a malicious model could run arbitrary code on the machine of any user who loads it. A fixed version of the library is available, and users should update.

## Details

| CVE | Description | CVSS v3.1 Base Score | Vector | CWE | Impacts |
|---|---|---|---|---|---|
| CVE-2025-27516 | Jinja2's sandbox can be bypassed through the `\|attr` filter, letting template content reach Python's unsandboxed string-format method. In this product, chat templates are read from model metadata, so the model's publisher controls template content. | 8.8 High | AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H | CWE-1336 | Code execution, information disclosure, data tampering, denial of service |

The base score is the one published by NVD. In this product the attack runs through a model the user chooses to download, so organizations scoring their own environment may reasonably raise User Interaction to Required.

## Affected products

| Product | Affected versions | Fixed |
|---|---|---|
| text-generation-webui | v1.8 (bundles jinja2 3.1.2) | Any build with jinja2 3.1.6 or later |

## Remediation

Update jinja2 to version 3.1.6 or later. In an existing install: `pip install "jinja2>=3.1.6"`.

Until you can update, load models only from publishers you trust, and check the chat template shown in the UI before using a newly downloaded model.

## Related findings not affecting this product

Two other Jinja2 sandbox issues, CVE-2024-56326 and CVE-2024-56201, appear in scanner output for this release but cannot be exploited here. The first needs a custom filter the application never registers; the second needs control of a template's filename, which the application never exposes. Both are documented in the VEX file in Project 1, and the same update closes them.

## Acknowledgements

The underlying Jinja2 vulnerability was reported to and fixed by the Pallets project. Product-specific analysis by Oliver Dozier.

## Revision history

| Version | Date | Description |
|---|---|---|
| 1.0 | October 23, 2026 | Initial release |
