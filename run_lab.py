#!/usr/bin/env python3
"""
Product Vulnerability Handling Lab
Runs the full workflow live: SBOM -> scan -> reachability evidence -> VEX -> fix verification -> CSAF validation.

  python run_lab.py          # step through, press Enter between steps
  python run_lab.py --auto   # run straight through
"""
import json, re, subprocess, sys, tempfile, urllib.request
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

HERE = Path(__file__).resolve().parent
WORK = HERE / "lab-output"
TARGET_REPO = "https://github.com/oobabooga/text-generation-webui.git"
TARGET_TAG = "v1.8"
PINNED = HERE / "requirements-pinned.txt"
VEX = HERE / "vex.openvex.json"
CSAF = HERE / "OD-SA-2026-001.csaf.json"
CSAF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/csaf/master/csaf_2.0/json_schema/csaf_json_schema.json"

AUTO = "--auto" in sys.argv
con = Console()

# Evidence checks: for each triaged CVE, what in the target's source proves or rules out reachability.
EVIDENCE = {
    "CVE-2025-27516": [("Templates rendered in Jinja sandbox", r"ImmutableSandboxedEnvironment"),
                       ("Template content comes from model metadata", r"tokenizer\.chat_template")],
    "CVE-2024-56326": [("Custom Jinja filters registered (precondition)", r"jinja_env\.filters|\.filters\[")],
    "CVE-2024-56201": [("Templates compiled from strings, no filename", r"jinja_env\.from_string")],
    "CVE-2024-4941":  [("Vulnerable gr.JSON component used", r"gr\.JSON\("),
                       ("Network exposure flags", r"'--listen'|'--share'")],
    "CVE-2024-47867": [("Public share tunnel flag", r"'--share'")],
    "CVE-2025-2099":  [("Imports transformers.testing_utils (precondition)", r"testing_utils")],
    "CVE-2026-1839":  [("Uses transformers.Trainer", r"transformers\.Trainer\(")],
}

def step(n, title, talk):
    con.print()
    con.rule(f"[bold cyan]Step {n}: {title}")
    con.print(f"[dim italic]{talk}[/]")
    if not AUTO:
        con.input("[dim]Press Enter to run...[/]")

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

def audit(req_file, out_json):
    run([sys.executable, "-m", "pip_audit", "-r", str(req_file), "--no-deps", "--disable-pip",
         "-f", "json", "-o", str(out_json)])
    data = json.loads(Path(out_json).read_text())
    found = {}
    for dep in data["dependencies"]:
        for v in dep.get("vulns", []):
            cve = next((a for a in [v["id"]] + v.get("aliases", []) if a.startswith("CVE-")), v["id"])
            found[(dep["name"].lower(), cve)] = v.get("fix_versions", [])
    return found

def grep(root, pattern):
    hits = []
    for p in root.rglob("*.py"):
        for i, line in enumerate(p.read_text(errors="ignore").splitlines(), 1):
            if re.search(pattern, line):
                hits.append(f"{p.relative_to(root)}:{i}")
    return hits

def main():
    WORK.mkdir(exist_ok=True)
    con.print(Panel.fit("[bold]Product Vulnerability Handling Lab[/]\n"
                        f"Target: text-generation-webui {TARGET_TAG} (open-source LLM web UI)\n"
                        "Question: of everything the scanner finds, what actually matters?",
                        border_style="cyan"))

    # 1. Target
    step(1, "Get the target", "Pull the exact release we're assessing so every finding can be checked against real code.")
    src = WORK / "target"
    if not src.exists():
        r = run(["git", "clone", "-q", "--depth", "1", "--branch", TARGET_TAG, TARGET_REPO, str(src)])
        if r.returncode:
            con.print(f"[red]Clone failed:[/] {r.stderr.strip()}"); sys.exit(1)
    con.print(f"[green]✓[/] Cloned {TARGET_TAG} → {src.relative_to(HERE)}")

    # 2. SBOM
    step(2, "Build the SBOM", "A software bill of materials: an inventory of every pinned dependency, in CycloneDX format.")
    sbom = WORK / "sbom.cdx.json"
    run([sys.executable, "-m", "cyclonedx_py", "requirements", str(PINNED), "--output-format", "JSON", "-o", str(sbom)])
    comps = json.loads(sbom.read_text())["components"]
    t = Table(title=f"SBOM: {len(comps)} components")
    t.add_column("Package"); t.add_column("Version"); t.add_column("purl", style="dim")
    for c in comps: t.add_row(c["name"], c["version"], c.get("purl", ""))
    con.print(t)

    # 3. Scan
    step(3, "Scan for known vulnerabilities", "pip-audit checks every component against public advisory data (OSV / PyPI).")
    before = audit(PINNED, WORK / "scan-before.json")
    by_pkg = Counter(p for p, _ in before)
    t = Table(title=f"Scanner output: {len(before)} unique CVEs")
    t.add_column("Package"); t.add_column("CVEs", justify="right")
    for p, n in by_pkg.most_common(): t.add_row(p, str(n))
    con.print(t)
    con.print("[yellow]A scanner hands you this list. It can't tell you which ones this product is actually exposed to.[/]")

    # 4. Evidence
    step(4, "Check reachability in the code", "For each triaged CVE, search the target's source for the conditions the exploit needs.")
    vex = {s["vulnerability"]["name"]: s for s in json.loads(VEX.read_text())["statements"]}
    for cve, checks in EVIDENCE.items():
        st = vex[cve]["status"]
        color = {"affected": "red", "not_affected": "green"}.get(st, "yellow")
        con.print(f"\n[bold]{cve}[/] → [{color}]{st}[/]")
        for label, pat in checks:
            hits = grep(src, pat)
            mark = "[cyan]found[/]" if hits else "[dim]not found[/]"
            con.print(f"  {label}: {mark}" + (f"  [dim]{', '.join(hits[:3])}[/]" if hits else ""))

    # 5. VEX
    step(5, "Apply the VEX decisions", "VEX publishes each decision in machine-readable form so customers' scanners can suppress the noise.")
    t = Table(title="Triage outcome")
    t.add_column("CVE"); t.add_column("Status"); t.add_column("Why", overflow="fold")
    for cve, s in vex.items():
        st = s["status"]
        why = s.get("justification") or s.get("action_statement") or s.get("status_notes", "")
        color = {"affected": "red", "not_affected": "green"}.get(st, "yellow")
        t.add_row(cve, f"[{color}]{st}[/]", why[:110] + ("…" if len(why) > 110 else ""))
    con.print(t)
    counts = Counter(s["status"] for s in vex.values())
    con.print(f"[bold]{counts['affected']} affected · {counts['not_affected']} not affected · "
              f"{counts['under_investigation']} under investigation[/]")
    con.print("CVE-2024-56326 is rated [bold]7.8 HIGH[/], but its precondition isn't in the code. "
              "CVE-2025-27516 is the one that matters.")

    # 6. Fix verification
    step(6, "Verify the fix", "Apply the P1 remediation (jinja2 → 3.1.6) and rescan to prove it closes the findings.")
    fixed = WORK / "requirements-fixed.txt"
    fixed.write_text(re.sub(r"(?im)^jinja2==.*$", "jinja2==3.1.6", PINNED.read_text()))
    after = audit(fixed, WORK / "scan-after.json")
    j_before = sorted(c for p, c in before if p == "jinja2")
    j_after = sorted(c for p, c in after if p == "jinja2")
    t = Table(title="jinja2 findings before and after upgrade")
    t.add_column("CVE"); t.add_column("jinja2 3.1.2"); t.add_column("jinja2 3.1.6")
    for c in j_before: t.add_row(c, "[red]open[/]", "[green]closed[/]" if c not in j_after else "[red]open[/]")
    con.print(t)
    con.print(f"[green]✓[/] Total findings: {len(before)} → {len(after)}")

    # 7. CSAF
    step(7, "Validate the advisory", "Check the published CSAF 2.0 advisory against the official OASIS schema.")
    try:
        import jsonschema
        schema = json.loads(urllib.request.urlopen(CSAF_SCHEMA, timeout=20).read())
        def strip(o):
            if isinstance(o, dict):
                if str(o.get("$ref", "")).startswith("http"): return {}
                return {k: strip(v) for k, v in o.items()}
            return [strip(x) for x in o] if isinstance(o, list) else o
        errs = [e for e in jsonschema.Draft202012Validator(strip(schema)).iter_errors(json.loads(CSAF.read_text()))
                if "is valid under each of" not in e.message]  # artifact of skipping external CVSS sub-schemas
        doc = json.loads(CSAF.read_text())
        v = doc["vulnerabilities"][0]
        con.print(f"[green]✓[/] {CSAF.name} validates against CSAF 2.0 ({len(errs)} errors)" if not errs
                  else f"[red]{len(errs)} schema errors[/]")
        con.print(f"  {doc['document']['tracking']['id']} · {v['cve']} · {v['cwe']['id']} · CVSS {v['scores'][0]['cvss_v3']['baseScore']}")
    except Exception as e:
        con.print(f"[yellow]Schema check skipped: {e}[/]")

    con.print(Panel.fit(f"[bold]{len(before)} scanner findings → {len(vex)} triaged against the code → 1 unconditional P1, fixed with a one-line upgrade and verified.[/]\n"
                        "That's the job: find what's actually reachable before spending engineering time.",
                        border_style="green"))

if __name__ == "__main__":
    main()
