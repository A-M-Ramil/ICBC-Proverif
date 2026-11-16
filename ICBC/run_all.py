#!/usr/bin/env python3
"""
run_all.py - run every ProVerif model, then mutation-test it.

1. Baseline: runs each model and prints every RESULT line.
   Any "cannot be proved" is reported as a problem.
2. Mutation testing (non-vacuity): for every security check tagged with a
   CHK marker, the check line is replaced by "if true then" and the model
   is re-run. The mutant is KILLED if at least one query that was true in
   the baseline is no longer true. A SURVIVING mutant means the queries do
   not depend on that check and must be investigated.
3. Extra mutants: NOPEPPER reproduces the old prototype's plain keccak(gov_id).

Usage:  python3 run_all.py            (PROVERIF=/path/to/proverif to override)
Exit code 0 only if: no "cannot be proved" in any baseline, and every
mutant is killed.
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent


def find_proverif():
    """PROVERIF env var, then PATH, then this folder and its parents
    (e.g. ...\\proverif2.05\\proverif.exe when the models sit in ...\\proverif2.05\\ICBC)."""
    env = os.environ.get("PROVERIF")
    if env:
        return env
    for name in ("proverif", "proverif.exe"):
        p = shutil.which(name)
        if p:
            return p
    for d in [HERE, *HERE.parents][:4]:
        for name in ("proverif.exe", "proverif"):
            cand = d / name
            if cand.is_file():
                return str(cand)
    sys.exit("ProVerif not found. Set it explicitly, e.g. in PowerShell:\n"
             '  $env:PROVERIF = "C:\\path\\to\\proverif.exe"; python run_all.py')


PV = find_proverif()
OUT = HERE / "out"
OUT.mkdir(exist_ok=True)

MODELS = [
    "p1_human_registration.pv",
    "p2_agent_registration.pv",
    "p345_credential_lifecycle.pv",
    "p6_delegation_execution.pv",
]
EXTRA_MUTANTS = {
    "p1_human_registration.pv": {"NOPEPPER": ("h((pepper, govID))", "h(govID)")},
}
RESULT_RE = re.compile(r"^RESULT (.*) (is true|is false|cannot be proved)\.?\s*$")
CHK_RE = re.compile(r"\(\*CHK:([a-z_]+)\*\)")


def run(path):
    t0 = time.time()
    p = subprocess.run([PV, str(path)], capture_output=True, text=True, timeout=7200)
    dt = time.time() - t0
    log = OUT / (path.stem + ".log")
    log.write_text(p.stdout + "\n--- stderr ---\n" + p.stderr)
    res = []
    for line in p.stdout.splitlines():
        m = RESULT_RE.match(line.strip())
        if m:
            res.append((m.group(1), m.group(2)))
    if not res:
        raise RuntimeError(f"{path.name}: no RESULT lines (syntax error?). See {log}")
    return res, dt


def main():
    print(f"Using ProVerif: {PV}")
    ok = True
    summary = []
    for model in MODELS:
        src_path = HERE / model
        src = src_path.read_text()
        print("=" * 78)
        print(model)
        print("=" * 78)
        base, dt = run(src_path)
        for q, v in base:
            flag = "  <-- PROBLEM" if v == "cannot be proved" else ""
            print(f"  [{v:16s}] {q}{flag}")
            if v == "cannot be proved":
                ok = False
        print(f"  ({dt:.1f}s)")

        mutants = {}
        for name in sorted(set(CHK_RE.findall(src))):
            pat = re.compile(r"\(\*CHK:" + name + r"\*\).*$", re.M)
            mutants[name] = pat.sub("if true then", src)
        for name, (a, b) in EXTRA_MUTANTS.get(model, {}).items():
            assert a in src, f"{model}: extra mutant {name} target not found"
            mutants[name] = src.replace(a, b)

        print("  mutation testing:")
        for name, msrc in mutants.items():
            mpath = OUT / f"{src_path.stem}__mut_{name}.pv"
            mpath.write_text(msrc)
            try:
                mres, mdt = run(mpath)
            except RuntimeError as e:
                print(f"    {name:24s} ERROR {e}")
                ok = False
                continue
            if len(mres) != len(base):
                print(f"    {name:24s} WARNING result count differs ({len(mres)} vs {len(base)})")
            flipped = [q for (q, v), (_, mv) in zip(base, mres) if v == "is true" and mv != "is true"]
            status = "KILLED" if flipped else "SURVIVED"
            if not flipped:
                ok = False
            print(f"    {name:24s} {status} ({mdt:.1f}s)")
            for q in flipped:
                print(f"        breaks: {q}")
            summary.append((model, name, status))

    print("=" * 78)
    print("ALL GOOD" if ok else "ATTENTION NEEDED (see above)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())