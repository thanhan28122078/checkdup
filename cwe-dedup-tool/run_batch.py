#!/usr/bin/env python3
"""
run_batch.py - chay dedup_repo.py lan luot cho cac repo trong repos.txt, roi tong hop out/summary.csv

  python3 run_batch.py                      # doc repos.txt
  python3 run_batch.py --repos my.txt --include-tests
  python3 run_batch.py --skip-existing      # bo qua repo da co ket qua
"""
import argparse, os, subprocess, sys
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
LEVELS = ["L1_strict", "L1_loose", "L2_AST", "L2_Near95", "L2_Near90"]


def read_repos(path):
    repos = []
    for ln in open(path, encoding="utf-8"):
        ln = ln.split("#")[0].strip()
        if ln:
            repos.append(ln)
    return repos


def summarize(repo, out):
    d = os.path.join(out, repo.replace("/", "__"))
    U = pd.read_csv(os.path.join(d, "units.csv")).fillna("")
    P = pd.read_csv(os.path.join(d, "pairs.csv")).fillna("")
    row = {"repo": repo, "cve_with_units": U.cve.nunique(), "units": len(U), "pairs": len(P)}
    dup = P[P.level != ""]
    for lv in LEVELS:                       # so cap theo muc CAO NHAT cua cap do (khong tich luy)
        row[lv] = int((P.level == lv).sum())
    row["dup_pairs_total"] = len(dup)
    row["dup_intra_cve"] = int((dup.scope == "intra_cve").sum())
    row["dup_inter_cve"] = int((dup.scope == "inter_cve").sum())
    g = U.groupby("rc_group").agg(n=("uid", "count"), ncve=("cve", "nunique"))
    g = g[g.n >= 2]
    row["rc_groups(>=2 method)"] = len(g)
    row["rc_groups_span_>=2_CVE"] = int((g.ncve >= 2).sum())
    row["units_in_rc_groups"] = int(g.n.sum())
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", default=os.path.join(HERE, "repos.txt"))
    ap.add_argument("--workdir", default="work")
    ap.add_argument("--out", default="out")
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--skip-existing", action="store_true")
    a = ap.parse_args()

    rows = []
    for repo in read_repos(a.repos):
        tag = repo.replace("/", "__")
        print(f"\n===== {repo} =====", flush=True)
        if not (a.skip_existing and os.path.exists(os.path.join(a.out, tag, "pairs.csv"))):
            cmd = [sys.executable, os.path.join(HERE, "dedup_repo.py"), "--repo", repo,
                   "--workdir", a.workdir, "--out", a.out]
            if a.include_tests:
                cmd.append("--include-tests")
            if subprocess.run(cmd).returncode != 0:
                print(f"!! {repo}: that bai, xem thong bao o tren")
                rows.append({"repo": repo, "status": "FAILED"})
                continue
        rows.append({**summarize(repo, a.out), "status": "ok"})

    if rows:
        S = pd.DataFrame(rows)
        os.makedirs(a.out, exist_ok=True)
        S.to_csv(os.path.join(a.out, "summary.csv"), index=False)
        pd.set_option("display.width", 250)
        print("\n===== TONG HOP =====")
        print(S.to_string(index=False))
        print(f"\nDa luu {os.path.join(a.out, 'summary.csv')}")


if __name__ == "__main__":
    main()
