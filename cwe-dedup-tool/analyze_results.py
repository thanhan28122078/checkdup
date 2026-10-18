#!/usr/bin/env python3
"""
analyze_results.py - doc ket qua trong out/ va tu viet file ket luan (out/conclusions.md).

Nguon doc:
  out/summary.csv                    (neu thieu se tu tinh lai tu cac thu muc repo)
  out/<owner>__<repo>/pairs.csv, units.csv, unresolved.csv   (neu co, de lay chi tiet)
  work/data/project_info.csv         (neu co, de biet repo co bao nhieu CVE tat ca)

Cach dung:
  python3 analyze_results.py                       # doc ./out, ghi ./out/conclusions.md
  python3 analyze_results.py --out out --workdir work
  python3 analyze_results.py --out folder_chi_co_summary_csv    # chi co summary.csv van chay duoc (it chi tiet hon)
"""
import argparse, os, sys
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from run_batch import summarize  # noqa: E402

LEVELS = ["L1_strict", "L1_loose", "L2_AST", "L2_Near95", "L2_Near90"]
RENAME = {"rc_groups(>=2 method)": "rcg", "rc_groups_span_>=2_CVE": "rcg_span", "units_in_rc_groups": "rc_units"}
SMALL_UNITS, SMALL_PAIRS = 8, 20          # mau nho: it hon nguong nay thi do tin cay thap


def rd(path):
    try:
        return pd.read_csv(path).fillna("")
    except (FileNotFoundError, pd.errors.EmptyDataError):
        return pd.DataFrame()


def tag(repo): return repo.replace("/", "__")


def load_summary(out):
    sp = os.path.join(out, "summary.csv")
    if os.path.exists(sp):
        S = pd.read_csv(sp)
    else:
        repos = sorted(d.replace("__", "/", 1) for d in os.listdir(out)
                       if os.path.exists(os.path.join(out, d, "pairs.csv")))
        if not repos:
            sys.exit(f"Khong thay summary.csv hay thu muc ket qua nao trong {out}")
        S = pd.DataFrame([{**summarize(r, out), "status": "ok"} for r in repos])
    S = S.rename(columns=RENAME)
    for c in S.columns:
        if c not in ("repo", "status"):
            S[c] = pd.to_numeric(S[c], errors="coerce")
    return S


def total_cves(workdir):
    p = rd(os.path.join(workdir, "data", "project_info.csv"))
    if p.empty: return {}
    p["repo"] = p.github_username + "/" + p.github_repository_name
    return p.groupby("repo").cve_id.nunique().to_dict()


def details(out, repo):
    d = os.path.join(out, tag(repo))
    return rd(os.path.join(d, "units.csv")), rd(os.path.join(d, "pairs.csv")), rd(os.path.join(d, "unresolved.csv"))


def priority(r):
    """diem uu tien duyet tay (minh bach): cap trung inter-CVE nang nhat, roi nhom root cause tra nhieu CVE."""
    return 3 * r.dup_inter_cve + 2 * r.rcg_span + 1 * r.dup_intra_cve + 0.5 * max(r.rcg - r.rcg_span, 0)


def tier(score): return "CAO" if score >= 3 else "TRUNG BINH" if score >= 1.5 else "THAP"


def pct(a, b): return f"{100 * a / b:.1f}%" if b else "n/a"


def names(rows, col="repo"): return ", ".join(rows[col].tolist())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="out")
    ap.add_argument("--workdir", default="work")
    ap.add_argument("--md", default=None, help="file ket luan (mac dinh <out>/conclusions.md)")
    a = ap.parse_args()
    md = a.md or os.path.join(a.out, "conclusions.md")

    S = load_summary(a.out)
    failed = S[S.status != "ok"]
    ok = S[S.status == "ok"].copy()
    if ok.empty: sys.exit("Khong co repo nao chay thanh cong trong summary.")
    cve_total = total_cves(a.workdir)
    ok["cve_total"] = ok.repo.map(cve_total)
    ok["score"] = ok.apply(priority, axis=1)
    ok["tier"] = ok.score.map(tier)
    ok["rc_ratio"] = ok.rc_units / ok.units

    T = {c: int(ok[c].sum()) for c in ["cve_with_units", "units", "pairs", "dup_pairs_total", "dup_intra_cve",
                                       "dup_inter_cve", "rcg", "rcg_span", "rc_units"] + LEVELS}
    C = []   # cac cau ket luan

    # --- 1. ban sao y het
    exact = T["L1_strict"] + T["L1_loose"]
    if exact == 0:
        C.append("**Khong co ban sao y het (L1) nao** o ca %d repo: code cua cac method bi sua khong trung nhau tung ky tu." % len(ok))
    else:
        w = ok[(ok.L1_strict + ok.L1_loose) > 0]
        C.append(f"**Co {exact} cap y het (L1)** o: {names(w)}. Can xem co phai cung mot method bi sua boi nhieu CVE khong.")

    # --- 2. trung giua cac CVE khac nhau
    if T["dup_inter_cve"] == 0:
        C.append("**Khong co trung code giua cac CVE khac nhau** (dup_inter_cve = 0 o moi repo). O muc code, cac CVE trong cung repo gan nhu doc lap, "
                 "khong can loai CVE nao vi ly do trung code.")
    else:
        w = ok[ok.dup_inter_cve > 0]
        C.append(f"**Co {T['dup_inter_cve']} cap trung code giua cac CVE khac nhau**, o: " +
                 ", ".join(f"{r.repo} ({int(r.dup_inter_cve)})" for r in w.itertuples()) + ". Day la loai trung dang quan tam nhat, can duyet tay.")

    # --- 3. ti le trung va ban chat
    if T["dup_pairs_total"]:
        intra_only = T["dup_inter_cve"] == 0
        w = ok[ok.dup_pairs_total > 0]
        C.append(f"**{T['dup_pairs_total']}/{T['pairs']} cap ({pct(T['dup_pairs_total'], T['pairs'])}) co trung o muc L1/L2** "
                 f"(o: {names(w)}); " + ("tat ca deu nam trong CUNG mot CVE, phu hop voi viec mot loi hay duoc va o nhieu cho co code gan giong nhau."
                                        if intra_only else f"gom {T['dup_intra_cve']} cap cung CVE va {T['dup_inter_cve']} cap khac CVE."))
    else:
        C.append(f"**Khong co cap nao trung o muc L1/L2** trong {T['pairs']} cap da so sanh.")

    # --- 4. root cause
    if T["rcg_span"]:
        w = ok[ok.rcg_span > 0]
        C.append(f"**Trung lap that su (neu co) nam o root cause, khong phai o code:** co {T['rcg_span']} nhom goi y tra tren >= 2 CVE, o " +
                 ", ".join(f"{r.repo} ({int(r.rcg_span)})" for r in w.itertuples()) +
                 ". Day la cho cac CVE khac nhau co the thuc chat la cung mot kieu loi.")
    else:
        C.append("Khong co nhom root cause nao tra tren nhieu CVE: cac nhom goi y deu nam trong tung CVE rieng le.")
    C.append(f"Con so method nam trong nhom root cause ({T['rc_units']}/{T['units']} = {pct(T['rc_units'], T['units'])}) la **tran cua so ung vien, khong phai ti le trung**: "
             "cach gom con long, tin hieu 'cung API fix' co the bat nham khi API pho bien.")

    # --- 5. uu tien
    rank = ok.sort_values("score", ascending=False)
    C.append("**Thu tu uu tien duyet tay:** " + "; ".join(
        f"{r.repo} [{r.tier}, diem {r.score:g}]" for r in rank.itertuples()) +
        ". Diem = 3 x cap trung khac CVE + 2 x nhom root cause tra nhieu CVE + 1 x cap trung cung CVE + 0.5 x nhom root cause con lai.")

    # --- 6. canh bao chat luong du lieu
    W = []
    for r in ok.itertuples():
        if pd.notna(r.cve_total) and r.cve_total > r.cve_with_units:
            W.append(f"**{r.repo}**: dataset co {int(r.cve_total)} CVE nhung chi {int(r.cve_with_units)} CVE co method de so sanh "
                     f"(thieu {int(r.cve_total - r.cve_with_units)}); mo `{tag(r.repo)}/unresolved.csv` xem ly do.")
        if r.units < SMALL_UNITS or r.pairs < SMALL_PAIRS:
            W.append(f"**{r.repo}**: mau nho ({int(r.units)} method, {int(r.pairs)} cap) nen ket luan 'khong trung' co do tin cay thap.")
    for r in failed.itertuples():
        W.append(f"**{r.repo}**: chay THAT BAI, chua co ket qua; chay lai rieng `dedup_repo.py --repo {r.repo}` de xem loi.")
    if not cve_total:
        W.append("Khong doc duoc `work/data/project_info.csv` nen khong kiem tra duoc CVE bi thieu (dung `--workdir`).")

    # --- chi tiet theo repo + tien do duyet tay
    D, prog = [], []
    for r in ok.itertuples():
        U, P, UN = details(a.out, r.repo)
        if U.empty or P.empty:
            D.append(f"### {r.repo}\n\n_(khong co units.csv/pairs.csv, chi co so tong hop)_\n"); continue
        L = [f"### {r.repo}", "", f"- {int(r.cve_with_units)} CVE co method, {int(r.units)} method, {int(r.pairs)} cap; muc uu tien **{r.tier}**"]
        dup = P[P.level != ""]
        for x in dup.itertuples():
            L.append(f"- Cap trung **{x.level}** ({x.scope}, Jaccard AST {x.jaccard_ast}): `{x.a}` <-> `{x.b}`")
        U["_cve"] = U.cve
        for gid, g in U.groupby("rc_group"):
            if len(g) < 2 or g.cve.nunique() < 2: continue
            apis = {}
            for x in P[(P.a.isin(g.uid)) & (P.b.isin(g.uid))].itertuples():
                for c in str(x.shared_fix_calls).split(";"):
                    if c: apis[c] = apis.get(c, 0) + 1
            top = ", ".join(k for k, _ in sorted(apis.items(), key=lambda kv: -kv[1])[:4]) or "-"
            L.append(f"- Nhom root cause tra {g.cve.nunique()} CVE ({', '.join(sorted(c.replace('CVE-', '') for c in g.cve.unique()))}), "
                     f"{len(g)} method, API fix chung: `{top}`")
            L += [f"    - `{u}`" for u in g.uid]
        if len(L) == 3 and not len(dup):
            L.append("- Khong co cap trung va khong co nhom root cause tra nhieu CVE.")
        if not UN.empty:
            L.append(f"- {len(UN)} muc khong xu ly duoc (xem unresolved.csv)")
        D.append("\n".join(L) + "\n")
        # tien do duyet tay
        cand = P[(P.level != "") | (P.rc_hint != "")]
        done = cand[cand.manual_verdict != ""] if "manual_verdict" in cand else cand.iloc[0:0]
        if len(cand):
            vc = done.manual_verdict.value_counts().to_dict() if len(done) else {}
            prog.append((r.repo, len(cand), len(done), vc))

    # --- ghi file
    out = ["# Ket luan tu dong", "",
           f"_Sinh boi analyze_results.py tu `{a.out}/`. Day la ket luan may sinh dua tren so lieu; moi nhom root cause van can duyet tay._", "",
           "## 1. Con so tong", "",
           f"- {len(ok)} repo, {T['cve_with_units']} CVE co method, {T['units']} method, {T['pairs']} cap so sanh",
           f"- Cap trung L1/L2: {T['dup_pairs_total']} (cung CVE {T['dup_intra_cve']}, khac CVE {T['dup_inter_cve']}); "
           f"theo muc: " + ", ".join(f"{k} {T[k]}" for k in LEVELS),
           f"- Nhom root cause goi y: {T['rcg']} (tra >= 2 CVE: {T['rcg_span']}); method trong nhom: {T['rc_units']}/{T['units']}", "",
           "## 2. Bang theo repo", "",
           "| Repo | CVE | Method | Cap | Cap trung L1/L2 | Nhom RC | Nhom RC tra >=2 CVE | Method trong nhom | Uu tien |",
           "|---|---|---|---|---|---|---|---|---|"]
    for r in rank.itertuples():
        out.append(f"| {r.repo} | {int(r.cve_with_units)} | {int(r.units)} | {int(r.pairs)} | {int(r.dup_pairs_total)} | "
                   f"{int(r.rcg)} | {int(r.rcg_span)} | {int(r.rc_units)} ({pct(r.rc_units, r.units)}) | {r.tier} |")
    out += ["", "## 3. Ket luan", ""] + [f"{i}. {c}" for i, c in enumerate(C, 1)]
    out += ["", "## 4. Canh bao ve du lieu", ""] + ([f"- {w}" for w in W] or ["- Khong co canh bao."])
    out += ["", "## 5. Chi tiet cac muc can xem", ""] + D
    if prog:
        out += ["## 6. Tien do duyet tay (cot manual_verdict trong pairs.csv)", "",
                "| Repo | Cap ung vien | Da dien | Phan bo |", "|---|---|---|---|"]
        for repo, n, d, vc in prog:
            out.append(f"| {repo} | {n} | {d} ({pct(d, n)}) | {', '.join(f'{k}: {v}' for k, v in vc.items()) or '-'} |")
        out.append("")
    os.makedirs(os.path.dirname(md) or ".", exist_ok=True)
    open(md, "w", encoding="utf-8").write("\n".join(out))
    print("\n".join(out[:out.index('## 5. Chi tiet cac muc can xem')]))
    print(f"\n-> Da ghi {md}")


if __name__ == "__main__":
    main()
