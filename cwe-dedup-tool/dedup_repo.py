#!/usr/bin/env python3
"""
dedup_repo.py - kiem tra trung lap giua cac lo hong trong DUNG MOT repo cua CWE-Bench-Java.

Don vi so sanh: 1 method bi fix (fix_info.csv), lay ban CON LOI (buggy commit).
Chi so sanh cac cap cung CWE.

Cac muc (doi chieu Rules.docx, bo L3):
  L1_strict   y het sau khi bo comment + chuan hoa khoang trang
  L1_loose    nhu tren nhung moi so -> NUM
  L2_AST      cung khung cu phap (bo ten bien/gia tri), bam AST
  L2_Near95/90  gan giong theo Jaccard 3-gram token AST (union-find)
  Root cause  KHONG tu ket luan duoc; script chi dua tin hieu (cung vi tri, cung mau fix,
              chung API) va de cot manual_verdict de ban duyet tay.

Cach dung:
  python3 dedup_repo.py --repo apache/jspwiki
  python3 dedup_repo.py --repo keycloak/keycloak --include-tests
Yeu cau: git, pandas, tree-sitter, tree-sitter-java
"""
import argparse, difflib, hashlib, itertools, json, os, re, subprocess, sys, urllib.request
from collections import defaultdict
import pandas as pd
import tree_sitter_java
from tree_sitter import Language, Parser

sys.setrecursionlimit(20000)
RAW = "https://raw.githubusercontent.com/iris-sast/cwe-bench-java/master/"
PARSER = Parser(Language(tree_sitter_java.language()))
COMMENTS = {"line_comment", "block_comment"}
ATOMIC = {"string_literal", "character_literal", "text_block"}
NUMS = {"decimal_integer_literal", "hex_integer_literal", "octal_integer_literal",
        "binary_integer_literal", "decimal_floating_point_literal", "hex_floating_point_literal"}
STOP_CALLS = set("""if for while switch catch return new get set size length equals hashCode toString append add put
contains isEmpty trim valueOf format getMessage close next hasNext iterator getName debug info warn error log
println print substring indexOf charAt startsWith endsWith""".split())
TEST_RE = re.compile(r"(^|/)src/test/|(^|/)test/|Test\.java$")


# ---------------------------------------------------------------- tien ich chung
def fetch(url, dest):
    if not os.path.exists(dest):
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with urllib.request.urlopen(url) as r, open(dest, "wb") as f:
            f.write(r.read())
    return dest


def git(repo, *args):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, errors="replace")
    return r.stdout if r.returncode == 0 else None


def ensure_commit(repo, sha):
    if git(repo, "cat-file", "-e", sha + "^{commit}") is None:
        subprocess.run(["git", "-C", repo, "fetch", "-q", "origin", sha], capture_output=True)


_show_cache = {}
def show(repo, rev, path):
    k = (rev, path)
    if k not in _show_cache:
        _show_cache[k] = git(repo, "show", f"{rev}:{path}")
    return _show_cache[k]


class UF:
    def __init__(self): self.p = {}
    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]; x = self.p[x]
        return x
    def union(self, a, b): self.p[self.find(a)] = self.find(b)


def sha(s): return hashlib.sha256(s.encode()).hexdigest()[:16]


# ---------------------------------------------------------------- tim method bang AST
def norm_type(t):
    t = re.sub(r"<[^<>]*>", "", t)           # bo generic (lap lai cho long nhau)
    t = re.sub(r"<[^<>]*>", "", t)
    t = t.replace("final ", "").replace(" ", "")
    return t.split(".")[-1]


def sig_param_types(sig):
    m = re.search(r"\((.*)\)", sig or "")
    if not m or not m.group(1).strip(): return []
    out, depth, cur = [], 0, ""
    for ch in m.group(1):
        depth += ch == "<"; depth -= ch == ">"
        if ch == "," and depth == 0: out.append(cur); cur = ""
        else: cur += ch
    out.append(cur)
    return [norm_type(x.strip().split(" ")[-1] if " " in x.strip() and "<" not in x else x.strip()) for x in out]


def node_param_types(m):
    ps = m.child_by_field_name("parameters")
    res = []
    for c in (ps.named_children if ps else []):
        t = c.child_by_field_name("type")
        if c.type == "spread_parameter":
            t = next((x for x in c.named_children if "type" in x.type), t)
        res.append(norm_type(t.text.decode()) if t is not None else "?")
    return res


def find_method(src, cls, name, sig, hint_line=None):
    """tra ve node method trong src; uu tien cung class, cung chu ky"""
    tree = PARSER.parse(src.encode())
    cands = []
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type in ("method_declaration", "constructor_declaration"):
            nm = n.child_by_field_name("name")
            if nm is not None and nm.text.decode() == name:
                cands.append(n)
        stack.extend(n.children)
    if not cands: return None
    def encl(n):
        a = n.parent
        while a is not None:
            if a.type in ("class_declaration", "enum_declaration", "interface_declaration", "record_declaration"):
                nm = a.child_by_field_name("name"); return nm.text.decode() if nm else None
            a = a.parent
    want = sig_param_types(sig)
    def score(n):
        s = 0
        if cls and encl(n) == cls: s += 4
        pt = node_param_types(n)
        if len(pt) == len(want): s += 2
        if pt == want: s += 2
        if hint_line: s -= min(abs(n.start_point[0] + 1 - hint_line), 5000) / 10000
        return s
    return max(cands, key=score)


# ---------------------------------------------------------------- chuan hoa / token
def leaf_tokens(node, loose):
    out = []
    def go(n):
        if n.type in COMMENTS: return
        if n.type in ATOMIC or n.child_count == 0:
            out.append("NUM" if (loose and n.type in NUMS) else n.text.decode()); return
        for c in n.children: go(c)
    go(node); return out


def ast_tokens(node):
    out = []
    def go(n):
        if n.type in COMMENTS or not n.is_named: 
            return
        t = n.type
        if t == "identifier": return
        if t == "method_invocation": out.append("Call:" + n.child_by_field_name("name").text.decode())
        elif t in ("binary_expression", "unary_expression", "assignment_expression", "update_expression"):
            op = n.child_by_field_name("operator"); out.append("Op:" + (op.text.decode() if op else t))
        elif t == "object_creation_expression":
            ty = n.child_by_field_name("type"); out.append("New:" + (norm_type(ty.text.decode()) if ty else "?"))
        elif t == "string_literal" or t == "text_block": out.append("Lit:str"); return
        elif t == "character_literal": out.append("Lit:char"); return
        elif t in NUMS: out.append("Lit:num"); return
        elif t in ("true", "false", "null_literal"): out.append("Lit:" + n.text.decode())
        elif t == "type_identifier": out.append("T:" + n.text.decode()); return
        else: out.append(t)
        for c in n.children: go(c)
    go(node); return out


def call_names(node):
    out = set()
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "method_invocation":
            out.add(n.child_by_field_name("name").text.decode())
        elif n.type == "object_creation_expression":
            ty = n.child_by_field_name("type")
            if ty is not None: out.add("new " + norm_type(ty.text.decode()))
        stack.extend(n.children)
    return out - STOP_CALLS


def shingles(tokens, k=3):
    if len(tokens) < k: return {tuple(tokens)}
    return {tuple(tokens[i:i + k]) for i in range(len(tokens) - k + 1)}


def jacc(a, b):
    return len(a & b) / len(a | b) if (a or b) else 1.0


# ---------------------------------------------------------------- diff cua ban fix (tin hieu root cause)
def fix_lines(repo, commit, path, m_start, m_end):
    """cac dong +/- cua commit fix nam trong pham vi method (theo ban fix)"""
    d = git(repo, "diff", "--unified=0", "--no-color", f"{commit}^", commit, "--", path) or ""
    added, removed, keep = [], [], False
    for ln in d.splitlines():
        h = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", ln)
        if h:
            c, cnt = int(h.group(1)), int(h.group(2) or 1)
            hi = c + max(cnt, 1) - 1
            keep = (not m_start) or (c <= m_end and hi >= m_start - 1)
        elif keep and ln.startswith("+") and not ln.startswith("+++") and not re.match(r"\+\s*(import|package)\s", ln): added.append(ln[1:])
        elif keep and ln.startswith("-") and not ln.startswith("---") and not re.match(r"-\s*(import|package)\s", ln): removed.append(ln[1:])
    return added, removed


def norm_line_tokens(lines):
    toks = []
    for ln in lines:
        ln = re.sub(r"//.*$", "", ln).strip()
        if not ln or ln.startswith(("*", "/*")): continue
        ln = re.sub(r"\b\d+\b", "NUM", ln)
        toks += re.findall(r"\w+|[^\s\w]", ln)
    return toks


def fix_calls(lines):
    s = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", "\n".join(lines)))
    return s - STOP_CALLS


# ---------------------------------------------------------------- pipeline
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="owner/name, vi du apache/jspwiki")
    ap.add_argument("--workdir", default="work")
    ap.add_argument("--out", default="out")
    ap.add_argument("--include-tests", action="store_true")
    a = ap.parse_args()
    owner, name = a.repo.split("/")
    tag = f"{owner}__{name}"
    outdir = os.path.join(a.out, tag); os.makedirs(outdir, exist_ok=True)

    # 1. du lieu
    proj = pd.read_csv(fetch(RAW + "data/project_info.csv", f"{a.workdir}/data/project_info.csv"))
    fix = pd.read_csv(fetch(RAW + "data/fix_info.csv", f"{a.workdir}/data/fix_info.csv"))
    proj = proj[(proj.github_username == owner) & (proj.github_repository_name == name)]
    if proj.empty: sys.exit(f"Khong thay repo {a.repo} trong project_info.csv")
    print(f"[1] {a.repo}: {len(proj)} CVE")

    # 2. clone nhe (partial clone, blob lay khi can)
    rp = os.path.join(a.workdir, "repos", tag)
    if not os.path.isdir(os.path.join(rp, ".git")):
        os.makedirs(os.path.dirname(rp), exist_ok=True)
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout",
                        proj.github_url.iloc[0], rp], check=True)
    print("[2] clone xong")

    # advisory (chi de ban doc khi duyet tay)
    adv = {}
    for s in proj.project_slug:
        try:
            d = json.load(open(fetch(RAW + f"advisory/{s}.json", f"{a.workdir}/advisory/{s}.json")))
            adv[s] = (d.get("summary", "") + " | " + (d.get("details", "") or "")[:400]).replace("\n", " ")
        except Exception:
            adv[s] = ""

    # 3. dung cac unit (method bi fix)
    units, unresolved = [], []
    for _, p in proj.iterrows():
        slug, buggy = p.project_slug, p.buggy_commit_id
        ensure_commit(rp, buggy)
        rows = fix[fix.project_slug == slug]
        if rows.empty:   # fix_info.csv doi khi ghi CVE duoi slug khac (duoi la ma commit / tag khac) -> doi chieu theo CVE + repo
            rows = fix[(fix.cve_id == p.cve_id) & (fix.github_username == owner) & (fix.github_repository_name == name)]
        rows = rows.dropna(subset=["method"])
        if not a.include_tests and len(rows):
            rows = rows[[not TEST_RE.search(x) for x in rows.file]]
        if rows.empty:   # CVE khong co method nao trong fix_info (vd: chi sua bien/file khac)
            unresolved.append(dict(slug=slug, file="", method="", signature="(fix_info khong co method nao)"))
            continue
        groups = rows.groupby(["file", "class", "method", "signature"], dropna=False)
        for (file, cls, meth, sig), g in groups:
            src, used = show(rp, buggy, file), "buggy"
            node = find_method(src, cls, meth, sig, g.method_start.iloc[0]) if src else None
            if node is None:   # file bi doi ten/di chuyen: lui ve cha cua commit fix dau tien
                c0 = g.commit.iloc[0]; ensure_commit(rp, c0)
                src, used = show(rp, c0 + "^", file), "fix_parent"
                node = find_method(src, cls, meth, sig, g.method_start.iloc[0]) if src else None
            if node is None:
                unresolved.append(dict(slug=slug, file=file, method=meth, signature=sig)); continue
            # tin hieu fix: gom cac dong +/- tu moi commit fix
            add, rem = [], []
            for _, r in g.iterrows():
                ensure_commit(rp, r.commit)
                ad, rm = fix_lines(rp, r.commit, file, int(r.method_start) if pd.notna(r.method_start) else 0,
                                   int(r.method_end) if pd.notna(r.method_end) else 10**9)
                add += ad; rem += rm
            t_strict, t_loose, t_ast = leaf_tokens(node, False), leaf_tokens(node, True), ast_tokens(node)
            units.append(dict(
                uid=f"{slug.split('_CVE-')[1].split('_')[0]}::{os.path.basename(file)}::{meth}",
                slug=slug, cve=p.cve_id, cwe=p.cwe_id, file=file, cls=cls, method=meth, signature=sig,
                src=used, ntok=len(t_strict), code=node.text.decode(),
                l1_strict=sha(" ".join(t_strict)), l1_loose=sha(" ".join(t_loose)), l2_ast=sha("\n".join(t_ast)),
                sh=shingles(t_ast), calls=call_names(node),
                fix_add_sh=shingles(norm_line_tokens(add)) if add else set(),
                fix_rem_sh=shingles(norm_line_tokens(rem)) if rem else set(),
                fix_add_calls=fix_calls(add), fix_rem_calls=fix_calls(rem),
                fix_add=add, fix_rem=rem))
    print(f"[3] {len(units)} unit (method bi fix), {len(unresolved)} khong tim duoc")
    if len(units) < 2: sys.exit("Qua it unit de so sanh")

    # 4. so sanh cap (cung CWE)
    pairs = []
    for x, y in itertools.combinations(units, 2):
        if x["cwe"] != y["cwe"]: continue
        j = jacc(x["sh"], y["sh"])
        lvl = ("L1_strict" if x["l1_strict"] == y["l1_strict"] else
               "L1_loose" if x["l1_loose"] == y["l1_loose"] else
               "L2_AST" if x["l2_ast"] == y["l2_ast"] else
               "L2_Near95" if j >= .95 else "L2_Near90" if j >= .90 else "")
        same_loc = (x["file"], x["cls"], x["signature"]) == (y["file"], y["cls"], y["signature"])
        fa, fr = jacc(x["fix_add_sh"], y["fix_add_sh"]), jacc(x["fix_rem_sh"], y["fix_rem_sh"])
        sfc = sorted((x["fix_add_calls"] & y["fix_add_calls"]) - (x["fix_rem_calls"] & y["fix_rem_calls"]) ) \
            if x["fix_add_calls"] and y["fix_add_calls"] else []
        shared = sorted(x["calls"] & y["calls"]); cj = jacc(x["calls"], y["calls"])
        # goi y root cause (chi la goi y, can duyet tay)
        if same_loc and (sfc or fa >= .5): hint = "same_location + same_fix_pattern"
        elif same_loc: hint = "same_location (fix khac)"
        elif fa >= .5: hint = "same_fix_pattern"
        elif sfc: hint = "same_fix_api"
        elif lvl and cj >= .5: hint = "same_structure_only"
        else: hint = ""
        pairs.append(dict(
            a=x["uid"], b=y["uid"], cwe=x["cwe"], scope="intra_cve" if x["slug"] == y["slug"] else "inter_cve",
            level=lvl, jaccard_ast=round(j, 3), same_location=same_loc, fix_added_sim=round(fa, 3),
            fix_removed_sim=round(fr, 3), shared_fix_calls=";".join(sfc), call_jaccard=round(cj, 3),
            shared_calls=";".join(shared[:10]), rc_hint=hint, manual_verdict="", manual_note=""))
    P = pd.DataFrame(pairs)

    # 5. cum (union-find) theo tung muc
    uids = [u["uid"] for u in units]
    def clusters(pred):
        uf = UF()
        for u in uids: uf.find(u)
        for r in pairs:
            if pred(r): uf.union(r["a"], r["b"])
        roots = {}
        return {u: roots.setdefault(uf.find(u), f"C{len(roots)+1}") for u in uids}
    order = ["L1_strict", "L1_loose", "L2_AST", "L2_Near95", "L2_Near90"]
    cl = {"L1_strict": clusters(lambda r: r["level"] == "L1_strict"),
          "L1_loose": clusters(lambda r: r["level"] in order[:2]),
          "L2_AST": clusters(lambda r: r["level"] in order[:3]),
          "L2_Near95": clusters(lambda r: r["level"] in order[:4]),
          "L2_Near90": clusters(lambda r: r["level"] in order)}
    RC_HINTS = ("same_location + same_fix_pattern", "same_fix_pattern", "same_fix_api")
    rc = clusters(lambda r: r["rc_hint"] in RC_HINTS)
    U = pd.DataFrame([{k: v for k, v in u.items() if k in
                       ("uid", "slug", "cve", "cwe", "file", "cls", "method", "signature", "src", "ntok")} |
                      {f"cluster_{k}": cl[k][u["uid"]] for k in cl} |
                      {"rc_group": rc[u["uid"]], "fix_new_calls": ";".join(sorted(u["fix_add_calls"] - u["fix_rem_calls"]))}
                      for u in units])

    # 6. bang chung cho muc near (de duyet tay xem rule gop nham/bo sot)
    ev = P[(P.jaccard_ast >= .80) & (P.jaccard_ast < .95) & (P.level.isin(["", "L2_Near90"]))].copy()
    ev["evidence"] = ev.jaccard_ast.apply(lambda v: "merged_at_0.90" if v >= .90 else "just_below_0.90")
    ev = pd.concat([ev[ev.evidence == "merged_at_0.90"].nlargest(20, "jaccard_ast"),
                    ev[ev.evidence == "just_below_0.90"].nlargest(20, "jaccard_ast")])

    # 7. xuat file
    U.to_csv(f"{outdir}/units.csv", index=False)
    P.sort_values(["level", "jaccard_ast"], ascending=[True, False]).to_csv(f"{outdir}/pairs.csv", index=False)
    ev.to_csv(f"{outdir}/near_evidence.csv", index=False)
    pd.DataFrame(unresolved).to_csv(f"{outdir}/unresolved.csv", index=False)
    write_report(outdir, a.repo, proj, units, U, P, ev, adv, unresolved, cl, rc)
    print(f"[7] xong -> {outdir}/ (report.md, units.csv, pairs.csv, near_evidence.csv, unresolved.csv)")


# ---------------------------------------------------------------- bao cao markdown
def write_report(outdir, repo, proj, units, U, P, ev, adv, unresolved, cl, rc):
    byid = {u["uid"]: u for u in units}
    L = [f"# Kiem tra trung lap: {repo}", "",
         f"- CVE: {len(proj)} | unit (method bi fix, ban con loi): {len(units)} | khong tim duoc: {len(unresolved)}",
         f"- Cap so sanh (cung CWE): {len(P)}", "", "## 1. Tom tat theo muc", "",
         "| Muc | So cap | Cum co >=2 unit | Unit nam trong cum trung |", "|---|---|---|---|"]
    order = ["L1_strict", "L1_loose", "L2_AST", "L2_Near95", "L2_Near90"]
    for i, lv in enumerate(order):
        n_pairs = int(P.level.isin(order[:i + 1]).sum())
        sizes = U[f"cluster_{lv}"].value_counts()
        multi = sizes[sizes >= 2]
        L.append(f"| {lv} (tich luy) | {n_pairs} | {len(multi)} | {int(multi.sum())}/{len(U)} |")
    L += ["", "Luu y: moi muc la tich luy (L2_AST bao gom ca L1). Tach intra_cve/inter_cve: "
          f"{int((P.level != '').sum())} cap co trung o it nhat 1 muc, trong do "
          f"{int(((P.level != '') & (P.scope == 'intra_cve')).sum())} cap cung CVE, "
          f"{int(((P.level != '') & (P.scope == 'inter_cve')).sum())} cap khac CVE.", "",
          "## 2. CVE va mo ta advisory (de doi chieu root cause)", ""]
    for _, p in proj.iterrows():
        L.append(f"- **{p.cve_id}** ({p.cwe_id}, tag {p.github_tag}): {adv.get(p.project_slug, '')[:350]}")
    L += ["", "## 3. Ma tran CVE x CVE (muc trung cao nhat giua cac method cua 2 CVE)", ""]
    rank = {k: i for i, k in enumerate(order)}
    cves = list(proj.cve_id)
    cell = {}
    for _, r in P.iterrows():
        ca, cb = byid[r.a]["cve"], byid[r.b]["cve"]
        if ca == cb or not r.level: continue
        k = tuple(sorted((ca, cb)))
        if k not in cell or rank[r.level] < rank[cell[k]]: cell[k] = r.level
    L.append("| |" + "|".join(c.replace("CVE-", "") for c in cves) + "|")
    L.append("|---|" + "|".join("---" for _ in cves) + "|")
    for ca in cves:
        L.append(f"|{ca.replace('CVE-', '')}|" + "|".join(
            "-" if ca == cb else cell.get(tuple(sorted((ca, cb))), "") for cb in cves) + "|")
    L += ["", "## 3b. Nhom root cause goi y (gom theo cung vi tri / cung mau fix / cung API fix)", "",
          "Day la goi y tu dong, KHONG phai ket luan. Nhom co nhieu CVE khac nhau la cho dang quan tam nhat.", ""]
    groups = defaultdict(list)
    for u in units: groups[rc[u["uid"]]].append(u)
    shown = 0
    for gid, mem in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        if len(mem) < 2: continue
        shown += 1
        apis = defaultdict(int)
        for r in P.itertuples():
            if rc[r.a] == gid and rc[r.b] == gid and r.shared_fix_calls:
                for c in r.shared_fix_calls.split(";"): apis[c] += 1
        top = ", ".join(c for c, _ in sorted(apis.items(), key=lambda kv: -kv[1])[:5]) or "-"
        cv = sorted({m["cve"] for m in mem})
        L.append(f"- **{gid}**: {len(mem)} method, {len(cv)} CVE ({', '.join(c.replace('CVE-','') for c in cv)}) | API fix chung: `{top}`")
        for m in mem: L.append(f"    - {m['uid']}")
    if not shown: L.append("- Khong co nhom nao gom tu 2 method tro len.")
    L += ["", "## 4. Cac cap can duyet tay (uu tien: co muc trung hoac co goi y root cause)", ""]
    cand = P[(P.level != "") | (P.rc_hint != "")].copy()
    cand["pri"] = cand.level.map(lambda x: rank.get(x, 9)); cand = cand.sort_values(["pri", "jaccard_ast"], ascending=[True, False])
    for _, r in cand.head(40).iterrows():
        x, y = byid[r.a], byid[r.b]
        L += [f"### {r.a}  <->  {r.b}", "",
              f"- muc: **{r.level or 'khong trung'}** | Jaccard AST: {r.jaccard_ast} | pham vi: {r.scope} | cung vi tri: {r.same_location}",
              f"- root cause goi y: `{r.rc_hint or 'khong'}` | fix_added_sim {r.fix_added_sim} | fix_removed_sim {r.fix_removed_sim}",
              f"- API chung trong fix: {r.shared_fix_calls or '-'} | API chung trong ma loi: {r.shared_calls or '-'}",
              "- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  ", ""]
        d = list(difflib.unified_diff(x["code"].splitlines(), y["code"].splitlines(), "A", "B", lineterm="", n=1))
        if r.level in ("L1_strict",): d = ["(y het - khong co khac biet)"]
        L += ["<details><summary>diff ma loi A vs B (cat 60 dong)</summary>", "", "```diff", *d[:60], "```", "</details>", "",
              "<details><summary>dong thay doi trong ban fix</summary>", "", "```",
              "A -: " + " / ".join(s.strip() for s in x["fix_rem"][:6]), "A +: " + " / ".join(s.strip() for s in x["fix_add"][:6]),
              "B -: " + " / ".join(s.strip() for s in y["fix_rem"][:6]), "B +: " + " / ".join(s.strip() for s in y["fix_add"][:6]),
              "```", "</details>", ""]
    if len(cand) > 40: L.append(f"_(con {len(cand)-40} cap nua trong pairs.csv)_")
    if unresolved:
        L += ["", "## 5. Khong tim duoc method", ""] + [f"- {u['slug']} :: {u['file']} :: {u['method']}" for u in unresolved]
    open(f"{outdir}/report.md", "w", encoding="utf-8").write("\n".join(L))


if __name__ == "__main__":
    main()
