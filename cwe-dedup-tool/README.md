# cwe-dedup-tool

Công cụ kiểm tra **trùng lặp giữa các lỗ hổng trong cùng một repo** của dataset
[CWE-Bench-Java](https://github.com/iris-sast/cwe-bench-java). Chạy trên từng repo, cho biết các
lỗ hổng trong repo đó trùng nhau như thế nào:

| Câu hỏi | Công cụ trả lời bằng |
|---|---|
| Có method nào **y hệt** nhau không? | L1 strict, L1 loose, L2 AST |
| Có method nào **chung kiểu** (gần giống) không? | L2 Near 0.95 / 0.90 |
| Có lỗ hổng nào **cùng root cause** không? | Tín hiệu gợi ý + bạn duyệt tay |

Bộ rule kế thừa từ `Rules.docx` (OWASP Benchmark), **bỏ L3**, và chỉnh lại cho code thật (xem mục 6).

---

## 1. Cấu trúc thư mục

```
cwe-dedup-tool/
├── README.md
├── requirements.txt
├── repos.txt            # danh sách repo cần chạy (sửa file này)
├── dedup_repo.py        # CÔNG CỤ CHÍNH: chạy 1 repo
├── run_batch.py         # chạy nhiều repo trong repos.txt + gộp out/summary.csv
├── tests/test_logic.py  # test L1/L2 (chạy để chắc công cụ hoạt động đúng)
├── examples/            # kết quả mẫu đã chạy: apache/jspwiki, nahsra/antisamy
│
├── work/                # (tự sinh) csv tải về, advisory, bản clone repo
└── out/                 # (tự sinh) kết quả
    ├── summary.csv      #   bảng tổng hợp các repo (chỉ có khi dùng run_batch.py)
    └── <owner>__<repo>/
        ├── report.md           # ĐỌC FILE NÀY TRƯỚC
        ├── pairs.csv           # mọi cặp + cột để điền kết luận
        ├── units.csv           # mọi method + mã cụm
        ├── near_evidence.csv   # bằng chứng kiểm tra ngưỡng near
        └── unresolved.csv      # CVE/method không xử lý được
```

## 2. Cài đặt

Cần: **Python ≥ 3.9**, **git ≥ 2.25** (cho partial clone), truy cập mạng tới `github.com` và
`raw.githubusercontent.com`.

```bash
cd cwe-dedup-tool
python -m venv .venv && .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m unittest discover -s tests -v                # phải báo OK (4 test)
```

## 3. Cách chạy

**Một repo:**
```bash
python dedup_repo.py --repo apache/jspwiki
```

**Nhiều repo:** sửa `repos.txt` (mỗi dòng một `owner/name`, `#` là chú thích), rồi:
```bash
python run_batch.py
```

Tham số:

| Tham số | Ý nghĩa |
|---|---|
| `--repo owner/name` | repo cần chạy (chỉ `dedup_repo.py`) |
| `--include-tests` | tính cả method trong file test (mặc định **bỏ**) |
| `--workdir DIR` | nơi lưu dữ liệu tải về và clone (mặc định `work`) |
| `--out DIR` | nơi ghi kết quả (mặc định `out`) |
| `--repos FILE` | file danh sách repo (chỉ `run_batch.py`, mặc định `repos.txt`) |
| `--skip-existing` | bỏ qua repo đã có kết quả (chỉ `run_batch.py`) |

Lần chạy đầu cần tải dữ liệu và clone repo (partial clone, không tải file blob). Repo lớn
như keycloak sẽ lâu hơn; các lần sau dùng lại `work/`. Các đường dẫn tương đối tính từ thư mục bạn đang đứng khi chạy.

## 4. Đọc kết quả

### 4.1 `report.md` (đọc theo thứ tự)

1. **Tóm tắt theo mức**: số cặp trùng và số cụm ở từng mức (mức tích lũy: L2_AST gồm cả L1).
   Có tách cặp **cùng CVE** (`intra_cve`) và **khác CVE** (`inter_cve`).
2. **CVE + mô tả advisory**: để biết lỗi là gì khi đánh giá root cause.
3. **Ma trận CVE × CVE**: mức trùng cao nhất giữa các method của 2 CVE.
3b. **Nhóm root cause gợi ý**: gom method theo cùng vị trí, cùng mẫu fix hoặc cùng API fix.
   Nhóm trải trên nhiều CVE là chỗ đáng xem nhất.
4. **Các cặp cần duyệt tay**: mỗi cặp có tín hiệu, diff mã lỗi và các dòng thay đổi ở bản fix.

### 4.2 `pairs.csv` – các cột chính

| Cột | Ý nghĩa |
|---|---|
| `a`, `b` | hai method, dạng `CVE::File.java::method` |
| `scope` | `intra_cve` (cùng CVE) hoặc `inter_cve` (khác CVE) |
| `level` | mức trùng cao nhất: `L1_strict` > `L1_loose` > `L2_AST` > `L2_Near95` > `L2_Near90`; rỗng = không trùng |
| `jaccard_ast` | độ giống cấu trúc AST (0–1), luôn được tính |
| `same_location` | cùng file + class + chữ ký (cùng một method bị sửa bởi 2 CVE) |
| `fix_added_sim`, `fix_removed_sim` | độ giống giữa các dòng được thêm / bị xóa ở bản fix |
| `shared_fix_calls` | API mà cả hai bản fix đều **thêm vào** (vd. `replaceEntities`) |
| `shared_calls` | API chung trong code lỗi |
| `rc_hint` | gợi ý root cause (xem dưới) |
| `manual_verdict`, `manual_note` | **bạn điền** |

Giá trị `rc_hint`: `same_location + same_fix_pattern` > `same_location (fix khác)` >
`same_fix_pattern` > `same_fix_api` > `same_structure_only` > rỗng.

### 4.3 `summary.csv` (khi dùng `run_batch.py`)

Mỗi dòng một repo: số CVE/method/cặp, số cặp ở từng mức (mỗi cặp tính một lần theo mức cao nhất),
số cặp cùng CVE/khác CVE, số nhóm root cause và số nhóm trải qua ≥ 2 CVE.

## 5. Quy trình duyệt tay gợi ý

1. Mở `report.md` mục 1 để biết repo có trùng ở mức nào.
2. Xem mục 3b để biết các nhóm root cause. Với mỗi nhóm, đọc advisory của các CVE trong nhóm.
3. Với mỗi cặp ở mục 4 (hoặc lọc `pairs.csv` theo `level != ""` hoặc `rc_hint != ""`), xem diff rồi điền
   `manual_verdict`:

| Giá trị | Nghĩa |
|---|---|
| `identical` | code giống hệt, hoặc chỉ khác tên/giá trị |
| `same_pattern` | khác chi tiết nhưng cùng khuôn mã / cùng cách sửa (bản sao có chỉnh) |
| `same_root_cause` | code khác nhưng cùng nguyên nhân gốc (vd. cùng thiếu escape đầu ra) |
| `different` | không liên quan |

   Một cặp thỏa nhiều giá trị thì ghi giá trị đứng trước trong bảng, phần còn lại ghi vào `manual_note`.
4. Xem `near_evidence.csv` để kiểm tra ngưỡng: các cặp `merged_at_0.90` có gộp nhầm không, các cặp
   `just_below_0.90` có bị bỏ sót không.

## 6. Quy ước, khác biệt so với Rules.docx và giới hạn

**Quy ước**
- Đơn vị so sánh là **method bị fix** (từ `fix_info.csv`), lấy **bản code còn lỗi** tại `buggy_commit_id`.
  Nếu file không còn ở commit đó thì lùi về cha của commit fix (cột `src` trong `units.csv` = `fix_parent`).
- Chỉ so sánh các cặp **cùng CWE**. Cặp cùng CVE vẫn được so (một CVE có thể sửa nhiều method giống nhau).
- Method được tìm bằng AST (tên + class + chữ ký), không dựa vào số dòng.
- Method trong file test bị loại, trừ khi dùng `--include-tests`.

**Khác Rules.docx**

| Rules.docx (OWASP Benchmark) | Ở đây |
|---|---|
| L1, L2, L3 | L1, L2; **bỏ L3**, thay bằng tín hiệu root cause + duyệt tay |
| P-02, P-03 (lấy thân class Benchmark, bỏ `doGet`) | không cần, vì không có khuôn mẫu chung |
| L1-03/04/05 (chuẩn hóa tên và số do máy sinh) | không dùng, vì tên biến thật không có số sinh tự động |
| L1-01/02/06/07, L2-01..04 | dùng (L1 chuẩn hóa ở mức token nên đã bỏ comment và khoảng trắng; L1 loose đổi số thành `NUM`) |
| L2: `Call:<tên đầy đủ>` | `Call:<tên method>` (không có tên đầy đủ khi chưa resolve type) |

**Giới hạn cần biết**
- `rc_hint` **chỉ là gợi ý**. Tín hiệu "cùng API fix" mạnh nhưng có thể bắt nhầm khi API quá phổ biến;
  danh sách API bị bỏ qua nằm ở `STOP_CALLS` trong `dedup_repo.py`.
- `fix_info.csv` đôi khi ghi một CVE dưới **slug khác** với `project_info.csv` (đuôi là mã commit hoặc tag khác).
  Công cụ tra theo slug trước, nếu không có thì đối chiếu theo `cve_id` + repo. Một số CVE vẫn thật sự
  không có dòng nào trong `fix_info.csv`.
- CVE không có method nào trong `fix_info.csv` (chỉ sửa biến, hoặc sửa file ngoài danh sách) sẽ không được so
  sánh và nằm trong `unresolved.csv`.
- Chưa có phân tích luồng dữ liệu (đã bỏ L3), nên "cùng root cause" ngoài tín hiệu fix là do bạn đánh giá.
- Phụ thuộc chất lượng `fix_info.csv`. Thiếu method ở đó thì thiếu ở đây.

## 7. Tùy chỉnh

| Muốn đổi | Sửa ở `dedup_repo.py` |
|---|---|
| Ngưỡng near (0.95 / 0.90), khoảng bằng chứng (0.80–0.90) | các số trong khối `lvl = (...)` và phần `ev = ...` |
| Danh sách API bị bỏ qua khi tìm tín hiệu | hằng `STOP_CALLS` |
| Luật gợi ý root cause | khối `# goi y root cause` |
| Cách loại file test | hằng `TEST_RE` |

## 8. Lỗi thường gặp

| Hiện tượng | Cách xử lý |
|---|---|
| `Khong thay repo ... trong project_info.csv` | gõ đúng `owner/name`, phân biệt hoa/thường (vd. `DSpace/DSpace`) |
| `Qua it unit de so sanh` | repo có < 2 method xử lý được; xem `unresolved.csv`, thử `--include-tests` |
| Lỗi tải dữ liệu / clone | kiểm tra mạng và proxy; xóa thư mục tương ứng trong `work/` rồi chạy lại |
| `git clone --filter` lỗi | nâng git lên ≥ 2.25 |
| Lỗi import `tree_sitter` | `pip install -U tree-sitter tree-sitter-java` (cần tree-sitter ≥ 0.23) |
| Muốn chạy lại từ đầu | xóa `out/` (và `work/repos/<repo>` nếu nghi clone hỏng) |

## 9. Kết quả mẫu (trong `examples/`)

- **apache/jspwiki** (15 method, 6 CVE): 0 cặp trùng ở L1/L2. 1 nhóm root cause gồm 7 method thuộc 2 CVE (2019-10078 và
  2022-46907), cùng được sửa bằng `TextUtil.replaceEntities` (đầu ra plugin không được escape HTML).
- **nahsra/antisamy**: 1 cặp `L2_AST` cùng CVE (`parseAllowedEmptyTags` và `parseRequireClosingTags`, hai hàm sao chép
  lẫn nhau, chỉ khác tên biến). Ngoài ra `processStyleTag` bị sửa bởi 2 CVE khác nhau (2022-28367 và 2022-29577),
  Jaccard AST 0.44, cần duyệt tay xem có cùng root cause không.
