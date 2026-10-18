# Ket luan tu dong

_Sinh boi analyze_results.py tu `out/`. Day la ket luan may sinh dua tren so lieu; moi nhom root cause van can duyet tay._

## 1. Con so tong

- 6 repo, 27 CVE co method, 72 method, 289 cap so sanh
- Cap trung L1/L2: 2 (cung CVE 2, khac CVE 0); theo muc: L1_strict 0, L1_loose 0, L2_AST 1, L2_Near95 0, L2_Near90 1
- Nhom root cause goi y: 13 (tra >= 2 CVE: 4); method trong nhom: 40/72

## 2. Bang theo repo

| Repo | CVE | Method | Cap | Cap trung L1/L2 | Nhom RC | Nhom RC tra >=2 CVE | Method trong nhom | Uu tien |
|---|---|---|---|---|---|---|---|---|
| nahsra/antisamy | 4 | 9 | 36 | 1 | 3 | 1 | 8 (88.9%) | CAO |
| keycloak/keycloak | 5 | 21 | 102 | 0 | 5 | 1 | 11 (52.4%) | CAO |
| DSpace/DSpace | 4 | 10 | 24 | 1 | 1 | 1 | 5 (50.0%) | CAO |
| apache/jspwiki | 6 | 15 | 91 | 0 | 1 | 1 | 7 (46.7%) | TRUNG BINH |
| apache/dolphinscheduler | 3 | 10 | 21 | 0 | 2 | 0 | 7 (70.0%) | THAP |
| xwiki/xwiki-commons | 5 | 7 | 15 | 0 | 1 | 0 | 2 (28.6%) | THAP |

## 3. Ket luan

1. **Khong co ban sao y het (L1) nao** o ca 6 repo: code cua cac method bi sua khong trung nhau tung ky tu.
2. **Khong co trung code giua cac CVE khac nhau** (dup_inter_cve = 0 o moi repo). O muc code, cac CVE trong cung repo gan nhu doc lap, khong can loai CVE nao vi ly do trung code.
3. **2/289 cap (0.7%) co trung o muc L1/L2** (o: DSpace/DSpace, nahsra/antisamy); tat ca deu nam trong CUNG mot CVE, phu hop voi viec mot loi hay duoc va o nhieu cho co code gan giong nhau.
4. **Trung lap that su (neu co) nam o root cause, khong phai o code:** co 4 nhom goi y tra tren >= 2 CVE, o apache/jspwiki (1), keycloak/keycloak (1), DSpace/DSpace (1), nahsra/antisamy (1). Day la cho cac CVE khac nhau co the thuc chat la cung mot kieu loi.
5. Con so method nam trong nhom root cause (40/72 = 55.6%) la **tran cua so ung vien, khong phai ti le trung**: cach gom con long, tin hieu 'cung API fix' co the bat nham khi API pho bien.
6. **Thu tu uu tien duyet tay:** nahsra/antisamy [CAO, diem 4]; keycloak/keycloak [CAO, diem 4]; DSpace/DSpace [CAO, diem 3]; apache/jspwiki [TRUNG BINH, diem 2]; apache/dolphinscheduler [THAP, diem 1]; xwiki/xwiki-commons [THAP, diem 0.5]. Diem = 3 x cap trung khac CVE + 2 x nhom root cause tra nhieu CVE + 1 x cap trung cung CVE + 0.5 x nhom root cause con lai.

## 4. Canh bao ve du lieu

- **xwiki/xwiki-commons**: mau nho (7 method, 15 cap) nen ket luan 'khong trung' co do tin cay thap.
- **apache/dolphinscheduler**: dataset co 4 CVE nhung chi 3 CVE co method de so sanh (thieu 1); mo `apache__dolphinscheduler/unresolved.csv` xem ly do.

## 5. Chi tiet cac muc can xem

### apache/jspwiki

- 6 CVE co method, 15 method, 91 cap; muc uu tien **TRUNG BINH**
- Nhom root cause tra 2 CVE (2019-10078, 2022-46907), 7 method, API fix chung: `replaceEntities`
    - `2019-10078::ReferredPagesPlugin.java::execute`
    - `2022-46907::FormOpen.java::execute`
    - `2022-46907::FormOutput.java::execute`
    - `2022-46907::BugReportHandler.java::execute`
    - `2022-46907::CurrentTimePlugin.java::execute`
    - `2022-46907::InsertPage.java::execute`
    - `2022-46907::Search.java::execute`

### xwiki/xwiki-commons

- 5 CVE co method, 7 method, 15 cap; muc uu tien **THAP**
- Khong co cap trung va khong co nhom root cause tra nhieu CVE.

### keycloak/keycloak

- 5 CVE co method, 21 method, 102 cap; muc uu tien **CAO**
- Nhom root cause tra 2 CVE (2014-3656, 2022-4361), 2 method, API fix chung: `-`
    - `2014-3656::UriUtils.java::getOrigin`
    - `2022-4361::RedirectUtils.java::matchesRedirects`

### DSpace/DSpace

- 4 CVE co method, 10 method, 24 cap; muc uu tien **CAO**
- Cap trung **L2_Near90** (intra_cve, Jaccard AST 0.933): `2022-31195::ItemImport.java::unzip` <-> `2022-31195::ItemImportServiceImpl.java::unzip`
- Nhom root cause tra 2 CVE (2022-31194, 2022-31195), 5 method, API fix chung: `IOException, getCanonicalPath, dir, getCurrentUser`
    - `2022-31195::ItemImport.java::unzip`
    - `2022-31195::ItemImportServiceImpl.java::unzip`
    - `2022-31194::SubmissionController.java::DoGetResumable`
    - `2022-31194::SubmissionController.java::doPostResumable`
    - `2022-31194::FileUploadRequest.java::FileUploadRequest`

### apache/dolphinscheduler

- 3 CVE co method, 10 method, 21 cap; muc uu tien **THAP**
- Khong co cap trung va khong co nhom root cause tra nhieu CVE.
- 5 muc khong xu ly duoc (xem unresolved.csv)

### nahsra/antisamy

- 4 CVE co method, 9 method, 36 cap; muc uu tien **CAO**
- Cap trung **L2_AST** (intra_cve, Jaccard AST 1.0): `2017-14735::Policy.java::parseAllowedEmptyTags` <-> `2017-14735::Policy.java::parseRequireClosingTags`
- Nhom root cause tra 2 CVE (2022-28367, 2022-29577), 2 method, API fix chung: `getChildNodes, getLength`
    - `2022-28367::AntiSamyDOMScanner.java::processStyleTag`
    - `2022-29577::AntiSamyDOMScanner.java::processStyleTag`

## 6. Tien do duyet tay (cot manual_verdict trong pairs.csv)

| Repo | Cap ung vien | Da dien | Phan bo |
|---|---|---|---|
| apache/jspwiki | 21 | 0 (0.0%) | - |
| xwiki/xwiki-commons | 1 | 0 (0.0%) | - |
| keycloak/keycloak | 6 | 0 (0.0%) | - |
| DSpace/DSpace | 10 | 0 (0.0%) | - |
| apache/dolphinscheduler | 9 | 0 (0.0%) | - |
| nahsra/antisamy | 7 | 0 (0.0%) | - |
