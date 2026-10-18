# Kiem tra trung lap: xwiki/xwiki-commons

- CVE: 5 | unit (method bi fix, ban con loi): 7 | khong tim duoc: 0
- Cap so sanh (cung CWE): 15

## 1. Tom tat theo muc

| Muc | So cap | Cum co >=2 unit | Unit nam trong cum trung |
|---|---|---|---|
| L1_strict (tich luy) | 0 | 0 | 0/7 |
| L1_loose (tich luy) | 0 | 0 | 0/7 |
| L2_AST (tich luy) | 0 | 0 | 0/7 |
| L2_Near95 (tich luy) | 0 | 0 | 0/7 |
| L2_Near90 (tich luy) | 0 | 0 | 0/7 |

Luu y: moi muc la tich luy (L2_AST bao gom ca L1). Tach intra_cve/inter_cve: 0 cap co trung o it nhat 1 muc, trong do 0 cap cung CVE, 0 cap khac CVE.

## 2. CVE va mo ta advisory (de doi chieu root cause)

- **CVE-2022-24897** (CWE-022, tag 12.6.6): Arbitrary filesystem write access from velocity. | ### Impact  The velocity scripts is not properly sandboxed against using the Java File API to perform read or write operations on the filesystem. Now writing an attacking script in velocity requires the Script rights in XWiki so not all users can use it, and it also requires finding an XWiki API wh
- **CVE-2023-29201** (CWE-079, tag 14.5): org.xwiki.commons:xwiki-commons-xml Cross-site Scripting vulnerability | ### Impact The "restricted" mode of the HTML cleaner in XWiki, introduced in version 4.2-milestone-1, only escaped `<script>` and `<style>`-tags but neither attributes that can be used to inject scripts nor other dangerous HTML tags like `<iframe>`. As a consequence, any code 
- **CVE-2023-29528** (CWE-079, tag 14.9-rc-1): Cross-site Scripting in org.xwiki.commons:xwiki-commons-xml | ### Impact The "restricted" mode of the HTML cleaner in XWiki, introduced in version 4.2-milestone-1 and massively improved in version 14.6-rc-1, allowed the injection of arbitrary HTML code and thus cross-site scripting via invalid HTML comments. As a consequence, any code relying on th
- **CVE-2023-31126** (CWE-079, tag 14.10.3): Improper Neutralization of Invalid Characters in Data Attribute Names in org.xwiki.commons:xwiki-commons-xml | ### Impact The HTML sanitizer, introduced in version 14.6-rc-1, allowed the injection of arbitrary HTML code and thus cross-site scripting via invalid data attributes. This can be exploited, e.g., via the link syntax in any content that su
- **CVE-2023-36471** (CWE-079, tag 14.10.5): org.xwiki.commons:xwiki-commons-xml's HTML sanitizer allows form elements in restricted | ### Impact  The HTML sanitizer that is included in XWiki since version 14.6RC1 allowed form and input HTML tags. In the context of XWiki, this allows an attacker without script right to either create forms that can be used for phishing attacks or also in the c

## 3. Ma tran CVE x CVE (muc trung cao nhat giua cac method cua 2 CVE)

| |2022-24897|2023-29201|2023-29528|2023-31126|2023-36471|
|---|---|---|---|---|---|
|2022-24897|-|||||
|2023-29201||-||||
|2023-29528|||-|||
|2023-31126||||-||
|2023-36471|||||-|

## 3b. Nhom root cause goi y (gom theo cung vi tri / cung mau fix / cung API fix)

Day la goi y tu dong, KHONG phai ket luan. Nhom co nhieu CVE khac nhau la cho dang quan tam nhat.

- **C3**: 2 method, 1 CVE (2023-29528) | API fix chung: `isRestricted`
    - 2023-29528::DefaultHTMLCleaner.java::getDefaultCleanerProperties
    - 2023-29528::DefaultHTMLCleaner.java::getDefaultCleanerTransformations

## 4. Cac cap can duyet tay (uu tien: co muc trung hoac co goi y root cause)

### 2023-29528::DefaultHTMLCleaner.java::getDefaultCleanerProperties  <->  2023-29528::DefaultHTMLCleaner.java::getDefaultCleanerTransformations

- muc: **khong trung** | Jaccard AST: 0.062 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.4 | fix_removed_sim 0.0
- API chung trong fix: isRestricted | API chung trong ma loi: getParameters
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,55 +1,51 @@
-private CleanerProperties getDefaultCleanerProperties(HTMLCleanerConfiguration configuration)
+private TrimAttributeCleanerTransformations getDefaultCleanerTransformations(HTMLCleanerConfiguration configuration)
     {
-        CleanerProperties defaultProperties = new CleanerProperties();
-        defaultProperties.setOmitUnknownTags(true);
+        TrimAttributeCleanerTransformations defaultTransformations = new TrimAttributeCleanerTransformations();
 
-        // HTML Cleaner uses the compact notation by default but we don't want that since:
-        // - it's more work and not required since not compact notation is valid XHTML
-        // - expanded elements can also be rendered fine in browsers that only support HTML.
-        defaultProperties.setUseEmptyElementTags(false);
+        TagTransformation tt;
 
-        // Wrap script and style content in CDATA blocks
-        defaultProperties.setUseCdataForScriptAndStyle(true);
+        // note that we do not care here to use a TrimAttributeTagTransformation, since the attributes are not preserved
+        if (!isHTML5(configuration)) {
+            // These tags are not obsolete in HTML5.
+            tt = new TagTransformation(HTMLConstants.TAG_B, HTMLConstants.TAG_STRONG, false);
+            defaultTransformations.addTransformation(tt);
 
-        // We need this for example to ignore CDATA sections not inside script or style elements.
-        defaultProperties.setIgnoreQuestAndExclam(true);
+            tt = new TagTransformation(HTMLConstants.TAG_I, HTMLConstants.TAG_EM, false);
+            defaultTransformations.addTransformation(tt);
 
-        // Remove CDATA outside of script and style since according to the spec it has no effect there.
-        defaultProperties.setOmitCdataOutsideScriptAndStyle(true);
+            tt = new TagTransformation(HTMLConstants.TAG_U, HTMLConstants.TAG_INS, false);
+            defaultTransformations.addTransformation(tt);
 
-        // If the caller has defined NAMESPACE_AWARE configuration property then use it, otherwise use our default.
-        String param = configuration.getParameters().get(HTMLCleanerConfiguration.NAMESPACES_AWARE);
-        boolean namespacesAware = (param == null) || Boolean.parseBoolean(param);
-        defaultProperties.setNamespacesAware(namespacesAware);
+            tt = new TagTransformation(HTMLConstants.TAG_S, HTMLConstants.TAG_DEL, false);
+            defaultTransformations.addTransformation(tt);
+        }
 
-        // Set Cleaner transformations
-        defaultProperties.setCleanerTransformations(getDefaultCleanerTransformations(configuration));
+        tt = new TagTransformation(HTMLConstants.TAG_STRIKE, HTMLConstants.TAG_DEL, false);
+        defaultTransformations.addTransformation(tt);
 
-        // Don't convert special HTML entities (i.e. &ocirc;, &permil;, &times;) with unicode characters they represent.
-        defaultProperties.setTranslateSpecialEntities(false);
+        tt = new TagTransformation(HTMLConstants.TAG_CENTER, HTMLConstants.TAG_P, false);
+        tt.addAttributeTransformation(HTMLConstants.ATTRIBUTE_STYLE, "text-align:center");
+        defaultTransformations.addTransformation(tt);
 
-        // Use character references rather than entity references if needed (for instance if you need to parse the
-        // output as XML)
-        param = configuration.getParameters().get(HTMLCleanerConfiguration.USE_CHARACTER_REFERENCES);
-        boolean useCharacterReferences = (param != null) && Boolean.parseBoolean(param);
-        defaultProperties.setTransResCharsToNCR(useCharacterReferences);
+        if (isHTML5(configuration)) {
+            // Font tags are removed before the filters are applied in HTML5, we thus need a transformation here.
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: 
A +: // Omit comments in restricted mode to avoid any potential parser confusion. / // Any part of the filtered HTML that contains unfiltered input is potentially dangerous/a candidate for / // parser confusion. Comments, style and script elements seem to be frequently found ingredients in successful / // attacks against good sanitizers. We're already removing style and script elements, so removing comments / // seems like a good defense against future attacks. / defaultProperties.setOmitComments(isRestricted(configuration));
B -: String restricted = configuration.getParameters().get(HTMLCleanerConfiguration.RESTRICTED); / if ("true".equalsIgnoreCase(restricted)) {
B +: if (isRestricted(configuration)) {
```
</details>
