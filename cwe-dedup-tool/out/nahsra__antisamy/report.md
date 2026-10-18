# Kiem tra trung lap: nahsra/antisamy

- CVE: 4 | unit (method bi fix, ban con loi): 9 | khong tim duoc: 0
- Cap so sanh (cung CWE): 36

## 1. Tom tat theo muc

| Muc | So cap | Cum co >=2 unit | Unit nam trong cum trung |
|---|---|---|---|
| L1_strict (tich luy) | 0 | 0 | 0/9 |
| L1_loose (tich luy) | 0 | 0 | 0/9 |
| L2_AST (tich luy) | 1 | 1 | 2/9 |
| L2_Near95 (tich luy) | 1 | 1 | 2/9 |
| L2_Near90 (tich luy) | 1 | 1 | 2/9 |

Luu y: moi muc la tich luy (L2_AST bao gom ca L1). Tach intra_cve/inter_cve: 1 cap co trung o it nhat 1 muc, trong do 1 cap cung CVE, 0 cap khac CVE.

## 2. CVE va mo ta advisory (de doi chieu root cause)

- **CVE-2016-10006** (CWE-079, tag 1.5.3): Moderate severity vulnerability that affects org.owasp.antisamy:antisamy | In OWASP AntiSamy before 1.5.5, by submitting a specially crafted input (a tag that supports style with active content), you could bypass the library protections and supply executable code. The impact is XSS.
- **CVE-2017-14735** (CWE-079, tag 1.5.6): OWASP AntiSamy Cross-site Scripting vulnerability | OWASP AntiSamy before 1.5.7 allows XSS via HTML5 entities, as demonstrated by use of &colon; to construct a javascript: URL.
- **CVE-2022-28367** (CWE-079, tag 1.6.5): Cross-site Scripting in OWASP AntiSamy | OWASP AntiSamy is a library for performing fast, configurable cleansing of HTML coming from untrusted sources. AntiSamy before 1.6.6 allows XSS via HTML tag smuggling on STYLE content with crafted input. The output serializer does not properly encode the supposed Cascading Style Sheets (CSS) content.
- **CVE-2022-29577** (CWE-079, tag 1.6.6.1): Cross-site Scripting in OWASP AntiSamy | AntiSamy is a library for performing fast, configurable cleansing of HTML coming from untrusted sources. OWASP AntiSamy before 1.6.7 allows XSS via HTML tag smuggling on STYLE content with crafted input. The output serializer does not properly encode the supposed Cascading Style Sheets (CSS) content. NOTE: t

## 3. Ma tran CVE x CVE (muc trung cao nhat giua cac method cua 2 CVE)

| |2016-10006|2017-14735|2022-28367|2022-29577|
|---|---|---|---|---|
|2016-10006|-||||
|2017-14735||-|||
|2022-28367|||-||
|2022-29577||||-|

## 3b. Nhom root cause goi y (gom theo cung vi tri / cung mau fix / cung API fix)

Day la goi y tu dong, KHONG phai ket luan. Nhom co nhieu CVE khac nhau la cho dang quan tam nhat.

- **C2**: 3 method, 1 CVE (2017-14735) | API fix chung: `-`
    - 2017-14735::Policy.java::parseAllowedEmptyTags
    - 2017-14735::Policy.java::parseGlobalAttributes
    - 2017-14735::Policy.java::parseRequireClosingTags
- **C3**: 3 method, 1 CVE (2017-14735) | API fix chung: `-`
    - 2017-14735::Policy.java::parseCommonAttributes
    - 2017-14735::AntiSamyDOMScanner.java::scan
    - 2017-14735::AntiSamySAXScanner.java::scan
- **C4**: 2 method, 2 CVE (2022-28367, 2022-29577) | API fix chung: `getChildNodes, getLength`
    - 2022-28367::AntiSamyDOMScanner.java::processStyleTag
    - 2022-29577::AntiSamyDOMScanner.java::processStyleTag

## 4. Cac cap can duyet tay (uu tien: co muc trung hoac co goi y root cause)

### 2017-14735::Policy.java::parseAllowedEmptyTags  <->  2017-14735::Policy.java::parseRequireClosingTags

- muc: **L2_AST** | Jaccard AST: 1.0 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 0.818 | fix_removed_sim 0.867
- API chung trong fix: - | API chung trong ma loi: addAll;getAttributeValue;getGrandChildrenByTagName
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,6 +1,6 @@
-private static void parseAllowedEmptyTags(
-      Element allowedEmptyTagsListNode, List<String> allowedEmptyTags) {
-    if (allowedEmptyTagsListNode != null) {
+private static void parseRequireClosingTags(
+      Element requireClosingTagsListNode, List<String> requireClosingTags) {
+    if (requireClosingTagsListNode != null) {
       for (Element literalNode :
-          getGrandChildrenByTagName(allowedEmptyTagsListNode, "literal-list", "literal")) {
+          getGrandChildrenByTagName(requireClosingTagsListNode, "literal-list", "literal")) {
 
@@ -8,6 +8,6 @@
         if (value != null && value.length() > 0) {
-          allowedEmptyTags.add(value);
+          requireClosingTags.add(value);
         }
       }
-    } else allowedEmptyTags.addAll(Constants.defaultAllowedEmptyTags);
+    } else requireClosingTags.addAll(Constants.defaultRequireClosingTags);
   }
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: allowedRegExp.add(Pattern.compile(REGEXP_BEGIN + value + REGEXP_END));
A +: allowedRegExp.add(Pattern.compile(value));
B -: allowedRegexps.add(Pattern.compile(REGEXP_BEGIN + value + REGEXP_END));
B +: allowedRegexps.add(Pattern.compile(value));
```
</details>

### 2022-28367::AntiSamyDOMScanner.java::processStyleTag  <->  2022-29577::AntiSamyDOMScanner.java::processStyleTag

- muc: **khong trung** | Jaccard AST: 0.443 | pham vi: inter_cve | cung vi tri: True
- root cause goi y: `same_location + same_fix_pattern` | fix_added_sim 0.128 | fix_removed_sim 0.011
- API chung trong fix: getChildNodes;getLength | API chung trong ma loi: addAll;addError;getCleanHTML;getErrorMessages;getFirstChild;getMaxInputSize;getNodeValue;htmlEntityEncode;isEmbedStyleSheets;new CssScanner
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -7,7 +7,14 @@
         try {
-            Node firstChild = ele.getFirstChild();
-            if (firstChild != null) {
+            if (ele.getChildNodes().getLength() > 0) {
+                StringBuffer toScan = new StringBuffer();
 
-                String toScan = firstChild.getNodeValue();
-                CleanResults cr = styleScanner.scanStyleSheet(toScan, policy.getMaxInputSize());
+                for (int i = 0; i < ele.getChildNodes().getLength(); i++) {
+                    Node childNode = ele.getChildNodes().item(i);
+                    if (toScan.length() > 0) {
+                        toScan.append("\n");
+                    }
+                    toScan.append(childNode.getTextContent());
+                }
+
+                CleanResults cr = styleScanner.scanStyleSheet(toScan.toString(), policy.getMaxInputSize());
                 errorMessages.addAll(cr.getErrorMessages());
@@ -22,8 +29,13 @@
 
-                final String cleanHTML = cr.getCleanHTML();
+                String cleanHTML = cr.getCleanHTML();
+                cleanHTML = cleanHTML == null || cleanHTML.equals("") ? "/* */" : cleanHTML;
 
-                if (cleanHTML == null || cleanHTML.equals("")) {
-                    firstChild.setNodeValue("/* */");
-                } else {
-                    firstChild.setNodeValue(cleanHTML);
+                ele.getFirstChild().setNodeValue(cleanHTML);
+                /*
+                 * Remove every other node after cleaning CSS, there will
+                 * be only one node in the end, as it always should have.
+                 */
+                for (int i = 1; i < ele.getChildNodes().getLength(); i++) {
+                    Node childNode = ele.getChildNodes().item(i);
+                    ele.removeChild(childNode);
                 }
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: Node firstChild = ele.getFirstChild(); / if (firstChild != null) { / String toScan = firstChild.getNodeValue(); / final String cleanHTML = cr.getCleanHTML(); / if (cleanHTML == null || cleanHTML.equals("")) { / firstChild.setNodeValue("/* */");
A +: if (ele.getChildNodes().getLength() > 0) { / String toScan = ""; /  / for (int i = 0; i < ele.getChildNodes().getLength(); i++) { / Node childNode = ele.getChildNodes().item(i); / if (!toScan.isEmpty()){
B -: if (ele.getChildNodes().getLength() > 0) { /  / for (int i = 1; i < ele.getChildNodes().getLength(); i++) { /  /  / 
B +: int childNodesCount = ele.getChildNodes().getLength(); / if (childNodesCount > 0) { / * Starting from the end due to list updating on the fly. / for (int i = childNodesCount - 1; i >= 1; i--) {
```
</details>

### 2017-14735::Policy.java::parseAllowedEmptyTags  <->  2017-14735::Policy.java::parseGlobalAttributes

- muc: **khong trung** | Jaccard AST: 0.188 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 1.0 | fix_removed_sim 1.0
- API chung trong fix: - | API chung trong ma loi: getAttributeValue
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,13 +1,16 @@
-private static void parseAllowedEmptyTags(
-      Element allowedEmptyTagsListNode, List<String> allowedEmptyTags) {
-    if (allowedEmptyTagsListNode != null) {
-      for (Element literalNode :
-          getGrandChildrenByTagName(allowedEmptyTagsListNode, "literal-list", "literal")) {
+private static void parseGlobalAttributes(
+      Element root,
+      Map<String, Attribute> globalAttributes1,
+      Map<String, Attribute> commonAttributes)
+      throws PolicyException {
+    for (Element ele : getByTagName(root, "attribute")) {
 
-        String value = getAttributeValue(literalNode, "value");
-        if (value != null && value.length() > 0) {
-          allowedEmptyTags.add(value);
-        }
-      }
-    } else allowedEmptyTags.addAll(Constants.defaultAllowedEmptyTags);
+      String name = getAttributeValue(ele, "name");
+      Attribute toAdd = commonAttributes.get(name.toLowerCase());
+
+      if (toAdd != null) globalAttributes1.put(name.toLowerCase(), toAdd);
+      else
+        throw new PolicyException(
+            "Global attribute '" + name + "' was not defined in <common-attributes>");
+    }
   }
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: allowedRegExp.add(Pattern.compile(REGEXP_BEGIN + value + REGEXP_END));
A +: allowedRegExp.add(Pattern.compile(value));
B -: allowedRegExp.add(Pattern.compile(REGEXP_BEGIN + value + REGEXP_END)); /  /  / 
B +: allowedRegExp.add(Pattern.compile(value)); / 
```
</details>

### 2017-14735::Policy.java::parseGlobalAttributes  <->  2017-14735::Policy.java::parseRequireClosingTags

- muc: **khong trung** | Jaccard AST: 0.188 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 0.818 | fix_removed_sim 0.867
- API chung trong fix: - | API chung trong ma loi: getAttributeValue
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,16 +1,13 @@
-private static void parseGlobalAttributes(
-      Element root,
-      Map<String, Attribute> globalAttributes1,
-      Map<String, Attribute> commonAttributes)
-      throws PolicyException {
-    for (Element ele : getByTagName(root, "attribute")) {
+private static void parseRequireClosingTags(
+      Element requireClosingTagsListNode, List<String> requireClosingTags) {
+    if (requireClosingTagsListNode != null) {
+      for (Element literalNode :
+          getGrandChildrenByTagName(requireClosingTagsListNode, "literal-list", "literal")) {
 
-      String name = getAttributeValue(ele, "name");
-      Attribute toAdd = commonAttributes.get(name.toLowerCase());
-
-      if (toAdd != null) globalAttributes1.put(name.toLowerCase(), toAdd);
-      else
-        throw new PolicyException(
-            "Global attribute '" + name + "' was not defined in <common-attributes>");
-    }
+        String value = getAttributeValue(literalNode, "value");
+        if (value != null && value.length() > 0) {
+          requireClosingTags.add(value);
+        }
+      }
+    } else requireClosingTags.addAll(Constants.defaultRequireClosingTags);
   }
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: allowedRegExp.add(Pattern.compile(REGEXP_BEGIN + value + REGEXP_END)); /  /  / 
A +: allowedRegExp.add(Pattern.compile(value)); / 
B -: allowedRegexps.add(Pattern.compile(REGEXP_BEGIN + value + REGEXP_END));
B +: allowedRegexps.add(Pattern.compile(value));
```
</details>

### 2017-14735::AntiSamyDOMScanner.java::scan  <->  2017-14735::AntiSamySAXScanner.java::scan

- muc: **khong trung** | Jaccard AST: 0.181 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 1.0 | fix_removed_sim 1.0
- API chung trong fix: - | API chung trong ma loi: clear;currentTimeMillis;getHTMLSerializer;getOutputFormat;new CachedItem;new CleanResults;new InputSource;new ScanException;poll
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,93 +1,39 @@
-@Override
-  public CleanResults scan(String html) throws ScanException {
-
-    if (html == null) {
-      throw new ScanException(new NullPointerException("Null HTML input"));
-    }
-
-    errorMessages.clear();
-    int maxInputSize = policy.getMaxInputSize();
-
-    if (maxInputSize < html.length()) {
-      addError(ErrorMessageUtil.ERROR_INPUT_SIZE, new Object[] {html.length(), maxInputSize});
-      throw new ScanException(errorMessages.get(0));
-    }
-
-    isNofollowAnchors = policy.isNofollowAnchors();
-    isNoopenerAndNoreferrerAnchors = policy.isNoopenerAndNoreferrerAnchors();
-    isValidateParamAsEmbed = policy.isValidateParamAsEmbed();
-
-    long startOfScan = System.currentTimeMillis();
-
+public CleanResults scan(Reader reader, Writer writer) throws ScanException {
     try {
 
-      CachedItem cachedItem;
-      cachedItem = cachedItems.poll();
-      if (cachedItem == null) {
-        cachedItem = new CachedItem();
+      CachedItem candidateCachedItem = cachedItems.poll();
+      if (candidateCachedItem == null) {
+        candidateCachedItem =
+            new CachedItem(getNewTransformer(), getParser(), new MagicSAXFilter(messages));
       }
 
-      /*
-       * We have to replace any invalid XML characters to prevent NekoHTML
-       * from breaking when it gets passed encodings like %21.
-       */
+      final CachedItem cachedItem = candidateCachedItem;
 
-      html = stripNonValidXMLCharacters(html, cachedItem.invalidXmlCharMatcher);
+      SAXParser parser = cachedItem.saxParser;
+      cachedItem.magicSAXFilter.reset(policy);
 
-      /*
-       * First thing we do is call the HTML cleaner ("NekoHTML") on it
-       * with the appropriate options. We choose not to omit tags due to
-       * the fallibility of our own listing in the ever changing world of
-       * W3C.
-       */
+      long startOfScan = System.currentTimeMillis();
 
-      DOMFragmentParser parser = cachedItem.getDomFragmentParser();
+      final SAXSource source = new SAXSource(parser, new InputSource(reader));
 
-      try {
-        parser.parse(new InputSource(new StringReader(html)), dom);
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: 
A +: 
B -: 
B +: 
```
</details>

### 2017-14735::Policy.java::parseCommonAttributes  <->  2017-14735::AntiSamyDOMScanner.java::scan

- muc: **khong trung** | Jaccard AST: 0.028 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 1.0 | fix_removed_sim 1.0
- API chung trong fix: - | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,27 +1,94 @@
-private static void parseCommonAttributes(
-      Element root,
-      Map<String, Attribute> commonAttributes1,
-      Map<String, AntiSamyPattern> commonRegularExpressions1) {
+@Override
+  public CleanResults scan(String html) throws ScanException {
 
-    for (Element ele : getByTagName(root, "attribute")) {
-      String onInvalid = getAttributeValue(ele, "onInvalid");
-      String name = getAttributeValue(ele, "name");
+    if (html == null) {
+      throw new ScanException(new NullPointerException("Null HTML input"));
+    }
 
-      List<Pattern> allowedRegexps = getAllowedRegexps(commonRegularExpressions1, ele);
-      List<String> allowedValues = getAllowedLiterals(ele);
+    errorMessages.clear();
+    int maxInputSize = policy.getMaxInputSize();
 
-      final String onInvalidStr;
-      if (onInvalid != null && onInvalid.length() > 0) {
-        onInvalidStr = onInvalid;
-      } else onInvalidStr = DEFAULT_ONINVALID;
+    if (maxInputSize < html.length()) {
+      addError(ErrorMessageUtil.ERROR_INPUT_SIZE, new Object[] {html.length(), maxInputSize});
+      throw new ScanException(errorMessages.get(0));
+    }
 
-      String description = getAttributeValue(ele, "description");
-      Attribute attribute =
-          new Attribute(
-              getAttributeValue(ele, "name"),
-              allowedRegexps,
-              allowedValues,
-              onInvalidStr,
-              description);
-      commonAttributes1.put(name.toLowerCase(), attribute);
+    isNofollowAnchors = policy.isNofollowAnchors();
+    isNoopenerAndNoreferrerAnchors = policy.isNoopenerAndNoreferrerAnchors();
+    isValidateParamAsEmbed = policy.isValidateParamAsEmbed();
+
+    long startOfScan = System.currentTimeMillis();
+
+    try {
+
+      CachedItem cachedItem;
+      cachedItem = cachedItems.poll();
+      if (cachedItem == null) {
+        cachedItem = new CachedItem();
+      }
+
+      /*
+       * We have to replace any invalid XML characters to prevent NekoHTML
+       * from breaking when it gets passed encodings like %21.
+       */
+
+      html = stripNonValidXMLCharacters(html, cachedItem.invalidXmlCharMatcher);
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: 
A +: 
B -: 
B +: 
```
</details>

### 2017-14735::Policy.java::parseCommonAttributes  <->  2017-14735::AntiSamySAXScanner.java::scan

- muc: **khong trung** | Jaccard AST: 0.01 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 1.0 | fix_removed_sim 1.0
- API chung trong fix: - | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,27 +1,40 @@
-private static void parseCommonAttributes(
-      Element root,
-      Map<String, Attribute> commonAttributes1,
-      Map<String, AntiSamyPattern> commonRegularExpressions1) {
+public CleanResults scan(Reader reader, Writer writer) throws ScanException {
+    try {
 
-    for (Element ele : getByTagName(root, "attribute")) {
-      String onInvalid = getAttributeValue(ele, "onInvalid");
-      String name = getAttributeValue(ele, "name");
+      CachedItem candidateCachedItem = cachedItems.poll();
+      if (candidateCachedItem == null) {
+        candidateCachedItem =
+            new CachedItem(getNewTransformer(), getParser(), new MagicSAXFilter(messages));
+      }
 
-      List<Pattern> allowedRegexps = getAllowedRegexps(commonRegularExpressions1, ele);
-      List<String> allowedValues = getAllowedLiterals(ele);
+      final CachedItem cachedItem = candidateCachedItem;
 
-      final String onInvalidStr;
-      if (onInvalid != null && onInvalid.length() > 0) {
-        onInvalidStr = onInvalid;
-      } else onInvalidStr = DEFAULT_ONINVALID;
+      SAXParser parser = cachedItem.saxParser;
+      cachedItem.magicSAXFilter.reset(policy);
 
-      String description = getAttributeValue(ele, "description");
-      Attribute attribute =
-          new Attribute(
-              getAttributeValue(ele, "name"),
-              allowedRegexps,
-              allowedValues,
-              onInvalidStr,
-              description);
-      commonAttributes1.put(name.toLowerCase(), attribute);
+      long startOfScan = System.currentTimeMillis();
+
+      final SAXSource source = new SAXSource(parser, new InputSource(reader));
+
+      final Transformer transformer = cachedItem.transformer;
+      boolean formatOutput = policy.isFormatOutput();
+      boolean omitXml = policy.isOmitXmlDeclaration();
+
+      transformer.setOutputProperty(OutputKeys.INDENT, formatOutput ? "yes" : "no");
+      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, omitXml ? "yes" : "no");
+      transformer.setOutputProperty(OutputKeys.METHOD, "html");
+
+      //noinspection deprecation
+      final org.apache.xml.serialize.OutputFormat format = getOutputFormat();
+      //noinspection deprecation
+      final org.apache.xml.serialize.HTMLSerializer serializer = getHTMLSerializer(writer, format);
+
+      transformer.transform(source, new SAXResult(serializer));
+      errorMessages.clear();
+      errorMessages.addAll(cachedItem.magicSAXFilter.getErrorMessages());
+      cachedItems.add(cachedItem);
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: 
A +: 
B -: 
B +: 
```
</details>
