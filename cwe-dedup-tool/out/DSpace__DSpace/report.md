# Kiem tra trung lap: DSpace/DSpace

- CVE: 4 | unit (method bi fix, ban con loi): 10 | khong tim duoc: 0
- Cap so sanh (cung CWE): 24

## 1. Tom tat theo muc

| Muc | So cap | Cum co >=2 unit | Unit nam trong cum trung |
|---|---|---|---|
| L1_strict (tich luy) | 0 | 0 | 0/10 |
| L1_loose (tich luy) | 0 | 0 | 0/10 |
| L2_AST (tich luy) | 0 | 0 | 0/10 |
| L2_Near95 (tich luy) | 0 | 0 | 0/10 |
| L2_Near90 (tich luy) | 1 | 1 | 2/10 |

Luu y: moi muc la tich luy (L2_AST bao gom ca L1). Tach intra_cve/inter_cve: 1 cap co trung o it nhat 1 muc, trong do 1 cap cung CVE, 0 cap khac CVE.

## 2. CVE va mo ta advisory (de doi chieu root cause)

- **CVE-2016-10726** (CWE-022, tag 4.4): High severity vulnerability that affects org.dspace:dspace-xmlui | The XMLUI feature in DSpace before 3.6, 4.x before 4.5, and 5.x before 5.5 allows directory traversal via the themes/ path in an attack with two or more arbitrary characters and a colon before a pathname, as demonstrated by a themes/Reference/aa:etc/passwd URI.
- **CVE-2022-31195** (CWE-022, tag 5.10): DSpace ItemImportService API Vulnerable to Path Traversal in Simple Archive Format Package Import | ### Impact ItemImportServiceImpl is vulnerable to a path traversal vulnerability. This means a malicious SAF (simple archive format) package could cause a file/directory to be created anywhere the Tomcat/DSpace user can write to on the server.  Howev
- **CVE-2022-31194** (CWE-022, tag 5.10): JSPUI vulnerable to path traversal in submission (resumable) upload | ### Impact The JSPUI resumable upload implementations in SubmissionController and FileUploadRequest are vulnerable to multiple path traversal attacks, allowing an attacker to create files/directories anywhere on the server writable by the Tomcat/DSpace user, by modifying some req
- **CVE-2022-31192** (CWE-079, tag 5.10): JSPUI Possible Cross Site Scripting in "Request a Copy" Feature | ### Impact The JSPUI "Request a Copy" feature does not properly escape values submitted and stored from the "Request a Copy" form.  This means that item requests could be vulnerable to XSS attacks.  This vulnerability only impacts the JSPUI.  _This vulnerability does NOT impact the X

## 3. Ma tran CVE x CVE (muc trung cao nhat giua cac method cua 2 CVE)

| |2016-10726|2022-31195|2022-31194|2022-31192|
|---|---|---|---|---|
|2016-10726|-||||
|2022-31195||-|||
|2022-31194|||-||
|2022-31192||||-|

## 3b. Nhom root cause goi y (gom theo cung vi tri / cung mau fix / cung API fix)

Day la goi y tu dong, KHONG phai ket luan. Nhom co nhieu CVE khac nhau la cho dang quan tam nhat.

- **C2**: 5 method, 2 CVE (2022-31194, 2022-31195) | API fix chung: `IOException, getCanonicalPath, dir, directory, mkdirs`
    - 2022-31195::ItemImport.java::unzip
    - 2022-31195::ItemImportServiceImpl.java::unzip
    - 2022-31194::SubmissionController.java::DoGetResumable
    - 2022-31194::SubmissionController.java::doPostResumable
    - 2022-31194::FileUploadRequest.java::FileUploadRequest

## 4. Cac cap can duyet tay (uu tien: co muc trung hoac co goi y root cause)

### 2022-31195::ItemImport.java::unzip  <->  2022-31195::ItemImportServiceImpl.java::unzip

- muc: **L2_Near90** | Jaccard AST: 0.933 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 0.898 | fix_removed_sim 1.0
- API chung trong fix: IOException;directory;getCanonicalPath;mkdirs | API chung trong ma loi: canRead;entries;exists;getAbsolutePath;getInputStream;getProperty;hasMoreElements;isDirectory;lastIndexOf;mkdir
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,2 +1,3 @@
-public static String unzip(File zipfile, String destDir) throws IOException {
+@Override
+    public String unzip(File zipfile, String destDir) throws IOException {
         // 2
@@ -73,3 +74,3 @@
                     if(entryChunks.length > 2) {
-                        if(sourceDirForZip == sourcedir) {
+                        if(StringUtils.equals(sourceDirForZip, sourcedir)) {
                             sourceDirForZip = sourcedir + "/" + entryChunks[0];
@@ -97,3 +98,3 @@
         
-        if(sourceDirForZip != sourcedir) {
+        if(!StringUtils.equals(sourceDirForZip, sourcedir)) {
             sourcedir = sourceDirForZip;
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: log.error("'" + ConfigurationManager.getProperty("org.dspace.app.itemexport.work.dir") + / "' as defined by the key 'org.dspace.app.itemexport.work.dir' in dspace.cfg " + / String sourcedir = destinationDir + System.getProperty("file.separator") + zipfile.getName(); / String zipDir = destinationDir + System.getProperty("file.separator") + zipfile.getName() + System.getProperty("file.separator"); / if (!new File(zipDir + entry.getName()).mkdir()) / {
A +: log.debug("Using directory " + destinationDir + " for zip extraction. (destDir arg is " + destDir + / ", tempWorkDir is " + tempWorkDir + ")"); / log.error("'" + ConfigurationManager.getProperty("org.dspace.app.batchitemimport.work.dir") + / "' as defined by the key 'org.dspace.app.batchitemimport.work.dir' in dspace.cfg " + / if(!destinationDir.endsWith(System.getProperty("file.separator"))) { / destinationDir += System.getProperty("file.separator");
B -: log.error("'" + ConfigurationManager.getProperty("org.dspace.app.itemexport.work.dir") + / "' as defined by the key 'org.dspace.app.itemexport.work.dir' in dspace.cfg " + / String sourcedir = destinationDir + System.getProperty("file.separator") + zipfile.getName(); / String zipDir = destinationDir + System.getProperty("file.separator") + zipfile.getName() + System.getProperty("file.separator"); / if (!new File(zipDir + entry.getName()).mkdir()) / {
B +: log.debug("Extracting zip at " + zipfile.getAbsolutePath()); / log.debug("Using directory " + destinationDir + " for zip extraction. (destDir arg is " + destDir + / ", tempWorkDir is " + tempWorkDir + ")"); / log.error("'" + ConfigurationManager.getProperty("org.dspace.app.batchitemexport.work.dir") + / "' as defined by the key 'org.dspace.app.batchitemexport.work.dir' in dspace.cfg " + / 
```
</details>

### 2022-31194::SubmissionController.java::DoGetResumable  <->  2022-31194::SubmissionController.java::doPostResumable

- muc: **khong trung** | Jaccard AST: 0.26 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 0.622 | fix_removed_sim 0.0
- API chung trong fix: IOException;dir;getCanonicalPath;getCurrentUser;getEmail | API chung trong ma loi: exists;getParameter;getProperty;new File
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,4 +1,7 @@
-protected void DoGetResumable(HttpServletRequest request, HttpServletResponse response) 
-        throws IOException
+protected File doPostResumable(HttpServletRequest request)
+            throws FileSizeLimitExceededException, IOException, ServletException 
     {
+        File completedFile = null;
+        FileUploadRequest wrapper = null;
+        
         if (ConfigurationManager.getProperty("upload.temp.dir") != null)
@@ -7,36 +10,69 @@
         }
-        else
-        {
+        else {
             tempDir = System.getProperty("java.io.tmpdir");
         }
+        
+        try
+        {
+            // if we already have a FileUploadRequest, use it
+            if (Class.forName("org.dspace.app.webui.util.FileUploadRequest").isInstance(request))
+            {
+                wrapper = (FileUploadRequest) request;
+            } 
+            else // if not wrap the mulitpart request to get the submission info
+            {
+                wrapper = new FileUploadRequest(request);
+            }
+        }
+        catch (ClassNotFoundException ex)
+        {
+            // Cannot find a class that is part of the JSPUI?
+            log.fatal("Cannot find class org.dspace.app.webui.util.FileUploadRequest");
+            throw new ServletException("Cannot find class org.dspace.app.webui.util.FileUploadRequest.", ex);
+        }
 
-        String resumableIdentifier = request.getParameter("resumableIdentifier");
-        String resumableChunkNumber = request.getParameter("resumableChunkNumber");
-        long resumableCurrentChunkSize = 
-                Long.valueOf(request.getParameter("resumableCurrentChunkSize"));
+        String resumableIdentifier = wrapper.getParameter("resumableIdentifier");
+        long resumableTotalSize = Long.valueOf(wrapper.getParameter("resumableTotalSize"));
+        int resumableTotalChunks = Integer.valueOf(wrapper.getParameter("resumableTotalChunks"));
 
-        tempDir = tempDir + File.separator + resumableIdentifier;
+        String chunkDirPath = tempDir + File.separator + resumableIdentifier;
+        File chunkDirPathFile = new File(chunkDirPath);
+        boolean foundAll = true;
+        long currentSize = 0l;
+        
+        // check whether all chunks were received.
+        if(chunkDirPathFile.exists())
+        {
+            for (int p = 1; p <= resumableTotalChunks; p++) 
+            {
+                File file = new File(chunkDirPath + File.separator + "part" + Integer.toString(p));
 
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: protected void DoGetResumable(HttpServletRequest request, HttpServletResponse response) / tempDir = ConfigurationManager.getProperty("upload.temp.dir"); / tempDir = System.getProperty("java.io.tmpdir"); / tempDir = tempDir + File.separator + resumableIdentifier; / protected void DoGetResumable(HttpServletRequest request, HttpServletResponse response) / tempDir = ConfigurationManager.getProperty("upload.temp.dir");
A +: protected void DoGetResumable(Context context, HttpServletRequest request, HttpServletResponse response) / String baseDir; /  / baseDir = ConfigurationManager.getProperty("upload.temp.dir"); / baseDir = System.getProperty("java.io.tmpdir"); / tempDir = baseDir + File.separator + resumableIdentifier;
B -: 
B +:  / // Test chunkFile to see if canonical path is within the original baseDir / if(!chunkFile.getCanonicalPath().startsWith(baseDir)) { / log.error("Error processing resumable upload chunk: temporary chunk file would be created outside " + / "permissible temp dir ("+ baseDir +") for submitter: " + context.getCurrentUser().getEmail()); / throw new IOException("Error processing resumableIdentifier: " + resumableIdentifier +
```
</details>

### 2022-31194::SubmissionController.java::DoGetResumable  <->  2022-31194::FileUploadRequest.java::FileUploadRequest

- muc: **khong trung** | Jaccard AST: 0.11 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.337 | fix_removed_sim 0.069
- API chung trong fix: IOException;dir;getCanonicalPath | API chung trong ma loi: exists;getProperty;new File
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,42 +1,101 @@
-protected void DoGetResumable(HttpServletRequest request, HttpServletResponse response) 
-        throws IOException
+public FileUploadRequest(HttpServletRequest req) throws IOException, FileSizeLimitExceededException
     {
-        if (ConfigurationManager.getProperty("upload.temp.dir") != null)
+        super(req);
+
+        original = req;
+
+        tempDir = (ConfigurationManager.getProperty("upload.temp.dir") != null)
+            ? ConfigurationManager.getProperty("upload.temp.dir") : System.getProperty("java.io.tmpdir"); 
+        long maxSize = ConfigurationManager.getLongProperty("upload.max");
+
+        // Create a factory for disk-based file items
+        DiskFileItemFactory factory = new DiskFileItemFactory();
+        factory.setRepository(new File(tempDir));
+
+        // Create a new file upload handler
+        ServletFileUpload upload = new ServletFileUpload(factory);
+
+        HttpSession session = req.getSession();
+        
+        if (ConfigurationManager.getBooleanProperty("webui.submit.upload.progressbar", true))
         {
-            tempDir = ConfigurationManager.getProperty("upload.temp.dir");
+            // set file upload progress listener
+            FileUploadListener listener = new FileUploadListener();
+    
+            session.setAttribute(FILE_UPLOAD_LISTNER, listener);
+    
+            // upload servlet allows to set upload listener
+            upload.setProgressListener(listener);
         }
-        else
+        
+        try
         {
-            tempDir = System.getProperty("java.io.tmpdir");
+            upload.setSizeMax(maxSize);
+            List<FileItem> items = upload.parseRequest(req);
+            for (FileItem item : items)
+            {
+                if (item.isFormField())
+                {
+                    parameters.put(item.getFieldName(), item.getString("UTF-8"));
+                }
+                else
+                {
+                    if (parameters.containsKey("resumableIdentifier")) 
+                    {
+                        String filename = getFilename(parameters.get("resumableFilename"));
+                        if (!StringUtils.isEmpty(filename)) 
+                        {
+                            String chunkDirPath = tempDir + File.separator + parameters.get("resumableIdentifier");
+                            String chunkPath = chunkDirPath + File.separator + "part" + parameters.get("resumableChunkNumber");
+                            File fileDir = new File(chunkDirPath);
+                            
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: protected void DoGetResumable(HttpServletRequest request, HttpServletResponse response) / tempDir = ConfigurationManager.getProperty("upload.temp.dir"); / tempDir = System.getProperty("java.io.tmpdir"); / tempDir = tempDir + File.separator + resumableIdentifier; / protected void DoGetResumable(HttpServletRequest request, HttpServletResponse response) / tempDir = ConfigurationManager.getProperty("upload.temp.dir");
A +: protected void DoGetResumable(Context context, HttpServletRequest request, HttpServletResponse response) / String baseDir; /  / baseDir = ConfigurationManager.getProperty("upload.temp.dir"); / baseDir = System.getProperty("java.io.tmpdir"); / tempDir = baseDir + File.separator + resumableIdentifier;
B -:  / item.write(new File(tempDir + File.separator / + filename)); /  / item.write(new File(tempDir + File.separator / + filename));
B +:  /  / // Test fileDir to see if canonical path is within the original tempDir / if(!fileDir.getCanonicalPath().startsWith(tempDir)) { / log.error("Error processing resumable upload chunk: temporary chunk file would be created outside " + / "permissible temp dir ("+ tempDir +") for file: " + filename);
```
</details>

### 2022-31194::SubmissionController.java::doPostResumable  <->  2022-31194::FileUploadRequest.java::FileUploadRequest

- muc: **khong trung** | Jaccard AST: 0.108 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.403 | fix_removed_sim 0.0
- API chung trong fix: IOException;dir;getCanonicalPath | API chung trong ma loi: exists;getProperty;new File
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,13 +1,29 @@
-protected File doPostResumable(HttpServletRequest request)
-            throws FileSizeLimitExceededException, IOException, ServletException 
+public FileUploadRequest(HttpServletRequest req) throws IOException, FileSizeLimitExceededException
     {
-        File completedFile = null;
-        FileUploadRequest wrapper = null;
+        super(req);
+
+        original = req;
+
+        tempDir = (ConfigurationManager.getProperty("upload.temp.dir") != null)
+            ? ConfigurationManager.getProperty("upload.temp.dir") : System.getProperty("java.io.tmpdir"); 
+        long maxSize = ConfigurationManager.getLongProperty("upload.max");
+
+        // Create a factory for disk-based file items
+        DiskFileItemFactory factory = new DiskFileItemFactory();
+        factory.setRepository(new File(tempDir));
+
+        // Create a new file upload handler
+        ServletFileUpload upload = new ServletFileUpload(factory);
+
+        HttpSession session = req.getSession();
         
-        if (ConfigurationManager.getProperty("upload.temp.dir") != null)
+        if (ConfigurationManager.getBooleanProperty("webui.submit.upload.progressbar", true))
         {
-            tempDir = ConfigurationManager.getProperty("upload.temp.dir");
-        }
-        else {
-            tempDir = System.getProperty("java.io.tmpdir");
+            // set file upload progress listener
+            FileUploadListener listener = new FileUploadListener();
+    
+            session.setAttribute(FILE_UPLOAD_LISTNER, listener);
+    
+            // upload servlet allows to set upload listener
+            upload.setProgressListener(listener);
         }
@@ -16,63 +32,70 @@
         {
-            // if we already have a FileUploadRequest, use it
-            if (Class.forName("org.dspace.app.webui.util.FileUploadRequest").isInstance(request))
+            upload.setSizeMax(maxSize);
+            List<FileItem> items = upload.parseRequest(req);
+            for (FileItem item : items)
             {
-                wrapper = (FileUploadRequest) request;
-            } 
-            else // if not wrap the mulitpart request to get the submission info
-            {
-                wrapper = new FileUploadRequest(request);
+                if (item.isFormField())
+                {
+                    parameters.put(item.getFieldName(), item.getString("UTF-8"));
+                }
+                else
+                {
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: 
A +:  / // Test chunkFile to see if canonical path is within the original baseDir / if(!chunkFile.getCanonicalPath().startsWith(baseDir)) { / log.error("Error processing resumable upload chunk: temporary chunk file would be created outside " + / "permissible temp dir ("+ baseDir +") for submitter: " + context.getCurrentUser().getEmail()); / throw new IOException("Error processing resumableIdentifier: " + resumableIdentifier +
B -:  / item.write(new File(tempDir + File.separator / + filename)); /  / item.write(new File(tempDir + File.separator / + filename));
B +:  /  / // Test fileDir to see if canonical path is within the original tempDir / if(!fileDir.getCanonicalPath().startsWith(tempDir)) { / log.error("Error processing resumable upload chunk: temporary chunk file would be created outside " + / "permissible temp dir ("+ tempDir +") for file: " + filename);
```
</details>

### 2022-31195::ItemImport.java::unzip  <->  2022-31194::SubmissionController.java::DoGetResumable

- muc: **khong trung** | Jaccard AST: 0.104 | pham vi: inter_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.099 | fix_removed_sim 0.057
- API chung trong fix: IOException;getCanonicalPath | API chung trong ma loi: exists;getProperty;mkdir;new File
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,105 +1,42 @@
-public static String unzip(File zipfile, String destDir) throws IOException {
-        // 2
-        // does the zip file exist and can we write to the temp directory
-        if (!zipfile.canRead())
+protected void DoGetResumable(HttpServletRequest request, HttpServletResponse response) 
+        throws IOException
+    {
+        if (ConfigurationManager.getProperty("upload.temp.dir") != null)
         {
-            log.error("Zip file '" + zipfile.getAbsolutePath() + "' does not exist, or is not readable.");
+            tempDir = ConfigurationManager.getProperty("upload.temp.dir");
+        }
+        else
+        {
+            tempDir = System.getProperty("java.io.tmpdir");
         }
 
-        String destinationDir = destDir;
-        if (destinationDir == null){
-        	destinationDir = tempWorkDir;
+        String resumableIdentifier = request.getParameter("resumableIdentifier");
+        String resumableChunkNumber = request.getParameter("resumableChunkNumber");
+        long resumableCurrentChunkSize = 
+                Long.valueOf(request.getParameter("resumableCurrentChunkSize"));
+
+        tempDir = tempDir + File.separator + resumableIdentifier;
+
+        File fileDir = new File(tempDir);
+
+        // create a new directory for each resumableIdentifier
+        if (!fileDir.exists()) {
+            fileDir.mkdir();
         }
+        // use the String "part" and the chunkNumber as filename of a chunk
+        String chunkPath = tempDir + File.separator + "part" + resumableChunkNumber;
 
-        File tempdir = new File(destinationDir);
-        if (!tempdir.isDirectory())
-        {
-            log.error("'" + ConfigurationManager.getProperty("org.dspace.app.itemexport.work.dir") +
-                    "' as defined by the key 'org.dspace.app.itemexport.work.dir' in dspace.cfg " +
-                    "is not a valid directory");
+        File chunkFile = new File(chunkPath);
+        // if the chunk was uploaded already, we send a status code of 200
+        if (chunkFile.exists()) {
+            if (chunkFile.length() == resumableCurrentChunkSize) {
+                response.setStatus(HttpServletResponse.SC_OK);
+                return;
+            }
+            // The chunk file does not have the expected size, delete it and 
+            // pretend that it wasn't uploaded already.
+            chunkFile.delete();
         }
-
-        if (!tempdir.exists() && !tempdir.mkdirs())
-        {
-            log.error("Unable to create temporary directory: " + tempdir.getAbsolutePath());
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: log.error("'" + ConfigurationManager.getProperty("org.dspace.app.itemexport.work.dir") + / "' as defined by the key 'org.dspace.app.itemexport.work.dir' in dspace.cfg " + / String sourcedir = destinationDir + System.getProperty("file.separator") + zipfile.getName(); / String zipDir = destinationDir + System.getProperty("file.separator") + zipfile.getName() + System.getProperty("file.separator"); / if (!new File(zipDir + entry.getName()).mkdir()) / {
A +: log.debug("Using directory " + destinationDir + " for zip extraction. (destDir arg is " + destDir + / ", tempWorkDir is " + tempWorkDir + ")"); / log.error("'" + ConfigurationManager.getProperty("org.dspace.app.batchitemimport.work.dir") + / "' as defined by the key 'org.dspace.app.batchitemimport.work.dir' in dspace.cfg " + / if(!destinationDir.endsWith(System.getProperty("file.separator"))) { / destinationDir += System.getProperty("file.separator");
B -: protected void DoGetResumable(HttpServletRequest request, HttpServletResponse response) / tempDir = ConfigurationManager.getProperty("upload.temp.dir"); / tempDir = System.getProperty("java.io.tmpdir"); / tempDir = tempDir + File.separator + resumableIdentifier; / protected void DoGetResumable(HttpServletRequest request, HttpServletResponse response) / tempDir = ConfigurationManager.getProperty("upload.temp.dir");
B +: protected void DoGetResumable(Context context, HttpServletRequest request, HttpServletResponse response) / String baseDir; /  / baseDir = ConfigurationManager.getProperty("upload.temp.dir"); / baseDir = System.getProperty("java.io.tmpdir"); / tempDir = baseDir + File.separator + resumableIdentifier;
```
</details>

### 2022-31195::ItemImportServiceImpl.java::unzip  <->  2022-31194::SubmissionController.java::DoGetResumable

- muc: **khong trung** | Jaccard AST: 0.1 | pham vi: inter_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.096 | fix_removed_sim 0.057
- API chung trong fix: IOException;getCanonicalPath | API chung trong ma loi: exists;getProperty;mkdir;new File
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,106 +1,42 @@
-@Override
-    public String unzip(File zipfile, String destDir) throws IOException {
-        // 2
-        // does the zip file exist and can we write to the temp directory
-        if (!zipfile.canRead())
+protected void DoGetResumable(HttpServletRequest request, HttpServletResponse response) 
+        throws IOException
+    {
+        if (ConfigurationManager.getProperty("upload.temp.dir") != null)
         {
-            log.error("Zip file '" + zipfile.getAbsolutePath() + "' does not exist, or is not readable.");
+            tempDir = ConfigurationManager.getProperty("upload.temp.dir");
+        }
+        else
+        {
+            tempDir = System.getProperty("java.io.tmpdir");
         }
 
-        String destinationDir = destDir;
-        if (destinationDir == null){
-        	destinationDir = tempWorkDir;
+        String resumableIdentifier = request.getParameter("resumableIdentifier");
+        String resumableChunkNumber = request.getParameter("resumableChunkNumber");
+        long resumableCurrentChunkSize = 
+                Long.valueOf(request.getParameter("resumableCurrentChunkSize"));
+
+        tempDir = tempDir + File.separator + resumableIdentifier;
+
+        File fileDir = new File(tempDir);
+
+        // create a new directory for each resumableIdentifier
+        if (!fileDir.exists()) {
+            fileDir.mkdir();
         }
+        // use the String "part" and the chunkNumber as filename of a chunk
+        String chunkPath = tempDir + File.separator + "part" + resumableChunkNumber;
 
-        File tempdir = new File(destinationDir);
-        if (!tempdir.isDirectory())
-        {
-            log.error("'" + ConfigurationManager.getProperty("org.dspace.app.itemexport.work.dir") +
-                    "' as defined by the key 'org.dspace.app.itemexport.work.dir' in dspace.cfg " +
-                    "is not a valid directory");
+        File chunkFile = new File(chunkPath);
+        // if the chunk was uploaded already, we send a status code of 200
+        if (chunkFile.exists()) {
+            if (chunkFile.length() == resumableCurrentChunkSize) {
+                response.setStatus(HttpServletResponse.SC_OK);
+                return;
+            }
+            // The chunk file does not have the expected size, delete it and 
+            // pretend that it wasn't uploaded already.
+            chunkFile.delete();
         }
-
-        if (!tempdir.exists() && !tempdir.mkdirs())
-        {
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: log.error("'" + ConfigurationManager.getProperty("org.dspace.app.itemexport.work.dir") + / "' as defined by the key 'org.dspace.app.itemexport.work.dir' in dspace.cfg " + / String sourcedir = destinationDir + System.getProperty("file.separator") + zipfile.getName(); / String zipDir = destinationDir + System.getProperty("file.separator") + zipfile.getName() + System.getProperty("file.separator"); / if (!new File(zipDir + entry.getName()).mkdir()) / {
A +: log.debug("Extracting zip at " + zipfile.getAbsolutePath()); / log.debug("Using directory " + destinationDir + " for zip extraction. (destDir arg is " + destDir + / ", tempWorkDir is " + tempWorkDir + ")"); / log.error("'" + ConfigurationManager.getProperty("org.dspace.app.batchitemexport.work.dir") + / "' as defined by the key 'org.dspace.app.batchitemexport.work.dir' in dspace.cfg " + / 
B -: protected void DoGetResumable(HttpServletRequest request, HttpServletResponse response) / tempDir = ConfigurationManager.getProperty("upload.temp.dir"); / tempDir = System.getProperty("java.io.tmpdir"); / tempDir = tempDir + File.separator + resumableIdentifier; / protected void DoGetResumable(HttpServletRequest request, HttpServletResponse response) / tempDir = ConfigurationManager.getProperty("upload.temp.dir");
B +: protected void DoGetResumable(Context context, HttpServletRequest request, HttpServletResponse response) / String baseDir; /  / baseDir = ConfigurationManager.getProperty("upload.temp.dir"); / baseDir = System.getProperty("java.io.tmpdir"); / tempDir = baseDir + File.separator + resumableIdentifier;
```
</details>

### 2022-31195::ItemImport.java::unzip  <->  2022-31194::SubmissionController.java::doPostResumable

- muc: **khong trung** | Jaccard AST: 0.076 | pham vi: inter_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.09 | fix_removed_sim 0.0
- API chung trong fix: IOException;getCanonicalPath | API chung trong ma loi: exists;getProperty;new File
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,92 +1,74 @@
-public static String unzip(File zipfile, String destDir) throws IOException {
-        // 2
-        // does the zip file exist and can we write to the temp directory
-        if (!zipfile.canRead())
+protected File doPostResumable(HttpServletRequest request)
+            throws FileSizeLimitExceededException, IOException, ServletException 
+    {
+        File completedFile = null;
+        FileUploadRequest wrapper = null;
+        
+        if (ConfigurationManager.getProperty("upload.temp.dir") != null)
         {
-            log.error("Zip file '" + zipfile.getAbsolutePath() + "' does not exist, or is not readable.");
+            tempDir = ConfigurationManager.getProperty("upload.temp.dir");
+        }
+        else {
+            tempDir = System.getProperty("java.io.tmpdir");
+        }
+        
+        try
+        {
+            // if we already have a FileUploadRequest, use it
+            if (Class.forName("org.dspace.app.webui.util.FileUploadRequest").isInstance(request))
+            {
+                wrapper = (FileUploadRequest) request;
+            } 
+            else // if not wrap the mulitpart request to get the submission info
+            {
+                wrapper = new FileUploadRequest(request);
+            }
+        }
+        catch (ClassNotFoundException ex)
+        {
+            // Cannot find a class that is part of the JSPUI?
+            log.fatal("Cannot find class org.dspace.app.webui.util.FileUploadRequest");
+            throw new ServletException("Cannot find class org.dspace.app.webui.util.FileUploadRequest.", ex);
         }
 
-        String destinationDir = destDir;
-        if (destinationDir == null){
-        	destinationDir = tempWorkDir;
+        String resumableIdentifier = wrapper.getParameter("resumableIdentifier");
+        long resumableTotalSize = Long.valueOf(wrapper.getParameter("resumableTotalSize"));
+        int resumableTotalChunks = Integer.valueOf(wrapper.getParameter("resumableTotalChunks"));
+
+        String chunkDirPath = tempDir + File.separator + resumableIdentifier;
+        File chunkDirPathFile = new File(chunkDirPath);
+        boolean foundAll = true;
+        long currentSize = 0l;
+        
+        // check whether all chunks were received.
+        if(chunkDirPathFile.exists())
+        {
+            for (int p = 1; p <= resumableTotalChunks; p++) 
+            {
+                File file = new File(chunkDirPath + File.separator + "part" + Integer.toString(p));
+
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: log.error("'" + ConfigurationManager.getProperty("org.dspace.app.itemexport.work.dir") + / "' as defined by the key 'org.dspace.app.itemexport.work.dir' in dspace.cfg " + / String sourcedir = destinationDir + System.getProperty("file.separator") + zipfile.getName(); / String zipDir = destinationDir + System.getProperty("file.separator") + zipfile.getName() + System.getProperty("file.separator"); / if (!new File(zipDir + entry.getName()).mkdir()) / {
A +: log.debug("Using directory " + destinationDir + " for zip extraction. (destDir arg is " + destDir + / ", tempWorkDir is " + tempWorkDir + ")"); / log.error("'" + ConfigurationManager.getProperty("org.dspace.app.batchitemimport.work.dir") + / "' as defined by the key 'org.dspace.app.batchitemimport.work.dir' in dspace.cfg " + / if(!destinationDir.endsWith(System.getProperty("file.separator"))) { / destinationDir += System.getProperty("file.separator");
B -: 
B +:  / // Test chunkFile to see if canonical path is within the original baseDir / if(!chunkFile.getCanonicalPath().startsWith(baseDir)) { / log.error("Error processing resumable upload chunk: temporary chunk file would be created outside " + / "permissible temp dir ("+ baseDir +") for submitter: " + context.getCurrentUser().getEmail()); / throw new IOException("Error processing resumableIdentifier: " + resumableIdentifier +
```
</details>

### 2022-31195::ItemImport.java::unzip  <->  2022-31194::FileUploadRequest.java::FileUploadRequest

- muc: **khong trung** | Jaccard AST: 0.076 | pham vi: inter_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.094 | fix_removed_sim 0.01
- API chung trong fix: IOException;getCanonicalPath | API chung trong ma loi: exists;getProperty;new File;write
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,105 +1,101 @@
-public static String unzip(File zipfile, String destDir) throws IOException {
-        // 2
-        // does the zip file exist and can we write to the temp directory
-        if (!zipfile.canRead())
+public FileUploadRequest(HttpServletRequest req) throws IOException, FileSizeLimitExceededException
+    {
+        super(req);
+
+        original = req;
+
+        tempDir = (ConfigurationManager.getProperty("upload.temp.dir") != null)
+            ? ConfigurationManager.getProperty("upload.temp.dir") : System.getProperty("java.io.tmpdir"); 
+        long maxSize = ConfigurationManager.getLongProperty("upload.max");
+
+        // Create a factory for disk-based file items
+        DiskFileItemFactory factory = new DiskFileItemFactory();
+        factory.setRepository(new File(tempDir));
+
+        // Create a new file upload handler
+        ServletFileUpload upload = new ServletFileUpload(factory);
+
+        HttpSession session = req.getSession();
+        
+        if (ConfigurationManager.getBooleanProperty("webui.submit.upload.progressbar", true))
         {
-            log.error("Zip file '" + zipfile.getAbsolutePath() + "' does not exist, or is not readable.");
+            // set file upload progress listener
+            FileUploadListener listener = new FileUploadListener();
+    
+            session.setAttribute(FILE_UPLOAD_LISTNER, listener);
+    
+            // upload servlet allows to set upload listener
+            upload.setProgressListener(listener);
         }
+        
+        try
+        {
+            upload.setSizeMax(maxSize);
+            List<FileItem> items = upload.parseRequest(req);
+            for (FileItem item : items)
+            {
+                if (item.isFormField())
+                {
+                    parameters.put(item.getFieldName(), item.getString("UTF-8"));
+                }
+                else
+                {
+                    if (parameters.containsKey("resumableIdentifier")) 
+                    {
+                        String filename = getFilename(parameters.get("resumableFilename"));
+                        if (!StringUtils.isEmpty(filename)) 
+                        {
+                            String chunkDirPath = tempDir + File.separator + parameters.get("resumableIdentifier");
+                            String chunkPath = chunkDirPath + File.separator + "part" + parameters.get("resumableChunkNumber");
+                            File fileDir = new File(chunkDirPath);
+                            
+                            if(fileDir.exists())
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: log.error("'" + ConfigurationManager.getProperty("org.dspace.app.itemexport.work.dir") + / "' as defined by the key 'org.dspace.app.itemexport.work.dir' in dspace.cfg " + / String sourcedir = destinationDir + System.getProperty("file.separator") + zipfile.getName(); / String zipDir = destinationDir + System.getProperty("file.separator") + zipfile.getName() + System.getProperty("file.separator"); / if (!new File(zipDir + entry.getName()).mkdir()) / {
A +: log.debug("Using directory " + destinationDir + " for zip extraction. (destDir arg is " + destDir + / ", tempWorkDir is " + tempWorkDir + ")"); / log.error("'" + ConfigurationManager.getProperty("org.dspace.app.batchitemimport.work.dir") + / "' as defined by the key 'org.dspace.app.batchitemimport.work.dir' in dspace.cfg " + / if(!destinationDir.endsWith(System.getProperty("file.separator"))) { / destinationDir += System.getProperty("file.separator");
B -:  / item.write(new File(tempDir + File.separator / + filename)); /  / item.write(new File(tempDir + File.separator / + filename));
B +:  /  / // Test fileDir to see if canonical path is within the original tempDir / if(!fileDir.getCanonicalPath().startsWith(tempDir)) { / log.error("Error processing resumable upload chunk: temporary chunk file would be created outside " + / "permissible temp dir ("+ tempDir +") for file: " + filename);
```
</details>

### 2022-31195::ItemImportServiceImpl.java::unzip  <->  2022-31194::FileUploadRequest.java::FileUploadRequest

- muc: **khong trung** | Jaccard AST: 0.076 | pham vi: inter_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.09 | fix_removed_sim 0.01
- API chung trong fix: IOException;getCanonicalPath | API chung trong ma loi: exists;getProperty;new File;write
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,106 +1,101 @@
-@Override
-    public String unzip(File zipfile, String destDir) throws IOException {
-        // 2
-        // does the zip file exist and can we write to the temp directory
-        if (!zipfile.canRead())
+public FileUploadRequest(HttpServletRequest req) throws IOException, FileSizeLimitExceededException
+    {
+        super(req);
+
+        original = req;
+
+        tempDir = (ConfigurationManager.getProperty("upload.temp.dir") != null)
+            ? ConfigurationManager.getProperty("upload.temp.dir") : System.getProperty("java.io.tmpdir"); 
+        long maxSize = ConfigurationManager.getLongProperty("upload.max");
+
+        // Create a factory for disk-based file items
+        DiskFileItemFactory factory = new DiskFileItemFactory();
+        factory.setRepository(new File(tempDir));
+
+        // Create a new file upload handler
+        ServletFileUpload upload = new ServletFileUpload(factory);
+
+        HttpSession session = req.getSession();
+        
+        if (ConfigurationManager.getBooleanProperty("webui.submit.upload.progressbar", true))
         {
-            log.error("Zip file '" + zipfile.getAbsolutePath() + "' does not exist, or is not readable.");
+            // set file upload progress listener
+            FileUploadListener listener = new FileUploadListener();
+    
+            session.setAttribute(FILE_UPLOAD_LISTNER, listener);
+    
+            // upload servlet allows to set upload listener
+            upload.setProgressListener(listener);
         }
+        
+        try
+        {
+            upload.setSizeMax(maxSize);
+            List<FileItem> items = upload.parseRequest(req);
+            for (FileItem item : items)
+            {
+                if (item.isFormField())
+                {
+                    parameters.put(item.getFieldName(), item.getString("UTF-8"));
+                }
+                else
+                {
+                    if (parameters.containsKey("resumableIdentifier")) 
+                    {
+                        String filename = getFilename(parameters.get("resumableFilename"));
+                        if (!StringUtils.isEmpty(filename)) 
+                        {
+                            String chunkDirPath = tempDir + File.separator + parameters.get("resumableIdentifier");
+                            String chunkPath = chunkDirPath + File.separator + "part" + parameters.get("resumableChunkNumber");
+                            File fileDir = new File(chunkDirPath);
+                            
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: log.error("'" + ConfigurationManager.getProperty("org.dspace.app.itemexport.work.dir") + / "' as defined by the key 'org.dspace.app.itemexport.work.dir' in dspace.cfg " + / String sourcedir = destinationDir + System.getProperty("file.separator") + zipfile.getName(); / String zipDir = destinationDir + System.getProperty("file.separator") + zipfile.getName() + System.getProperty("file.separator"); / if (!new File(zipDir + entry.getName()).mkdir()) / {
A +: log.debug("Extracting zip at " + zipfile.getAbsolutePath()); / log.debug("Using directory " + destinationDir + " for zip extraction. (destDir arg is " + destDir + / ", tempWorkDir is " + tempWorkDir + ")"); / log.error("'" + ConfigurationManager.getProperty("org.dspace.app.batchitemexport.work.dir") + / "' as defined by the key 'org.dspace.app.batchitemexport.work.dir' in dspace.cfg " + / 
B -:  / item.write(new File(tempDir + File.separator / + filename)); /  / item.write(new File(tempDir + File.separator / + filename));
B +:  /  / // Test fileDir to see if canonical path is within the original tempDir / if(!fileDir.getCanonicalPath().startsWith(tempDir)) { / log.error("Error processing resumable upload chunk: temporary chunk file would be created outside " + / "permissible temp dir ("+ tempDir +") for file: " + filename);
```
</details>

### 2022-31195::ItemImportServiceImpl.java::unzip  <->  2022-31194::SubmissionController.java::doPostResumable

- muc: **khong trung** | Jaccard AST: 0.073 | pham vi: inter_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.086 | fix_removed_sim 0.0
- API chung trong fix: IOException;getCanonicalPath | API chung trong ma loi: exists;getProperty;new File
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,93 +1,74 @@
-@Override
-    public String unzip(File zipfile, String destDir) throws IOException {
-        // 2
-        // does the zip file exist and can we write to the temp directory
-        if (!zipfile.canRead())
+protected File doPostResumable(HttpServletRequest request)
+            throws FileSizeLimitExceededException, IOException, ServletException 
+    {
+        File completedFile = null;
+        FileUploadRequest wrapper = null;
+        
+        if (ConfigurationManager.getProperty("upload.temp.dir") != null)
         {
-            log.error("Zip file '" + zipfile.getAbsolutePath() + "' does not exist, or is not readable.");
+            tempDir = ConfigurationManager.getProperty("upload.temp.dir");
+        }
+        else {
+            tempDir = System.getProperty("java.io.tmpdir");
+        }
+        
+        try
+        {
+            // if we already have a FileUploadRequest, use it
+            if (Class.forName("org.dspace.app.webui.util.FileUploadRequest").isInstance(request))
+            {
+                wrapper = (FileUploadRequest) request;
+            } 
+            else // if not wrap the mulitpart request to get the submission info
+            {
+                wrapper = new FileUploadRequest(request);
+            }
+        }
+        catch (ClassNotFoundException ex)
+        {
+            // Cannot find a class that is part of the JSPUI?
+            log.fatal("Cannot find class org.dspace.app.webui.util.FileUploadRequest");
+            throw new ServletException("Cannot find class org.dspace.app.webui.util.FileUploadRequest.", ex);
         }
 
-        String destinationDir = destDir;
-        if (destinationDir == null){
-        	destinationDir = tempWorkDir;
+        String resumableIdentifier = wrapper.getParameter("resumableIdentifier");
+        long resumableTotalSize = Long.valueOf(wrapper.getParameter("resumableTotalSize"));
+        int resumableTotalChunks = Integer.valueOf(wrapper.getParameter("resumableTotalChunks"));
+
+        String chunkDirPath = tempDir + File.separator + resumableIdentifier;
+        File chunkDirPathFile = new File(chunkDirPath);
+        boolean foundAll = true;
+        long currentSize = 0l;
+        
+        // check whether all chunks were received.
+        if(chunkDirPathFile.exists())
+        {
+            for (int p = 1; p <= resumableTotalChunks; p++) 
+            {
+                File file = new File(chunkDirPath + File.separator + "part" + Integer.toString(p));
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: log.error("'" + ConfigurationManager.getProperty("org.dspace.app.itemexport.work.dir") + / "' as defined by the key 'org.dspace.app.itemexport.work.dir' in dspace.cfg " + / String sourcedir = destinationDir + System.getProperty("file.separator") + zipfile.getName(); / String zipDir = destinationDir + System.getProperty("file.separator") + zipfile.getName() + System.getProperty("file.separator"); / if (!new File(zipDir + entry.getName()).mkdir()) / {
A +: log.debug("Extracting zip at " + zipfile.getAbsolutePath()); / log.debug("Using directory " + destinationDir + " for zip extraction. (destDir arg is " + destDir + / ", tempWorkDir is " + tempWorkDir + ")"); / log.error("'" + ConfigurationManager.getProperty("org.dspace.app.batchitemexport.work.dir") + / "' as defined by the key 'org.dspace.app.batchitemexport.work.dir' in dspace.cfg " + / 
B -: 
B +:  / // Test chunkFile to see if canonical path is within the original baseDir / if(!chunkFile.getCanonicalPath().startsWith(baseDir)) { / log.error("Error processing resumable upload chunk: temporary chunk file would be created outside " + / "permissible temp dir ("+ baseDir +") for submitter: " + context.getCurrentUser().getEmail()); / throw new IOException("Error processing resumableIdentifier: " + resumableIdentifier +
```
</details>
