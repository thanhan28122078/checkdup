# Kiem tra trung lap: apache/dolphinscheduler

- CVE: 4 | unit (method bi fix, ban con loi): 10 | khong tim duoc: 5
- Cap so sanh (cung CWE): 21

## 1. Tom tat theo muc

| Muc | So cap | Cum co >=2 unit | Unit nam trong cum trung |
|---|---|---|---|
| L1_strict (tich luy) | 0 | 0 | 0/10 |
| L1_loose (tich luy) | 0 | 0 | 0/10 |
| L2_AST (tich luy) | 0 | 0 | 0/10 |
| L2_Near95 (tich luy) | 0 | 0 | 0/10 |
| L2_Near90 (tich luy) | 0 | 0 | 0/10 |

Luu y: moi muc la tich luy (L2_AST bao gom ca L1). Tach intra_cve/inter_cve: 0 cap co trung o it nhat 1 muc, trong do 0 cap cung CVE, 0 cap khac CVE.

## 2. CVE va mo ta advisory (de doi chieu root cause)

- **CVE-2022-26884** (CWE-022, tag 2.0.5): Apache DolphinScheduler vulnerable to Path Traversal | Users can read any files by log server, Apache DolphinScheduler users should upgrade to version 2.0.6 or higher.
- **CVE-2022-34662** (CWE-022, tag 2.0.9): Apache DolphinScheduler vulnerable to Path Traversal | When users add resources to the resource center with a relation path, this vulnerability will cause path traversal issues for logged-in users. Users should upgrade to version 3.0.0 to avoid this issue.
- **CVE-2023-51770** (CWE-094, tag 3.2.0): Arbitrary File Read Vulnerability in Apache Dolphinscheduler | Arbitrary File Read Vulnerability in Apache Dolphinscheduler.  This issue affects Apache DolphinScheduler: before 3.2.1.   We recommend users to upgrade Apache DolphinScheduler to version 3.2.1, which fixes the issue.
- **CVE-2023-49109** (CWE-094, tag 3.2.0): Remote Code Execution in Apache Dolphinscheduler | This issue affects Apache DolphinScheduler 3.0.0 before 3.2.1. We recommend users to upgrade Apache DolphinScheduler to version 3.2.1, which fixes the issue. 

## 3. Ma tran CVE x CVE (muc trung cao nhat giua cac method cua 2 CVE)

| |2022-26884|2022-34662|2023-51770|2023-49109|
|---|---|---|---|---|
|2022-26884|-||||
|2022-34662||-|||
|2023-51770|||-||
|2023-49109||||-|

## 3b. Nhom root cause goi y (gom theo cung vi tri / cung mau fix / cung API fix)

Day la goi y tu dong, KHONG phai ket luan. Nhom co nhieu CVE khac nhau la cho dang quan tam nhat.

- **C3**: 4 method, 1 CVE (2023-49109) | API fix chung: `-`
    - 2023-49109::K8sNamespaceController.java::createNamespace
    - 2023-49109::K8sClientService.java::deleteNamespaceToK8s
    - 2023-49109::K8SNamespaceServiceImpl.java::queryListPaging
    - 2023-49109::K8SNamespaceServiceImpl.java::updateK8sNamespace
- **C2**: 3 method, 1 CVE (2022-34662) | API fix chung: `directoryTraversal, putMsg`
    - 2022-34662::ResourcesServiceImpl.java::createDirectory
    - 2022-34662::ResourcesServiceImpl.java::onlineCreateResource
    - 2022-34662::ResourcesServiceImpl.java::verifyFile

## 4. Cac cap can duyet tay (uu tien: co muc trung hoac co goi y root cause)

### 2022-34662::ResourcesServiceImpl.java::createDirectory  <->  2022-34662::ResourcesServiceImpl.java::onlineCreateResource

- muc: **khong trung** | Jaccard AST: 0.547 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 0.583 | fix_removed_sim 0.0
- API chung trong fix: directoryTraversal;putMsg | API chung trong ma loi: checkResourceUploadStartupState;directoryTraversal;entrySet;equalsIgnoreCase;getCode;getId;getKey;getValue;insert;new BeanMap
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -2,8 +2,3 @@
     @Transactional(rollbackFor = Exception.class)
-    public Result<Object> createDirectory(User loginUser,
-                                          String name,
-                                          String description,
-                                          ResourceType type,
-                                          int pid,
-                                          String currentDir) {
+    public Result<Object> onlineCreateResource(User loginUser, ResourceType type, String fileName, String fileSuffix, String desc, String content,int pid,String currentDir) {
         Result<Object> result = checkResourceUploadStartupState();
@@ -12,3 +7,3 @@
         }
-        if (FileUtils.directoryTraversal(name)) {
+        if (FileUtils.directoryTraversal(fileName)) {
             putMsg(result, Status.VERIFY_PARAMETER_NAME_FAILED);
@@ -16,2 +11,16 @@
         }
+
+        //check file suffix
+        String nameSuffix = fileSuffix.trim();
+        String resourceViewSuffixs = FileUtils.getResourceViewSuffixs();
+        if (StringUtils.isNotEmpty(resourceViewSuffixs)) {
+            List<String> strList = Arrays.asList(resourceViewSuffixs.split(","));
+            if (!strList.contains(nameSuffix)) {
+                logger.error("resource suffix {} not support create", nameSuffix);
+                putMsg(result, Status.RESOURCE_SUFFIX_NOT_SUPPORT_VIEW);
+                return result;
+            }
+        }
+
+        String name = fileName.trim() + "." + nameSuffix;
         String fullName = currentDir.equals("/") ? String.format("%s%s",currentDir,name) : String.format("%s/%s",currentDir,name);
@@ -22,33 +31,25 @@
 
-        if (checkResourceExists(fullName, 0, type.ordinal())) {
-            logger.error("resource directory {} has exist, can't recreate", fullName);
-            putMsg(result, Status.RESOURCE_EXIST);
-            return result;
+        // save data
+        Date now = new Date();
+        Resource resource = new Resource(pid,name,fullName,false,desc,name,loginUser.getId(),type,content.getBytes().length,now,now);
+
+        resourcesMapper.insert(resource);
+        updateParentResourceSize(resource, resource.getSize());
+
+        putMsg(result, Status.SUCCESS);
+        Map<Object, Object> dataMap = new BeanMap(resource);
+        Map<String, Object> resultMap = new HashMap<>();
+        for (Map.Entry<Object, Object> entry: dataMap.entrySet()) {
+            if (!Constants.CLASS.equalsIgnoreCase(entry.getKey().toString())) {
+                resultMap.put(entry.getKey().toString(), entry.getValue());
+            }
         }
+        result.setData(resultMap);
 
-        Date now = new Date();
+        String tenantCode = tenantMapper.queryById(loginUser.getTenantId()).getTenantCode();
 
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: if (name.endsWith(FOLDER_SEPARATOR)) { / result.setCode(Status.VERIFY_PARAMETER_NAME_FAILED.getCode());
A +: if (FileUtils.directoryTraversal(name)) { / putMsg(result, Status.VERIFY_PARAMETER_NAME_FAILED);
B -: 
B +: if (FileUtils.directoryTraversal(fileName)) { / putMsg(result, Status.VERIFY_PARAMETER_NAME_FAILED); / return result; / }
```
</details>

### 2022-34662::ResourcesServiceImpl.java::createDirectory  <->  2022-34662::ResourcesServiceImpl.java::verifyFile

- muc: **khong trung** | Jaccard AST: 0.128 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.224 | fix_removed_sim 0.0
- API chung trong fix: directoryTraversal;putMsg | API chung trong ma loi: directoryTraversal;equalsIgnoreCase;putMsg
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,14 +1,7 @@
-@Override
-    @Transactional(rollbackFor = Exception.class)
-    public Result<Object> createDirectory(User loginUser,
-                                          String name,
-                                          String description,
-                                          ResourceType type,
-                                          int pid,
-                                          String currentDir) {
-        Result<Object> result = checkResourceUploadStartupState();
-        if (!result.getCode().equals(Status.SUCCESS.getCode())) {
-            return result;
-        }
+private Result<Object> verifyFile(String name, ResourceType type, MultipartFile file) {
+        Result<Object> result = new Result<>();
+        putMsg(result, Status.SUCCESS);
+
         if (FileUtils.directoryTraversal(name)) {
+            logger.error("file alias name {} verify failed", name);
             putMsg(result, Status.VERIFY_PARAMETER_NAME_FAILED);
@@ -16,5 +9,6 @@
         }
-        String fullName = currentDir.equals("/") ? String.format("%s%s",currentDir,name) : String.format("%s/%s",currentDir,name);
-        result = verifyResource(loginUser, type, fullName, pid);
-        if (!result.getCode().equals(Status.SUCCESS.getCode())) {
+
+        if (file != null && FileUtils.directoryTraversal(Objects.requireNonNull(file.getOriginalFilename()))) {
+            logger.error("file original name {} verify failed", file.getOriginalFilename());
+            putMsg(result, Status.VERIFY_PARAMETER_NAME_FAILED);
             return result;
@@ -22,33 +16,34 @@
 
-        if (checkResourceExists(fullName, 0, type.ordinal())) {
-            logger.error("resource directory {} has exist, can't recreate", fullName);
-            putMsg(result, Status.RESOURCE_EXIST);
-            return result;
+        if (file != null) {
+            // file is empty
+            if (file.isEmpty()) {
+                logger.error("file is empty: {}", RegexUtils.escapeNRT(file.getOriginalFilename()));
+                putMsg(result, Status.RESOURCE_FILE_IS_EMPTY);
+                return result;
+            }
+
+            // file suffix
+            String fileSuffix = Files.getFileExtension(file.getOriginalFilename());
+            String nameSuffix = Files.getFileExtension(name);
+
+            // determine file suffix
+            if (!(StringUtils.isNotEmpty(fileSuffix) && fileSuffix.equalsIgnoreCase(nameSuffix))) {
+                // rename file suffix and original suffix must be consistent
+                logger.error("rename file suffix and original suffix must be consistent: {}", RegexUtils.escapeNRT(file.getOriginalFilename()));
+                putMsg(result, Status.RESOURCE_SUFFIX_FORBID_CHANGE);
+                return result;
+            }
+
+            //If resource type is UDF, only jar packages are allowed to be uploaded, and the suffix must be .jar
+            if (Constants.UDF.equals(type.name()) && !JAR.equalsIgnoreCase(fileSuffix)) {
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: if (name.endsWith(FOLDER_SEPARATOR)) { / result.setCode(Status.VERIFY_PARAMETER_NAME_FAILED.getCode());
A +: if (FileUtils.directoryTraversal(name)) { / putMsg(result, Status.VERIFY_PARAMETER_NAME_FAILED);
B -: 
B +:  / if (FileUtils.directoryTraversal(name)) { / logger.error("file alias name {} verify failed", name); / putMsg(result, Status.VERIFY_PARAMETER_NAME_FAILED); / return result; / }
```
</details>

### 2022-34662::ResourcesServiceImpl.java::onlineCreateResource  <->  2022-34662::ResourcesServiceImpl.java::verifyFile

- muc: **khong trung** | Jaccard AST: 0.113 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.229 | fix_removed_sim 1.0
- API chung trong fix: directoryTraversal;putMsg | API chung trong ma loi: directoryTraversal;equalsIgnoreCase;getMsg;getSize;isNotEmpty;putMsg
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,9 +1,7 @@
-@Override
-    @Transactional(rollbackFor = Exception.class)
-    public Result<Object> onlineCreateResource(User loginUser, ResourceType type, String fileName, String fileSuffix, String desc, String content,int pid,String currentDir) {
-        Result<Object> result = checkResourceUploadStartupState();
-        if (!result.getCode().equals(Status.SUCCESS.getCode())) {
-            return result;
-        }
-        if (FileUtils.directoryTraversal(fileName)) {
+private Result<Object> verifyFile(String name, ResourceType type, MultipartFile file) {
+        Result<Object> result = new Result<>();
+        putMsg(result, Status.SUCCESS);
+
+        if (FileUtils.directoryTraversal(name)) {
+            logger.error("file alias name {} verify failed", name);
             putMsg(result, Status.VERIFY_PARAMETER_NAME_FAILED);
@@ -12,10 +10,37 @@
 
-        //check file suffix
-        String nameSuffix = fileSuffix.trim();
-        String resourceViewSuffixs = FileUtils.getResourceViewSuffixs();
-        if (StringUtils.isNotEmpty(resourceViewSuffixs)) {
-            List<String> strList = Arrays.asList(resourceViewSuffixs.split(","));
-            if (!strList.contains(nameSuffix)) {
-                logger.error("resource suffix {} not support create", nameSuffix);
-                putMsg(result, Status.RESOURCE_SUFFIX_NOT_SUPPORT_VIEW);
+        if (file != null && FileUtils.directoryTraversal(Objects.requireNonNull(file.getOriginalFilename()))) {
+            logger.error("file original name {} verify failed", file.getOriginalFilename());
+            putMsg(result, Status.VERIFY_PARAMETER_NAME_FAILED);
+            return result;
+        }
+
+        if (file != null) {
+            // file is empty
+            if (file.isEmpty()) {
+                logger.error("file is empty: {}", RegexUtils.escapeNRT(file.getOriginalFilename()));
+                putMsg(result, Status.RESOURCE_FILE_IS_EMPTY);
+                return result;
+            }
+
+            // file suffix
+            String fileSuffix = Files.getFileExtension(file.getOriginalFilename());
+            String nameSuffix = Files.getFileExtension(name);
+
+            // determine file suffix
+            if (!(StringUtils.isNotEmpty(fileSuffix) && fileSuffix.equalsIgnoreCase(nameSuffix))) {
+                // rename file suffix and original suffix must be consistent
+                logger.error("rename file suffix and original suffix must be consistent: {}", RegexUtils.escapeNRT(file.getOriginalFilename()));
+                putMsg(result, Status.RESOURCE_SUFFIX_FORBID_CHANGE);
+                return result;
+            }
+
+            //If resource type is UDF, only jar packages are allowed to be uploaded, and the suffix must be .jar
+            if (Constants.UDF.equals(type.name()) && !JAR.equalsIgnoreCase(fileSuffix)) {
+                logger.error(Status.UDF_RESOURCE_SUFFIX_NOT_JAR.getMsg());
+                putMsg(result, Status.UDF_RESOURCE_SUFFIX_NOT_JAR);
+                return result;
+            }
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: 
A +: if (FileUtils.directoryTraversal(fileName)) { / putMsg(result, Status.VERIFY_PARAMETER_NAME_FAILED); / return result; / }
B -: 
B +:  / if (FileUtils.directoryTraversal(name)) { / logger.error("file alias name {} verify failed", name); / putMsg(result, Status.VERIFY_PARAMETER_NAME_FAILED); / return result; / }
```
</details>

### 2023-49109::K8SNamespaceServiceImpl.java::queryListPaging  <->  2023-49109::K8SNamespaceServiceImpl.java::updateK8sNamespace

- muc: **khong trung** | Jaccard AST: 0.105 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 1.0 | fix_removed_sim 0.0
- API chung trong fix: - | API chung trong ma loi: getUserName;putMsg
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,7 +1,7 @@
 @Override
-    public Result queryListPaging(User loginUser, String searchVal, Integer pageNo, Integer pageSize) {
-        Result result = new Result();
-        if (!isAdmin(loginUser)) {
-            log.warn("Only admin can query namespace list, current login user name:{}.", loginUser.getUserName());
-            putMsg(result, Status.USER_NO_OPERATION_PERM);
+    public Map<String, Object> updateK8sNamespace(User loginUser, int id, String userName, Double limitsCpu,
+                                                  Integer limitsMemory) {
+        Map<String, Object> result = new HashMap<>();
+        if (isNotAdmin(loginUser, result)) {
+            log.warn("Only admin can update K8s namespace, current login user name:{}.", loginUser.getUserName());
             return result;
@@ -9,13 +9,40 @@
 
-        Page<K8sNamespace> page = new Page<>(pageNo, pageSize);
+        if (limitsCpu != null && limitsCpu < 0.0) {
+            log.warn("Parameter limitsCpu is invalid.");
+            putMsg(result, Status.REQUEST_PARAMS_NOT_VALID_ERROR, Constants.LIMITS_CPU);
+            return result;
+        }
 
-        IPage<K8sNamespace> k8sNamespaceList = k8sNamespaceMapper.queryK8sNamespacePaging(page, searchVal);
+        if (limitsMemory != null && limitsMemory < 0) {
+            log.warn("Parameter limitsMemory is invalid.");
+            putMsg(result, Status.REQUEST_PARAMS_NOT_VALID_ERROR, Constants.LIMITS_MEMORY);
+            return result;
+        }
 
-        Integer count = (int) k8sNamespaceList.getTotal();
-        PageInfo<K8sNamespace> pageInfo = new PageInfo<>(pageNo, pageSize);
-        pageInfo.setTotal(count);
-        pageInfo.setTotalList(k8sNamespaceList.getRecords());
-        result.setData(pageInfo);
+        K8sNamespace k8sNamespaceObj = k8sNamespaceMapper.selectById(id);
+        if (k8sNamespaceObj == null) {
+            log.error("K8s namespace does not exist, namespaceId:{}.", id);
+            putMsg(result, Status.K8S_NAMESPACE_NOT_EXIST, id);
+            return result;
+        }
+
+        Date now = new Date();
+        k8sNamespaceObj.setLimitsCpu(limitsCpu);
+        k8sNamespaceObj.setLimitsMemory(limitsMemory);
+        k8sNamespaceObj.setUpdateTime(now);
+
+        if (!Constants.K8S_LOCAL_TEST_CLUSTER_CODE.equals(k8sNamespaceObj.getClusterCode())) {
+            try {
+                String yamlStr = genDefaultResourceYaml(k8sNamespaceObj);
+                k8sClientService.upsertNamespaceAndResourceToK8s(k8sNamespaceObj, yamlStr);
+            } catch (Exception e) {
+                log.error("Namespace update to k8s error", e);
+                putMsg(result, Status.K8S_CLIENT_OPS_ERROR, e.getMessage());
+                return result;
+            }
+        }
+        // update to db
+        k8sNamespaceMapper.updateById(k8sNamespaceObj);
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: * @param limitsCpu    limits cpu, can null means not limit / * @param limitsMemory limits memory, can null means not limit
A +: 
B -: /** / * use cpu memory create yaml / * / * @param k8sNamespace / * @return yaml file / */
B +: 
```
</details>

### 2023-49109::K8sNamespaceController.java::createNamespace  <->  2023-49109::K8SNamespaceServiceImpl.java::updateK8sNamespace

- muc: **khong trung** | Jaccard AST: 0.038 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 1.0 | fix_removed_sim 0.0
- API chung trong fix: - | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,20 +1,49 @@
-@Operation(summary = "createK8sNamespace", description = "CREATE_NAMESPACE_NOTES")
-    @Parameters({
-            @Parameter(name = "namespace", description = "NAMESPACE", required = true, schema = @Schema(implementation = String.class)),
-            @Parameter(name = "clusterCode", description = "CLUSTER_CODE", required = true, schema = @Schema(implementation = long.class)),
-            @Parameter(name = "limits_cpu", description = "LIMITS_CPU", required = false, schema = @Schema(implementation = double.class)),
-            @Parameter(name = "limits_memory", description = "LIMITS_MEMORY", required = false, schema = @Schema(implementation = int.class))
-    })
-    @PostMapping()
-    @ResponseStatus(HttpStatus.CREATED)
-    @ApiException(CREATE_K8S_NAMESPACE_ERROR)
-    @AccessLogAnnotation(ignoreRequestArgs = "loginUser")
-    public Result createNamespace(@Parameter(hidden = true) @RequestAttribute(value = Constants.SESSION_USER) User loginUser,
-                                  @RequestParam(value = "namespace") String namespace,
-                                  @RequestParam(value = "clusterCode") Long clusterCode,
-                                  @RequestParam(value = "limitsCpu", required = false) Double limitsCpu,
-                                  @RequestParam(value = "limitsMemory", required = false) Integer limitsMemory) {
-        Map<String, Object> result =
-                k8sNamespaceService.createK8sNamespace(loginUser, namespace, clusterCode, limitsCpu, limitsMemory);
-        return returnDataList(result);
+@Override
+    public Map<String, Object> updateK8sNamespace(User loginUser, int id, String userName, Double limitsCpu,
+                                                  Integer limitsMemory) {
+        Map<String, Object> result = new HashMap<>();
+        if (isNotAdmin(loginUser, result)) {
+            log.warn("Only admin can update K8s namespace, current login user name:{}.", loginUser.getUserName());
+            return result;
+        }
+
+        if (limitsCpu != null && limitsCpu < 0.0) {
+            log.warn("Parameter limitsCpu is invalid.");
+            putMsg(result, Status.REQUEST_PARAMS_NOT_VALID_ERROR, Constants.LIMITS_CPU);
+            return result;
+        }
+
+        if (limitsMemory != null && limitsMemory < 0) {
+            log.warn("Parameter limitsMemory is invalid.");
+            putMsg(result, Status.REQUEST_PARAMS_NOT_VALID_ERROR, Constants.LIMITS_MEMORY);
+            return result;
+        }
+
+        K8sNamespace k8sNamespaceObj = k8sNamespaceMapper.selectById(id);
+        if (k8sNamespaceObj == null) {
+            log.error("K8s namespace does not exist, namespaceId:{}.", id);
+            putMsg(result, Status.K8S_NAMESPACE_NOT_EXIST, id);
+            return result;
+        }
+
+        Date now = new Date();
+        k8sNamespaceObj.setLimitsCpu(limitsCpu);
+        k8sNamespaceObj.setLimitsMemory(limitsMemory);
+        k8sNamespaceObj.setUpdateTime(now);
+
+        if (!Constants.K8S_LOCAL_TEST_CLUSTER_CODE.equals(k8sNamespaceObj.getClusterCode())) {
+            try {
+                String yamlStr = genDefaultResourceYaml(k8sNamespaceObj);
+                k8sClientService.upsertNamespaceAndResourceToK8s(k8sNamespaceObj, yamlStr);
+            } catch (Exception e) {
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: 
A +: 
B -: /** / * use cpu memory create yaml / * / * @param k8sNamespace / * @return yaml file / */
B +: 
```
</details>

### 2023-49109::K8sClientService.java::deleteNamespaceToK8s  <->  2023-49109::K8SNamespaceServiceImpl.java::updateK8sNamespace

- muc: **khong trung** | Jaccard AST: 0.017 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 1.0 | fix_removed_sim 0.093
- API chung trong fix: - | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,13 +1,49 @@
-public Optional<Namespace> deleteNamespaceToK8s(String name, Long clusterCode) throws RemotingException {
-        Optional<Namespace> result = getNamespaceFromK8s(name, clusterCode);
-        if (result.isPresent()) {
-            KubernetesClient client = k8sManager.getK8sClient(clusterCode);
-            Namespace body = new Namespace();
-            ObjectMeta meta = new ObjectMeta();
-            meta.setNamespace(name);
-            meta.setName(name);
-            body.setMetadata(meta);
-            client.namespaces().delete(body);
+@Override
+    public Map<String, Object> updateK8sNamespace(User loginUser, int id, String userName, Double limitsCpu,
+                                                  Integer limitsMemory) {
+        Map<String, Object> result = new HashMap<>();
+        if (isNotAdmin(loginUser, result)) {
+            log.warn("Only admin can update K8s namespace, current login user name:{}.", loginUser.getUserName());
+            return result;
         }
-        return getNamespaceFromK8s(name, clusterCode);
+
+        if (limitsCpu != null && limitsCpu < 0.0) {
+            log.warn("Parameter limitsCpu is invalid.");
+            putMsg(result, Status.REQUEST_PARAMS_NOT_VALID_ERROR, Constants.LIMITS_CPU);
+            return result;
+        }
+
+        if (limitsMemory != null && limitsMemory < 0) {
+            log.warn("Parameter limitsMemory is invalid.");
+            putMsg(result, Status.REQUEST_PARAMS_NOT_VALID_ERROR, Constants.LIMITS_MEMORY);
+            return result;
+        }
+
+        K8sNamespace k8sNamespaceObj = k8sNamespaceMapper.selectById(id);
+        if (k8sNamespaceObj == null) {
+            log.error("K8s namespace does not exist, namespaceId:{}.", id);
+            putMsg(result, Status.K8S_NAMESPACE_NOT_EXIST, id);
+            return result;
+        }
+
+        Date now = new Date();
+        k8sNamespaceObj.setLimitsCpu(limitsCpu);
+        k8sNamespaceObj.setLimitsMemory(limitsMemory);
+        k8sNamespaceObj.setUpdateTime(now);
+
+        if (!Constants.K8S_LOCAL_TEST_CLUSTER_CODE.equals(k8sNamespaceObj.getClusterCode())) {
+            try {
+                String yamlStr = genDefaultResourceYaml(k8sNamespaceObj);
+                k8sClientService.upsertNamespaceAndResourceToK8s(k8sNamespaceObj, yamlStr);
+            } catch (Exception e) {
+                log.error("Namespace update to k8s error", e);
+                putMsg(result, Status.K8S_CLIENT_OPS_ERROR, e.getMessage());
+                return result;
+            }
+        }
+        // update to db
+        k8sNamespaceMapper.updateById(k8sNamespaceObj);
+        log.info("K8s namespace update complete, namespace:{}.", k8sNamespaceObj.getNamespace());
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: private ResourceQuota upsertNamespacedResourceToK8s(K8sNamespace k8sNamespace, / String yamlStr) { /  / KubernetesClient client = k8sManager.getK8sClient(k8sNamespace.getClusterCode()); /  / // åˆ›å»ºèµ„æº�
A +: 
B -: /** / * use cpu memory create yaml / * / * @param k8sNamespace / * @return yaml file / */
B +: 
```
</details>

### 2023-49109::K8sClientService.java::deleteNamespaceToK8s  <->  2023-49109::K8SNamespaceServiceImpl.java::queryListPaging

- muc: **khong trung** | Jaccard AST: 0.015 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 1.0 | fix_removed_sim 0.0
- API chung trong fix: - | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,13 +1,22 @@
-public Optional<Namespace> deleteNamespaceToK8s(String name, Long clusterCode) throws RemotingException {
-        Optional<Namespace> result = getNamespaceFromK8s(name, clusterCode);
-        if (result.isPresent()) {
-            KubernetesClient client = k8sManager.getK8sClient(clusterCode);
-            Namespace body = new Namespace();
-            ObjectMeta meta = new ObjectMeta();
-            meta.setNamespace(name);
-            meta.setName(name);
-            body.setMetadata(meta);
-            client.namespaces().delete(body);
+@Override
+    public Result queryListPaging(User loginUser, String searchVal, Integer pageNo, Integer pageSize) {
+        Result result = new Result();
+        if (!isAdmin(loginUser)) {
+            log.warn("Only admin can query namespace list, current login user name:{}.", loginUser.getUserName());
+            putMsg(result, Status.USER_NO_OPERATION_PERM);
+            return result;
         }
-        return getNamespaceFromK8s(name, clusterCode);
+
+        Page<K8sNamespace> page = new Page<>(pageNo, pageSize);
+
+        IPage<K8sNamespace> k8sNamespaceList = k8sNamespaceMapper.queryK8sNamespacePaging(page, searchVal);
+
+        Integer count = (int) k8sNamespaceList.getTotal();
+        PageInfo<K8sNamespace> pageInfo = new PageInfo<>(pageNo, pageSize);
+        pageInfo.setTotal(count);
+        pageInfo.setTotalList(k8sNamespaceList.getRecords());
+        result.setData(pageInfo);
+        putMsg(result, Status.SUCCESS);
+
+        return result;
     }
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: private ResourceQuota upsertNamespacedResourceToK8s(K8sNamespace k8sNamespace, / String yamlStr) { /  / KubernetesClient client = k8sManager.getK8sClient(k8sNamespace.getClusterCode()); /  / // åˆ›å»ºèµ„æº�
A +: 
B -: * @param limitsCpu    limits cpu, can null means not limit / * @param limitsMemory limits memory, can null means not limit
B +: 
```
</details>

### 2023-49109::K8sNamespaceController.java::createNamespace  <->  2023-49109::K8SNamespaceServiceImpl.java::queryListPaging

- muc: **khong trung** | Jaccard AST: 0.014 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 1.0 | fix_removed_sim 0.0
- API chung trong fix: - | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,20 +1,22 @@
-@Operation(summary = "createK8sNamespace", description = "CREATE_NAMESPACE_NOTES")
-    @Parameters({
-            @Parameter(name = "namespace", description = "NAMESPACE", required = true, schema = @Schema(implementation = String.class)),
-            @Parameter(name = "clusterCode", description = "CLUSTER_CODE", required = true, schema = @Schema(implementation = long.class)),
-            @Parameter(name = "limits_cpu", description = "LIMITS_CPU", required = false, schema = @Schema(implementation = double.class)),
-            @Parameter(name = "limits_memory", description = "LIMITS_MEMORY", required = false, schema = @Schema(implementation = int.class))
-    })
-    @PostMapping()
-    @ResponseStatus(HttpStatus.CREATED)
-    @ApiException(CREATE_K8S_NAMESPACE_ERROR)
-    @AccessLogAnnotation(ignoreRequestArgs = "loginUser")
-    public Result createNamespace(@Parameter(hidden = true) @RequestAttribute(value = Constants.SESSION_USER) User loginUser,
-                                  @RequestParam(value = "namespace") String namespace,
-                                  @RequestParam(value = "clusterCode") Long clusterCode,
-                                  @RequestParam(value = "limitsCpu", required = false) Double limitsCpu,
-                                  @RequestParam(value = "limitsMemory", required = false) Integer limitsMemory) {
-        Map<String, Object> result =
-                k8sNamespaceService.createK8sNamespace(loginUser, namespace, clusterCode, limitsCpu, limitsMemory);
-        return returnDataList(result);
+@Override
+    public Result queryListPaging(User loginUser, String searchVal, Integer pageNo, Integer pageSize) {
+        Result result = new Result();
+        if (!isAdmin(loginUser)) {
+            log.warn("Only admin can query namespace list, current login user name:{}.", loginUser.getUserName());
+            putMsg(result, Status.USER_NO_OPERATION_PERM);
+            return result;
+        }
+
+        Page<K8sNamespace> page = new Page<>(pageNo, pageSize);
+
+        IPage<K8sNamespace> k8sNamespaceList = k8sNamespaceMapper.queryK8sNamespacePaging(page, searchVal);
+
+        Integer count = (int) k8sNamespaceList.getTotal();
+        PageInfo<K8sNamespace> pageInfo = new PageInfo<>(pageNo, pageSize);
+        pageInfo.setTotal(count);
+        pageInfo.setTotalList(k8sNamespaceList.getRecords());
+        result.setData(pageInfo);
+        putMsg(result, Status.SUCCESS);
+
+        return result;
     }
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: 
A +: 
B -: * @param limitsCpu    limits cpu, can null means not limit / * @param limitsMemory limits memory, can null means not limit
B +: 
```
</details>

### 2023-49109::K8sNamespaceController.java::createNamespace  <->  2023-49109::K8sClientService.java::deleteNamespaceToK8s

- muc: **khong trung** | Jaccard AST: 0.008 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 1.0 | fix_removed_sim 0.0
- API chung trong fix: - | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,20 +1,13 @@
-@Operation(summary = "createK8sNamespace", description = "CREATE_NAMESPACE_NOTES")
-    @Parameters({
-            @Parameter(name = "namespace", description = "NAMESPACE", required = true, schema = @Schema(implementation = String.class)),
-            @Parameter(name = "clusterCode", description = "CLUSTER_CODE", required = true, schema = @Schema(implementation = long.class)),
-            @Parameter(name = "limits_cpu", description = "LIMITS_CPU", required = false, schema = @Schema(implementation = double.class)),
-            @Parameter(name = "limits_memory", description = "LIMITS_MEMORY", required = false, schema = @Schema(implementation = int.class))
-    })
-    @PostMapping()
-    @ResponseStatus(HttpStatus.CREATED)
-    @ApiException(CREATE_K8S_NAMESPACE_ERROR)
-    @AccessLogAnnotation(ignoreRequestArgs = "loginUser")
-    public Result createNamespace(@Parameter(hidden = true) @RequestAttribute(value = Constants.SESSION_USER) User loginUser,
-                                  @RequestParam(value = "namespace") String namespace,
-                                  @RequestParam(value = "clusterCode") Long clusterCode,
-                                  @RequestParam(value = "limitsCpu", required = false) Double limitsCpu,
-                                  @RequestParam(value = "limitsMemory", required = false) Integer limitsMemory) {
-        Map<String, Object> result =
-                k8sNamespaceService.createK8sNamespace(loginUser, namespace, clusterCode, limitsCpu, limitsMemory);
-        return returnDataList(result);
+public Optional<Namespace> deleteNamespaceToK8s(String name, Long clusterCode) throws RemotingException {
+        Optional<Namespace> result = getNamespaceFromK8s(name, clusterCode);
+        if (result.isPresent()) {
+            KubernetesClient client = k8sManager.getK8sClient(clusterCode);
+            Namespace body = new Namespace();
+            ObjectMeta meta = new ObjectMeta();
+            meta.setNamespace(name);
+            meta.setName(name);
+            body.setMetadata(meta);
+            client.namespaces().delete(body);
+        }
+        return getNamespaceFromK8s(name, clusterCode);
     }
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: 
A +: 
B -: private ResourceQuota upsertNamespacedResourceToK8s(K8sNamespace k8sNamespace, / String yamlStr) { /  / KubernetesClient client = k8sManager.getK8sClient(k8sNamespace.getClusterCode()); /  / // åˆ›å»ºèµ„æº�
B +: 
```
</details>


## 5. Khong tim duoc method

- apache__dolphinscheduler_CVE-2023-51770_3.2.0 :: dolphinscheduler-datasource-plugin/dolphinscheduler-datasource-mysql/src/main/java/org/apache/dolphinscheduler/plugin/datasource/mysql/param/MySQLDataSourceProcessor.java :: checkKeyIsLegitimate
- apache__dolphinscheduler_CVE-2023-51770_3.2.0 :: dolphinscheduler-datasource-plugin/dolphinscheduler-datasource-mysql/src/main/java/org/apache/dolphinscheduler/plugin/datasource/mysql/param/MySQLDataSourceProcessor.java :: getConnection
- apache__dolphinscheduler_CVE-2023-51770_3.2.0 :: dolphinscheduler-datasource-plugin/dolphinscheduler-datasource-mysql/src/main/java/org/apache/dolphinscheduler/plugin/datasource/mysql/param/MySQLDataSourceProcessor.java :: getJdbcUrl
- apache__dolphinscheduler_CVE-2023-51770_3.2.0 :: dolphinscheduler-datasource-plugin/dolphinscheduler-datasource-mysql/src/main/java/org/apache/dolphinscheduler/plugin/datasource/mysql/param/MySQLDataSourceProcessor.java :: getValidationQuery
- apache__dolphinscheduler_CVE-2023-51770_3.2.0 :: dolphinscheduler-datasource-plugin/dolphinscheduler-datasource-mysql/src/main/java/org/apache/dolphinscheduler/plugin/datasource/mysql/param/MySQLDataSourceProcessor.java :: transformOther