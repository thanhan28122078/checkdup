# Kiem tra trung lap: keycloak/keycloak

- CVE: 5 | unit (method bi fix, ban con loi): 21 | khong tim duoc: 0
- Cap so sanh (cung CWE): 102

## 1. Tom tat theo muc

| Muc | So cap | Cum co >=2 unit | Unit nam trong cum trung |
|---|---|---|---|
| L1_strict (tich luy) | 0 | 0 | 0/21 |
| L1_loose (tich luy) | 0 | 0 | 0/21 |
| L2_AST (tich luy) | 0 | 0 | 0/21 |
| L2_Near95 (tich luy) | 0 | 0 | 0/21 |
| L2_Near90 (tich luy) | 0 | 0 | 0/21 |

Luu y: moi muc la tich luy (L2_AST bao gom ca L1). Tach intra_cve/inter_cve: 0 cap co trung o it nhat 1 muc, trong do 0 cap cung CVE, 0 cap khac CVE.

## 2. CVE va mo ta advisory (de doi chieu root cause)

- **CVE-2022-3782** (CWE-022, tag 20.0.1): Keycloak vulnerable to path traversal via double URL encoding  | Keycloak does not properly validate URLs included in a redirect. An attacker could construct a malicious request to bypass validation and access other URLs and potentially sensitive information within the domain, or possibly conduct further attacks.
- **CVE-2014-3656** (CWE-079, tag 1.0.5.Final): JBoss KeyCloak Cross-site Scripting Vulnerability | If a JBoss Keycloak application was configured to use `*` as a permitted web origin in the Keycloak administrative console, crafted requests to the `login-status-iframe.html` endpoint could inject arbitrary Javascript into the generated HTML code via the "origin" query parameter, leading to a cros
- **CVE-2022-4137** (CWE-079, tag 20.0.3): Keycloak Cross-site Scripting on OpenID connect login service | A reflected cross-site scripting (XSS) vulnerability was found in the `oob` OAuth endpoint due to incorrect null-byte handling. This issue allows a malicious link to insert an arbitrary URI into a Keycloak error page.
- **CVE-2022-1274** (CWE-079, tag 20.0.3): HTML Injection in Keycloak Admin REST API | The `execute-actions-email` endpoint of the Keycloak Admin REST API allows a malicious actor to send emails containing phishing links to Keycloak users. 
- **CVE-2022-4361** (CWE-079, tag 21.1.1): Keycloak vulnerable to cross-site scripting when validating URI-schemes on SAML and OIDC | AssertionConsumerServiceURL is a Java implementation for SAML Service Providers (org.keycloak.protocol.saml). Affected versions of this package are vulnerable to Cross-site Scripting (XSS).  AssertionConsumerServiceURL allows XSS when sending a crafted SAML X

## 3. Ma tran CVE x CVE (muc trung cao nhat giua cac method cua 2 CVE)

| |2022-3782|2014-3656|2022-4137|2022-1274|2022-4361|
|---|---|---|---|---|---|
|2022-3782|-|||||
|2014-3656||-||||
|2022-4137|||-|||
|2022-1274||||-||
|2022-4361|||||-|

## 3b. Nhom root cause goi y (gom theo cung vi tri / cung mau fix / cung API fix)

Day la goi y tu dong, KHONG phai ket luan. Nhom co nhieu CVE khac nhau la cho dang quan tam nhat.

- **C13**: 3 method, 1 CVE (2022-4361) | API fix chung: `getNormalizedRedirectUri, debugf, equalsIgnoreCase, getScheme, http`
    - 2022-4361::RedirectUtils.java::decodeRedirectUri
    - 2022-4361::RedirectUtils.java::getNormalizedRedirectUri
    - 2022-4361::RedirectUtils.java::verifyRedirectUri
- **C4**: 2 method, 1 CVE (2022-3782) | API fix chung: `-`
    - 2022-3782::RedirectUtils.java::getSingleValidRedirectUri
    - 2022-3782::AuthenticationSessionManager.java::getAuthSessionCookies
- **C5**: 2 method, 1 CVE (2022-3782) | API fix chung: `decodeRedirectUri`
    - 2022-3782::RedirectUtils.java::lowerCaseHostname
    - 2022-3782::RedirectUtils.java::verifyRedirectUri
- **C6**: 2 method, 1 CVE (2022-3782) | API fix chung: `authenticateIdentityCookie, getSession, lockUserSessionsForModification`
    - 2022-3782::UserSessionCrossDCManager.java::getUserSessionIfExistsRemotely
    - 2022-3782::SessionCodeChecks.java::initialVerifyAuthSession
- **C7**: 2 method, 2 CVE (2014-3656, 2022-4361) | API fix chung: `-`
    - 2014-3656::UriUtils.java::getOrigin
    - 2022-4361::RedirectUtils.java::matchesRedirects

## 4. Cac cap can duyet tay (uu tien: co muc trung hoac co goi y root cause)

### 2022-4361::RedirectUtils.java::decodeRedirectUri  <->  2022-4361::RedirectUtils.java::verifyRedirectUri

- muc: **khong trung** | Jaccard AST: 0.087 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.035 | fix_removed_sim 0.0
- API chung trong fix: getNormalizedRedirectUri | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,33 +1,63 @@
-private static String decodeRedirectUri(String redirectUri) {
-        if (redirectUri == null) return null;
-        int MAX_DECODING_COUNT = 5; // Max count of attempts for decoding URL (in case it was encoded multiple times)
+public static String verifyRedirectUri(KeycloakSession session, String rootUrl, String redirectUri, Set<String> validRedirects, boolean requireRedirectUri) {
+        KeycloakUriInfo uriInfo = session.getContext().getUri();
+        RealmModel realm = session.getContext().getRealm();
 
-        try {
-            KeycloakUriBuilder uriBuilder = KeycloakUriBuilder.fromUri(redirectUri).preserveDefaultPort();
-            String origQuery = uriBuilder.getQuery();
-            String origFragment = uriBuilder.getFragment();
-            String encodedRedirectUri = uriBuilder
-                    .replaceQuery(null)
-                    .fragment(null)
-                    .buildAsString();
-            String decodedRedirectUri = null;
+        if (redirectUri == null) {
+            if (!requireRedirectUri) {
+                redirectUri = getSingleValidRedirectUri(validRedirects);
+            }
 
-            for (int i = 0; i < MAX_DECODING_COUNT; i++) {
-                decodedRedirectUri = Encode.decode(encodedRedirectUri);
-                if (decodedRedirectUri.equals(encodedRedirectUri)) {
-                    // URL is decoded. We can return it (after attach original query and fragment)
-                    return KeycloakUriBuilder.fromUri(decodedRedirectUri).preserveDefaultPort()
-                            .replaceQuery(origQuery)
-                            .fragment(origFragment)
-                            .buildAsString();
-                } else {
-                    // Next attempt
-                    encodedRedirectUri = decodedRedirectUri;
+            if (redirectUri == null) {
+                logger.debug("No Redirect URI parameter specified");
+                return null;
+            }
+        } else if (validRedirects.isEmpty()) {
+            logger.debug("No Redirect URIs supplied");
+            redirectUri = null;
+        } else {
+            // Make the validations against fully decoded and normalized redirect-url. This also allows wildcards (case when client configured "Valid redirect-urls" contain wildcards)
+            String decodedRedirectUri = decodeRedirectUri(redirectUri);
+            decodedRedirectUri = getNormalizedRedirectUri(decodedRedirectUri);
+            if (decodedRedirectUri == null) return null;
+
+            String r = decodedRedirectUri;
+            Set<String> resolveValidRedirects = resolveValidRedirects(session, rootUrl, validRedirects);
+
+            boolean valid = matchesRedirects(resolveValidRedirects, r, true);
+
+            if (!valid && (r.startsWith(Constants.INSTALLED_APP_URL) || r.startsWith(Constants.INSTALLED_APP_LOOPBACK)) && r.indexOf(':', Constants.INSTALLED_APP_URL.length()) >= 0) {
+                int i = r.indexOf(':', Constants.INSTALLED_APP_URL.length());
+
+                StringBuilder sb = new StringBuilder();
+                sb.append(r.substring(0, i));
+
+                i = r.indexOf('/', i);
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: return null; / return null;
A +: } / return uri; / } /  / private static String getNormalizedRedirectUri(URI uri) { / String redirectUri = null;
B -: decodedRedirectUri = getNormalizedRedirectUri(decodedRedirectUri); / boolean valid = matchesRedirects(resolveValidRedirects, r, true); / if (!valid && (r.startsWith(Constants.INSTALLED_APP_URL) || r.startsWith(Constants.INSTALLED_APP_LOOPBACK)) && r.indexOf(':', Constants.INSTALLED_APP_URL.length()) >= 0) { / redirectUri = getNormalizedRedirectUri(redirectUri); / if (!valid) { / if (valid && redirectUri.startsWith("/")) {
B +: URI decodedRedirect = toUri(decodedRedirectUri); / decodedRedirectUri = getNormalizedRedirectUri(decodedRedirect); / String valid = matchesRedirects(resolveValidRedirects, r, true); / if (valid == null && (r.startsWith(Constants.INSTALLED_APP_URL) || r.startsWith(Constants.INSTALLED_APP_LOOPBACK)) && r.indexOf(':', Constants.INSTALLED_APP_URL.length()) >= 0) { / URI redirect = toUri(redirectUri); / redirectUri = getNormalizedRedirectUri(redirect);
```
</details>

### 2022-3782::RedirectUtils.java::lowerCaseHostname  <->  2022-3782::RedirectUtils.java::verifyRedirectUri

- muc: **khong trung** | Jaccard AST: 0.061 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.011 | fix_removed_sim 1.0
- API chung trong fix: decodeRedirectUri | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,7 +1,63 @@
-private static String lowerCaseHostname(String redirectUri) {
-        int n = redirectUri.indexOf('/', 7);
-        if (n == -1) {
-            return redirectUri.toLowerCase();
+public static String verifyRedirectUri(KeycloakSession session, String rootUrl, String redirectUri, Set<String> validRedirects, boolean requireRedirectUri) {
+        KeycloakUriInfo uriInfo = session.getContext().getUri();
+        RealmModel realm = session.getContext().getRealm();
+
+        if (redirectUri != null) {
+            try {
+                URI uri = URI.create(redirectUri);
+                redirectUri = uri.normalize().toString();
+            } catch (IllegalArgumentException cause) {
+                logger.debug("Invalid redirect uri", cause);
+                return null;
+            } catch (Exception cause) {
+                logger.debug("Unexpected error when parsing redirect uri", cause);
+                return null;
+            }
+        }
+
+        if (redirectUri == null) {
+            if (!requireRedirectUri) {
+                redirectUri = getSingleValidRedirectUri(validRedirects);
+            }
+
+            if (redirectUri == null) {
+                logger.debug("No Redirect URI parameter specified");
+                return null;
+            }
+        } else if (validRedirects.isEmpty()) {
+            logger.debug("No Redirect URIs supplied");
+            redirectUri = null;
         } else {
-            return redirectUri.substring(0, n).toLowerCase() + redirectUri.substring(n);
+            redirectUri = lowerCaseHostname(redirectUri);
+
+            String r = redirectUri;
+            Set<String> resolveValidRedirects = resolveValidRedirects(session, rootUrl, validRedirects);
+
+            boolean valid = matchesRedirects(resolveValidRedirects, r);
+
+            if (!valid && (r.startsWith(Constants.INSTALLED_APP_URL) || r.startsWith(Constants.INSTALLED_APP_LOOPBACK)) && r.indexOf(':', Constants.INSTALLED_APP_URL.length()) >= 0) {
+                int i = r.indexOf(':', Constants.INSTALLED_APP_URL.length());
+
+                StringBuilder sb = new StringBuilder();
+                sb.append(r.substring(0, i));
+
+                i = r.indexOf('/', i);
+                if (i >= 0) {
+                    sb.append(r.substring(i));
+                }
+
+                r = sb.toString();
+
+                valid = matchesRedirects(resolveValidRedirects, r);
+            }
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: 
A +: // Decode redirectUri. We don't decode query and fragment as those can be encoded in the original URL. / // URL can be decoded multiple times (in case it was encoded multiple times, or some of it's parts were encoded multiple times) / private static String decodeRedirectUri(String redirectUri) { / if (redirectUri == null) return null; / int MAX_DECODING_COUNT = 5; // Max count of attempts for decoding URL (in case it was encoded multiple times) / 
B -: 
B +: redirectUri = decodeRedirectUri(redirectUri);
```
</details>

### 2022-4361::RedirectUtils.java::getNormalizedRedirectUri  <->  2022-4361::RedirectUtils.java::verifyRedirectUri

- muc: **khong trung** | Jaccard AST: 0.054 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.47 | fix_removed_sim 0.062
- API chung trong fix: debugf;equalsIgnoreCase;getScheme;http;toUri | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,16 +1,63 @@
-private static String getNormalizedRedirectUri(String redirectUri) {
-        if (redirectUri != null) {
-            try {
-                URI uri = URI.create(redirectUri);
-                redirectUri = uri.normalize().toString();
-            } catch (IllegalArgumentException cause) {
-                logger.debug("Invalid redirect uri", cause);
-                return null;
-            } catch (Exception cause) {
-                logger.debug("Unexpected error when parsing redirect uri", cause);
+public static String verifyRedirectUri(KeycloakSession session, String rootUrl, String redirectUri, Set<String> validRedirects, boolean requireRedirectUri) {
+        KeycloakUriInfo uriInfo = session.getContext().getUri();
+        RealmModel realm = session.getContext().getRealm();
+
+        if (redirectUri == null) {
+            if (!requireRedirectUri) {
+                redirectUri = getSingleValidRedirectUri(validRedirects);
+            }
+
+            if (redirectUri == null) {
+                logger.debug("No Redirect URI parameter specified");
                 return null;
             }
-            redirectUri = lowerCaseHostname(redirectUri);
+        } else if (validRedirects.isEmpty()) {
+            logger.debug("No Redirect URIs supplied");
+            redirectUri = null;
+        } else {
+            // Make the validations against fully decoded and normalized redirect-url. This also allows wildcards (case when client configured "Valid redirect-urls" contain wildcards)
+            String decodedRedirectUri = decodeRedirectUri(redirectUri);
+            decodedRedirectUri = getNormalizedRedirectUri(decodedRedirectUri);
+            if (decodedRedirectUri == null) return null;
+
+            String r = decodedRedirectUri;
+            Set<String> resolveValidRedirects = resolveValidRedirects(session, rootUrl, validRedirects);
+
+            boolean valid = matchesRedirects(resolveValidRedirects, r, true);
+
+            if (!valid && (r.startsWith(Constants.INSTALLED_APP_URL) || r.startsWith(Constants.INSTALLED_APP_LOOPBACK)) && r.indexOf(':', Constants.INSTALLED_APP_URL.length()) >= 0) {
+                int i = r.indexOf(':', Constants.INSTALLED_APP_URL.length());
+
+                StringBuilder sb = new StringBuilder();
+                sb.append(r.substring(0, i));
+
+                i = r.indexOf('/', i);
+                if (i >= 0) {
+                    sb.append(r.substring(i));
+                }
+
+                r = sb.toString();
+
+                valid = matchesRedirects(resolveValidRedirects, r, true);
+            }
+
+            // Return the original redirectUri, which can be partially encoded - for example http://localhost:8280/foo/bar%20bar%2092%2F72/3 . Just make sure it is normalized
+            redirectUri = getNormalizedRedirectUri(redirectUri);
+
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: redirectUri = valid ? redirectUri : null; / private static String getNormalizedRedirectUri(String redirectUri) {
A +:  / String scheme = decodedRedirect.getScheme(); / if (valid != null && scheme != null) { / // check the scheme is valid, it should be http(s) or explicitly allowed by the validation / if (!valid.startsWith(scheme + ":") && !"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) { / logger.debugf("Invalid URI because scheme is not allowed: %s", redirectUri);
B -: decodedRedirectUri = getNormalizedRedirectUri(decodedRedirectUri); / boolean valid = matchesRedirects(resolveValidRedirects, r, true); / if (!valid && (r.startsWith(Constants.INSTALLED_APP_URL) || r.startsWith(Constants.INSTALLED_APP_LOOPBACK)) && r.indexOf(':', Constants.INSTALLED_APP_URL.length()) >= 0) { / redirectUri = getNormalizedRedirectUri(redirectUri); / if (!valid) { / if (valid && redirectUri.startsWith("/")) {
B +: URI decodedRedirect = toUri(decodedRedirectUri); / decodedRedirectUri = getNormalizedRedirectUri(decodedRedirect); / String valid = matchesRedirects(resolveValidRedirects, r, true); / if (valid == null && (r.startsWith(Constants.INSTALLED_APP_URL) || r.startsWith(Constants.INSTALLED_APP_LOOPBACK)) && r.indexOf(':', Constants.INSTALLED_APP_URL.length()) >= 0) { / URI redirect = toUri(redirectUri); / redirectUri = getNormalizedRedirectUri(redirect);
```
</details>

### 2014-3656::UriUtils.java::getOrigin  <->  2022-4361::RedirectUtils.java::matchesRedirects

- muc: **khong trung** | Jaccard AST: 0.053 | pham vi: inter_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 1.0 | fix_removed_sim 1.0
- API chung trong fix: - | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,4 +1,18 @@
-public static String getOrigin(String uri) {
-        String u = uri.toString();
-        return u.substring(0, u.indexOf('/', 8));
+private static boolean matchesRedirects(Set<String> validRedirects, String redirect, boolean allowWildcards) {
+        logger.tracef("matchesRedirects: redirect URL to check: %s, allow wildcards: %b, Configured valid redirect URLs: %s", redirect, allowWildcards, validRedirects);
+        for (String validRedirect : validRedirects) {
+            if (validRedirect.endsWith("*") && !validRedirect.contains("?") && allowWildcards) {
+                // strip off the query component - we don't check them when wildcards are effective
+                String r = redirect.contains("?") ? redirect.substring(0, redirect.indexOf("?")) : redirect;
+                // strip off *
+                int length = validRedirect.length() - 1;
+                validRedirect = validRedirect.substring(0, length);
+                if (r.startsWith(validRedirect)) return true;
+                // strip off trailing '/'
+                if (length - 1 > 0 && validRedirect.charAt(length - 1) == '/') length--;
+                validRedirect = validRedirect.substring(0, length);
+                if (validRedirect.equals(r)) return true;
+            } else if (validRedirect.equals(redirect)) return true;
+        }
+        return false;
     }
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

### 2022-3782::UserSessionCrossDCManager.java::getUserSessionIfExistsRemotely  <->  2022-3782::SessionCodeChecks.java::initialVerifyAuthSession

- muc: **khong trung** | Jaccard AST: 0.034 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.351 | fix_removed_sim 1.0
- API chung trong fix: authenticateIdentityCookie;getSession;lockUserSessionsForModification | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,20 +1,70 @@
-public UserSessionModel getUserSessionIfExistsRemotely(AuthenticationSessionManager asm, RealmModel realm) {
-        List<String> sessionCookies = asm.getAuthSessionCookies(realm);
+public AuthenticationSessionModel initialVerifyAuthSession() {
+        // Basic realm checks
+        if (!checkSsl()) {
+            event.error(Errors.SSL_REQUIRED);
+            response = ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.HTTPS_REQUIRED);
+            return null;
+        }
+        if (!realm.isEnabled()) {
+            event.error(Errors.REALM_DISABLED);
+            response = ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.REALM_NOT_ENABLED);
+            return null;
+        }
 
-        return sessionCookies.stream().map(oldEncodedId -> {
-            AuthSessionId authSessionId = asm.decodeAuthSessionId(oldEncodedId);
-            String sessionId = authSessionId.getDecodedId();
+        // Setup client to be shown on error/info page based on "client_id" parameter
+        logger.debugf("Will use client '%s' in back-to-application link", clientId);
+        ClientModel client = null;
+        if (clientId != null) {
+            client = realm.getClientByClientId(clientId);
+        }
+        if (client != null) {
+            session.getContext().setClient(client);
+        }
 
-            // This will remove userSession "locally" if it doesn't exist on remoteCache
-            lockUserSessionsForModification(kcSession, () -> kcSession.sessions().getUserSessionWithPredicate(realm, sessionId, false, (UserSessionModel userSession2) -> userSession2 == null));
 
-            UserSessionModel userSession = lockUserSessionsForModification(kcSession, () -> kcSession.sessions().getUserSession(realm, sessionId));
+        // object retrieve
+        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
+        AuthenticationSessionModel authSession = null;
+        if (authSessionId != null)
+            authSession = authSessionManager.getAuthenticationSessionByIdAndClient(realm, authSessionId, client, tabId);
+        AuthenticationSessionModel authSessionCookie = authSessionManager.getCurrentAuthenticationSession(realm, client, tabId);
 
-            if (userSession != null) {
-                asm.reencodeAuthSessionCookie(oldEncodedId, authSessionId, realm);
-                return userSession;
+        if (authSession != null && authSessionCookie != null && !authSession.getParentSession().getId().equals(authSessionCookie.getParentSession().getId())) {
+            event.detail(Details.REASON, "cookie does not match auth_session query parameter");
+            event.error(Errors.INVALID_CODE);
+            response = ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_CODE);
+            return null;
+
+        }
+
+        if (authSession != null) {
+            session.getProvider(LoginFormsProvider.class).setAuthenticationSession(authSession);
+            return authSession;
+        }
+
+        if (authSessionCookie != null) {
+            session.getProvider(LoginFormsProvider.class).setAuthenticationSession(authSessionCookie);
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: 
A +: if (sessionCookies.isEmpty()) { / // ideally, we should not rely on auth session id to retrieve user sessions / // in case the auth session was removed, we fall back to the identity cookie / // we are here doing the user session lookup twice, however the second lookup is going to make sure the / // session exists in remote caches / AuthenticationManager.AuthResult authResult = lockUserSessionsForModification(kcSession, () -> authenticateIdentityCookie(kcSession, realm, true));
B -: 
B +: if (userSession == null) { / // fallback to check if there is an identity cookie / AuthenticationManager.AuthResult authResult = lockUserSessionsForModification(session, () -> authenticateIdentityCookie(session, realm, false)); /  / if (authResult != null) { / userSession = authResult.getSession();
```
</details>

### 2022-3782::RedirectUtils.java::getSingleValidRedirectUri  <->  2022-3782::AuthenticationSessionManager.java::getAuthSessionCookies

- muc: **khong trung** | Jaccard AST: 0.026 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_pattern` | fix_added_sim 1.0 | fix_removed_sim 1.0
- API chung trong fix: - | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,5 +1,15 @@
-private static String getSingleValidRedirectUri(Collection<String> validRedirects) {
-        if (validRedirects.size() != 1) return null;
-        String validRedirect = validRedirects.iterator().next();
-        return validateRedirectUriWildcard(validRedirect);
+List<String> getAuthSessionCookies(RealmModel realm) {
+        Set<String> cookiesVal = CookieHelper.getCookieValue(AUTH_SESSION_ID);
+
+        if (cookiesVal.size() > 1) {
+            AuthenticationManager.expireOldAuthSessionCookie(realm, session.getContext().getUri(), session.getContext().getConnection());
+        }
+
+        List<String> authSessionIds = cookiesVal.stream().limit(AUTH_SESSION_COOKIE_LIMIT).collect(Collectors.toList());
+
+        if (authSessionIds.isEmpty()) {
+            log.debugf("Not found AUTH_SESSION_ID cookie");
+        }
+
+        return authSessionIds;
     }
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
