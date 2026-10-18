# Kiem tra trung lap: apache/jspwiki

- CVE: 6 | unit (method bi fix, ban con loi): 15 | khong tim duoc: 0
- Cap so sanh (cung CWE): 91

## 1. Tom tat theo muc

| Muc | So cap | Cum co >=2 unit | Unit nam trong cum trung |
|---|---|---|---|
| L1_strict (tich luy) | 0 | 0 | 0/15 |
| L1_loose (tich luy) | 0 | 0 | 0/15 |
| L2_AST (tich luy) | 0 | 0 | 0/15 |
| L2_Near95 (tich luy) | 0 | 0 | 0/15 |
| L2_Near90 (tich luy) | 0 | 0 | 0/15 |

Luu y: moi muc la tich luy (L2_AST bao gom ca L1). Tach intra_cve/inter_cve: 0 cap co trung o it nhat 1 muc, trong do 0 cap cung CVE, 0 cap khac CVE.

## 2. CVE va mo ta advisory (de doi chieu root cause)

- **CVE-2019-0225** (CWE-022, tag 2.11.0.M2): Improper Limitation of a Pathname ('Path Traversal')  in org.apache.jspwiki:jspwiki-war | A specially crafted url could be used to access files under the ROOT directory of the application on Apache JSPWiki 2.9.0 to 2.11.0.M2, which could be used by an attacker to obtain registered users' details.
- **CVE-2019-10077** (CWE-079, tag 2.11.0.M3): Cross-site Scripting in JSPWiki | A carefully crafted InterWiki link could trigger an XSS vulnerability on Apache JSPWiki 2.9.0 to 2.11.0.M3, which could lead to session hijacking.
- **CVE-2019-10076** (CWE-079, tag 2.11.0.M3): Cross-Site Scripting in JSPWiki | A carefully crafted malicious attachment could trigger an XSS vulnerability on Apache JSPWiki 2.9.0 to 2.11.0.M3, which could lead to session hijacking.
- **CVE-2019-10078** (CWE-079, tag 2.11.0.M3): Cross-site Scriptin in JSPWiki | A carefully crafted plugin link invocation could trigger an XSS vulnerability on Apache JSPWiki 2.9.0 to 2.11.0.M3, which could lead to session hijacking. Initial reporting indicated ReferredPagesPlugin, but further analysis showed that multiple plugins were vulnerable.
- **CVE-2019-10089** (CWE-079, tag 2.11.0.M4): Cross-site scripting in Apache JSPWiki | On Apache JSPWiki, up to version 2.11.0.M4, a carefully crafted plugin link invocation could trigger an XSS vulnerability on Apache JSPWiki, related to the WYSIWYG editor, which could allow the attacker to execute javascript in the victim's browser and get some sensitive information about the victim.
- **CVE-2022-46907** (CWE-079, tag 2.11.3): Apache JSPWiki vulnerable to cross-site scripting on several plugins | A carefully crafted request on several JSPWiki plugins could trigger an XSS vulnerability on Apache JSPWiki, which could allow the attacker to execute javascript in the victim's browser and get some sensitive information about the victim. Apache JSPWiki users should upgrade to 2

## 3. Ma tran CVE x CVE (muc trung cao nhat giua cac method cua 2 CVE)

| |2019-0225|2019-10077|2019-10076|2019-10078|2019-10089|2022-46907|
|---|---|---|---|---|---|---|
|2019-0225|-||||||
|2019-10077||-|||||
|2019-10076|||-||||
|2019-10078||||-|||
|2019-10089|||||-||
|2022-46907||||||-|

## 3b. Nhom root cause goi y (gom theo cung vi tri / cung mau fix / cung API fix)

Day la goi y tu dong, KHONG phai ket luan. Nhom co nhieu CVE khac nhau la cho dang quan tam nhat.

- **C7**: 7 method, 2 CVE (2019-10078, 2022-46907) | API fix chung: `replaceEntities`
    - 2019-10078::ReferredPagesPlugin.java::execute
    - 2022-46907::FormOpen.java::execute
    - 2022-46907::FormOutput.java::execute
    - 2022-46907::BugReportHandler.java::execute
    - 2022-46907::CurrentTimePlugin.java::execute
    - 2022-46907::InsertPage.java::execute
    - 2022-46907::Search.java::execute

## 4. Cac cap can duyet tay (uu tien: co muc trung hoac co goi y root cause)

### 2022-46907::FormOpen.java::execute  <->  2022-46907::FormOutput.java::execute

- muc: **khong trung** | Jaccard AST: 0.286 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.483 | fix_removed_sim 0.375
- API chung trong fix: replaceEntities | API chung trong ma loi: getBundle;getEngine;getFormInfo;getPage;getRequestContext;getString;getURL;new FormInfo;setAction;setName
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -2,53 +2,78 @@
     public String execute( final Context ctx, final Map< String, String > params ) throws PluginException {
+        //  If there is no HTTP request, returns immediately.
+        if( ctx.getHttpRequest() == null ) {
+            return "";
+        }
         final ResourceBundle rb = Preferences.getBundle( ctx, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-        final String formName = params.get( PARAM_FORM );
-        if( formName == null ) {
-            throw new PluginException( MessageFormat.format( rb.getString( "formopen.missingparam" ), PARAM_FORM ) );
-        }
-        final String hide     = params.get( PARAM_HIDEFORM );
-        final String sourcePage = ctx.getPage().getName();
-        String submitServlet = params.get( PARAM_SUBMITHANDLER );
-        if( submitServlet == null )
-            submitServlet = ctx.getURL( ContextEnum.PAGE_VIEW.getRequestContext(), sourcePage );
+        
+        // If we are NOT here due to this form being submitted, we do nothing.
+        // The submitted form MUST have parameter 'formname' equal to the name
+        // parameter of this Form plugin.
 
-        String method = params.get( PARAM_METHOD );
-        if( method == null ) {
-            method="post";
+        final String formName   = params.get( PARAM_FORM );
+        final String submitForm = ctx.getHttpParameter( PARAM_FORMNAMEHIDDEN );
+        final String populator  = params.get( PARAM_POPULATE );
+
+        if( formName == null || !formName.equals( submitForm ) ) {
+            // No submitForm -> this was not a submission from the
+            // generated form.  If populate is specified, we'll go
+            // ahead and let the handler (populator) put stuff into
+            // the context, otherwise we'll just hide.
+            if( !PARAM_HANDLER.equals( populator ) )
+                return "";
+            // If population was allowed, we should first  
         }
 
-        if( !( method.equalsIgnoreCase( "get" ) || method.equalsIgnoreCase( "post" ) ) ) {
-            throw new PluginException( rb.getString( "formopen.postorgetonly" ) );
+        final String handler = params.get( PARAM_HANDLER );
+        if( handler == null || handler.isEmpty() ) {
+            // Need to print out an error here as this form is misconfigured
+            return "<p class=\"error\">" + MessageFormat.format( rb.getString( "formoutput.missingargument" ), PARAM_HANDLER ) + "</p>";
         }
 
+        final String sourcePage = ctx.getPage().getName();
+        final String submitServlet = ctx.getURL( ContextEnum.PAGE_VIEW.getRequestContext(), sourcePage );
+
+        // If there is previous FormInfo available - say, from a
+        // FormSet plugin - use it.
         FormInfo info = getFormInfo( ctx );
-        if( info != null ) {
-            // Previous information may be the result of submitting
-            // this form, or of a FormSet plugin, or both. If it
-            // exists and is for this form, fine.
-            if( formName.equals( info.getName() ) ) {
-                LOG.debug( "Previous FormInfo for this form was found in context." );
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: final String formName = params.get( PARAM_FORM ); / String submitServlet = params.get( PARAM_SUBMITHANDLER );
A +: final String formName = TextUtil.replaceEntities( params.get( PARAM_FORM ) ); / String submitServlet = TextUtil.replaceEntities( params.get( PARAM_SUBMITHANDLER ) );
B -:  / final String formName   = params.get( PARAM_FORM ); / // If population was allowed, we should first / final String handler = params.get( PARAM_HANDLER );
B +:  / final String formName   = TextUtil.replaceEntities( params.get( PARAM_FORM ) ); / // If population was allowed, we should first / final String handler = TextUtil.replaceEntities( params.get( PARAM_HANDLER ) );
```
</details>

### 2022-46907::CurrentTimePlugin.java::execute  <->  2022-46907::Search.java::execute

- muc: **khong trung** | Jaccard AST: 0.237 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.051 | fix_removed_sim 0.0
- API chung trong fix: replaceEntities | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,20 +1,31 @@
 @Override
-    public String execute( final Context context, final Map< String, String > params ) throws PluginException {
-        final String formatString = params.get( "format" );
+    public String execute( final Context context, final Map<String, String> params ) throws PluginException {
+        int maxItems = Integer.MAX_VALUE;
+        final Collection< SearchResult > results;
 
-        try {
-            final SimpleDateFormat fmt;
-            if( formatString != null ) {
-                fmt = new SimpleDateFormat( formatString );
-            } else {
-                fmt = Preferences.getDateFormat( context, TimeFormat.DATETIME );
+        final String queryString = params.get( PARAM_QUERY );
+        String set               = params.get( PARAM_SET );
+        final String max         = params.get( PARAM_MAX );
+
+        if ( set == null ) set = DEFAULT_SETNAME;
+        if ( max != null ) maxItems = Integer.parseInt( max );
+
+        if ( queryString == null ) {
+            results = context.getVariable( set );
+        } else {
+            try {
+                results = doBasicQuery( context, queryString );
+                context.setVariable( set, results );
+            } catch( final Exception e ) {
+                return "<div class='error'>" + e.getMessage() + "</div>\n";
             }
+        }
 
-            final Date d = new Date();  // Now.
+        String res = "";
 
-            return fmt.format( d );
-        } catch( final IllegalArgumentException e ) {
-            final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-            throw new PluginException( rb.getString( "currenttimeplugin.badformat" ) + e.getMessage() );
+        if ( results != null ) {
+            res = renderResults(results,context,maxItems);
         }
+
+        return res;
     }
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: return fmt.format( d );
A +: return TextUtil.replaceEntities( fmt.format( d ) ); / 
B -: return "<div class='error'>" + e.getMessage() + "</div>\n";
B +: return "<div class='error'>" + TextUtil.replaceEntities(e.getMessage()) + "</div>\n";
```
</details>

### 2022-46907::FormOpen.java::execute  <->  2022-46907::Search.java::execute

- muc: **khong trung** | Jaccard AST: 0.218 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.041 | fix_removed_sim 0.0
- API chung trong fix: replaceEntities | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,54 +1,31 @@
 @Override
-    public String execute( final Context ctx, final Map< String, String > params ) throws PluginException {
-        final ResourceBundle rb = Preferences.getBundle( ctx, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-        final String formName = params.get( PARAM_FORM );
-        if( formName == null ) {
-            throw new PluginException( MessageFormat.format( rb.getString( "formopen.missingparam" ), PARAM_FORM ) );
-        }
-        final String hide     = params.get( PARAM_HIDEFORM );
-        final String sourcePage = ctx.getPage().getName();
-        String submitServlet = params.get( PARAM_SUBMITHANDLER );
-        if( submitServlet == null )
-            submitServlet = ctx.getURL( ContextEnum.PAGE_VIEW.getRequestContext(), sourcePage );
+    public String execute( final Context context, final Map<String, String> params ) throws PluginException {
+        int maxItems = Integer.MAX_VALUE;
+        final Collection< SearchResult > results;
 
-        String method = params.get( PARAM_METHOD );
-        if( method == null ) {
-            method="post";
+        final String queryString = params.get( PARAM_QUERY );
+        String set               = params.get( PARAM_SET );
+        final String max         = params.get( PARAM_MAX );
+
+        if ( set == null ) set = DEFAULT_SETNAME;
+        if ( max != null ) maxItems = Integer.parseInt( max );
+
+        if ( queryString == null ) {
+            results = context.getVariable( set );
+        } else {
+            try {
+                results = doBasicQuery( context, queryString );
+                context.setVariable( set, results );
+            } catch( final Exception e ) {
+                return "<div class='error'>" + e.getMessage() + "</div>\n";
+            }
         }
 
-        if( !( method.equalsIgnoreCase( "get" ) || method.equalsIgnoreCase( "post" ) ) ) {
-            throw new PluginException( rb.getString( "formopen.postorgetonly" ) );
+        String res = "";
+
+        if ( results != null ) {
+            res = renderResults(results,context,maxItems);
         }
 
-        FormInfo info = getFormInfo( ctx );
-        if( info != null ) {
-            // Previous information may be the result of submitting
-            // this form, or of a FormSet plugin, or both. If it
-            // exists and is for this form, fine.
-            if( formName.equals( info.getName() ) ) {
-                LOG.debug( "Previous FormInfo for this form was found in context." );
-                // If the FormInfo exists, and if we're supposed to display on error only, we need to exit now.
-                if( HIDE_SUCCESS.equals( hide ) && info.getStatus() == FormInfo.EXECUTED ) {
-                    info.setHide( true );
-                    return "<p>" + rb.getString( "formopen.noneedtoshow" ) + "</p>";
-                }
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: final String formName = params.get( PARAM_FORM ); / String submitServlet = params.get( PARAM_SUBMITHANDLER );
A +: final String formName = TextUtil.replaceEntities( params.get( PARAM_FORM ) ); / String submitServlet = TextUtil.replaceEntities( params.get( PARAM_SUBMITHANDLER ) );
B -: return "<div class='error'>" + e.getMessage() + "</div>\n";
B +: return "<div class='error'>" + TextUtil.replaceEntities(e.getMessage()) + "</div>\n";
```
</details>

### 2022-46907::FormOpen.java::execute  <->  2022-46907::CurrentTimePlugin.java::execute

- muc: **khong trung** | Jaccard AST: 0.205 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.103 | fix_removed_sim 0.0
- API chung trong fix: replaceEntities | API chung trong ma loi: getBundle;getString;new PluginException
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,54 +1,20 @@
 @Override
-    public String execute( final Context ctx, final Map< String, String > params ) throws PluginException {
-        final ResourceBundle rb = Preferences.getBundle( ctx, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-        final String formName = params.get( PARAM_FORM );
-        if( formName == null ) {
-            throw new PluginException( MessageFormat.format( rb.getString( "formopen.missingparam" ), PARAM_FORM ) );
+    public String execute( final Context context, final Map< String, String > params ) throws PluginException {
+        final String formatString = params.get( "format" );
+
+        try {
+            final SimpleDateFormat fmt;
+            if( formatString != null ) {
+                fmt = new SimpleDateFormat( formatString );
+            } else {
+                fmt = Preferences.getDateFormat( context, TimeFormat.DATETIME );
+            }
+
+            final Date d = new Date();  // Now.
+
+            return fmt.format( d );
+        } catch( final IllegalArgumentException e ) {
+            final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
+            throw new PluginException( rb.getString( "currenttimeplugin.badformat" ) + e.getMessage() );
         }
-        final String hide     = params.get( PARAM_HIDEFORM );
-        final String sourcePage = ctx.getPage().getName();
-        String submitServlet = params.get( PARAM_SUBMITHANDLER );
-        if( submitServlet == null )
-            submitServlet = ctx.getURL( ContextEnum.PAGE_VIEW.getRequestContext(), sourcePage );
-
-        String method = params.get( PARAM_METHOD );
-        if( method == null ) {
-            method="post";
-        }
-
-        if( !( method.equalsIgnoreCase( "get" ) || method.equalsIgnoreCase( "post" ) ) ) {
-            throw new PluginException( rb.getString( "formopen.postorgetonly" ) );
-        }
-
-        FormInfo info = getFormInfo( ctx );
-        if( info != null ) {
-            // Previous information may be the result of submitting
-            // this form, or of a FormSet plugin, or both. If it
-            // exists and is for this form, fine.
-            if( formName.equals( info.getName() ) ) {
-                LOG.debug( "Previous FormInfo for this form was found in context." );
-                // If the FormInfo exists, and if we're supposed to display on error only, we need to exit now.
-                if( HIDE_SUCCESS.equals( hide ) && info.getStatus() == FormInfo.EXECUTED ) {
-                    info.setHide( true );
-                    return "<p>" + rb.getString( "formopen.noneedtoshow" ) + "</p>";
-                }
-            } else {
-                // This would mean that a new form was started without closing an old one.  Get rid of the garbage.
-                info = new FormInfo();
-            }
-        } else {
-            // No previous FormInfo available; store now, so it'll be available for upcoming Form input elements.
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: final String formName = params.get( PARAM_FORM ); / String submitServlet = params.get( PARAM_SUBMITHANDLER );
A +: final String formName = TextUtil.replaceEntities( params.get( PARAM_FORM ) ); / String submitServlet = TextUtil.replaceEntities( params.get( PARAM_SUBMITHANDLER ) );
B -: return fmt.format( d );
B +: return TextUtil.replaceEntities( fmt.format( d ) ); / 
```
</details>

### 2022-46907::FormOpen.java::execute  <->  2022-46907::BugReportHandler.java::execute

- muc: **khong trung** | Jaccard AST: 0.204 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.2 | fix_removed_sim 0.067
- API chung trong fix: replaceEntities | API chung trong ma loi: getBundle;getEngine;getString;new PluginException
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,54 +1,85 @@
 @Override
-    public String execute( final Context ctx, final Map< String, String > params ) throws PluginException {
-        final ResourceBundle rb = Preferences.getBundle( ctx, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-        final String formName = params.get( PARAM_FORM );
-        if( formName == null ) {
-            throw new PluginException( MessageFormat.format( rb.getString( "formopen.missingparam" ), PARAM_FORM ) );
-        }
-        final String hide     = params.get( PARAM_HIDEFORM );
-        final String sourcePage = ctx.getPage().getName();
-        String submitServlet = params.get( PARAM_SUBMITHANDLER );
-        if( submitServlet == null )
-            submitServlet = ctx.getURL( ContextEnum.PAGE_VIEW.getRequestContext(), sourcePage );
+    public String execute( final Context context, final Map< String, String > params ) throws PluginException {
+        final String title = params.get( PARAM_TITLE );
+        String description = params.get( PARAM_DESCRIPTION );
+        String version = params.get( PARAM_VERSION );
+        String submitter = null;
+        final SimpleDateFormat format = new SimpleDateFormat( DEFAULT_DATEFORMAT );
+        final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
+        final Principal wup = context.getCurrentUser();
 
-        String method = params.get( PARAM_METHOD );
-        if( method == null ) {
-            method="post";
+        if( wup != null ) {
+            submitter = wup.getName();
         }
 
-        if( !( method.equalsIgnoreCase( "get" ) || method.equalsIgnoreCase( "post" ) ) ) {
-            throw new PluginException( rb.getString( "formopen.postorgetonly" ) );
+        if( title == null ) {
+            throw new PluginException(rb.getString("bugreporthandler.titlerequired"));
+        }
+        if( title.isEmpty() ) {
+            return "";
         }
 
-        FormInfo info = getFormInfo( ctx );
-        if( info != null ) {
-            // Previous information may be the result of submitting
-            // this form, or of a FormSet plugin, or both. If it
-            // exists and is for this form, fine.
-            if( formName.equals( info.getName() ) ) {
-                LOG.debug( "Previous FormInfo for this form was found in context." );
-                // If the FormInfo exists, and if we're supposed to display on error only, we need to exit now.
-                if( HIDE_SUCCESS.equals( hide ) && info.getStatus() == FormInfo.EXECUTED ) {
-                    info.setHide( true );
-                    return "<p>" + rb.getString( "formopen.noneedtoshow" ) + "</p>";
-                }
-            } else {
-                // This would mean that a new form was started without closing an old one.  Get rid of the garbage.
-                info = new FormInfo();
-            }
-        } else {
-            // No previous FormInfo available; store now, so it'll be available for upcoming Form input elements.
-            info = new FormInfo();
-            storeFormInfo( ctx, info );
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: final String formName = params.get( PARAM_FORM ); / String submitServlet = params.get( PARAM_SUBMITHANDLER );
A +: final String formName = TextUtil.replaceEntities( params.get( PARAM_FORM ) ); / String submitServlet = TextUtil.replaceEntities( params.get( PARAM_SUBMITHANDLER ) );
B -: final String pageName = findNextPage( context, title, params.get( PARAM_PAGE ) );
B +: final String pageName = findNextPage( context, title, TextUtil.replaceEntities(params.get( PARAM_PAGE )) );
```
</details>

### 2022-46907::BugReportHandler.java::execute  <->  2022-46907::CurrentTimePlugin.java::execute

- muc: **khong trung** | Jaccard AST: 0.196 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.103 | fix_removed_sim 0.0
- API chung trong fix: replaceEntities | API chung trong ma loi: getBundle;getString;new Date;new PluginException;new SimpleDateFormat
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -2,83 +2,18 @@
     public String execute( final Context context, final Map< String, String > params ) throws PluginException {
-        final String title = params.get( PARAM_TITLE );
-        String description = params.get( PARAM_DESCRIPTION );
-        String version = params.get( PARAM_VERSION );
-        String submitter = null;
-        final SimpleDateFormat format = new SimpleDateFormat( DEFAULT_DATEFORMAT );
-        final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-        final Principal wup = context.getCurrentUser();
+        final String formatString = params.get( "format" );
 
-        if( wup != null ) {
-            submitter = wup.getName();
-        }
-
-        if( title == null ) {
-            throw new PluginException(rb.getString("bugreporthandler.titlerequired"));
-        }
-        if( title.isEmpty() ) {
-            return "";
-        }
-
-        if( description == null ) {
-            description = "";
-        }
-        if( version == null ) {
-            version = "unknown";
-        }
-
-        final Properties mappings = parseMappings( params.get( PARAM_MAPPINGS ) );
-
-        //  Start things
         try {
-            final StringWriter str = new StringWriter();
-            final PrintWriter out = new PrintWriter( str );
-            final Date d = new Date();
-
-            //  Outputting of basic data
-            out.println( "|" + mappings.getProperty(PARAM_TITLE,"Title" ) + "|" + title );
-            out.println( "|" + mappings.getProperty("date","Date" ) + "|" + format.format( d ) );
-            out.println( "|" + mappings.getProperty(PARAM_VERSION,"Version" ) + "|" + version );
-            if( submitter != null ) {
-                out.println("|"+mappings.getProperty("submitter","Submitter") + "|" + submitter );
+            final SimpleDateFormat fmt;
+            if( formatString != null ) {
+                fmt = new SimpleDateFormat( formatString );
+            } else {
+                fmt = Preferences.getDateFormat( context, TimeFormat.DATETIME );
             }
 
-            //  Outputting the other parameters added to this.
-            for( final Map.Entry< String, String > entry : params.entrySet() ) {
-                if( !( entry.getKey().equals( PARAM_TITLE ) ||
-                       entry.getKey().equals( PARAM_DESCRIPTION ) ||
-                       entry.getKey().equals( PARAM_VERSION ) ||
-                       entry.getKey().equals( PARAM_MAPPINGS ) ||
-                       entry.getKey().equals( PARAM_PAGE ) ||
-                       entry.getKey().startsWith( "_" )
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: final String pageName = findNextPage( context, title, params.get( PARAM_PAGE ) );
A +: final String pageName = findNextPage( context, title, TextUtil.replaceEntities(params.get( PARAM_PAGE )) );
B -: return fmt.format( d );
B +: return TextUtil.replaceEntities( fmt.format( d ) ); / 
```
</details>

### 2022-46907::FormOutput.java::execute  <->  2022-46907::Search.java::execute

- muc: **khong trung** | Jaccard AST: 0.187 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.04 | fix_removed_sim 0.0
- API chung trong fix: replaceEntities | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,79 +1,31 @@
 @Override
-    public String execute( final Context ctx, final Map< String, String > params ) throws PluginException {
-        //  If there is no HTTP request, returns immediately.
-        if( ctx.getHttpRequest() == null ) {
-            return "";
-        }
-        final ResourceBundle rb = Preferences.getBundle( ctx, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-        
-        // If we are NOT here due to this form being submitted, we do nothing.
-        // The submitted form MUST have parameter 'formname' equal to the name
-        // parameter of this Form plugin.
+    public String execute( final Context context, final Map<String, String> params ) throws PluginException {
+        int maxItems = Integer.MAX_VALUE;
+        final Collection< SearchResult > results;
 
-        final String formName   = params.get( PARAM_FORM );
-        final String submitForm = ctx.getHttpParameter( PARAM_FORMNAMEHIDDEN );
-        final String populator  = params.get( PARAM_POPULATE );
+        final String queryString = params.get( PARAM_QUERY );
+        String set               = params.get( PARAM_SET );
+        final String max         = params.get( PARAM_MAX );
 
-        if( formName == null || !formName.equals( submitForm ) ) {
-            // No submitForm -> this was not a submission from the
-            // generated form.  If populate is specified, we'll go
-            // ahead and let the handler (populator) put stuff into
-            // the context, otherwise we'll just hide.
-            if( !PARAM_HANDLER.equals( populator ) )
-                return "";
-            // If population was allowed, we should first  
+        if ( set == null ) set = DEFAULT_SETNAME;
+        if ( max != null ) maxItems = Integer.parseInt( max );
+
+        if ( queryString == null ) {
+            results = context.getVariable( set );
+        } else {
+            try {
+                results = doBasicQuery( context, queryString );
+                context.setVariable( set, results );
+            } catch( final Exception e ) {
+                return "<div class='error'>" + e.getMessage() + "</div>\n";
+            }
         }
 
-        final String handler = params.get( PARAM_HANDLER );
-        if( handler == null || handler.isEmpty() ) {
-            // Need to print out an error here as this form is misconfigured
-            return "<p class=\"error\">" + MessageFormat.format( rb.getString( "formoutput.missingargument" ), PARAM_HANDLER ) + "</p>";
+        String res = "";
+
+        if ( results != null ) {
+            res = renderResults(results,context,maxItems);
         }
 
-        final String sourcePage = ctx.getPage().getName();
-        final String submitServlet = ctx.getURL( ContextEnum.PAGE_VIEW.getRequestContext(), sourcePage );
-
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -:  / final String formName   = params.get( PARAM_FORM ); / // If population was allowed, we should first / final String handler = params.get( PARAM_HANDLER );
A +:  / final String formName   = TextUtil.replaceEntities( params.get( PARAM_FORM ) ); / // If population was allowed, we should first / final String handler = TextUtil.replaceEntities( params.get( PARAM_HANDLER ) );
B -: return "<div class='error'>" + e.getMessage() + "</div>\n";
B +: return "<div class='error'>" + TextUtil.replaceEntities(e.getMessage()) + "</div>\n";
```
</details>

### 2022-46907::BugReportHandler.java::execute  <->  2022-46907::InsertPage.java::execute

- muc: **khong trung** | Jaccard AST: 0.172 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.163 | fix_removed_sim 0.053
- API chung trong fix: replaceEntities | API chung trong ma loi: clone;getBundle;getEngine;getManager;getString;new PluginException;setPage
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,85 +1,130 @@
-@Override
-    public String execute( final Context context, final Map< String, String > params ) throws PluginException {
-        final String title = params.get( PARAM_TITLE );
-        String description = params.get( PARAM_DESCRIPTION );
-        String version = params.get( PARAM_VERSION );
-        String submitter = null;
-        final SimpleDateFormat format = new SimpleDateFormat( DEFAULT_DATEFORMAT );
+@Override @SuppressWarnings("unchecked")
+    public String execute( final Context context, final Map<String, String> params ) throws PluginException {
+        final Engine engine = context.getEngine();
+
+        final StringBuilder res = new StringBuilder();
+
+        final String clazz        = params.get( PARAM_CLASS );
+        final String includedPage = params.get( PARAM_PAGENAME );
+        String style              = params.get( PARAM_STYLE );
+        final boolean showOnce    = "once".equals( params.get( PARAM_SHOW ) );
+        final String defaultstr   = params.get( PARAM_DEFAULT );
+        final int section         = TextUtil.parseIntParameter(params.get( PARAM_SECTION ), -1 );
+        int maxlen                = TextUtil.parseIntParameter(params.get( PARAM_MAXLENGTH ), -1 );
+
         final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-        final Principal wup = context.getCurrentUser();
 
-        if( wup != null ) {
-            submitter = wup.getName();
+        if( style == null ) {
+            style = DEFAULT_STYLE;
         }
 
-        if( title == null ) {
-            throw new PluginException(rb.getString("bugreporthandler.titlerequired"));
-        }
-        if( title.isEmpty() ) {
-            return "";
+        if( maxlen == -1 ) {
+            maxlen = Integer.MAX_VALUE;
         }
 
-        if( description == null ) {
-            description = "";
-        }
-        if( version == null ) {
-            version = "unknown";
-        }
-
-        final Properties mappings = parseMappings( params.get( PARAM_MAPPINGS ) );
-
-        //  Start things
-        try {
-            final StringWriter str = new StringWriter();
-            final PrintWriter out = new PrintWriter( str );
-            final Date d = new Date();
-
-            //  Outputting of basic data
-            out.println( "|" + mappings.getProperty(PARAM_TITLE,"Title" ) + "|" + title );
-            out.println( "|" + mappings.getProperty("date","Date" ) + "|" + format.format( d ) );
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: final String pageName = findNextPage( context, title, params.get( PARAM_PAGE ) );
A +: final String pageName = findNextPage( context, title, TextUtil.replaceEntities(params.get( PARAM_PAGE )) );
B -: final String clazz        = params.get( PARAM_CLASS ); / final String includedPage = params.get( PARAM_PAGENAME ); / String style              = params.get( PARAM_STYLE );
B +: final String clazz        = TextUtil.replaceEntities(params.get( PARAM_CLASS )); / final String includedPage = TextUtil.replaceEntities(params.get( PARAM_PAGENAME )); / String style              = TextUtil.replaceEntities(params.get( PARAM_STYLE ));
```
</details>

### 2022-46907::FormOutput.java::execute  <->  2022-46907::BugReportHandler.java::execute

- muc: **khong trung** | Jaccard AST: 0.17 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.194 | fix_removed_sim 0.065
- API chung trong fix: replaceEntities | API chung trong ma loi: getBundle;getEngine;getManager;getString
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,79 +1,85 @@
 @Override
-    public String execute( final Context ctx, final Map< String, String > params ) throws PluginException {
-        //  If there is no HTTP request, returns immediately.
-        if( ctx.getHttpRequest() == null ) {
+    public String execute( final Context context, final Map< String, String > params ) throws PluginException {
+        final String title = params.get( PARAM_TITLE );
+        String description = params.get( PARAM_DESCRIPTION );
+        String version = params.get( PARAM_VERSION );
+        String submitter = null;
+        final SimpleDateFormat format = new SimpleDateFormat( DEFAULT_DATEFORMAT );
+        final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
+        final Principal wup = context.getCurrentUser();
+
+        if( wup != null ) {
+            submitter = wup.getName();
+        }
+
+        if( title == null ) {
+            throw new PluginException(rb.getString("bugreporthandler.titlerequired"));
+        }
+        if( title.isEmpty() ) {
             return "";
         }
-        final ResourceBundle rb = Preferences.getBundle( ctx, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-        
-        // If we are NOT here due to this form being submitted, we do nothing.
-        // The submitted form MUST have parameter 'formname' equal to the name
-        // parameter of this Form plugin.
 
-        final String formName   = params.get( PARAM_FORM );
-        final String submitForm = ctx.getHttpParameter( PARAM_FORMNAMEHIDDEN );
-        final String populator  = params.get( PARAM_POPULATE );
-
-        if( formName == null || !formName.equals( submitForm ) ) {
-            // No submitForm -> this was not a submission from the
-            // generated form.  If populate is specified, we'll go
-            // ahead and let the handler (populator) put stuff into
-            // the context, otherwise we'll just hide.
-            if( !PARAM_HANDLER.equals( populator ) )
-                return "";
-            // If population was allowed, we should first  
+        if( description == null ) {
+            description = "";
+        }
+        if( version == null ) {
+            version = "unknown";
         }
 
-        final String handler = params.get( PARAM_HANDLER );
-        if( handler == null || handler.isEmpty() ) {
-            // Need to print out an error here as this form is misconfigured
-            return "<p class=\"error\">" + MessageFormat.format( rb.getString( "formoutput.missingargument" ), PARAM_HANDLER ) + "</p>";
+        final Properties mappings = parseMappings( params.get( PARAM_MAPPINGS ) );
+
+        //  Start things
+        try {
+            final StringWriter str = new StringWriter();
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -:  / final String formName   = params.get( PARAM_FORM ); / // If population was allowed, we should first / final String handler = params.get( PARAM_HANDLER );
A +:  / final String formName   = TextUtil.replaceEntities( params.get( PARAM_FORM ) ); / // If population was allowed, we should first / final String handler = TextUtil.replaceEntities( params.get( PARAM_HANDLER ) );
B -: final String pageName = findNextPage( context, title, params.get( PARAM_PAGE ) );
B +: final String pageName = findNextPage( context, title, TextUtil.replaceEntities(params.get( PARAM_PAGE )) );
```
</details>

### 2022-46907::FormOutput.java::execute  <->  2022-46907::CurrentTimePlugin.java::execute

- muc: **khong trung** | Jaccard AST: 0.17 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.1 | fix_removed_sim 0.0
- API chung trong fix: replaceEntities | API chung trong ma loi: getBundle;getString
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,79 +1,20 @@
 @Override
-    public String execute( final Context ctx, final Map< String, String > params ) throws PluginException {
-        //  If there is no HTTP request, returns immediately.
-        if( ctx.getHttpRequest() == null ) {
-            return "";
+    public String execute( final Context context, final Map< String, String > params ) throws PluginException {
+        final String formatString = params.get( "format" );
+
+        try {
+            final SimpleDateFormat fmt;
+            if( formatString != null ) {
+                fmt = new SimpleDateFormat( formatString );
+            } else {
+                fmt = Preferences.getDateFormat( context, TimeFormat.DATETIME );
+            }
+
+            final Date d = new Date();  // Now.
+
+            return fmt.format( d );
+        } catch( final IllegalArgumentException e ) {
+            final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
+            throw new PluginException( rb.getString( "currenttimeplugin.badformat" ) + e.getMessage() );
         }
-        final ResourceBundle rb = Preferences.getBundle( ctx, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-        
-        // If we are NOT here due to this form being submitted, we do nothing.
-        // The submitted form MUST have parameter 'formname' equal to the name
-        // parameter of this Form plugin.
-
-        final String formName   = params.get( PARAM_FORM );
-        final String submitForm = ctx.getHttpParameter( PARAM_FORMNAMEHIDDEN );
-        final String populator  = params.get( PARAM_POPULATE );
-
-        if( formName == null || !formName.equals( submitForm ) ) {
-            // No submitForm -> this was not a submission from the
-            // generated form.  If populate is specified, we'll go
-            // ahead and let the handler (populator) put stuff into
-            // the context, otherwise we'll just hide.
-            if( !PARAM_HANDLER.equals( populator ) )
-                return "";
-            // If population was allowed, we should first  
-        }
-
-        final String handler = params.get( PARAM_HANDLER );
-        if( handler == null || handler.isEmpty() ) {
-            // Need to print out an error here as this form is misconfigured
-            return "<p class=\"error\">" + MessageFormat.format( rb.getString( "formoutput.missingargument" ), PARAM_HANDLER ) + "</p>";
-        }
-
-        final String sourcePage = ctx.getPage().getName();
-        final String submitServlet = ctx.getURL( ContextEnum.PAGE_VIEW.getRequestContext(), sourcePage );
-
-        // If there is previous FormInfo available - say, from a
-        // FormSet plugin - use it.
-        FormInfo info = getFormInfo( ctx );
-        if( info == null ) {
-            // Reconstruct the form info from post data
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -:  / final String formName   = params.get( PARAM_FORM ); / // If population was allowed, we should first / final String handler = params.get( PARAM_HANDLER );
A +:  / final String formName   = TextUtil.replaceEntities( params.get( PARAM_FORM ) ); / // If population was allowed, we should first / final String handler = TextUtil.replaceEntities( params.get( PARAM_HANDLER ) );
B -: return fmt.format( d );
B +: return TextUtil.replaceEntities( fmt.format( d ) ); / 
```
</details>

### 2022-46907::FormOpen.java::execute  <->  2022-46907::InsertPage.java::execute

- muc: **khong trung** | Jaccard AST: 0.167 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.22 | fix_removed_sim 0.111
- API chung trong fix: replaceEntities | API chung trong ma loi: getBundle;getEngine;getPage;getRequestContext;getString;getURL;getWikiSession;new PluginException
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,54 +1,130 @@
-@Override
-    public String execute( final Context ctx, final Map< String, String > params ) throws PluginException {
-        final ResourceBundle rb = Preferences.getBundle( ctx, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-        final String formName = params.get( PARAM_FORM );
-        if( formName == null ) {
-            throw new PluginException( MessageFormat.format( rb.getString( "formopen.missingparam" ), PARAM_FORM ) );
-        }
-        final String hide     = params.get( PARAM_HIDEFORM );
-        final String sourcePage = ctx.getPage().getName();
-        String submitServlet = params.get( PARAM_SUBMITHANDLER );
-        if( submitServlet == null )
-            submitServlet = ctx.getURL( ContextEnum.PAGE_VIEW.getRequestContext(), sourcePage );
+@Override @SuppressWarnings("unchecked")
+    public String execute( final Context context, final Map<String, String> params ) throws PluginException {
+        final Engine engine = context.getEngine();
 
-        String method = params.get( PARAM_METHOD );
-        if( method == null ) {
-            method="post";
+        final StringBuilder res = new StringBuilder();
+
+        final String clazz        = params.get( PARAM_CLASS );
+        final String includedPage = params.get( PARAM_PAGENAME );
+        String style              = params.get( PARAM_STYLE );
+        final boolean showOnce    = "once".equals( params.get( PARAM_SHOW ) );
+        final String defaultstr   = params.get( PARAM_DEFAULT );
+        final int section         = TextUtil.parseIntParameter(params.get( PARAM_SECTION ), -1 );
+        int maxlen                = TextUtil.parseIntParameter(params.get( PARAM_MAXLENGTH ), -1 );
+
+        final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
+
+        if( style == null ) {
+            style = DEFAULT_STYLE;
         }
 
-        if( !( method.equalsIgnoreCase( "get" ) || method.equalsIgnoreCase( "post" ) ) ) {
-            throw new PluginException( rb.getString( "formopen.postorgetonly" ) );
+        if( maxlen == -1 ) {
+            maxlen = Integer.MAX_VALUE;
         }
 
-        FormInfo info = getFormInfo( ctx );
-        if( info != null ) {
-            // Previous information may be the result of submitting
-            // this form, or of a FormSet plugin, or both. If it
-            // exists and is for this form, fine.
-            if( formName.equals( info.getName() ) ) {
-                LOG.debug( "Previous FormInfo for this form was found in context." );
-                // If the FormInfo exists, and if we're supposed to display on error only, we need to exit now.
-                if( HIDE_SUCCESS.equals( hide ) && info.getStatus() == FormInfo.EXECUTED ) {
-                    info.setHide( true );
-                    return "<p>" + rb.getString( "formopen.noneedtoshow" ) + "</p>";
+        if( includedPage != null ) {
+            final Page page;
+            try {
+                final String pageName = engine.getFinalPageName( includedPage );
+                if( pageName != null ) {
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: final String formName = params.get( PARAM_FORM ); / String submitServlet = params.get( PARAM_SUBMITHANDLER );
A +: final String formName = TextUtil.replaceEntities( params.get( PARAM_FORM ) ); / String submitServlet = TextUtil.replaceEntities( params.get( PARAM_SUBMITHANDLER ) );
B -: final String clazz        = params.get( PARAM_CLASS ); / final String includedPage = params.get( PARAM_PAGENAME ); / String style              = params.get( PARAM_STYLE );
B +: final String clazz        = TextUtil.replaceEntities(params.get( PARAM_CLASS )); / final String includedPage = TextUtil.replaceEntities(params.get( PARAM_PAGENAME )); / String style              = TextUtil.replaceEntities(params.get( PARAM_STYLE ));
```
</details>

### 2022-46907::InsertPage.java::execute  <->  2022-46907::Search.java::execute

- muc: **khong trung** | Jaccard AST: 0.151 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.035 | fix_removed_sim 0.0
- API chung trong fix: replaceEntities | API chung trong ma loi: getVariable;setVariable
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,130 +1,31 @@
-@Override @SuppressWarnings("unchecked")
+@Override
     public String execute( final Context context, final Map<String, String> params ) throws PluginException {
-        final Engine engine = context.getEngine();
+        int maxItems = Integer.MAX_VALUE;
+        final Collection< SearchResult > results;
 
-        final StringBuilder res = new StringBuilder();
+        final String queryString = params.get( PARAM_QUERY );
+        String set               = params.get( PARAM_SET );
+        final String max         = params.get( PARAM_MAX );
 
-        final String clazz        = params.get( PARAM_CLASS );
-        final String includedPage = params.get( PARAM_PAGENAME );
-        String style              = params.get( PARAM_STYLE );
-        final boolean showOnce    = "once".equals( params.get( PARAM_SHOW ) );
-        final String defaultstr   = params.get( PARAM_DEFAULT );
-        final int section         = TextUtil.parseIntParameter(params.get( PARAM_SECTION ), -1 );
-        int maxlen                = TextUtil.parseIntParameter(params.get( PARAM_MAXLENGTH ), -1 );
+        if ( set == null ) set = DEFAULT_SETNAME;
+        if ( max != null ) maxItems = Integer.parseInt( max );
 
-        final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-
-        if( style == null ) {
-            style = DEFAULT_STYLE;
+        if ( queryString == null ) {
+            results = context.getVariable( set );
+        } else {
+            try {
+                results = doBasicQuery( context, queryString );
+                context.setVariable( set, results );
+            } catch( final Exception e ) {
+                return "<div class='error'>" + e.getMessage() + "</div>\n";
+            }
         }
 
-        if( maxlen == -1 ) {
-            maxlen = Integer.MAX_VALUE;
+        String res = "";
+
+        if ( results != null ) {
+            res = renderResults(results,context,maxItems);
         }
 
-        if( includedPage != null ) {
-            final Page page;
-            try {
-                final String pageName = engine.getFinalPageName( includedPage );
-                if( pageName != null ) {
-                    page = engine.getManager( PageManager.class ).getPage( pageName );
-                } else {
-                    page = engine.getManager( PageManager.class ).getPage( includedPage );
-                }
-            } catch( final ProviderException e ) {
-                res.append( "<span class=\"error\">Page could not be found by the page provider.</span>" );
-                return res.toString();
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: final String clazz        = params.get( PARAM_CLASS ); / final String includedPage = params.get( PARAM_PAGENAME ); / String style              = params.get( PARAM_STYLE );
A +: final String clazz        = TextUtil.replaceEntities(params.get( PARAM_CLASS )); / final String includedPage = TextUtil.replaceEntities(params.get( PARAM_PAGENAME )); / String style              = TextUtil.replaceEntities(params.get( PARAM_STYLE ));
B -: return "<div class='error'>" + e.getMessage() + "</div>\n";
B +: return "<div class='error'>" + TextUtil.replaceEntities(e.getMessage()) + "</div>\n";
```
</details>

### 2022-46907::FormOutput.java::execute  <->  2022-46907::InsertPage.java::execute

- muc: **khong trung** | Jaccard AST: 0.148 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.244 | fix_removed_sim 0.139
- API chung trong fix: replaceEntities | API chung trong ma loi: getBundle;getEngine;getHttpRequest;getManager;getPage;getRequestContext;getString;getURL
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,79 +1,130 @@
-@Override
-    public String execute( final Context ctx, final Map< String, String > params ) throws PluginException {
-        //  If there is no HTTP request, returns immediately.
-        if( ctx.getHttpRequest() == null ) {
-            return "";
-        }
-        final ResourceBundle rb = Preferences.getBundle( ctx, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-        
-        // If we are NOT here due to this form being submitted, we do nothing.
-        // The submitted form MUST have parameter 'formname' equal to the name
-        // parameter of this Form plugin.
+@Override @SuppressWarnings("unchecked")
+    public String execute( final Context context, final Map<String, String> params ) throws PluginException {
+        final Engine engine = context.getEngine();
 
-        final String formName   = params.get( PARAM_FORM );
-        final String submitForm = ctx.getHttpParameter( PARAM_FORMNAMEHIDDEN );
-        final String populator  = params.get( PARAM_POPULATE );
+        final StringBuilder res = new StringBuilder();
 
-        if( formName == null || !formName.equals( submitForm ) ) {
-            // No submitForm -> this was not a submission from the
-            // generated form.  If populate is specified, we'll go
-            // ahead and let the handler (populator) put stuff into
-            // the context, otherwise we'll just hide.
-            if( !PARAM_HANDLER.equals( populator ) )
-                return "";
-            // If population was allowed, we should first  
+        final String clazz        = params.get( PARAM_CLASS );
+        final String includedPage = params.get( PARAM_PAGENAME );
+        String style              = params.get( PARAM_STYLE );
+        final boolean showOnce    = "once".equals( params.get( PARAM_SHOW ) );
+        final String defaultstr   = params.get( PARAM_DEFAULT );
+        final int section         = TextUtil.parseIntParameter(params.get( PARAM_SECTION ), -1 );
+        int maxlen                = TextUtil.parseIntParameter(params.get( PARAM_MAXLENGTH ), -1 );
+
+        final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
+
+        if( style == null ) {
+            style = DEFAULT_STYLE;
         }
 
-        final String handler = params.get( PARAM_HANDLER );
-        if( handler == null || handler.isEmpty() ) {
-            // Need to print out an error here as this form is misconfigured
-            return "<p class=\"error\">" + MessageFormat.format( rb.getString( "formoutput.missingargument" ), PARAM_HANDLER ) + "</p>";
+        if( maxlen == -1 ) {
+            maxlen = Integer.MAX_VALUE;
         }
 
-        final String sourcePage = ctx.getPage().getName();
-        final String submitServlet = ctx.getURL( ContextEnum.PAGE_VIEW.getRequestContext(), sourcePage );
+        if( includedPage != null ) {
+            final Page page;
+            try {
+                final String pageName = engine.getFinalPageName( includedPage );
+                if( pageName != null ) {
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -:  / final String formName   = params.get( PARAM_FORM ); / // If population was allowed, we should first / final String handler = params.get( PARAM_HANDLER );
A +:  / final String formName   = TextUtil.replaceEntities( params.get( PARAM_FORM ) ); / // If population was allowed, we should first / final String handler = TextUtil.replaceEntities( params.get( PARAM_HANDLER ) );
B -: final String clazz        = params.get( PARAM_CLASS ); / final String includedPage = params.get( PARAM_PAGENAME ); / String style              = params.get( PARAM_STYLE );
B +: final String clazz        = TextUtil.replaceEntities(params.get( PARAM_CLASS )); / final String includedPage = TextUtil.replaceEntities(params.get( PARAM_PAGENAME )); / String style              = TextUtil.replaceEntities(params.get( PARAM_STYLE ));
```
</details>

### 2022-46907::BugReportHandler.java::execute  <->  2022-46907::Search.java::execute

- muc: **khong trung** | Jaccard AST: 0.148 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.041 | fix_removed_sim 0.0
- API chung trong fix: replaceEntities | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,85 +1,31 @@
 @Override
-    public String execute( final Context context, final Map< String, String > params ) throws PluginException {
-        final String title = params.get( PARAM_TITLE );
-        String description = params.get( PARAM_DESCRIPTION );
-        String version = params.get( PARAM_VERSION );
-        String submitter = null;
-        final SimpleDateFormat format = new SimpleDateFormat( DEFAULT_DATEFORMAT );
-        final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-        final Principal wup = context.getCurrentUser();
+    public String execute( final Context context, final Map<String, String> params ) throws PluginException {
+        int maxItems = Integer.MAX_VALUE;
+        final Collection< SearchResult > results;
 
-        if( wup != null ) {
-            submitter = wup.getName();
+        final String queryString = params.get( PARAM_QUERY );
+        String set               = params.get( PARAM_SET );
+        final String max         = params.get( PARAM_MAX );
+
+        if ( set == null ) set = DEFAULT_SETNAME;
+        if ( max != null ) maxItems = Integer.parseInt( max );
+
+        if ( queryString == null ) {
+            results = context.getVariable( set );
+        } else {
+            try {
+                results = doBasicQuery( context, queryString );
+                context.setVariable( set, results );
+            } catch( final Exception e ) {
+                return "<div class='error'>" + e.getMessage() + "</div>\n";
+            }
         }
 
-        if( title == null ) {
-            throw new PluginException(rb.getString("bugreporthandler.titlerequired"));
-        }
-        if( title.isEmpty() ) {
-            return "";
+        String res = "";
+
+        if ( results != null ) {
+            res = renderResults(results,context,maxItems);
         }
 
-        if( description == null ) {
-            description = "";
-        }
-        if( version == null ) {
-            version = "unknown";
-        }
-
-        final Properties mappings = parseMappings( params.get( PARAM_MAPPINGS ) );
-
-        //  Start things
-        try {
-            final StringWriter str = new StringWriter();
-            final PrintWriter out = new PrintWriter( str );
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: final String pageName = findNextPage( context, title, params.get( PARAM_PAGE ) );
A +: final String pageName = findNextPage( context, title, TextUtil.replaceEntities(params.get( PARAM_PAGE )) );
B -: return "<div class='error'>" + e.getMessage() + "</div>\n";
B +: return "<div class='error'>" + TextUtil.replaceEntities(e.getMessage()) + "</div>\n";
```
</details>

### 2019-10078::ReferredPagesPlugin.java::execute  <->  2022-46907::FormOpen.java::execute

- muc: **khong trung** | Jaccard AST: 0.144 | pham vi: inter_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.04 | fix_removed_sim 0.0
- API chung trong fix: replaceEntities | API chung trong ma loi: getEngine;getPage;new PluginException
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,80 +1,54 @@
-public String execute( WikiContext context, Map<String, String> params ) throws PluginException {
-        m_engine = context.getEngine();
+@Override
+    public String execute( final Context ctx, final Map< String, String > params ) throws PluginException {
+        final ResourceBundle rb = Preferences.getBundle( ctx, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
+        final String formName = params.get( PARAM_FORM );
+        if( formName == null ) {
+            throw new PluginException( MessageFormat.format( rb.getString( "formopen.missingparam" ), PARAM_FORM ) );
+        }
+        final String hide     = params.get( PARAM_HIDEFORM );
+        final String sourcePage = ctx.getPage().getName();
+        String submitServlet = params.get( PARAM_SUBMITHANDLER );
+        if( submitServlet == null )
+            submitServlet = ctx.getURL( ContextEnum.PAGE_VIEW.getRequestContext(), sourcePage );
 
-        WikiPage         page   = context.getPage();
-        if( page == null ) return "";
-
-        // parse parameters
-        String rootname = params.get( PARAM_ROOT );
-        if( rootname == null ) rootname = page.getName() ;
-
-        String format = params.get( PARAM_FORMAT );
-        if( format == null) format = "";
-        if( format.indexOf( "full" ) >=0 ) m_formatCompact = false ;
-        if( format.indexOf( "sort" ) >=0 ) m_formatSort    = true  ;
-
-        m_depth = TextUtil.parseIntParameter( params.get( PARAM_DEPTH ), MIN_DEPTH );
-        if( m_depth > MAX_DEPTH )  m_depth = MAX_DEPTH;
-
-        String includePattern = params.get(PARAM_INCLUDE);
-        if( includePattern == null ) includePattern = ".*";
-
-        String excludePattern = params.get(PARAM_EXCLUDE);
-        if( excludePattern == null ) excludePattern = "^$";
-
-        log.debug( "Fetching referred pages for "+ rootname +
-                   " with a depth of "+ m_depth +
-                   " with include pattern of "+ includePattern +
-                   " with exclude pattern of "+ excludePattern );
-
-        //
-        // do the actual work
-        //
-        String href  = context.getViewURL(rootname);
-        String title = "ReferredPagesPlugin: depth["+m_depth+
-                       "] include["+includePattern+"] exclude["+excludePattern+
-                       "] format["+(m_formatCompact ? "compact" : "full") +
-                       (m_formatSort ? " sort" : "") + "]";
-
-        m_result.append("<div class=\"ReferredPagesPlugin\">\n");
-        m_result.append("<a class=\"wikipage\" href=\""+ href +
-                        "\" title=\"" + title +
-                        "\">" + rootname + "</a>\n");
-        m_exists.add(rootname);
-
-        // pre compile all needed patterns
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: "\" title=\"" + title + / "\">" + rootname + "</a>\n");
A +: "\" title=\"" + TextUtil.replaceEntities(title) + / "\">" + TextUtil.replaceEntities(rootname) + "</a>\n");
B -: final String formName = params.get( PARAM_FORM ); / String submitServlet = params.get( PARAM_SUBMITHANDLER );
B +: final String formName = TextUtil.replaceEntities( params.get( PARAM_FORM ) ); / String submitServlet = TextUtil.replaceEntities( params.get( PARAM_SUBMITHANDLER ) );
```
</details>

### 2022-46907::CurrentTimePlugin.java::execute  <->  2022-46907::InsertPage.java::execute

- muc: **khong trung** | Jaccard AST: 0.131 | pham vi: intra_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.081 | fix_removed_sim 0.0
- API chung trong fix: replaceEntities | API chung trong ma loi: getBundle;getString;new PluginException
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,20 +1,130 @@
-@Override
-    public String execute( final Context context, final Map< String, String > params ) throws PluginException {
-        final String formatString = params.get( "format" );
+@Override @SuppressWarnings("unchecked")
+    public String execute( final Context context, final Map<String, String> params ) throws PluginException {
+        final Engine engine = context.getEngine();
 
-        try {
-            final SimpleDateFormat fmt;
-            if( formatString != null ) {
-                fmt = new SimpleDateFormat( formatString );
-            } else {
-                fmt = Preferences.getDateFormat( context, TimeFormat.DATETIME );
+        final StringBuilder res = new StringBuilder();
+
+        final String clazz        = params.get( PARAM_CLASS );
+        final String includedPage = params.get( PARAM_PAGENAME );
+        String style              = params.get( PARAM_STYLE );
+        final boolean showOnce    = "once".equals( params.get( PARAM_SHOW ) );
+        final String defaultstr   = params.get( PARAM_DEFAULT );
+        final int section         = TextUtil.parseIntParameter(params.get( PARAM_SECTION ), -1 );
+        int maxlen                = TextUtil.parseIntParameter(params.get( PARAM_MAXLENGTH ), -1 );
+
+        final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
+
+        if( style == null ) {
+            style = DEFAULT_STYLE;
+        }
+
+        if( maxlen == -1 ) {
+            maxlen = Integer.MAX_VALUE;
+        }
+
+        if( includedPage != null ) {
+            final Page page;
+            try {
+                final String pageName = engine.getFinalPageName( includedPage );
+                if( pageName != null ) {
+                    page = engine.getManager( PageManager.class ).getPage( pageName );
+                } else {
+                    page = engine.getManager( PageManager.class ).getPage( includedPage );
+                }
+            } catch( final ProviderException e ) {
+                res.append( "<span class=\"error\">Page could not be found by the page provider.</span>" );
+                return res.toString();
             }
 
-            final Date d = new Date();  // Now.
+            if( page != null ) {
+                //  Check for recursivity
+                List<String> previousIncludes = context.getVariable( ATTR_RECURSE );
 
-            return fmt.format( d );
-        } catch( final IllegalArgumentException e ) {
-            final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
-            throw new PluginException( rb.getString( "currenttimeplugin.badformat" ) + e.getMessage() );
+                if( previousIncludes != null ) {
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: return fmt.format( d );
A +: return TextUtil.replaceEntities( fmt.format( d ) ); / 
B -: final String clazz        = params.get( PARAM_CLASS ); / final String includedPage = params.get( PARAM_PAGENAME ); / String style              = params.get( PARAM_STYLE );
B +: final String clazz        = TextUtil.replaceEntities(params.get( PARAM_CLASS )); / final String includedPage = TextUtil.replaceEntities(params.get( PARAM_PAGENAME )); / String style              = TextUtil.replaceEntities(params.get( PARAM_STYLE ));
```
</details>

### 2019-10078::ReferredPagesPlugin.java::execute  <->  2022-46907::Search.java::execute

- muc: **khong trung** | Jaccard AST: 0.124 | pham vi: inter_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.196 | fix_removed_sim 0.109
- API chung trong fix: replaceEntities | API chung trong ma loi: -
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,70 +1,21 @@
-public String execute( WikiContext context, Map<String, String> params ) throws PluginException {
-        m_engine = context.getEngine();
+@Override
+    public String execute( final Context context, final Map<String, String> params ) throws PluginException {
+        int maxItems = Integer.MAX_VALUE;
+        final Collection< SearchResult > results;
 
-        WikiPage         page   = context.getPage();
-        if( page == null ) return "";
+        final String queryString = params.get( PARAM_QUERY );
+        String set               = params.get( PARAM_SET );
+        final String max         = params.get( PARAM_MAX );
 
-        // parse parameters
-        String rootname = params.get( PARAM_ROOT );
-        if( rootname == null ) rootname = page.getName() ;
+        if ( set == null ) set = DEFAULT_SETNAME;
+        if ( max != null ) maxItems = Integer.parseInt( max );
 
-        String format = params.get( PARAM_FORMAT );
-        if( format == null) format = "";
-        if( format.indexOf( "full" ) >=0 ) m_formatCompact = false ;
-        if( format.indexOf( "sort" ) >=0 ) m_formatSort    = true  ;
-
-        m_depth = TextUtil.parseIntParameter( params.get( PARAM_DEPTH ), MIN_DEPTH );
-        if( m_depth > MAX_DEPTH )  m_depth = MAX_DEPTH;
-
-        String includePattern = params.get(PARAM_INCLUDE);
-        if( includePattern == null ) includePattern = ".*";
-
-        String excludePattern = params.get(PARAM_EXCLUDE);
-        if( excludePattern == null ) excludePattern = "^$";
-
-        log.debug( "Fetching referred pages for "+ rootname +
-                   " with a depth of "+ m_depth +
-                   " with include pattern of "+ includePattern +
-                   " with exclude pattern of "+ excludePattern );
-
-        //
-        // do the actual work
-        //
-        String href  = context.getViewURL(rootname);
-        String title = "ReferredPagesPlugin: depth["+m_depth+
-                       "] include["+includePattern+"] exclude["+excludePattern+
-                       "] format["+(m_formatCompact ? "compact" : "full") +
-                       (m_formatSort ? " sort" : "") + "]";
-
-        m_result.append("<div class=\"ReferredPagesPlugin\">\n");
-        m_result.append("<a class=\"wikipage\" href=\""+ href +
-                        "\" title=\"" + title +
-                        "\">" + rootname + "</a>\n");
-        m_exists.add(rootname);
-
-        // pre compile all needed patterns
-        // glob compiler :  * is 0..n instance of any char  -- more convenient as input
-        // perl5 compiler : .* is 0..n instances of any char -- more powerful
-        //PatternCompiler g_compiler = new GlobCompiler();
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: "\" title=\"" + title + / "\">" + rootname + "</a>\n");
A +: "\" title=\"" + TextUtil.replaceEntities(title) + / "\">" + TextUtil.replaceEntities(rootname) + "</a>\n");
B -: return "<div class='error'>" + e.getMessage() + "</div>\n";
B +: return "<div class='error'>" + TextUtil.replaceEntities(e.getMessage()) + "</div>\n";
```
</details>

### 2019-10078::ReferredPagesPlugin.java::execute  <->  2022-46907::BugReportHandler.java::execute

- muc: **khong trung** | Jaccard AST: 0.12 | pham vi: inter_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.04 | fix_removed_sim 0.0
- API chung trong fix: replaceEntities | API chung trong ma loi: getEngine;getViewURL;new PluginException
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,80 +1,85 @@
-public String execute( WikiContext context, Map<String, String> params ) throws PluginException {
-        m_engine = context.getEngine();
+@Override
+    public String execute( final Context context, final Map< String, String > params ) throws PluginException {
+        final String title = params.get( PARAM_TITLE );
+        String description = params.get( PARAM_DESCRIPTION );
+        String version = params.get( PARAM_VERSION );
+        String submitter = null;
+        final SimpleDateFormat format = new SimpleDateFormat( DEFAULT_DATEFORMAT );
+        final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
+        final Principal wup = context.getCurrentUser();
 
-        WikiPage         page   = context.getPage();
-        if( page == null ) return "";
-
-        // parse parameters
-        String rootname = params.get( PARAM_ROOT );
-        if( rootname == null ) rootname = page.getName() ;
-
-        String format = params.get( PARAM_FORMAT );
-        if( format == null) format = "";
-        if( format.indexOf( "full" ) >=0 ) m_formatCompact = false ;
-        if( format.indexOf( "sort" ) >=0 ) m_formatSort    = true  ;
-
-        m_depth = TextUtil.parseIntParameter( params.get( PARAM_DEPTH ), MIN_DEPTH );
-        if( m_depth > MAX_DEPTH )  m_depth = MAX_DEPTH;
-
-        String includePattern = params.get(PARAM_INCLUDE);
-        if( includePattern == null ) includePattern = ".*";
-
-        String excludePattern = params.get(PARAM_EXCLUDE);
-        if( excludePattern == null ) excludePattern = "^$";
-
-        log.debug( "Fetching referred pages for "+ rootname +
-                   " with a depth of "+ m_depth +
-                   " with include pattern of "+ includePattern +
-                   " with exclude pattern of "+ excludePattern );
-
-        //
-        // do the actual work
-        //
-        String href  = context.getViewURL(rootname);
-        String title = "ReferredPagesPlugin: depth["+m_depth+
-                       "] include["+includePattern+"] exclude["+excludePattern+
-                       "] format["+(m_formatCompact ? "compact" : "full") +
-                       (m_formatSort ? " sort" : "") + "]";
-
-        m_result.append("<div class=\"ReferredPagesPlugin\">\n");
-        m_result.append("<a class=\"wikipage\" href=\""+ href +
-                        "\" title=\"" + title +
-                        "\">" + rootname + "</a>\n");
-        m_exists.add(rootname);
-
-        // pre compile all needed patterns
-        // glob compiler :  * is 0..n instance of any char  -- more convenient as input
-        // perl5 compiler : .* is 0..n instances of any char -- more powerful
-        //PatternCompiler g_compiler = new GlobCompiler();
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: "\" title=\"" + title + / "\">" + rootname + "</a>\n");
A +: "\" title=\"" + TextUtil.replaceEntities(title) + / "\">" + TextUtil.replaceEntities(rootname) + "</a>\n");
B -: final String pageName = findNextPage( context, title, params.get( PARAM_PAGE ) );
B +: final String pageName = findNextPage( context, title, TextUtil.replaceEntities(params.get( PARAM_PAGE )) );
```
</details>

### 2019-10078::ReferredPagesPlugin.java::execute  <->  2022-46907::InsertPage.java::execute

- muc: **khong trung** | Jaccard AST: 0.114 | pham vi: inter_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.034 | fix_removed_sim 0.0
- API chung trong fix: replaceEntities | API chung trong ma loi: getEngine;getPage;new PluginException;parseIntParameter
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,80 +1,130 @@
-public String execute( WikiContext context, Map<String, String> params ) throws PluginException {
-        m_engine = context.getEngine();
+@Override @SuppressWarnings("unchecked")
+    public String execute( final Context context, final Map<String, String> params ) throws PluginException {
+        final Engine engine = context.getEngine();
 
-        WikiPage         page   = context.getPage();
-        if( page == null ) return "";
+        final StringBuilder res = new StringBuilder();
 
-        // parse parameters
-        String rootname = params.get( PARAM_ROOT );
-        if( rootname == null ) rootname = page.getName() ;
+        final String clazz        = params.get( PARAM_CLASS );
+        final String includedPage = params.get( PARAM_PAGENAME );
+        String style              = params.get( PARAM_STYLE );
+        final boolean showOnce    = "once".equals( params.get( PARAM_SHOW ) );
+        final String defaultstr   = params.get( PARAM_DEFAULT );
+        final int section         = TextUtil.parseIntParameter(params.get( PARAM_SECTION ), -1 );
+        int maxlen                = TextUtil.parseIntParameter(params.get( PARAM_MAXLENGTH ), -1 );
 
-        String format = params.get( PARAM_FORMAT );
-        if( format == null) format = "";
-        if( format.indexOf( "full" ) >=0 ) m_formatCompact = false ;
-        if( format.indexOf( "sort" ) >=0 ) m_formatSort    = true  ;
+        final ResourceBundle rb = Preferences.getBundle( context, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
 
-        m_depth = TextUtil.parseIntParameter( params.get( PARAM_DEPTH ), MIN_DEPTH );
-        if( m_depth > MAX_DEPTH )  m_depth = MAX_DEPTH;
-
-        String includePattern = params.get(PARAM_INCLUDE);
-        if( includePattern == null ) includePattern = ".*";
-
-        String excludePattern = params.get(PARAM_EXCLUDE);
-        if( excludePattern == null ) excludePattern = "^$";
-
-        log.debug( "Fetching referred pages for "+ rootname +
-                   " with a depth of "+ m_depth +
-                   " with include pattern of "+ includePattern +
-                   " with exclude pattern of "+ excludePattern );
-
-        //
-        // do the actual work
-        //
-        String href  = context.getViewURL(rootname);
-        String title = "ReferredPagesPlugin: depth["+m_depth+
-                       "] include["+includePattern+"] exclude["+excludePattern+
-                       "] format["+(m_formatCompact ? "compact" : "full") +
-                       (m_formatSort ? " sort" : "") + "]";
-
-        m_result.append("<div class=\"ReferredPagesPlugin\">\n");
-        m_result.append("<a class=\"wikipage\" href=\""+ href +
-                        "\" title=\"" + title +
-                        "\">" + rootname + "</a>\n");
-        m_exists.add(rootname);
-
-        // pre compile all needed patterns
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: "\" title=\"" + title + / "\">" + rootname + "</a>\n");
A +: "\" title=\"" + TextUtil.replaceEntities(title) + / "\">" + TextUtil.replaceEntities(rootname) + "</a>\n");
B -: final String clazz        = params.get( PARAM_CLASS ); / final String includedPage = params.get( PARAM_PAGENAME ); / String style              = params.get( PARAM_STYLE );
B +: final String clazz        = TextUtil.replaceEntities(params.get( PARAM_CLASS )); / final String includedPage = TextUtil.replaceEntities(params.get( PARAM_PAGENAME )); / String style              = TextUtil.replaceEntities(params.get( PARAM_STYLE ));
```
</details>

### 2019-10078::ReferredPagesPlugin.java::execute  <->  2022-46907::FormOutput.java::execute

- muc: **khong trung** | Jaccard AST: 0.076 | pham vi: inter_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.039 | fix_removed_sim 0.0
- API chung trong fix: replaceEntities | API chung trong ma loi: getEngine;getPage
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,80 +1,79 @@
-public String execute( WikiContext context, Map<String, String> params ) throws PluginException {
-        m_engine = context.getEngine();
+@Override
+    public String execute( final Context ctx, final Map< String, String > params ) throws PluginException {
+        //  If there is no HTTP request, returns immediately.
+        if( ctx.getHttpRequest() == null ) {
+            return "";
+        }
+        final ResourceBundle rb = Preferences.getBundle( ctx, Plugin.CORE_PLUGINS_RESOURCEBUNDLE );
+        
+        // If we are NOT here due to this form being submitted, we do nothing.
+        // The submitted form MUST have parameter 'formname' equal to the name
+        // parameter of this Form plugin.
 
-        WikiPage         page   = context.getPage();
-        if( page == null ) return "";
+        final String formName   = params.get( PARAM_FORM );
+        final String submitForm = ctx.getHttpParameter( PARAM_FORMNAMEHIDDEN );
+        final String populator  = params.get( PARAM_POPULATE );
 
-        // parse parameters
-        String rootname = params.get( PARAM_ROOT );
-        if( rootname == null ) rootname = page.getName() ;
-
-        String format = params.get( PARAM_FORMAT );
-        if( format == null) format = "";
-        if( format.indexOf( "full" ) >=0 ) m_formatCompact = false ;
-        if( format.indexOf( "sort" ) >=0 ) m_formatSort    = true  ;
-
-        m_depth = TextUtil.parseIntParameter( params.get( PARAM_DEPTH ), MIN_DEPTH );
-        if( m_depth > MAX_DEPTH )  m_depth = MAX_DEPTH;
-
-        String includePattern = params.get(PARAM_INCLUDE);
-        if( includePattern == null ) includePattern = ".*";
-
-        String excludePattern = params.get(PARAM_EXCLUDE);
-        if( excludePattern == null ) excludePattern = "^$";
-
-        log.debug( "Fetching referred pages for "+ rootname +
-                   " with a depth of "+ m_depth +
-                   " with include pattern of "+ includePattern +
-                   " with exclude pattern of "+ excludePattern );
-
-        //
-        // do the actual work
-        //
-        String href  = context.getViewURL(rootname);
-        String title = "ReferredPagesPlugin: depth["+m_depth+
-                       "] include["+includePattern+"] exclude["+excludePattern+
-                       "] format["+(m_formatCompact ? "compact" : "full") +
-                       (m_formatSort ? " sort" : "") + "]";
-
-        m_result.append("<div class=\"ReferredPagesPlugin\">\n");
-        m_result.append("<a class=\"wikipage\" href=\""+ href +
-                        "\" title=\"" + title +
-                        "\">" + rootname + "</a>\n");
-        m_exists.add(rootname);
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: "\" title=\"" + title + / "\">" + rootname + "</a>\n");
A +: "\" title=\"" + TextUtil.replaceEntities(title) + / "\">" + TextUtil.replaceEntities(rootname) + "</a>\n");
B -:  / final String formName   = params.get( PARAM_FORM ); / // If population was allowed, we should first / final String handler = params.get( PARAM_HANDLER );
B +:  / final String formName   = TextUtil.replaceEntities( params.get( PARAM_FORM ) ); / // If population was allowed, we should first / final String handler = TextUtil.replaceEntities( params.get( PARAM_HANDLER ) );
```
</details>

### 2019-10078::ReferredPagesPlugin.java::execute  <->  2022-46907::CurrentTimePlugin.java::execute

- muc: **khong trung** | Jaccard AST: 0.068 | pham vi: inter_cve | cung vi tri: False
- root cause goi y: `same_fix_api` | fix_added_sim 0.05 | fix_removed_sim 0.0
- API chung trong fix: replaceEntities | API chung trong ma loi: new PluginException
- **Ban duyet:** `identical` / `same_pattern` / `same_root_cause` / `different`  ->  

<details><summary>diff ma loi A vs B (cat 60 dong)</summary>

```diff
--- A
+++ B
@@ -1,80 +1,20 @@
-public String execute( WikiContext context, Map<String, String> params ) throws PluginException {
-        m_engine = context.getEngine();
+@Override
+    public String execute( final Context context, final Map< String, String > params ) throws PluginException {
+        final String formatString = params.get( "format" );
 
-        WikiPage         page   = context.getPage();
-        if( page == null ) return "";
+        try {
+            final SimpleDateFormat fmt;
+            if( formatString != null ) {
+                fmt = new SimpleDateFormat( formatString );
+            } else {
+                fmt = Preferences.getDateFormat( context, TimeFormat.DATETIME );
+            }
 
-        // parse parameters
-        String rootname = params.get( PARAM_ROOT );
-        if( rootname == null ) rootname = page.getName() ;
+            final Date d = new Date();  // Now.
 
-        String format = params.get( PARAM_FORMAT );
-        if( format == null) format = "";
-        if( format.indexOf( "full" ) >=0 ) m_formatCompact = false ;
-        if( format.indexOf( "sort" ) >=0 ) m_formatSort    = true  ;
-
-        m_depth = TextUtil.parseIntParameter( params.get( PARAM_DEPTH ), MIN_DEPTH );
-        if( m_depth > MAX_DEPTH )  m_depth = MAX_DEPTH;
-
-        String includePattern = params.get(PARAM_INCLUDE);
-        if( includePattern == null ) includePattern = ".*";
-
-        String excludePattern = params.get(PARAM_EXCLUDE);
-        if( excludePattern == null ) excludePattern = "^$";
-
-        log.debug( "Fetching referred pages for "+ rootname +
-                   " with a depth of "+ m_depth +
-                   " with include pattern of "+ includePattern +
-                   " with exclude pattern of "+ excludePattern );
-
-        //
-        // do the actual work
-        //
-        String href  = context.getViewURL(rootname);
-        String title = "ReferredPagesPlugin: depth["+m_depth+
-                       "] include["+includePattern+"] exclude["+excludePattern+
-                       "] format["+(m_formatCompact ? "compact" : "full") +
-                       (m_formatSort ? " sort" : "") + "]";
-
-        m_result.append("<div class=\"ReferredPagesPlugin\">\n");
-        m_result.append("<a class=\"wikipage\" href=\""+ href +
-                        "\" title=\"" + title +
-                        "\">" + rootname + "</a>\n");
-        m_exists.add(rootname);
-
-        // pre compile all needed patterns
-        // glob compiler :  * is 0..n instance of any char  -- more convenient as input
```
</details>

<details><summary>dong thay doi trong ban fix</summary>

```
A -: "\" title=\"" + title + / "\">" + rootname + "</a>\n");
A +: "\" title=\"" + TextUtil.replaceEntities(title) + / "\">" + TextUtil.replaceEntities(rootname) + "</a>\n");
B -: return fmt.format( d );
B +: return TextUtil.replaceEntities( fmt.format( d ) ); / 
```
</details>
