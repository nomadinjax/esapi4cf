<!---
 * Loads encrypted properties file based on the location passed in args then prompts the
 * user to input key-value pairs.  When the user enters a null or blank key, the values
 * are stored to the properties file.

 TODO: NOT COMPLETED
--->
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8" />
	<title>DefaultEncryptedProperties Modify Files</title>
</head>
<body>
<p>Loads encrypted properties file based on the location passed in args then prompts the user to input key-value pairs.  When the user enters a null or blank key, the values are stored to the properties file.</p>
<form method="post">
	<label for="file">Properties File Location</label>
	<input type="text" id="file" name="file" size="100" required="required" />
	<br />
	<button type="submit">Load</button>
</form>
<cfif cgi.request_method EQ "post" AND structKeyExists(form, "file")>
<cffunction name="throwException">
	<cfargument required="true" name="exception"/>
	<cfif isInstanceOf( arguments.exception, "java.lang.Throwable" )>
		<cfthrow object="#arguments.exception#"/>
	</cfif>
</cffunction>
<cfscript>
	function getSecurity(required String type) {
		var logger = createObject("java", "org.owasp.esapi.Logger" );
		// ESAPI 1.4.4
		if(structKeyExists( logger, "SECURITY" )) {
			return logger.SECURITY;
		}
		// ESAPI 2.0_rc10
		else {
			return logger[arguments.type];
		}
	}

	ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI").init();
	ESAPI.securityConfiguration().setResourceDirectory(expandPath("../../../../test/resources/"));

	f = createObject("java", "java.io.File").init(form.file);
	ESAPI.getLogger( "EncryptedProperties.main" ).debug(getSecurity("SECURITY_SUCCESS"), true, "Loading encrypted properties from " & f.getAbsolutePath() );
	if ( !f.exists() ) throwException( createObject("java", "java.io.IOException").init("Properties file not found: " & f.getAbsolutePath() ) );
	ESAPI.getLogger( "EncryptedProperties.main" ).debug(getSecurity("SECURITY_SUCCESS"), true, "Encrypted properties found in " & f.getAbsolutePath() );
	ep = createObject("component", "DefaultEncryptedProperties").init(ESAPI);

	fis = "";
	//try {
		fis = createObject("java", "java.io.FileInputStream").init(f);
        ep.load(fis);
	//} catch(any e) {}
	try { fis.close(); } catch( java.lang.Exception e ) {}

	if (structKeyExists(form, "key") && len(form.key) && structKeyExists(form, "value") && len(form.value)) {
		out = "";
		//try {
	        out = createObject("java", "java.io.FileOutputStream").init(f);
			ep.setProperty(form.key, form.value);
			ep.store(out, "Encrypted Properties File");
		//} catch(any e) {}
		try { out.close(); } catch( java.lang.Exception e ) {}

		i = ep.keySet().iterator();
		while (i.hasNext()) {
			k = i.next();
			value = ep.getProperty(k);
			writeOutput("   " & k & "=" & value);
		}
	}
</cfscript>
<cfoutput>
<p>Current properties: #ep.keySet().size()#</p>
<form method="post">
	<label for="key">Enter key</label>
	<input type="text" id="key" name="key" required="required" />
	<br />
	<label for="value">Enter value</label>
	<input type="text" id="value" name="value" required="required" />
	<br />
	<button type="submit">Save</button>
	<input type="hidden" id="file" name="file" value="#form.file#" />
</form>
</cfoutput>
</cfif>
</body>
</html>