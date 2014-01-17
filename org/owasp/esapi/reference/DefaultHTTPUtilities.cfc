<!---
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 */
--->
<cfcomponent implements="org.owasp.esapi.HTTPUtilities" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the HTTPUtilities interface. This implementation uses the Apache Commons FileUploader library, which in turn uses the Apache Commons IO library. To simplify the interface, this class uses the current request and response that are tracked by ThreadLocal variables in the Authenticator. This means that you must have called ESAPI.authenticator().setCurrentHTTP(request, response) before calling these methods. Typically, this is done by calling the Authenticator.login() method, which calls setCurrentHTTP() automatically. However if you want to use these methods in another application, you should explicitly call setCurrentHTTP() in your own code.">

	<cfscript>
		/** Key for remember token cookie */
		this.REMEMBER_TOKEN_COOKIE_NAME = "ESAPIRememberToken";

		variables.ESAPI = "";

		/** The logger. */
		variables.logger = "";

		/** The max bytes. */
		variables.maxBytes = "";

		/*
		 * The currentRequest ThreadLocal variable is used to make the currentRequest available to any call in any part of an
		 * application. This enables API's for actions that require the request to be much simpler. For example, the logout()
		 * method in the Authenticator class requires the currentRequest to get the session in order to invalidate it.
		 */
		variables.currentRequest = "";

		/*
		 * The currentResponse ThreadLocal variable is used to make the currentResponse available to any call in any part of an
		 * application. This enables API's for actions that require the response to be much simpler. For example, the logout()
		 * method in the Authenticator class requires the currentResponse to kill the JSESSIONID cookie.
		 */
		variables.currentResponse = "";
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.HTTPUtilities" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.logger = variables.ESAPI.getLogger("HTTPUtilities");
			variables.maxBytes = variables.ESAPI.securityConfiguration().getAllowedFileUploadSize();

			variables.currentRequest = createObject("component", "DefaultHTTPUtilities$ThreadLocalRequest").init(variables.ESAPI);
			variables.currentResponse = createObject("component", "DefaultHTTPUtilities$ThreadLocalResponse").init(variables.ESAPI);

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="addCSRFToken" output="false">
		<cfargument required="true" type="String" name="href"/>

		<cfscript>
			var user = variables.ESAPI.authenticator().getCurrentUser();
			if(user.isAnonymous()) {
				return arguments.href;
			}

			if((arguments.href.indexOf('?') != -1) || (arguments.href.indexOf('&') != -1)) {
				return arguments.href & "&" & user.getCSRFToken();
			}
			else {
				return arguments.href & "?" & user.getCSRFToken();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getCookie" output="false" hint="Returns the first cookie matching the provided name.">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var cookies = "";
			var i = "";
			var httpCookie = "";

			cookies = arguments.httpRequest.getCookies();
			if(isArray(cookies)) {
				for(i = 1; i <= arrayLen(cookies); i++) {
					httpCookie = cookies[i];
					if(httpCookie.getName() == arguments.name) {
						return httpCookie;
					}
				}
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCSRFToken" output="false">

		<cfscript>
			var user = variables.ESAPI.authenticator().getCurrentUser();

			if(!isObject(user))
				return "";
			return user.getCSRFToken();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="setRememberToken" output="false"
	            hint="Save the user's remember me data in an encrypted cookie and send it to the user. Any old remember me cookie is destroyed first. Setting this cookie will keep the user logged in until the maxAge passes, the password is changed, or the cookie is deleted. If the cookie exists for the current user, it will automatically be used by ESAPI to log the user in, if the data is valid and not expired.">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" name="httpResponse"/>
		<cfargument required="true" type="String" name="password"/>
		<cfargument required="true" type="numeric" name="maxAge"/>
		<cfargument required="true" type="String" name="domain"/>
		<cfargument required="true" type="String" name="path"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var random = "";
			var clearToken = "";
			var expiry = "";
			var cryptToken = "";
			var httpCookie = "";

			user = variables.ESAPI.authenticator().getCurrentUser();
			try {
				killCookie(arguments.httpRequest, arguments.httpResponse, this.REMEMBER_TOKEN_COOKIE_NAME);
				random = variables.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
				clearToken = random & ":" & user.getAccountName() & ":" & arguments.password;
				expiry = variables.ESAPI.encryptor().getRelativeTimeStamp(arguments.maxAge * 1000);
				cryptToken = variables.ESAPI.encryptor().seal(clearToken, expiry);
				httpCookie = createObject("java", "javax.servlet.http.Cookie").init(this.REMEMBER_TOKEN_COOKIE_NAME, cryptToken);
				httpCookie.setMaxAge(arguments.maxAge);
				httpCookie.setDomain(arguments.domain);
				httpCookie.setPath(arguments.path);
				arguments.httpResponse.addCookie(httpCookie);
				variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "Enabled remember me token for " & user.getAccountName());
				return cryptToken;
			}
			catch(org.owasp.esapi.errors.IntegrityException e) {
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Attempt to set remember me token failed for " & user.getAccountName(), e);
				return "";
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertSecureRequest" output="false"
	            hint="Verifies that the request is 'secure' by checking that the method is a POST and that SSL has been used.  The POST ensures that the data does not end up in bookmarks, web logs, referer headers, and other exposed sources.  The SSL ensures that data has not been exposed in transit.">
		<cfargument required="true" name="httpRequest"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var receivedMethod = "";
			var requiredMethod = "";

			if(!isSecureChannel(arguments.httpRequest)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AccessControlException").init(variables.ESAPI, "Insecure request received", "Received non-SSL request"));
			}
			receivedMethod = arguments.httpRequest.getMethod();
			requiredMethod = "POST";
			if(!receivedMethod.equals(requiredMethod)) {
				throwException(createObject("component", "org.owasp.esapi.errors.AccessControlException").init(variables.ESAPI, "Insecure request received", "Received request using " & receivedMethod & " when only " & requiredMethod & " is allowed"));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" name="changeSessionIdentifier" output="false">
		<cfargument required="true" name="httpRequest"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var oldSession = "";
			var temp = "";
			var atts = "";
			var name = "";
			var value = "";
			var newSession = "";
			var user = "";
			var entry = "";

			// get the current session
			oldSession = arguments.httpRequest.getSession();

			// make a copy of the session content
			temp = {};
			attrs = oldSession.getAttributeNames();
			while (!isNull(attrs) && attrs.hasMoreElements()) {
				name = attrs.nextElement();
				value = oldSession.getAttribute(name);
				temp.put(name, value);
			}

			// kill the old session and create a new one
			oldSession.invalidate();
			newSession = arguments.httpRequest.getSession();
			user = variables.ESAPI.authenticator().getCurrentUser();
			user.addSession(newSession);
			user.removeSession(oldSession);

			// copy back the session content
			for(entry in temp) {
				newSession.setAttribute(entry, temp[entry]);
			}
			return newSession;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="verifyCSRFToken" output="false"
	            hint="This implementation uses the parameter name to store the token. This makes the CSRF token a bit harder to search for in an XSS attack.">
		<cfargument required="true" name="httpRequest"/>

		<cfscript>
			var user = variables.ESAPI.authenticator().getCurrentUser();

			// check if user authenticated with this request - no CSRF protection required
			if(arguments.httpRequest.getAttribute(user.getCSRFToken()) != "") {
				return;
			}
			if(arguments.httpRequest.getParameter(user.getCSRFToken()) == "") {
				throwException(createObject("component", "org.owasp.esapi.errors.IntrusionException").init(variables.ESAPI, "Authentication failed", "Possibly forged HTTP request without proper CSRF token detected"));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="decryptHiddenField" output="false">
		<cfargument required="true" type="String" name="encrypted"/>

		<cfscript>
			try {
				return variables.ESAPI.encryptor().decryptString(arguments.encrypted);
			}
			catch(org.owasp.esapi.errors.EncryptionException e) {
				throwException(createObject("component", "org.owasp.esapi.errors.IntrusionException").init(variables.ESAPI, "Invalid request", "Tampering detected. Hidden field data did not decrypt properly.", e));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Struct" name="decryptQueryString" output="false">
		<cfargument required="true" type="String" name="encrypted"/>

		<cfscript>
			var plaintext = variables.ESAPI.encryptor().decryptString(arguments.encrypted);
			return queryToMap(plaintext);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Struct" name="decryptStateFromCookie" output="false">
		<cfargument required="true" name="httpRequest"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var cookies = "";
			var c = "";
			var i = "";
			var encrypted = "";
			var plaintext = "";

			cookies = arguments.httpRequest.getCookies();
			c = "";
			for(i = 1; i <= arrayLen(cookies); i++) {
				if(cookies[i].getName() == "state") {
					c = cookies[i];
				}
			}
			encrypted = c.getValue();
			plaintext = variables.ESAPI.encryptor().decryptString(encrypted);

			return queryToMap(plaintext);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encryptHiddenField" output="false">
		<cfargument required="true" type="String" name="value"/>

		<cfscript>
			return variables.ESAPI.encryptor().encryptString(arguments.value);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encryptQueryString" output="false">
		<cfargument required="true" type="String" name="query"/>

		<cfscript>
			return variables.ESAPI.encryptor().encryptString(arguments.query);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="encryptStateInCookie" output="false">
		<cfargument required="true" name="httpResponse"/>
		<cfargument required="true" type="Struct" name="cleartext"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var sb = "";
			var i = "";
			var entry = "";
			var name = "";
			var value = "";
			var encrypted = "";
			var httpCookie = "";

			sb = createObject("java", "java.lang.StringBuffer").init();
			i = arguments.cleartext.entrySet().iterator();
			while(i.hasNext()) {
				try {
					entry = i.next();
					name = variables.ESAPI.encoder().encodeForURL(entry.getKey().toString());
					value = variables.ESAPI.encoder().encodeForURL(entry.getValue().toString());
					sb.append(name & "=" & value);
					if(i.hasNext())
						sb.append("&");
				}
				catch(org.owasp.esapi.errors.EncodingException e) {
					variables.logger.error(Logger.SECURITY, false, "Problem encrypting state in cookie - skipping entry", e);
				}
			}
			encrypted = variables.ESAPI.encryptor().encryptString(sb.toString());
			httpCookie = createObject("java", "javax.servlet.http.Cookie").init("state", encrypted);
			arguments.httpResponse.addCookie(httpCookie);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getSafeFileUploads" output="false"
	            hint="Uses the Apache Commons FileUploader to parse the multipart HTTP request and extract any files therein. Note that the progress of any uploads is put into a session attribute, where it can be retrieved with a simple JSP.">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" name="tempDir"/>
		<cfargument required="true" name="finalDir"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var newFiles = "";
			var httpSession = "";
			var factory = "";
			var upload = "";
			var items = "";
			var i = "";
			var item = "";
			var fparts = "";
			var filename = "";
			var f = "";
			var parts = "";
			var extension = "";
			var filenm = "";

			if(!arguments.tempDir.exists()) {
				if(!arguments.tempDir.mkdirs())
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationUploadException").init(variables.ESAPI, "Upload failed", "Could not create temp directory: " & arguments.tempDir.getAbsolutePath()));
			}
			if(!arguments.finalDir.exists()) {
				if(!arguments.finalDir.mkdirs())
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationUploadException").init(variables.ESAPI, "Upload failed", "Could not create final upload directory: " & arguments.finalDir.getAbsolutePath()));
			}
			newFiles = [];
			try {
				httpSession = arguments.httpRequest.getSession(false);
				if(!createObject("java", "org.apache.commons.fileupload.servlet.ServletFileUpload").isMultipartContent(arguments.httpRequest)) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationUploadException").init(variables.ESAPI, "Upload failed", "Not a multipart request"));
				}

				// this factory will store ALL files in the temp directory, regardless of size
				factory = createObject("java", "org.apache.commons.fileupload.disk.DiskFileItemFactory").init(0, arguments.tempDir);
				upload = createObject("java", "org.apache.commons.fileupload.servlet.ServletFileUpload").init(factory);
				upload.setSizeMax(variables.maxBytes);

				/* TODO: no idea how to make this work in CF
				// Create a progress listener
				ProgressListener progressListener = new ProgressListener() {
				    private long megaBytes = -1;
				    private long progress = 0;

				    public void update(long pBytesRead, long pContentLength, int pItems) {
				        if (pItems == 0)
				            return;
				        long mBytes = pBytesRead / 1000000;
				        if (megaBytes == mBytes)
				            return;
				        megaBytes = mBytes;
				        progress = (long) (((double) pBytesRead / (double) pContentLength) * 100);
				        if ( httpSession != null ) {
				            httpSession.setAttribute("progress", Long.toString(progress));
				        }
				        // logger.logSuccess(Logger.SECURITY, "   Item " & pItems & " (" & progress & "% of " & pContentLength & " bytes]");
				    }
				};
				upload.setProgressListener(progressListener); */

				items = upload.parseRequest(arguments.httpRequest);
				i = items.iterator();
				while(i.hasNext()) {
					item = i.next();
					if(!item.isFormField() && item.getName() != "" && !(item.getName() == "")) {
						fparts = item.getName().split("[\\/\\\\]");
						filename = fparts[fparts.length - 1];

						if(!variables.ESAPI.validator().isValidFileName("upload", filename, false)) {
							throwException(createObject("component", "org.owasp.esapi.errors.ValidationUploadException").init(variables.ESAPI, "Upload only simple filenames with the following extensions " & variables.ESAPI.securityConfiguration().getAllowedFileExtensions(), "Upload failed isValidFileName check"));
						}

						variables.logger.info(Logger.SECURITY, true, "File upload requested: " & filename);
						f = createObject("java", "java.io.File").init(arguments.finalDir, filename);
						if(f.exists()) {
							parts = filename.split("\\/.");
							extension = "";
							if(parts.length > 1) {
								extension = parts[parts.length - 1];
							}
							filenm = filename.substring(0, filename.length() - extension.length());
							f = createObject("java", "java.io.File").createTempFile(filenm, "." & extension, arguments.finalDir);
						}
						item.write(f);
						newFiles.add(f);
						// delete temporary file
						item.delete();
						variables.logger.fatal(Logger.SECURITY, true, "File successfully uploaded: " & f);
						if(httpSession != "") {
							session.setAttribute("progress", Long.toString(0));
						}
					}
				}
			}
			catch(java.lang.Exception e) {
				if(isInstanceOf(e, "org.owasp.esapi.errors.ValidationUploadException")) {
					throwException(e);
				}
				throwException(createObject("component", "org.owasp.esapi.errors.ValidationUploadException").init(variables.ESAPI, "Upload failure", "Problem during upload:" & e.getMessage(), e));
			}
			return newFiles;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isSecureChannel" output="false"
	            hint="Returns true if the request was transmitted over an SSL enabled connection. This implementation ignores the built-in isSecure() method and uses the URL to determine if the request was transmitted over SSL.">
		<cfargument required="true" name="httpRequest"/>

		<cfscript>
			if(!isObject(arguments.httpRequest.getRequestURL()) || arguments.httpRequest.getRequestURL().toString().length() == 0)
				return false;
			return (mid(arguments.httpRequest.getRequestURL().toString(), 5, 1) == "s");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="killAllCookies" output="false">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" name="httpResponse"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var cookies = "";
			var i = "";
			var httpCookie = "";

			cookies = arguments.httpRequest.getCookies();
			if(isArray(cookies)) {
				for(i = 1; i <= arrayLen(cookies); i++) {
					httpCookie = cookies[i];
					killCookie(arguments.httpRequest, arguments.httpResponse, httpCookie.getName());
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="killCookie" output="false">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" name="httpResponse"/>
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var path = "";
			var domain = "";
			var httpCookie = "";
			var deleter = "";

			path = "/";
			domain = "";
			httpCookie = variables.ESAPI.httpUtilities().getCookie(arguments.httpRequest, arguments.name);
			if(isObject(httpCookie)) {
				path = httpCookie.getPath();
				domain = httpCookie.getDomain();
			}
			deleter = createObject("java", "javax.servlet.http.Cookie").init(arguments.name, "deleted");
			deleter.setMaxAge(0);
			if(isDefined("domain") && !isNull(domain))
				deleter.setDomain(domain);
			if(isDefined("path") && !isNull(path))
				deleter.setPath(path);
			arguments.httpResponse.addCookie(deleter);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="Struct" name="queryToMap" output="false">
		<cfargument required="true" type="String" name="query"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var map = "";
			var parts = "";
			var j = "";
			var nvpair = "";
			var name = "";
			var value = "";

			map = {};
			parts = arguments.query.split("&");
			for(j = 1; j <= arrayLen(parts); j++) {
				try {
					nvpair = parts[j].split("=");
					name = variables.ESAPI.encoder().decodeFromURL(nvpair[1]);
					value = variables.ESAPI.encoder().decodeFromURL(nvpair[2]);
					map.put(name, value);
				}
				catch(org.owasp.esapi.errors.EncodingException e) {
					// skip the nvpair with the encoding problem - note this is already logged.
				}
			}
			return map;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="safeSendForward" output="false"
	            hint="This implementation simply checks to make sure that the forward location starts with 'WEB-INF' and is intended for use in frameworks that forward to JSP files inside the WEB-INF folder.">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" name="httpResponse"/>
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="location"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var dispatched = "";

			if(!arguments.location.startsWith("WEB-INF")) {
				throwException(createObject("component", "org.owasp.esapi.errors.AccessControlException").init(variables.ESAPI, "Forward failed", "Bad forward location: " & arguments.location));
			}
			dispatcher = arguments.httpRequest.getRequestDispatcher(arguments.location);
			dispatcher.forward(arguments.httpRequest, arguments.httpResponse);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setSafeContentType" output="false">
		<cfargument required="true" name="httpResponse"/>

		<cfscript>
			arguments.httpResponse.setContentType(variables.ESAPI.securityConfiguration().getResponseContentType());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setNoCacheHeaders" output="false">
		<cfargument required="true" name="httpResponse"/>

		<cfscript>
			// HTTP 1.1
			arguments.httpResponse.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");

			// HTTP 1.0
			arguments.httpResponse.setHeader("Pragma", "no-cache");
			arguments.httpResponse.setDateHeader("Expires", -1);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="org.owasp.esapi.filters.SafeRequest" name="getCurrentRequest" output="false">

		<cfscript>
			var httpRequest = variables.currentRequest.getRequest();
			if(!isObject(httpRequest))
				throw(object=createObject("java", "java.lang.NullPointerException").init("Cannot use current request until it is set with HTTPUtilities.setCurrentHTTP()"));
			return httpRequest;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="org.owasp.esapi.filters.SafeResponse" name="getCurrentResponse" output="false">

		<cfscript>
			var httpResponse = variables.currentResponse.getResponse();
			if(!isObject(httpResponse))
				throw(object=createObject("java", "java.lang.NullPointerException").init("Cannot use current response until it is set with HTTPUtilities.setCurrentHTTP()"));
			return httpResponse;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCurrentHTTP" output="false">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" name="httpResponse"/>

		<cfscript>
			var safeRequest = "";
			var safeResponse = "";

			// wrap if necessary
			if(isInstanceOf(arguments.httpRequest, "org.owasp.esapi.filters.SafeRequest"))
				safeRequest = arguments.httpRequest;
			else if(isObject(arguments.httpRequest))
				safeRequest = createObject("component", "org.owasp.esapi.filters.SafeRequest").init(variables.ESAPI, arguments.httpRequest);
			if(isInstanceOf(arguments.httpResponse, "org.owasp.esapi.filters.SafeResponse"))
				safeResponse = arguments.httpResponse;
			else if(isObject(arguments.httpRequest))
				safeResponse = createObject("component", "org.owasp.esapi.filters.SafeResponse").init(variables.ESAPI, arguments.httpResponse);

			if(isObject(safeRequest)) {
				variables.currentRequest.setRequest(safeRequest);
			}
			else {
				variables.currentRequest.remove();
			}
			if(isObject(safeResponse)) {
				variables.currentResponse.setResponse(safeResponse);
			}
			else {
				variables.currentResponse.remove();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="logHTTPRequest" output="false"
	            hint="Formats an HTTP request into a log suitable string. This implementation logs the remote host IP address (or hostname if available), the request method (GET/POST), the URL, and all the querystring and form parameters. All the parameters are presented as though they were in the URL even if they were in a form. Any parameters that match items in the parameterNamesToObfuscate are shown as eight asterisks.">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" type="org.owasp.esapi.Logger" name="logger"/>
		<cfargument required="false" type="Array" name="parameterNamesToObfuscate"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var params = "";
			var i = "";
			var key = "";
			var value = "";
			var j = "";
			var cookies = "";
			var c = "";
			var msg = "";

			params = createObject("java", "java.lang.StringBuffer").init();
			i = arguments.httpRequest.getParameterMap().keySet().iterator();
			while(i.hasNext()) {
				key = i.next();
				value = arguments.httpRequest.getParameterMap().get(key);
				for(j = 1; j <= arrayLen(value); j++) {
					params.append(key & "=");
					if(structKeyExists(arguments, "parameterNamesToObfuscate") && arguments.parameterNamesToObfuscate.contains(key)) {
						params.append("********");
					}
					else {
						params.append(value[j]);
					}
					if(j < arrayLen(value)) {
						params.append("&");
					}
				}
				if(i.hasNext())
					params.append("&");
			}
			cookies = arguments.httpRequest.getCookies();
			if(isObject(cookies)) {
				for(c = 1; c <= arrayLen(cookies); c++) {
					if(!cookies[c].getName() == "JSESSIONID") {
						params.append("+" & cookies[c].getName() & "=" & cookies[c].getValue());
					}
				}
			}
			msg = arguments.httpRequest.getMethod() & " " & arguments.httpRequest.getRequestURL() & iif(len(params.toString()) > 0, de("?" & params), de(""));
			arguments.logger.info(getSecurityType("SECURITY_SUCCESS"), true, msg);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getApplicationName" output="false">

		<cfscript>
			// return the CF application name
			return application.applicationName;
		</cfscript>

	</cffunction>

</cfcomponent>