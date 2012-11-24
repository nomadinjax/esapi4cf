<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 --->
<cfcomponent implements="cfesapi.org.owasp.esapi.HTTPUtilities" extends="cfesapi.org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the HTTPUtilities interface. This implementation uses the Apache Commons FileUploader library, which in turn uses the Apache Commons IO library. To simplify the interface, this class uses the current request and response that are tracked by ThreadLocal variables in the Authenticator. This means that you must have called ESAPI.authenticator().setCurrentHTTP(request, response) before calling these methods. Typically, this is done by calling the Authenticator.login() method, which calls setCurrentHTTP() automatically. However if you want to use these methods in another application, you should explicitly call setCurrentHTTP() in your own code.">

	<cfscript>
		/** Key for remember token cookie */
		this.REMEMBER_TOKEN_COOKIE_NAME = "ESAPIRememberToken";

		instance.ESAPI = "";

		/** The logger. */
		instance.logger = "";

		/** The max bytes. */
		instance.maxBytes = "";

		/*
		 * The currentRequest ThreadLocal variable is used to make the currentRequest available to any call in any part of an
		 * application. This enables API's for actions that require the request to be much simpler. For example, the logout()
		 * method in the Authenticator class requires the currentRequest to get the session in order to invalidate it.
		 */
		instance.currentRequest = "";

		/*
		 * The currentResponse ThreadLocal variable is used to make the currentResponse available to any call in any part of an
		 * application. This enables API's for actions that require the response to be much simpler. For example, the logout()
		 * method in the Authenticator class requires the currentResponse to kill the JSESSIONID cookie.
		 */
		instance.currentResponse = "";
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.HTTPUtilities" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger( "HTTPUtilities" );
			instance.maxBytes = instance.ESAPI.securityConfiguration().getAllowedFileUploadSize();

			instance.currentRequest = createObject( "component", "DefaultHTTPUtilities$ThreadLocalRequest" ).init( instance.ESAPI );
			instance.currentResponse = createObject( "component", "DefaultHTTPUtilities$ThreadLocalResponse" ).init( instance.ESAPI );

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="addCSRFToken" output="false">
		<cfargument required="true" type="String" name="href"/>

		<cfscript>
			var local = {};
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			if(local.user.isAnonymous()) {
				return arguments.href;
			}

			if((arguments.href.indexOf( '?' ) != -1) || (arguments.href.indexOf( '&' ) != -1)) {
				return arguments.href & "&" & local.user.getCSRFToken();
			}
			else {
				return arguments.href & "?" & local.user.getCSRFToken();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getCookie" output="false" hint="Returns the first cookie matching the provided name.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			var local = {};
			local.cookies = arguments.request.getCookies();
			if(isArray( local.cookies )) {
				for(local.i = 1; local.i <= arrayLen( local.cookies ); local.i++) {
					local.cookie = local.cookies[local.i];
					if(local.cookie.getName() == arguments.name) {
						return local.cookie;
					}
				}
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCSRFToken" output="false">

		<cfscript>
			var local = {};
			local.user = instance.ESAPI.authenticator().getCurrentUser();

			if(!isObject( local.user ))
				return "";
			return local.user.getCSRFToken();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="setRememberToken" output="false"
	            hint="Save the user's remember me data in an encrypted cookie and send it to the user. Any old remember me cookie is destroyed first. Setting this cookie will keep the user logged in until the maxAge passes, the password is changed, or the cookie is deleted. If the cookie exists for the current user, it will automatically be used by ESAPI to log the user in, if the data is valid and not expired.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response"/>
		<cfargument required="true" type="String" name="password"/>
		<cfargument required="true" type="numeric" name="maxAge"/>
		<cfargument required="true" type="String" name="domain"/>
		<cfargument required="true" type="String" name="path"/>

		<cfscript>
			var local = {};
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			try {
				killCookie( arguments.request, arguments.response, this.REMEMBER_TOKEN_COOKIE_NAME );
				local.random = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
				local.clearToken = local.random & ":" & local.user.getAccountName() & ":" & arguments.password;
				local.expiry = instance.ESAPI.encryptor().getRelativeTimeStamp( arguments.maxAge * 1000 );
				local.cryptToken = instance.ESAPI.encryptor().seal( local.clearToken, local.expiry );
				local.cookie = getJava( "javax.servlet.http.Cookie" ).init( this.REMEMBER_TOKEN_COOKIE_NAME, local.cryptToken );
				local.cookie.setMaxAge( arguments.maxAge );
				local.cookie.setDomain( arguments.domain );
				local.cookie.setPath( arguments.path );
				arguments.response.addCookie( local.cookie );
				instance.logger.info( getSecurity("SECURITY_SUCCESS"), true, "Enabled remember me token for " & local.user.getAccountName() );
				return local.cryptToken;
			}
			catch(cfesapi.org.owasp.esapi.errors.IntegrityException e) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Attempt to set remember me token failed for " & local.user.getAccountName(), e );
				return "";
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertSecureRequest" output="false"
	            hint="Verifies that the request is 'secure' by checking that the method is a POST and that SSL has been used.  The POST ensures that the data does not end up in bookmarks, web logs, referer headers, and other exposed sources.  The SSL ensures that data has not been exposed in transit.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>

		<cfscript>
			var local = {};
			if(!isSecureChannel( arguments.request )) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AccessControlException" ).init( instance.ESAPI, "Insecure request received", "Received non-SSL request" ) );
			}
			local.receivedMethod = arguments.request.getMethod();
			local.requiredMethod = "POST";
			if(!local.receivedMethod.equals( local.requiredMethod )) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AccessControlException" ).init( instance.ESAPI, "Insecure request received", "Received request using " & local.receivedMethod & " when only " & local.requiredMethod & " is allowed" ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" name="changeSessionIdentifier" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>

		<cfscript>
			var local = {};

			// get the current session
			local.oldSession = arguments.request.getSession();

			// make a copy of the session content
			local.temp = {};
			local.e = local.oldSession.getAttributeNames();
			for(local.i = 1; local.i <= arrayLen(local.e); local.i++) {
				local.name = local.e[local.i];
				local.value = local.oldSession.getAttribute( local.name );
				local.temp.put( local.name, local.value );
			}

			// kill the old session and create a new one
			local.oldSession.invalidate();
			local.newSession = arguments.request.getSession();
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			local.user.addSession( local.newSession );
			local.user.removeSession( local.oldSession );

			// copy back the session content
			for(local.entry in local.temp) {
				local.newSession.setAttribute( local.entry, local.temp[local.entry] );
			}
			return local.newSession;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="verifyCSRFToken" output="false"
	            hint="This implementation uses the parameter name to store the token. This makes the CSRF token a bit harder to search for in an XSS attack.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>

		<cfscript>
			var local = {};
			local.user = instance.ESAPI.authenticator().getCurrentUser();

			// check if user authenticated with this request - no CSRF protection required
			if(arguments.request.getAttribute( local.user.getCSRFToken() ) != "") {
				return;
			}
			if(arguments.request.getParameter( local.user.getCSRFToken() ) == "") {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.IntrusionException" ).init( instance.ESAPI, "Authentication failed", "Possibly forged HTTP request without proper CSRF token detected" ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="decryptHiddenField" output="false">
		<cfargument required="true" type="String" name="encrypted"/>

		<cfscript>
			try {
				return instance.ESAPI.encryptor().decryptString( arguments.encrypted );
			}
			catch(cfesapi.org.owasp.esapi.errors.EncryptionException e) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.IntrusionException" ).init( instance.ESAPI, "Invalid request", "Tampering detected. Hidden field data did not decrypt properly.", e ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Struct" name="decryptQueryString" output="false">
		<cfargument required="true" type="String" name="encrypted"/>

		<cfscript>
			var local = {};
			local.plaintext = instance.ESAPI.encryptor().decryptString( arguments.encrypted );
			return queryToMap( local.plaintext );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Struct" name="decryptStateFromCookie" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>

		<cfscript>
			var local = {};
			local.cookies = arguments.request.getCookies();
			local.c = "";
			for(local.i = 1; local.i <= arrayLen( local.cookies ); local.i++) {
				if(local.cookies[local.i].getName() == "state") {
					local.c = local.cookies[local.i];
				}
			}
			local.encrypted = local.c.getValue();
			local.plaintext = instance.ESAPI.encryptor().decryptString( local.encrypted );

			return queryToMap( local.plaintext );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encryptHiddenField" output="false">
		<cfargument required="true" type="String" name="value"/>

		<cfscript>
			return instance.ESAPI.encryptor().encryptString( arguments.value );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encryptQueryString" output="false">
		<cfargument required="true" type="String" name="query"/>

		<cfscript>
			return instance.ESAPI.encryptor().encryptString( arguments.query );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="encryptStateInCookie" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response"/>
		<cfargument required="true" type="Struct" name="cleartext"/>

		<cfscript>
			var local = {};
			local.sb = getJava( "java.lang.StringBuffer" ).init();
			local.i = arguments.cleartext.entrySet().iterator();
			while(local.i.hasNext()) {
				try {
					local.entry = local.i.next();
					local.name = instance.ESAPI.encoder().encodeForURL( local.entry.getKey().toString() );
					local.value = instance.ESAPI.encoder().encodeForURL( local.entry.getValue().toString() );
					local.sb.append( local.name & "=" & local.value );
					if(local.i.hasNext())
						local.sb.append( "&" );
				}
				catch(cfesapi.org.owasp.esapi.errors.EncodingException e) {
					instance.logger.error( Logger.SECURITY, false, "Problem encrypting state in cookie - skipping entry", e );
				}
			}
			local.encrypted = instance.ESAPI.encryptor().encryptString( local.sb.toString() );
			local.cookie = getJava( "javax.servlet.http.Cookie" ).init( "state", local.encrypted );
			arguments.response.addCookie( local.cookie );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getSafeFileUploads" output="false"
	            hint="Uses the Apache Commons FileUploader to parse the multipart HTTP request and extract any files therein. Note that the progress of any uploads is put into a session attribute, where it can be retrieved with a simple JSP.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>
		<cfargument required="true" name="tempDir"/>
		<cfargument required="true" name="finalDir"/>

		<cfscript>
			var local = {};
			if(!arguments.tempDir.exists()) {
				if(!arguments.tempDir.mkdirs())
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationUploadException" ).init( instance.ESAPI, "Upload failed", "Could not create temp directory: " & arguments.tempDir.getAbsolutePath() ) );
			}
			if(!arguments.finalDir.exists()) {
				if(!arguments.finalDir.mkdirs())
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationUploadException" ).init( instance.ESAPI, "Upload failed", "Could not create final upload directory: " & arguments.finalDir.getAbsolutePath() ) );
			}
			local.newFiles = [];
			try {
				local.session = arguments.request.getSession( false );
				if(!getJava( "org.apache.commons.fileupload.servlet.ServletFileUpload" ).isMultipartContent( arguments.request.getHttpServletRequest() )) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationUploadException" ).init( instance.ESAPI, "Upload failed", "Not a multipart request" ) );
				}

				// this factory will store ALL files in the temp directory, regardless of size
				local.factory = getJava( "org.apache.commons.fileupload.disk.DiskFileItemFactory" ).init( 0, arguments.tempDir );
				local.upload = getJava( "org.apache.commons.fileupload.servlet.ServletFileUpload" ).init( local.factory );
				local.upload.setSizeMax( instance.maxBytes );

				/* TODO
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
				        if ( local.session != "" ) {
				            local.session.setAttribute("progress", Long.toString(progress));
				        }
				        // logger.logSuccess(Logger.SECURITY, "   Item " & pItems & " (" & progress & "% of " & pContentLength & " bytes]");
				    }
				}; */
				local.upload.setProgressListener( local.progressListener );

				local.items = upload.parseRequest( arguments.request );
				local.i = local.items.iterator();
				while(local.i.hasNext()) {
					local.item = local.i.next();
					if(!local.item.isFormField() && local.item.getName() != "" && !(local.item.getName() == "")) {
						local.fparts = local.item.getName().split( "[\\/\\\\]" );
						local.filename = local.fparts[local.fparts.length - 1];

						if(!instance.ESAPI.validator().isValidFileName( "upload", local.filename, false )) {
							throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationUploadException" ).init( instance.ESAPI, "Upload only simple filenames with the following extensions " & instance.ESAPI.securityConfiguration().getAllowedFileExtensions(), "Upload failed isValidFileName check" ) );
						}

						instance.logger.info( Logger.SECURITY, true, "File upload requested: " & local.filename );
						local.f = getJava( "java.io.File" ).init( arguments.finalDir, local.filename );
						if(local.f.exists()) {
							local.parts = local.filename.split( "\\/." );
							local.extension = "";
							if(local.parts.length > 1) {
								local.extension = local.parts[local.parts.length - 1];
							}
							local.filenm = local.filename.substring( 0, local.filename.length() - local.extension.length() );
							local.f = getJava( "java.io.File" ).createTempFile( local.filenm, "." & local.extension, arguments.finalDir );
						}
						local.item.write( local.f );
						local.newFiles.add( local.f );
						// delete temporary file
						local.item.delete();
						instance.logger.fatal( Logger.SECURITY, true, "File successfully uploaded: " & local.f );
						if(local.session != "") {
							local.session.setAttribute( "progress", Long.toString( 0 ) );
						}
					}
				}
			}
			catch(java.lang.Exception e) {
				if(isInstanceOf( e, "cfesapi.org.owasp.esapi.errors.ValidationUploadException" )) {
					throwException( e );
				}
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationUploadException" ).init( instance.ESAPI, "Upload failure", "Problem during upload:" & e.getMessage(), e ) );
			}
			return local.newFiles;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isSecureChannel" output="false"
	            hint="Returns true if the request was transmitted over an SSL enabled connection. This implementation ignores the built-in isSecure() method and uses the URL to determine if the request was transmitted over SSL.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>

		<cfscript>
			if(!isObject( arguments.request.getRequestURL() ) || arguments.request.getRequestURL().toString().length() == 0)
				return false;
			return (arguments.request.getRequestURL().charAt( 4 ) == 's');
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="killAllCookies" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response"/>

		<cfscript>
			var local = {};
			local.cookies = arguments.request.getCookies();
			if(isArray( local.cookies )) {
				for(local.i = 1; local.i <= arrayLen( local.cookies ); local.i++) {
					local.cookie = local.cookies[local.i];
					killCookie( arguments.request, arguments.response, local.cookie.getName() );
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="killCookie" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response"/>
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			var local = {};
			local.path = "/";
			local.domain = "";
			local.cookie = instance.ESAPI.httpUtilities().getCookie( arguments.request, arguments.name );
			if(isObject( local.cookie )) {
				local.path = local.cookie.getPath();
				local.domain = local.cookie.getDomain();
			}
			local.deleter = getJava( "javax.servlet.http.Cookie" ).init( arguments.name, "deleted" );
			local.deleter.setMaxAge( 0 );
			if(structKeyExists( local, "domain" ))
				local.deleter.setDomain( local.domain );
			if(structKeyExists( local, "path" ))
				local.deleter.setPath( local.path );
			arguments.response.addCookie( local.deleter );
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="Struct" name="queryToMap" output="false">
		<cfargument required="true" type="String" name="query"/>

		<cfscript>
			var local = {};
			local.map = {};
			local.parts = arguments.query.split( "&" );
			for(local.j = 1; local.j <= arrayLen( local.parts ); local.j++) {
				try {
					local.nvpair = local.parts[local.j].split( "=" );
					local.name = instance.ESAPI.encoder().decodeFromURL( local.nvpair[1] );
					local.value = instance.ESAPI.encoder().decodeFromURL( local.nvpair[2] );
					local.map.put( local.name, local.value );
				}
				catch(cfesapi.org.owasp.esapi.errors.EncodingException e) {
					// skip the nvpair with the encoding problem - note this is already logged.
				}
			}
			return local.map;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="safeSendForward" output="false"
	            hint="This implementation simply checks to make sure that the forward location starts with 'WEB-INF' and is intended for use in frameworks that forward to JSP files inside the WEB-INF folder.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response"/>
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="location"/>

		<cfscript>
			var local = {};
			if(!arguments.location.startsWith( "WEB-INF" )) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AccessControlException" ).init( instance.ESAPI, "Forward failed", "Bad forward location: " & arguments.location ) );
			}
			local.dispatcher = arguments.request.getRequestDispatcher( arguments.location );
			local.dispatcher.forward( arguments.request, arguments.response );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setSafeContentType" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response"/>

		<cfscript>
			arguments.response.setContentType( instance.ESAPI.securityConfiguration().getResponseContentType() );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setNoCacheHeaders" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response"/>

		<cfscript>
			// HTTP 1.1
			arguments.response.setHeader( "Cache-Control", "no-store, no-cache, must-revalidate" );

			// HTTP 1.0
			arguments.response.setHeader( "Pragma", "no-cache" );
			arguments.response.setDateHeader( "Expires", -1 );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.filters.SafeRequest" name="getCurrentRequest" output="false">

		<cfscript>
			var local = {};
			local.request = instance.currentRequest.getRequest();
			if(!isObject( local.request ))
				throwException( getJava( "java.lang.NullPointerException" ).init( "Cannot use current request until it is set with HTTPUtilities.setCurrentHTTP()" ) );
			return local.request;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.filters.SafeResponse" name="getCurrentResponse" output="false">

		<cfscript>
			var local = {};
			local.response = instance.currentResponse.getResponse();
			if(!isObject( local.response ))
				throwException( getJava( "java.lang.NullPointerException" ).init( "Cannot use current response until it is set with HTTPUtilities.setCurrentHTTP()" ) );
			return local.response;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCurrentHTTP" output="false">
		<cfargument required="true" name="request"/>
		<cfargument required="true" name="response"/>

		<cfscript>
			var local = {};
			local.safeRequest = "";
			local.safeResponse = "";

			// wrap if necessary
			if(isInstanceOf( arguments.request, "cfesapi.org.owasp.esapi.filters.SafeRequest" ))
				local.safeRequest = arguments.request;
			else if(isObject( arguments.request ))
				local.safeRequest = createObject( "component", "cfesapi.org.owasp.esapi.filters.SafeRequest" ).init( instance.ESAPI, arguments.request );
			if(isInstanceOf( arguments.response, "cfesapi.org.owasp.esapi.filters.SafeResponse" ))
				local.safeResponse = arguments.response;
			else if(isObject( arguments.request ))
				local.safeResponse = createObject( "component", "cfesapi.org.owasp.esapi.filters.SafeResponse" ).init( instance.ESAPI, arguments.response );

			if (isObject(local.safeRequest)) {
				instance.currentRequest.setRequest( local.safeRequest );
			}
			else {
				instance.currentRequest.remove();
			}
			if (isObject(local.safeResponse)) {
				instance.currentResponse.setResponse( local.safeResponse );
			}
			else {
				instance.currentResponse.remove();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="logHTTPRequest" output="false"
	            hint="Formats an HTTP request into a log suitable string. This implementation logs the remote host IP address (or hostname if available), the request method (GET/POST), the URL, and all the querystring and form parameters. All the parameters are presented as though they were in the URL even if they were in a form. Any parameters that match items in the parameterNamesToObfuscate are shown as eight asterisks.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request"/>
		<cfargument required="true" type="cfesapi.org.owasp.esapi.Logger" name="logger"/>
		<cfargument required="false" type="Array" name="parameterNamesToObfuscate"/>

		<cfscript>
			var local = {};
			local.params = getJava( "java.lang.StringBuffer" ).init();
			local.i = arguments.request.getParameterMap().keySet().iterator();
			while(local.i.hasNext()) {
				local.key = local.i.next();
				local.value = arguments.request.getParameterMap().get( local.key );
				for(local.j = 1; local.j <= arrayLen( local.value ); local.j++) {
					local.params.append( local.key & "=" );
					if(structKeyExists( arguments, "parameterNamesToObfuscate" ) && arguments.parameterNamesToObfuscate.contains( local.key )) {
						local.params.append( "********" );
					}
					else {
						local.params.append( local.value[local.j] );
					}
					if(local.j < arrayLen( local.value )) {
						local.params.append( "&" );
					}
				}
				if(local.i.hasNext())
					local.params.append( "&" );
			}
			local.cookies = arguments.request.getCookies();
			if(isObject( local.cookies )) {
				for(local.c = 1; local.c <= arrayLen( local.cookies ); local.c++) {
					if(!local.cookies[local.c].getName() == "JSESSIONID") {
						local.params.append( "+" & local.cookies[local.c].getName() & "=" & local.cookies[local.c].getValue() );
					}
				}
			}
			local.msg = arguments.request.getMethod() & " " & arguments.request.getRequestURL() & iif( local.params.length() > 0, de( "?" & local.params ), de( "" ) );
			arguments.logger.info( getSecurity("SECURITY_SUCCESS"), true, local.msg );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getApplicationName" output="false">

		<cfscript>
			return application.applicationName;
		</cfscript>

	</cffunction>

</cfcomponent>