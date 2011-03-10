<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.HTTPUtilities" output="false">

	<cfscript>
		this.REMEMBER_TOKEN_COOKIE_NAME = "rtoken";
		this.MAX_COOKIE_LEN = 4096;            // From RFC 2109
		//this.MAX_COOKIE_PAIRS = 20;			// From RFC 2109
		this.CSRF_TOKEN_NAME = "ctoken";
		this.ESAPI_STATE = "estate";

		//this.PARAMETER = 0;
		//this.HEADER = 1;
		//this.COOKIE = 2;

		instance.ESAPI = "";

		/* The logger. */
		instance.logger = "";

		/* The max bytes. */
		instance.maxBytes = 0;

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
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			instance.logger = instance.ESAPI.getLogger("HTTPUtilities");
			instance.maxBytes = instance.ESAPI.securityConfiguration().getAllowedFileUploadSize();

			instance.currentRequest = createObject('component', 'ThreadLocalRequest').init(instance.ESAPI);
			instance.currentResponse = createObject('component', 'ThreadLocalResponse').init(instance.ESAPI);

	        return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="addCookie" output="false" hint="This implementation uses a custom 'set-cookie' header rather than Java's cookie interface which doesn't allow the use of HttpOnly. Configure the HttpOnly and Secure settings in ESAPI.properties.">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response" required="true">
		<cfargument type="any" name="cookie" required="true" hint="javax.servlet.http.Cookie">
		<cfscript>
	        local.name = arguments.cookie.getName();
	        local.value = arguments.cookie.getValue();
	        local.maxAge = arguments.cookie.getMaxAge();
	        local.domain = arguments.cookie.getDomain();
	        if (isNull(local.domain)) {
	        	local.domain = "";
			}
	        local.path = arguments.cookie.getPath();
	        if (isNull(local.path)) {
	        	local.path = "";
			}
	        local.secure = arguments.cookie.getSecure();

	        // validate the name and value
	        local.errors = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");
	        local.cookieName = instance.ESAPI.validator().getValidInput(context="cookie name", input=local.name, type="HTTPCookieName", maxLength=50, allowNull=false, errors=local.errors);
	        local.cookieValue = instance.ESAPI.validator().getValidInput(context="cookie value", input=local.value, type="HTTPCookieValue", maxLength=5000, allowNull=false, errors=local.errors);

	        // if there are no errors, then set the cookie either with a header or normally
	        if (local.errors.size() == 0) {
	        	if ( instance.ESAPI.securityConfiguration().getForceHttpOnlyCookies() ) {
		            local.header = createCookieHeader(local.cookieName, local.cookieValue, local.maxAge, local.domain, local.path, local.secure);
		            this.addHeader(arguments.response, "Set-Cookie", local.header);
	        	} else {
	                // Issue 23 - If the ESAPI Configuration is set to force secure cookies, force the secure flag on the cookie before setting it
	                arguments.cookie.setSecure( local.secure || instance.ESAPI.securityConfiguration().getForceSecureCookies() );
	        		arguments.response.addCookie(arguments.cookie);
	        	}
	            return;
	        }
	        instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Attempt to add unsafe data to cookie (skip mode). Skipping cookie and continuing.");
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="addCSRFToken" output="false">
		<cfargument type="String" name="href" required="true">
		<cfscript>
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			if (local.user.isAnonymous()) {
				return arguments.href;
			}

			// if there are already parameters append with &, otherwise append with ?
			local.token = this.CSRF_TOKEN_NAME & "=" & local.user.getCSRFToken();
			return arguments.href.indexOf( '?') != -1 ? arguments.href & "&" & local.token : arguments.href & "?" & local.token;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="addHeader" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response" required="true">
		<cfargument type="String" name="name" required="true">
		<cfargument type="String" name="value" required="true">
		<cfscript>
	        try {
	            local.strippedName = javaLoader().create("org.owasp.esapi.StringUtilities").replaceLinearWhiteSpace(arguments.name);
	            local.strippedValue = javaLoader().create("org.owasp.esapi.StringUtilities").replaceLinearWhiteSpace(arguments.value);
	            local.safeName = instance.ESAPI.validator().getValidInput("addHeader", local.strippedName, "HTTPHeaderName", 20, false);
	            local.safeValue = instance.ESAPI.validator().getValidInput("addHeader", local.strippedValue, "HTTPHeaderValue", 500, false);
	            arguments.response.addHeader(local.safeName, local.safeValue);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Attempt to add invalid header denied", e);
	        }
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="assertSecureChannel" output="false" hint="This implementation ignores the built-in isSecure() method and uses the URL to determine if the request was transmitted over SSL. This is because SSL may have been terminated somewhere outside the container.">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="false" default="#getCurrentRequest()#">
		<cfscript>
		    local.sb = arguments.request.getRequestURL();
		    if ( isNull(local.sb) ) {
		    	cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Insecure request received", "HTTP request URL was null" );
				throw(message=cfex.getMessage(), type=cfex.getType());
		    }
		    local.url = local.sb.toString();
		    if ( !local.url.startsWith( "https" ) ) {
		    	cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Insecure request received", "HTTP request did not use SSL" );
				throw(message=cfex.getMessage(), type=cfex.getType());
		    }
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="assertSecureRequest" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="false" default="#getCurrentRequest()#">
		<cfscript>
			try {
				assertSecureChannel( arguments.request );
			} catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				throw(message=e.getMessage(), type=e.getType());
			}
			local.receivedMethod = arguments.request.getMethod();
			local.requiredMethod = "POST";
			if ( !local.receivedMethod.equals( local.requiredMethod ) ) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Insecure request received", "Received request using " & local.receivedMethod & " when only " & local.requiredMethod & " is allowed" );
				throw(message=cfex.getMessage(), type=cfex.getType());
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.HttpSession" name="changeSessionIdentifier" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="false" default="#getCurrentRequest()#">
		<cfscript>
    		// get the current session
			local.oldSession = arguments.request.getSession();

			// make a copy of the session content
			local.temp = {};
			local.e = local.oldSession.getAttributeNames();
			while (!isNull(local.e) && local.e.hasMoreElements()) {
				local.name = local.e.nextElement();
				local.value = local.oldSession.getAttribute(local.name);
				local.temp.put(local.name, local.value);
			}

			// kill the old session and create a new one
			local.oldSession.invalidate();
			local.newSession = arguments.request.getSession();
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			local.user.addSession( local.newSession );
			local.user.removeSession( local.oldSession );

			// copy back the session content
			for (local.stringObjectEntry in local.temp) {
				local.newSession.setAttribute(local.stringObjectEntry, local.temp[local.stringObjectEntry]);
			}
			return local.newSession;
    	</cfscript>
	</cffunction>

	<!--- clearCurrent --->

	<cffunction access="private" returntype="String" name="createCookieHeader" output="false">
		<cfargument type="String" name="name" required="true">
		<cfargument type="String" name="value" required="true">
		<cfargument type="numeric" name="maxAge" required="true">
		<cfargument type="String" name="domain" required="true">
		<cfargument type="String" name="path" required="true">
		<cfargument type="boolean" name="secure" required="true">
		<cfscript>
	        // create the special cookie header instead of creating a Java cookie
	        // Set-Cookie:<name>=<value>[; <name>=<value>][; expires=<date>][;
	        // domain=<domain_name>][; path=<some_path>][; secure][;HttpOnly]
	        local.header = arguments.name & "=" & arguments.value;
	        local.header &= "; Max-Age=" & arguments.maxAge;
	        if (arguments.domain != "") {
	            local.header &= "; Domain=" & arguments.domain;
	        }
	        if (arguments.path != "") {
	            local.header &= "; Path=" & arguments.path;
	        }
	        if ( arguments.secure || instance.ESAPI.securityConfiguration().getForceSecureCookies() ) {
	            local.header &= "; Secure";
	        }
	        if ( instance.ESAPI.securityConfiguration().getForceHttpOnlyCookies() ) {
	            local.header &= "; HttpOnly";
	        }
	        return local.header;
    	</cfscript>
	</cffunction>

	<!--- decryptHiddenField --->
	<!--- decryptQueryString --->

	<cffunction access="public" returntype="Struct" name="decryptStateFromCookie" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="false" default="#getCurrentRequest()#">
		<cfscript>
	    	try {
	    		local.encrypted = getCookie( arguments.request, this.ESAPI_STATE );
	    		if ( local.encrypted == "" ) return {};
	    		local.plaintext = decryptString(local.encrypted);
	    		return queryToMap( local.plaintext );
	    	} catch( cfesapi.org.owasp.esapi.errors..ValidationException e ) {
	        	return {};
	    	}
    	</cfscript>
	</cffunction>

	<!--- encryptHiddenField --->
	<!--- encryptQueryString --->
	<!--- decryptStateFromCookie --->

	<cffunction access="public" returntype="void" name="encryptStateInCookie" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response" required="false" default="#getCurrentResponse()#">
		<cfargument type="Struct" name="cleartext" required="true">
		<cfscript>
	    	local.sb = createObject("java", "java.lang.StringBuilder").init();
	    	local.i = arguments.cleartext.entrySet().iterator();
	    	while ( local.i.hasNext() ) {
	    		try {
		    		local.entry = local.i.next();

		    		// What do these need to be URL encoded? They are encrypted!
		    		local.name = instance.ESAPI.encoder().encodeForURL( local.entry.getKey().toString() );
		    		local.value = instance.ESAPI.encoder().encodeForURL( local.entry.getValue().toString() );
	             	local.sb.append(local.name).append("=").append(local.value);
		    		if ( local.i.hasNext() ) local.sb.append( "&" );
	    		} catch( cfesapi.org.owasp.esapi.errors.EncodingException e ) {
	    			instance.logger.error(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Problem encrypting state in cookie - skipping entry", e );
	    		}
	    	}

			local.encrypted = encryptString(local.sb.toString());

			if ( local.encrypted.length() > (this.MAX_COOKIE_LEN ) ) {
				instance.logger.error(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Problem encrypting state in cookie - skipping entry");
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption failure", "Encrypted cookie state of " & local.encrypted.length() & " longer than allowed " & this.MAX_COOKIE_LEN );
				throw(message=cfex.getMessage(), type=cfex.getType());
			}

	    	local.cookie = createObject("java", "javax.servlet.http.Cookie").init( this.ESAPI_STATE, local.encrypted );
	    	addCookie( arguments.response, local.cookie );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getCookie" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="false" default="#getCurrentRequest()#">
		<cfargument type="String" name="name" required="true">
		<cfscript>
	        local.c = getFirstCookie( arguments.request, arguments.name );
	        if ( isNull(local.c) ) return "";
			local.value = local.c.getValue();
			return instance.ESAPI.validator().getValidInput("HTTP cookie value: " & local.value, local.value, "HTTPCookieValue", 1000, false);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getCSRFToken" output="false">
		<cfscript>
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			if (isNull(local.user)) return "";
			return local.user.getCSRFToken();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getCurrentRequest" output="false" hint="cfesapi.org.owasp.esapi.HttpServletRequest">
		<cfscript>
	    	return instance.currentRequest.getRequest();
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.HttpServletResponse" name="getCurrentResponse" output="false">
		<cfscript>
        	return instance.currentResponse.getResponse();
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getFileUploads" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="false" default="#getCurrentRequest()#">
		<cfargument type="any" name="finalDir" required="false" default="#instance.ESAPI.securityConfiguration().getUploadDirectory()#" hint="java.io.File">
		<cfargument type="Array" name="allowedExtensions" required="false" default="#instance.ESAPI.securityConfiguration().getAllowedFileExtensions()#">
		<cfscript>
    		local.tempDir = instance.ESAPI.securityConfiguration().getUploadTempDirectory();
			if ( !local.tempDir.exists() ) {
			    if ( !local.tempDir.mkdirs() ) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationUploadException").init(instance.ESAPI, "Upload failed", "Could not create temp directory: " & local.tempDir.getAbsolutePath() );
					throw(message=cfex.getMessage(), type=cfex.getType());
			    }
			}

			if( arguments.finalDir != ""){
				if ( !arguments.finalDir.exists() ) {
					if ( !arguments.finalDir.mkdirs() ) {
						cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationUploadException").init(instance.ESAPI, "Upload failed", "Could not create final upload directory: " & arguments.finalDir.getAbsolutePath() );
						throw(message=cfex.getMessage(), type=cfex.getType());
					}
				}
			}
			else {
				if ( !instance.ESAPI.securityConfiguration().getUploadDirectory().exists()) {
					if ( !instance.ESAPI.securityConfiguration().getUploadDirectory().mkdirs() ) {
						cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationUploadException").init(instance.ESAPI, "Upload failed", "Could not create final upload directory: " & instance.ESAPI.securityConfiguration().getUploadDirectory().getAbsolutePath() );
						throw(message=cfex.getMessage(), type=cfex.getType());
					}
				}
				arguments.finalDir = instance.ESAPI.securityConfiguration().getUploadDirectory();
			}

			local.newFiles = [];
			try {
				local.session = arguments.request.getSession(false);
				if (!arguments.request.isMultipartContent()) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationUploadException").init(instance.ESAPI, "Upload failed", "Not a multipart request");
					throw(message=cfex.getMessage(), type=cfex.getType());
				}

				// this factory will store ALL files in the temp directory, regardless of size
				local.factory = javaLoader().create("org.apache.commons.fileupload.disk.DiskFileItemFactory").init(0, local.tempDir);
				local.upload = javaLoader().create("org.apache.commons.fileupload.servlet.ServletFileUpload").init(local.factory);
				local.upload.setSizeMax(instance.maxBytes);

				if (local.session != "") {
					local.progressListener = createObject("component", "ProgressListener").init(instance.ESAPI, local.session);
					local.upload.setProgressListener(local.progressListener);
				}
				// ERROR: parseRequest(javax.servlet.http.HttpServletRequest)
				local.items = local.upload.parseRequest(arguments.request);
	         	for (local.item in local.items) {
	            	if (!local.item.isFormField() && !isNull(local.item.getName()) && !(local.item.getName() == "")) {
						local.fparts = local.item.getName().split("[\\/\\\\]");
						local.filename = local.fparts[local.fparts.length - 1];

	               		if (!instance.ESAPI.validator().isValidFileName("upload", local.filename, arguments.allowedExtensions, false)) {
							cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationUploadException").init(instance.ESAPI, "Upload only simple filenames with the following extensions " & arguments.allowedExtensions, "Upload failed isValidFileName check");
							throw(message=cfex.getMessage(), type=cfex.getType());
						}

						instance.logger.info(Logger.SECURITY_SUCCESS, "File upload requested: " & local.filename);
						local.f = createObject("java", "java.io.File").init(arguments.finalDir, local.filename);
	               		if (local.f.exists()) {
							local.parts = local.filename.split("\\/.");
							local.extension = "";
	                  		if (local.parts.length > 1) {
								local.extension = local.parts[local.parts.length - 1];
							}
							local.filenm = filename.substring(0, filename.length() - local.extension.length());
							local.f = createObject("java", "java.io.File").createTempFile(local.filenm, "." & local.extension, arguments.finalDir);
						}
						local.item.write(local.f);
	               		local.newFiles.add(local.f);
						// delete temporary file
						local.item.delete();
						logger.fatal(Logger.SECURITY_SUCCESS, "File successfully uploaded: " & local.f);
	               		if (local.session != "") {
						    local.session.setAttribute("progress", createObject("java", "java.lang.Long").toString(0));
						}
					}
				}
			} catch (Exception e) {
				if (isInstanceOf(e, "cfesapi.org.owasp.esapi.errors.ValidationUploadException")) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, e.getUserMessage(), e.getLogMessage(), e);
					throw(message=cfex.getMessage(), type=cfex.getType());
				}
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationUploadException").init(instance.ESAPI, "Upload failure", "Problem during upload:" & e.getMessage(), e);
				throw(message=cfex.getMessage(), type=cfex.getType());
			}
			return Collections.synchronizedList(local.newFiles);
    	</cfscript>
	</cffunction>


	<cffunction access="private" returntype="any" name="getFirstCookie" output="false" hint="Utility to return the first cookie matching the provided name.">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="true">
		<cfargument type="String" name="name" required="true">
		<cfscript>
			local.cookies = arguments.request.getCookies();
			if (!isNull(local.cookies)) {
				for (local.i=1; local.i<=arrayLen(local.cookies); local.i++) {
					local.cookie = local.cookies[local.i];
					if (local.cookie.getName() == arguments.name) {
						return local.cookie;
					}
				}
			}
			return;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getHeader" output="false">
		<cfargument type="String" name="name" required="true">
		<cfscript>
    		local.value = getCurrentRequest().getHeader(arguments.name);
        	return instance.ESAPI.validator().getValidInput("HTTP header value: " & local.value, local.value, "HTTPHeaderValue", 150, false);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getParameter" output="false">
		<cfargument type="String" name="name" required="true">
		<cfscript>
    		local.value = getCurrentRequest().getParameter(arguments.name);
	    	return instance.ESAPI.validator().getValidInput("HTTP parameter value: " & local.value, local.value, "HTTPParameterValue", 2000, true);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="killAllCookies" output="false">
		<cfscript>
			local.cookies = getCurrentRequest().getCookies();
			if (arrayLen(local.cookies)) {
				for (local.i=1; local.i<=arrayLen(local.cookies); local.i++) {
					local.cookie = local.cookies[local.i];
					killCookie(name=local.cookie.getName());
				}
			}
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="killCookie" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="false" default="#getCurrentRequest()#">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response" required="false" default="#getCurrentResponse()#">
		<cfargument type="String" name="name" required="true">
		<cfscript>
    		local.path = "/";
			local.domain = "";
			local.cookie = getFirstCookie(arguments.request, arguments.name);
			if ( !isNull(local.cookie) ) {
				local.path = local.cookie.getPath();
				local.domain = local.cookie.getDomain();
			}
			local.deleter = createObject("java", "javax.servlet.http.Cookie").init( arguments.name, "deleted" );
			local.deleter.setMaxAge( 0 );
			if ( !isNull(local.domain) ) local.deleter.setDomain( local.domain );
			if ( !isNull(local.path) ) local.deleter.setPath( local.path );
			arguments.response.addCookie( local.deleter );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="logHTTPRequest" output="false" hint="Formats an HTTP request into a log suitable string. This implementation logs the remote host IP address (or hostname if available), the request method (GET/POST), the URL, and all the querystring and form parameters. All the parameters are presented as though they were in the URL even if they were in a form. Any parameters that match items in the parameterNamesToObfuscate are shown as eight asterisks.">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="false" default="#getCurrentRequest()#">
		<cfargument type="cfesapi.org.owasp.esapi.Logger" name="logger" required="false">
		<cfargument type="Array" name="parameterNamesToObfuscate" required="false">
		<cfscript>
			local.params = createObject("java", "java.lang.StringBuilder").init();
		    local.i = arguments.request.getParameterMap().keySet().iterator();
		    while (local.i.hasNext()) {
		        local.key = local.i.next();
		        local.value = arguments.request.getParameterMap().get(local.key);
		        for (local.j = 1; local.j <= arrayLen(local.value); local.j++) {
	                local.params.append(local.key).append("=");
		            if (!isNull(arguments.parameterNamesToObfuscate) && arguments.parameterNamesToObfuscate.contains(local.key)) {
		                local.params.append("********");
		            } else {
		                local.params.append(local.value[local.j]);
		            }
		            if (local.j < arrayLen(local.value)) {
		                local.params.append("&");
		            }
		        }
		        if (local.i.hasNext())
		            local.params.append("&");
		    }
		    local.cookies = arguments.request.getCookies();
		    if ( !isNull(local.cookies) ) {
	            for (local.cooky in local.cookies) {
	               if (!local.cooky.getName() == "JSESSIONID") {
	                  local.params.append("+").append(local.cooky.getName()).append("=").append(local.cooky.getValue());
		            }
				}
		    }
		    local.msg = arguments.request.getMethod() & " " & arguments.request.getRequestURL() & (local.params.length() > 0 ? "?" & local.params : "");
		    arguments.logger.info(javaLoader().create("org.owasp.esapi.Logger").SECURITY_SUCCESS, local.msg);
	    </cfscript>
	</cffunction>


	<cffunction access="private" returntype="Struct" name="queryToMap" output="false">
		<cfargument type="String" name="query" required="true">
		<cfscript>
			local.map = {};
			local.parts = arguments.query.split("&");
			for (local.i=1; local.i<=arrayLen(local.parts); local.i++) {
				local.part = local.parts[local.i];
				try {
					local.nvpair = local.part.split("=");
					local.name = instance.ESAPI.encoder().decodeFromURL(local.nvpair[1]);
					local.value = instance.ESAPI.encoder().decodeFromURL(local.nvpair[2]);
					local.map.put(local.name, local.value);
				}
				catch (cfesapi.org.owasp.esapi.EncodingException e) {
					// skip the nvpair with the encoding problem - note this is already logged.
				}
			}
			return local.map;
		</cfscript>
	</cffunction>

	<!--- sendForward --->

	<cffunction access="public" returntype="void" name="sendRedirect" output="false" hint="This implementation checks against the list of safe redirect locations defined in ESAPI.properties.">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response" required="true">
		<cfargument type="String" name="location" required="true">
		<cfscript>
	        if (!instance.ESAPI.validator().isValidRedirectLocation("Redirect", arguments.location, false)) {
	            instance.logger.fatal(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Bad redirect location: " & arguments.location);
	            throw(object=createObject("java", "java.io.IOException").init("Redirect failed"));
	        }
	        arguments.response.sendRedirect(arguments.location);
    	</cfscript>
	</cffunction>

	<!--- setContentType --->

	<cffunction access="public" returntype="void" name="setCurrentHTTP" output="false">
		<cfargument type="any" name="request" required="true">
		<cfargument type="any" name="response" required="true">
		<cfscript>
			var wrappedRequest = '';
			var wrappedResponse = '';

			// wrap if necessary
			if (isInstanceOf(arguments.request, 'cfesapi.org.owasp.esapi.HttpServletRequest')) {
				wrappedRequest = arguments.request;
			}
			else if (isObject(arguments.request)) {
				wrappedRequest = createObject('component', 'cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest').init(instance.ESAPI, arguments.request);
			}

			if (isInstanceOf(arguments.response, 'cfesapi.org.owasp.esapi.HttpServletResponse')) {
				wrappedResponse = arguments.response;
			}
			else if (isObject(arguments.request)) {
				wrappedResponse = createObject('component', 'cfesapi.org.owasp.esapi.filters.SecurityWrapperResponse').init(instance.ESAPI, arguments.response);
			}

	     	instance.currentRequest.setRequest(wrappedRequest);
	        instance.currentResponse.setResponse(wrappedResponse);
	    </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setHeader" output="false">
		<cfargument type="String" name="name" required="true">
		<cfargument type="String" name="value" required="true">
		<cfscript>
	        try {
	            local.strippedName = javaLoader().create("org.owasp.esapi.StringUtilities").replaceLinearWhiteSpace(arguments.name);
	            local.strippedValue = javaLoader().create("org.owasp.esapi.StringUtilities").replaceLinearWhiteSpace(arguments.value);
	            local.safeName = instance.ESAPI.validator().getValidInput("setHeader", local.strippedName, "HTTPHeaderName", 20, false);
	            local.safeValue = instance.ESAPI.validator().getValidInput("setHeader", local.strippedValue, "HTTPHeaderValue", 500, false);
	            getCurrentResponse().setHeader(local.safeName, local.safeValue);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Attempt to set invalid header denied", e);
	        }
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setNoCacheHeaders" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response" required="false" default="#getCurrentResponse()#">
		<cfscript>
			// HTTP 1.1
			arguments.response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");

			// HTTP 1.0
			arguments.response.setHeader("Pragma","no-cache");
			arguments.response.setDateHeader("Expires", -1);
		</cfscript>
	</cffunction>

	<!--- setRememberToken --->

	<cffunction access="public" returntype="void" name="verifyCSRFToken" output="false" hint="This implementation uses the CSRF_TOKEN_NAME parameter for the token.">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="false" default="#getCurrentRequest()#">
		<cfscript>
    		local.user = instance.ESAPI.authenticator().getCurrentUser();

			// check if user authenticated with this request - no CSRF protection required
			if( arguments.request.getAttribute(local.user.getCSRFToken()) != "" ) {
				return;
			}
			local.token = arguments.request.getParameter(this.CSRF_TOKEN_NAME);
			if ( !local.user.getCSRFToken() == local.token ) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.IntrusionException").init(instance.ESAPI, "Authentication failed", "Possibly forged HTTP request without proper CSRF token detected");
				throw(message=cfex.getMessage(), type=cfex.getType());
			}
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getSessionAttribute" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpSession" name="session" required="false" default="#instance.ESAPI.currentRequest().getSession(false)#">
		<cfargument type="String" name="key" required="true">
		<cfscript>
	        if ( isObject(arguments.session) ) {
	            return arguments.session.getAttribute(arguments.key);
	        }
	        return "";
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getRequestAttribute" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" required="false" default="#instance.ESAPI.currentRequest()#">
		<cfargument type="String" name="key" required="true">
		<cfscript>
			return arguments.request.getAttribute(arguments.key);
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="String" name="encryptString" output="false" hint="Helper method to encrypt using new Encryptor encryption methods and return the serialized ciphertext as a hex-encoded string.">
		<cfargument type="String" name="plaintext" required="true">
		<cfscript>
	        local.pt = createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, arguments.plaintext);
	        local.ct = instance.ESAPI.encryptor().encrypt(local.pt);
	        local.serializedCiphertext = local.ct.asPortableSerializedByteArray();
	        return javaLoader().create("org.owasp.esapi.codecs.Hex").encode(local.serializedCiphertext, false);
    	</cfscript>
	</cffunction>


	<cffunction access="private" returntype="String" name="decryptString" output="false" hint="Helper method to decrypt a hex-encode serialized ciphertext string and to decrypt it using the new Encryptor decryption methods.">
		<cfargument type="String" name="ciphertext" required="true">
		<cfscript>
	        local.serializedCiphertext = javaLoader().create("org.owasp.esapi.codecs.Hex").decode(arguments.ciphertext);
	        local.restoredCipherText = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherText").init(instance.ESAPI).fromPortableSerializedBytes(local.serializedCiphertext);
	        local.plaintext = instance.ESAPI.encryptor().decrypt(local.restoredCipherText);
	        return local.plaintext.toString();
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getApplicationName" output="false">
		<cfscript>
			return application.applicationName;
		</cfscript>
	</cffunction>


</cfcomponent>
