/*
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
import "org.owasp.esapi.beans.SafeRequest";
import "org.owasp.esapi.beans.SafeResponse";
import "org.owasp.esapi.beans.ThreadLocalRequest";
import "org.owasp.esapi.beans.ThreadLocalResponse";
import "org.owasp.esapi.crypto.PlainText";
import "org.owasp.esapi.crypto.CipherText";
import "org.owasp.esapi.errors.AccessControlException";
import "org.owasp.esapi.errors.IntrusionException";
import "org.owasp.esapi.errors.EncryptionException";

/**
 * Reference implementation of the HTTPUtilities interface. This implementation
 * uses the Apache Commons FileUploader library, which in turn uses the Apache
 * Commons IO library.
 * <P>
 * To simplify the interface, some methods use the current request and response that
 * are tracked by ThreadLocal variables in the Authenticator. This means that you
 * must have called ESAPI.authenticator().setCurrentHTTP(request, response) before
 * calling these methods.
 * <P>
 * Typically, this is done by calling the Authenticator.login() method, which
 * calls setCurrentHTTP() automatically. However if you want to use these methods
 * in another application, you should explicitly call setCurrentHTTP() in your
 * own code. In either case, you *must* call ESAPI.clearCurrent() to clear threadlocal
 * variables before the thread is reused. The advantages of having identity everywhere
 * outweigh the disadvantages of this approach.
 */
component implements="org.owasp.esapi.HTTPUtilities" extends="org.owasp.esapi.util.Object" {

	this.REMEMBER_TOKEN_COOKIE_NAME = "rtoken";
    this.MAX_COOKIE_LEN = 4096;            // From RFC 2109
	this.MAX_COOKIE_PAIRS = 20;			// From RFC 2109
	this.CSRF_TOKEN_NAME = "ctoken";
	this.ESAPI_STATE = "estate";

	this.PARAMETER = 0;
	this.HEADER = 1;
	this.COOKIE = 2;

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
     * method in the Authenticator class requires the currentResponse to kill the Session ID cookie.
     */
    variables.currentResponse = "";

	public org.owasp.esapi.HTTPUtilities function init(required org.owasp.esapi.ESAPI ESAPI) {
		variables.ESAPI = arguments.ESAPI;
		variables.logger = variables.ESAPI.getLogger("HTTPUtilities");
		variables.maxBytes = variables.ESAPI.securityConfiguration().getAllowedFileUploadSize();

		variables.currentRequest = new ThreadLocalRequest(variables.ESAPI);
		variables.currentResponse = new ThreadLocalResponse(variables.ESAPI);

		return this;
	}

   /**
     * This implementation uses a custom "set-cookie" header rather than Java's
     * cookie interface which doesn't allow the use of HttpOnly. Configure the
     * HttpOnly and Secure settings in ESAPI.properties.
	 */
    public void function addCookie(required httpCookie, httpResponse=getCurrentResponse()) {
        var cookieArgs = {
        	name = arguments.httpCookie.getName(),
        	value = arguments.httpCookie.getValue(),
        	maxAge = arguments.httpCookie.getMaxAge(),
        	domain = arguments.httpCookie.getDomain(),
        	path = arguments.httpCookie.getPath(),
        	secure = arguments.httpCookie.getSecure()
        };

        // validate the name and value
        var errors = {};
        cookieArgs.name = variables.ESAPI.validator().getValidInput("cookie name", cookieArgs.name, "HTTPCookieName", 50, false, true, errors);
        cookieArgs.value = variables.ESAPI.validator().getValidInput("cookie value", cookieArgs.value, "HTTPCookieValue", 5000, false, true, errors);

        // if there are no errors, then set the cookie either with a header or normally
        if (errors.size() == 0) {
        	if ( variables.ESAPI.securityConfiguration().getForceHttpOnlyCookies() ) {
	            var httpHeader = createCookieHeader(argumentCollection=cookieArgs);
	            addHeader("Set-Cookie", httpHeader, arguments.httpResponse);
        	} else {
                // Issue 23 - If the ESAPI Configuration is set to force secure cookies, force the secure flag on the cookie before setting it
                arguments.httpCookie.setSecure( cookieArgs.secure || variables.ESAPI.securityConfiguration().getForceSecureCookies() );
        		arguments.httpResponse.addCookie(arguments.httpCookie);
        	}
            return;
        }
        variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Attempt to add unsafe data to cookie (skip mode). Skipping cookie and continuing.");
    }

	public string function addCSRFToken(required string href) {
		var user = variables.ESAPI.authenticator().getCurrentUser();
		if (user.isAnonymous()) {
			return arguments.href;
		}

		// if there are already parameters append with &, otherwise append with ?
		var token = this.CSRF_TOKEN_NAME & "=" & user.getCSRFToken();
		return arguments.href.indexOf( '?') != -1 ? arguments.href & "&" & token : arguments.href & "?" & token;
	}

    public void function addHeader(required string name, required string value, httpResponse=getCurrentResponse()) {
    	var StringUtilities = createObject("java", "org.owasp.esapi.StringUtilities");
        try {
            var strippedName = StringUtilities.replaceLinearWhiteSpace(arguments.name);
            var strippedValue = StringUtilities.replaceLinearWhiteSpace(arguments.value);
            var safeName = variables.ESAPI.validator().getValidInput("addHeader", strippedName, "HTTPHeaderName", 20, false);
            var safeValue = variables.ESAPI.validator().getValidInput("addHeader", strippedValue, "HTTPHeaderValue", 500, false);
            arguments.httpResponse.addHeader(safeName, safeValue);
        } catch (org.owasp.esapi.errors.ValidationException e) {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Attempt to add invalid header denied", e);
        }
    }

	/**
	 * This implementation ignores the built-in isSecure() method
	 * and uses the URL to determine if the request was transmitted over SSL.
	 * This is because SSL may have been terminated somewhere outside the
	 * container.
	 */
	public void function assertSecureChannel(httpRequest=getCurrentRequest()) {
	    if ( isNull(arguments.httpRequest) ) {
	    	raiseException(new AccessControlException( variables.ESAPI, "Insecure request received", "HTTP request was null" ));
	    }
	    var sb = arguments.httpRequest.getRequestURL();
	    if (isNull(sb)) {
	    	raiseException(new AccessControlException( variables.ESAPI, "Insecure request received", "HTTP request URL was null" ));
	    }
	    var protocol = sb.toString();
	    if (left(protocol, 5) != "https") {
	    	raiseException(new AccessControlException( variables.ESAPI, "Insecure request received", "HTTP request did not use SSL" ));
	    }
	}

	public void function assertSecureRequest(httpRequest=getCurrentRequest()) {
		assertSecureChannel(httpRequest);
		var receivedMethod = arguments.httpRequest.getMethod();
		var requiredMethod = "POST";
		if ( receivedMethod != requiredMethod ) {
			raiseException(new AccessControlException( variables.ESAPI, "Insecure request received", "Received request using " & receivedMethod & " when only " & requiredMethod & " is allowed" ));
		}
	}

	public function changeSessionIdentifier(httpRequest=getCurrentRequest()) {

		// get the current session
		var oldSession = arguments.httpRequest.getSession();

		// make a copy of the session content
		var temp = {};
		var attrs = oldSession.getAttributeNames();
		while (!isNull(attrs) && isObject(attrs) && attrs.hasMoreElements()) {
			var name = attrs.nextElement();
			var value = oldSession.getAttribute(name);
			temp.put(name, value);
		}

		// kill the old session and create a new one
		oldSession.invalidate();
		var newSession = arguments.httpRequest.getSession();

		var user = variables.ESAPI.authenticator().getCurrentUser();
		user.addSession( newSession );
		user.removeSession( oldSession );

		// copy back the session content
		for (var stringObjectEntry in temp) {
			newSession.setAttribute(stringObjectEntry, temp[stringObjectEntry]);
		}
		return newSession;
	}

    public void function clearCurrent() {
		variables.currentRequest.remove();
		variables.currentResponse.remove();
	}

	private string function createCookieHeader(required string name, required string value, required numeric maxAge, string domain, string path, boolean secure=true) {
        // create the special cookie header instead of creating a Java cookie
        // Set-Cookie:<name>=<value>[; <name>=<value>][; expires=<date>][;
        // domain=<domain_name>][; path=<some_path>][; secure][;HttpOnly]
        var httpHeader = name & "=" & value;
        httpHeader &= "; Max-Age=" & maxAge;
        if (!isNull(domain)) {
            httpHeader &= "; Domain=" & domain;
        }
        if (!isNull(path)) {
            httpHeader &= "; Path=" & path;
        }
        if ( secure || variables.ESAPI.securityConfiguration().getForceSecureCookies() ) {
            httpHeader &= "; Secure";
        }
        if ( variables.ESAPI.securityConfiguration().getForceHttpOnlyCookies() ) {
            httpHeader &= "; HttpOnly";
        }
        return httpHeader;
    }

	public string function decryptHiddenField(required string encrypted) {
    	try {
    		return decryptString(arguments.encrypted);
    	} catch( org.owasp.esapi.errors.EncryptionException e ) {
    		raiseException(new IntrusionException(variables.ESAPI, "Invalid request","Tampering detected. Hidden field data did not decrypt properly.", e));
    	}
    }

	public struct function decryptQueryString(required string encrypted) {
        var plaintext = decryptString(arguments.encrypted);
		return queryToMap(plaintext);
	}

    public struct function decryptStateFromCookie(httpRequest=getCurrentRequest()) {
    	try {
    		var encrypted = getCookie(this.ESAPI_STATE, arguments.httpRequest);
    		if ( isNull(encrypted) ) return {};
    		var plaintext = decryptString(encrypted);
    		return queryToMap( plaintext );
    	} catch( org.owasp.esapi.errors.ValidationException e ) {
        	return;
    	}
    }

	public string function encryptHiddenField(required string value) {
    	return encryptString(arguments.value);
	}

	public string function encryptQueryString(required string queryString) {
	    return encryptString(arguments.queryString);
	}

    public void function encryptStateInCookie(required struct cleartext, httpResponse=getCurrentResponse()) {
    	var sb = createObject("java", "java.lang.StringBuilder").init();
    	var i = cleartext.entrySet().iterator();
    	while ( i.hasNext() ) {
    		try {
	    		var entry = i.next();

	    		    // What do these need to be URL encoded? They are encrypted!
	    		var name = variables.ESAPI.encoder().encodeForURL( entry.getKey().toString() );
	    		var value = variables.ESAPI.encoder().encodeForURL( entry.getValue().toString() );
             sb.append(name).append("=").append(value);
	    		if ( i.hasNext() ) sb.append( "&" );
    		} catch( org.owasp.esapi.errors.EncodingException e ) {
    			variables.logger.error(variables.Logger.SECURITY_FAILURE, "Problem encrypting state in cookie - skipping entry", e );
    		}
    	}

		var encrypted = encryptString(sb.toString());

		if ( encrypted.length() > (this.MAX_COOKIE_LEN ) ) {
			variables.logger.error(variables.Logger.SECURITY_FAILURE, "Problem encrypting state in cookie - skipping entry");
			raiseException(new EncryptionException(variables.ESAPI, "Encryption failure", "Encrypted cookie state of " & encrypted.length() & " longer than allowed " & this.MAX_COOKIE_LEN ));
		}

    	var httpCookie = createObject("java", "javax.servlet.http.Cookie").init( this.ESAPI_STATE, encrypted );
    	addCookie(httpCookie, arguments.httpResponse);
    }

	public string function getCookie(required string name, httpRequest=getCurrentRequest()) {
        var c = getFirstCookie(arguments.httpRequest, arguments.name);
        if (isNull(c)) return;
		var value = c.getValue();
		return variables.ESAPI.validator().getValidInput("HTTP cookie value: " & value, value, "HTTPCookieValue", 1000, false);
	}


	public string function getCSRFToken() {
		var user = variables.ESAPI.authenticator().getCurrentUser();
		if (isNull(user)) return;
		return user.getCSRFToken();
	}


    public function getCurrentRequest() {
		return variables.currentRequest.getRequest();
    }

    public function getCurrentResponse() {
		return variables.currentResponse.getResponse();
    }

	public array function getFileUploads(uploadDir=variables.ESAPI.securityConfiguration().getUploadDirectory(), array allowedExtensions=variables.ESAPI.securityConfiguration().getAllowedFileExtensions(), httpRequest=getCurrentRequest()) {
        var tempDir = createObject("java", "java.io.File").init(variables.ESAPI.securityConfiguration().getUploadTempDirectory());
		if ( !tempDir.exists() ) {
		    if ( !tempDir.mkdirs() ) raiseException(new ValidationUploadException( variables.ESAPI, "Upload failed", "Could not create temp directory: " & tempDir.getAbsolutePath() ));
		}

		var uploadDirObject = "";
		if(len(arguments.uploadDir)) {
			uploadDirObject = createObject("java", "java.io.File").init(arguments.uploadDir);
		}

		if (!isNull(uploadDirObject)) {
			if ( !uploadDirObject.exists() ) {
				if ( !uploadDirObject.mkdirs() ) raiseException(new ValidationUploadException( variables.ESAPI, "Upload failed", "Could not create final upload directory: " & uploadDirObject.getAbsolutePath() ));
			}
		}
		else {
			uploadDirObject = createObject("java", "java.io.File").init(variables.ESAPI.securityConfiguration().getUploadDirectory());
			if ( !uploadDirObject.exists()) {
				if ( !uploadDirObject.mkdirs() ) raiseException(new ValidationUploadException( variables.ESAPI, "Upload failed", "Could not create final upload directory: " & uploadDirObject.getAbsolutePath() ));
			}
		}

		var ServletFileUpload = createObject("java", "org.apache.commons.fileupload.servlet.ServletFileUpload");
		var DiskFileItemFactory = createObject("java", "org.apache.commons.fileupload.disk.DiskFileItemFactory");

		var newFiles = [];
		try {
			var httpSession = arguments.httpRequest.getSession(false);
			if (!ServletFileUpload.isMultipartContent(arguments.httpRequest)) {
				raiseException(new ValidationUploadException(variables.ESAPI, "Upload failed", "Not a multipart request"));
			}

			// this factory will store ALL files in the temp directory,
			// regardless of size
			var factory = new DiskFileItemFactory(0, tempDir);
			var upload = new ServletFileUpload(factory);
			upload.setSizeMax(maxBytes);

			// Create a progress listener
			/*var progressListener = new ProgressListener() {
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
					// variables.logger.logSuccess(variables.Logger.SECURITY, "   Item " & pItems & " (" & progress & "% of " & pContentLength & " bytes]");
				}
			};
			upload.setProgressListener(progressListener);*/

			var items = upload.parseRequest(httpRequest);
         for (var item in items)
         {
            if (!item.isFormField() && !isNull(item.getName()) && item.getName() != "")
            {
					var fparts = item.getName().split("[\\/\\\\]");
					var filename = fparts[fparts.length - 1];

               if (!variables.ESAPI.validator().isValidFileName("upload", filename, allowedExtensions, false))
               {
						raiseException(new ValidationUploadException(variables.ESAPI, "Upload only simple filenames with the following extensions " & allowedExtensions, "Upload failed isValidFileName check"));
					}

					variables.logger.info(variables.Logger.SECURITY_SUCCESS, "File upload requested: " & filename);
					var f = new File(uploadDirObject, filename);
               if (f.exists())
               {
						var parts = filename.split("\\/.");
						var extension = "";
                  if (parts.length > 1)
                  {
							extension = parts[parts.length - 1];
						}
						var filenm = filename.substring(0, filename.length() - extension.length());
						f = File.createTempFile(filenm, "." & extension, uploadDirObject);
					}
					item.write(f);
               newFiles.add(f);
					// delete temporary file
					item.delete();
					variables.logger.fatal(variables.Logger.SECURITY_SUCCESS, "File successfully uploaded: " & f);
               if (!isNull(httpSession))
               {
					    httpSession.setAttribute("progress", Long.toString(0));
					}
				}
			}
		} catch (Exception e) {
			if (instanceOf(e, org.owasp.esapi.errors.ValidationUploadException)) {
				rethrow;
			}
			raiseException(new ValidationUploadException(variables.ESAPI, "Upload failure", "Problem during upload:" & e.getMessage(), e));
		}
		return newFiles;
	}



	/**
     * Utility to return the first cookie matching the provided name.
     * @param httpRequest
     * @param name
     */
	private function getFirstCookie(required httpRequest, required string name) {
		var httpCookies = arguments.httpRequest.getCookies();
		if (!isNull(httpCookies)) {
			for (var httpCookie in httpCookies) {
				if (httpCookie.getName() == arguments.name) {
					return httpCookie;
				}
			}
		}
		return;
	}

	public string function getHeader(required string name, httpRequest=getCurrentRequest()) {
        var value = arguments.httpRequest.getHeader(arguments.name);
        return variables.ESAPI.validator().getValidInput("HTTP header value: " & value, value, "HTTPHeaderValue", 150, false);
	}

	public string function getParameter(required string name, httpRequest=getCurrentRequest()) {
	    var value = arguments.httpRequest.getParameter(arguments.name);
	    return variables.ESAPI.validator().getValidInput("HTTP parameter value: " & value, value, "HTTPParameterValue", 2000, true);
	}

	/**
     * @param httpRequest
     * @param httpResponse
     */
	public void function killAllCookies(httpRequest=getCurrentRequest(), httpResponse=getCurrentResponse()) {
		var httpCookies = arguments.httpRequest.getCookies();
		if (!isNull(httpCookies)) {
			for (var httpCookie in httpCookies) {
				killCookie(httpCookie.getName(), arguments.httpRequest, arguments.httpResponse);
			}
		}
	}


	/**
     * @param httpRequest
     * @param httpResponse
     * @param name
     */
	public void function killCookie(required string name, httpRequest=getCurrentRequest(), httpResponse=getCurrentResponse()) {
		var path = "/";
		var domain="";
		var httpCookie = getFirstCookie(arguments.httpRequest, arguments.name);
		if ( !isNull(httpCookie) ) {
			path = httpCookie.getPath();
			domain = httpCookie.getDomain();
		}
		var deleter = createObject("java", "javax.servlet.http.Cookie").init( arguments.name, "deleted" );
		deleter.setMaxAge( 0 );
		if ( !isNull(domain) ) deleter.setDomain( domain );
		if ( !isNull(path) ) deleter.setPath( path );
		arguments.httpResponse.addCookie( deleter );
	}

	/**
	 * Formats an HTTP request into a log suitable string. This implementation logs the remote host IP address (or
	 * hostname if available), the request method (GET/POST), the URL, and all the querystring and form parameters. All
	 * the parameters are presented as though they were in the URL even if they were in a form. Any parameters that
	 * match items in the parameterNamesToObfuscate are shown as eight asterisks.
	 */
	public void function logHTTPRequest(httpRequest=getCurrentRequest(), logger=variables.logger, array parameterNamesToObfuscate) {
		var params = createObject("java", "java.lang.StringBuilder").init();
		var i = httpRequest.getParameterMap().keySet().iterator();
		while (i.hasNext()) {
			var key = i.next();
			var value = httpRequest.getParameterMap().get(key);
			for (var j = 1; j <= arrayLen(value); j++) {
				params.append(key).append("=");
				if (!isNull(arguments.parameterNamesToObfuscate) && arrayFind(arguments.parameterNamesToObfuscate, key)) {
					params.append("********");
				}
				else {
					params.append(value[j]);
				}
				if (j < arrayLen(value) - 1) {
	                params.append("&");
	            }
			}
			if (i.hasNext()) params.append("&");
		}
		var httpCookies = arguments.httpRequest.getCookies();
		if (!isNull(httpCookies)) {
			for (var httpCookie in httpCookies) {
				var ignoreCookies = [variables.ESAPI.securityConfiguration().getHttpSessionIdName(), "CFID", "CFTOKEN"];
				if (!arrayFindNoCase(ignoreCookies, httpCookie.getName())) {
					params.append("&").append(httpCookie.getName()).append("=").append(httpCookie.getValue());
				}
			}
		}
		var msg = arguments.httpRequest.getMethod() & " " & arguments.httpRequest.getRequestURL() & (params.length() > 0 ? "?" & params : "");
		arguments.logger.info(arguments.logger.SECURITY_SUCCESS, msg);
	}

	private struct function queryToMap(required string queryString) {
		var map = {};
		var parts = listToArray(arguments.queryString, "&");
		for (var part in parts) {
	        try {
	            var nvpair = listToArray(part, "=");
				var name = variables.ESAPI.encoder().decodeFromURL(nvpair[1]);
				var value = variables.ESAPI.encoder().decodeFromURL(nvpair[2]);
	            map[name] = value;
	         }
	         catch (org.owasp.esapi.errors.EncodingException e) {
				// skip the nvpair with the encoding problem - note this is already logged.
			}
		}
		return map;
	}

	/**
	 * This implementation simply checks to make sure that the forward location starts with "WEB-INF" and
	 * is intended for use in frameworks that forward to JSP files inside the WEB-INF folder.
	 */
	public void function sendForward(required string location, httpRequest=getCurrentRequest(), httpResponse=getCurrentResponse()) {
		if (!arguments.location.startsWith("WEB-INF")) {
			raiseException(new AccessControlException(variables.ESAPI, "Forward failed", "Bad forward location: " & arguments.location));
		}
		var dispatcher = arguments.httpRequest.getRequestDispatcher(arguments.location);
		dispatcher.forward( arguments.httpRequest, arguments.httpResponse );
	}

	/**
	 * This implementation checks against the list of safe redirect locations defined in ESAPI.properties.
     *
     * @param httpResponse
     */
    public void function sendRedirect(required string location, httpResponse=getCurrentResponse()){
        if (!variables.ESAPI.validator().isValidRedirectLocation("Redirect", arguments.location, false)) {
            variables.logger.fatal(variables.Logger.SECURITY_FAILURE, "Bad redirect location: " & arguments.location);
            raiseException(createObject("java", "java.io.IOException").init("Redirect failed"));
        }
		arguments.httpResponse.sendRedirect(location);
    }

	public void function setContentType(httpResponse=getCurrentResponse()) {
		arguments.httpResponse.setContentType(variables.ESAPI.securityConfiguration().getResponseContentType());
	}

	public void function setCurrentHTTP(required httpRequest, required httpResponse) {
		if (isInstanceOf(arguments.httpRequest, "org.owasp.esapi.beans.SafeRequest")) {
			variables.currentRequest.setRequest(arguments.httpRequest);
		}
		else {
			variables.currentRequest.setRequest(new SafeRequest(variables.ESAPI, arguments.httpRequest));
		}
		if (isInstanceOf(arguments.httpResponse, "org.owasp.esapi.beans.SafeResponse")) {
			variables.currentResponse.setResponse(arguments.httpResponse);
		}
		else {
			variables.currentResponse.setResponse(new SafeResponse(variables.ESAPI, arguments.httpResponse));
		}
	}

    public void function setHeader(required string name, required string value, httpResponse=getCurrentResponse()) {
    	var StringUtilities = createObject("java", "org.owasp.esapi.StringUtilities");
        try {
            var strippedName = StringUtilities.replaceLinearWhiteSpace(arguments.name);
            var strippedValue = StringUtilities.replaceLinearWhiteSpace(arguments.value);
            var safeName = variables.ESAPI.validator().getValidInput("setHeader", strippedName, "HTTPHeaderName", 20, false);
            var safeValue = variables.ESAPI.validator().getValidInput("setHeader", strippedValue, "HTTPHeaderValue", 500, false);
            httpResponse.setHeader(safeName, safeValue);
        } catch (org.owasp.esapi.errors.ValidationException e) {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Attempt to set invalid header denied", e);
        }
    }

	/**
     * @param httpResponse
     */
	public void function setNoCacheHeaders(httpResponse=getCurrentResponse()) {
		// HTTP 1.1
		arguments.httpResponse.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");

		// HTTP 1.0
		arguments.httpResponse.setHeader("Pragma", "no-cache");
		arguments.httpResponse.setDateHeader("Expires", -1);
	}

	/**
	 * Save the user's remember me data in an encrypted cookie and send it to the user.
	 * Any old remember me cookie is destroyed first. Setting this cookie will keep the user
	 * logged in until the maxAge passes, the password is changed, or the cookie is deleted.
	 * If the cookie exists for the current user, it will automatically be used by ESAPI to
	 * log the user in, if the data is valid and not expired.
     *
     * @param httpRequest
     * @param httpResponse
     */
	public string function setRememberToken(required string password, required numeric maxAge, required string domain, required string path, httpRequest=getCurrentRequest(), httpResponse=getCurrentResponse()) {
		var user = variables.ESAPI.authenticator().getCurrentUser();
		try {
			killCookie(this.REMEMBER_TOKEN_COOKIE_NAME, arguments.httpRequest, arguments.httpResponse );
			// seal already contains random data
			var clearToken = user.getAccountName() & "|" & arguments.password;
			var expiry = variables.ESAPI.encryptor().getRelativeTimeStamp(arguments.maxAge * 1000);
			var cryptToken = variables.ESAPI.encryptor().seal(clearToken, expiry);

            // Do NOT URLEncode cryptToken before creating cookie. See Google Issue # 144,
			// which was marked as "WontFix".

			var httpCookie = createObject("java", "javax.servlet.http.Cookie").init( this.REMEMBER_TOKEN_COOKIE_NAME, cryptToken );
			httpCookie.setMaxAge( arguments.maxAge );
			httpCookie.setDomain( arguments.domain );
			httpCookie.setPath( arguments.path );
			arguments.httpResponse.addCookie( httpCookie );
			variables.logger.info(variables.Logger.SECURITY_SUCCESS, "Enabled remember me token for " & user.getAccountName() );
			return cryptToken;
		} catch( org.owasp.esapi.errors.IntegrityException e ) {
			variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Attempt to set remember me token failed for " & user.getAccountName(), e );
			return;
		}
	}

    /**
	 * This implementation uses the CSRF_TOKEN_NAME parameter for the token.
     *
     * @param httpRequest
     */
	public void function verifyCSRFToken(httpRequest=getCurrentRequest()) {
		var user = variables.ESAPI.authenticator().getCurrentUser();

		// check if user authenticated with this request - no CSRF protection required
		if(!isNull(arguments.httpRequest.getAttribute(user.getCSRFToken()))) {
			return;
		}
		var token = arguments.httpRequest.getParameter(this.CSRF_TOKEN_NAME);
		if (!isDefined("token")) token = "";
		if (user.getCSRFToken() != token) {
			raiseException(new IntrusionException(variables.ESAPI, "Authentication failed", "Possibly forged HTTP request without proper CSRF token detected"));
		}
	}

    public function getSessionAttribute(required string key, httpSession=getCurrentRequest().getSession(false)) {
        if (!isNull(arguments.httpSession) && isObject(arguments.httpSession)) {
            return arguments.httpSession.getAttribute(arguments.key);
        }
        return;
    }

    public function getRequestAttribute(required string key, httpRequest=getCurrentRequest()) {
    	if (!isNull(arguments.httpRequest) && isObject(arguments.httpRequest)) {
        	return arguments.httpRequest.getAttribute(arguments.key);
        }
        return;
    }

    /////////////////////

    /* Helper method to encrypt using new Encryptor encryption methods and
     * return the serialized ciphertext as a hex-encoded string.
     */
    private string function encryptString(required string plaintext) {
        var pt = new PlainText(variables.ESAPI, plaintext);
        var ct = variables.ESAPI.encryptor().encrypt(pt);
        var serializedCiphertext = ct.asPortableSerializedByteArray();
        return createObject("java", "org.owasp.esapi.codecs.Hex").encode(serializedCiphertext, false);
    }

    /* Helper method to decrypt a hex-encode serialized ciphertext string and
     * to decrypt it using the new Encryptor decryption methods.
     */
    private string function decryptString(required string ciphertext) {
        var serializedCiphertext = createObject("java", "org.owasp.esapi.codecs.Hex").decode(ciphertext);
        var restoredCipherText = new CipherText(variables.ESAPI).fromPortableSerializedBytes(serializedCiphertext);
        var plaintext = variables.ESAPI.encryptor().decrypt(restoredCipherText);
        return plaintext.toString();
    }

}