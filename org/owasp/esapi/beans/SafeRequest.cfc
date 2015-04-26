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

/**
 * This request wrapper simply overrides unsafe methods in the
 * HttpServletRequest API with safe versions that return canonicalized data
 * where possible. The wrapper returns a safe value when a validation error is
 * detected, including stripped or empty strings.
 */
component implements="org.owasp.esapi.HttpRequest" extends="org.owasp.esapi.util.Object" {

	variables.ESAPI = "";
	variables.logger = "";

	variables.httpRequest = "";

    variables.allowableContentRoot = "WEB-INF";

	this.BASIC_AUTH = "BASIC";
	this.FORM_AUTH = "FORM";
	this.CLIENT_CERT_AUTH = "CLIENT_CERT";
	this.DIGEST_AUTH = "DIGEST";

    /**
     * Construct a safe request that overrides the default request methods with
     * safer versions.
     *
     * @param request The {@code HttpServletRequest} we are wrapping.
     */
    public org.owasp.esapi.HttpRequest function init(required org.owasp.esapi.ESAPI ESAPI, httpRequest) {
    	variables.ESAPI = arguments.ESAPI;
    	variables.logger = variables.ESAPI.getLogger(getMetaData(this).fullName);

    	if (structKeyExists(arguments, "httpRequest")) {
    		variables.httpRequest = arguments.httpRequest;
    	}
    	return this;
    }

    private function getHttpServletRequest() {
    	if (!isObject(variables.httpRequest)) {
    		//variables.httpRequest = getPageContext().getRequest();
    	}
    	return variables.httpRequest;
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @param name The attribute name
     * @return The attribute value
     */
    public function getAttribute(required string name) {
        return getHttpServletRequest().getAttribute(javaCast("string", arguments.name));
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return An {@code Enumeration} of attribute names.
     */
    public function getAttributeNames() {
        return getHttpServletRequest().getAttributeNames();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return The authentication type
     */
    public string function getAuthType() {
        return getHttpServletRequest().getAuthType();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return  The character-encoding for this {@code HttpServletRequest}
     */
    public string function getCharacterEncoding() {
        return getHttpServletRequest().getCharacterEncoding();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return The content-length for this {@code HttpServletRequest}
     */
    public numeric function getContentLength() {
        return getHttpServletRequest().getContentLength();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return The content-type for this {@code HttpServletRequest}
     */
    public string function getContentType() {
        return getHttpServletRequest().getContentType();
    }

    /**
     * Returns the context path from the HttpServletRequest after canonicalizing
     * and filtering out any dangerous characters.
     * @return The context path for this {@code HttpServletRequest}
     */
    public string function getContextPath() {
        var path = getHttpServletRequest().getContextPath();

		//Return empty String for the ROOT context
		if (isNull(path) || trim(path) == "") return "";

        var clean = "";
        try {
            clean = variables.ESAPI.validator().getValidInput("HTTP context path: " & path, path, "HTTPContextPath", 150, false);
        } catch (org.owasp.esapi.errors.ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Returns the array of Cookies from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @return An array of {@code Cookie}s for this {@code HttpServletRequest}
     */
    public array function getCookies() {
        var httpCookies = getHttpServletRequest().getCookies();
        if (isNull(httpCookies)) return [];

        var newCookies = [];
        for (var c in httpCookies) {
            // build a new clean cookie
            try {
                // get data from original cookie
                var name = variables.ESAPI.validator().getValidInput("Cookie name: " & c.getName(), c.getName(), "HTTPCookieName", 150, true);
                var value = variables.ESAPI.validator().getValidInput("Cookie value: " & c.getValue(), c.getValue(), "HTTPCookieValue", 1000, true);
                var maxAge = c.getMaxAge();
                var domain = c.getDomain();
                var path = c.getPath();

                var n = createObject("java", "javax.servlet.http.Cookie").init(name, value);
                n.setMaxAge(maxAge);

                if (!isNull(domain)) {
                    n.setDomain(variables.ESAPI.validator().getValidInput("Cookie domain: " & domain, domain, "HTTPHeaderValue", 200, false));
                }
                if (!isNull(path)) {
                    n.setPath(variables.ESAPI.validator().getValidInput("Cookie path: " & path, path, "HTTPHeaderValue", 200, false));
                }
                newCookies.add(n);
            }
            catch (org.owasp.esapi.errors.ValidationException e) {
                variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Skipping bad cookie: " & c.getName() & "=" & c.getValue(), e );
            }
        }
        return newCookies;
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @param name Specifies the name of the HTTP request header; e.g.,
     *             {@code If-Modified-Since}.
     * @return a long value representing the date specified in the header
     * expressed as the number of milliseconds since {@code January 1, 1970 GMT},
     * or {@code -1} if the named header was not included with the request.
     */
    public numeric function getDateHeader(required string name) {
        return getHttpServletRequest().getDateHeader(javaCast("string", arguments.name));
    }

    /**
     * Returns the named header from the HttpServletRequest after canonicalizing
     * and filtering out any dangerous characters.
     * @param name The name of an HTTP request header
     * @return The specified header value is returned.
     */
    public string function getHeader(required string name) {
        var value = getHttpServletRequest().getHeader(javaCast("string", arguments.name));
        var clean = "";
        if (isDefined("value")) {
	        try {
	            clean = variables.ESAPI.validator().getValidInput("HTTP header value: " & value, value, "HTTPHeaderValue", 150, true);
	        } catch (org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	    }
        return clean;
    }

    /**
     * Returns the enumeration of header names from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @return An {@code Enumeration} of header names associated with this request.
     */
    public array function getHeaderNames() {
        var v = [];
        var en = getHttpServletRequest().getHeaderNames();
        while (en.hasMoreElements()) {
            try {
                var name = en.nextElement();
                var clean = variables.ESAPI.validator().getValidInput("HTTP header name: " & name, name, "HTTPHeaderName", 150, true);
                arrayAppend(v, clean);
            } catch (org.owasp.esapi.errors.ValidationException e) {
                // already logged
            }
        }
        return v;
    }

    /**
     * Returns the enumeration of headers from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @param name The name of an HTTP request header.
     * @return An {@code Enumeration} of headers from the request after
     *         canonicalizing and filtering has been performed.
     */
    public function getHeaders(required string name) {
        var v = [];
        var en = getHttpServletRequest().getHeaders(javaCast("string", arguments.name));
        while (en.hasMoreElements()) {
            try {
                var value = en.nextElement();
                var clean = variables.ESAPI.validator().getValidInput("HTTP header value (" & arguments.name & "): " & value, value, "HTTPHeaderValue", 150, true);
                v.add(clean);
            } catch (org.owasp.esapi.errors.ValidationException e) {
                // already logged
            }
        }
        return v.elements();
    }

    /**
     * Same as HttpServletRequest, no security changes required. Note that this
     * input stream may contain attacks and the developer is responsible for
     * canonicalizing, validating, and encoding any data from this stream.
     * @return The {@code ServletInputStream} associated with this
     *         {@code HttpServletRequest}.
     * @throws IOException Thrown if an input exception is thrown, such as the
     *         remote peer closing the connection.
     */
    public function getInputStream() {
        return getHttpServletRequest().getInputStream();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @param name The name of an HTTP request header.
     * @return Returns the value of the specified request header as an {@code int}.
     */
    public numeric function getIntHeader(required string name) {
        return getHttpServletRequest().getIntHeader(javaCast("string", arguments.name));
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return A {@code String} containing the IP address on which the
     *         request was received.
     */
    public string function getLocalAddr() {
        return getHttpServletRequest().getLocalAddr();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return The preferred {@code Locale} for the client.
     */
    public function getLocale() {
        return getHttpServletRequest().getLocale();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return An {@code Enumeration} of preferred {@code Locale}
     *         objects for the client.
     */
    public function getLocales() {
        return getHttpServletRequest().getLocales();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return A {@code String} containing the host name of the IP on which
     *         the request was received.
     */
    public string function getLocalName() {
        return getHttpServletRequest().getLocalName();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Returns the Internet Protocol (IP) port number of the interface
     *         on which the request was received.
     */
    public function getLocalPort() {
        return getHttpServletRequest().getLocalPort();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Returns the name of the HTTP method with which this request was made.
     */
    public string function getMethod() {
        return getHttpServletRequest().getMethod();
    }

    /**
     * Returns the named parameter from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @param name The parameter name for the request
     * @param allowNull Whether null values are allowed
     * @param maxLength The maximum length allowed
     * @param regexName The name of the regex mapped from variables.ESAPI.properties
     * @return The "scrubbed" parameter value.
     */
    public string function getParameter(required string name, boolean allowNull=true, numeric maxLength=2000, string regexName="HTTPParameterValue") {
        var orig = getHttpServletRequest().getParameter(arguments.name);

        // *** begin workarounds ***
		//	Reference: https://github.com/damonmiller/esapi4cf/issues/39

        // 1- Railo/Lucee workaround - if value is null, fallback on getParameterMap()
		if (isNull(orig)) {
			var params = variables.httpRequest.getParameterMap();
			if (structKeyExists(params, arguments.name)) {
				orig = params[arguments.name][1];
				variables.logger.info(variables.logger.SECURITY_FAILURE, "Server incorrectly implements RequestContext. getParameterMap() fallback used to retrieve parameter '" & arguments.name & "' - see Issue 39.");
			}
		}

		// 2- CF10+ workaround  - if value is null, fallback on form scope <----- worst hack in ESAPI4CF by far!!!
		//    referencing the form scope violates encapsulation but unit tests will never hit this condition thankfully
		if (isNull(orig)) {
			if (structKeyExists(form, arguments.name)) {
				orig = form[arguments.name];
				variables.logger.info(variables.logger.SECURITY_FAILURE, "Server incorrectly implements RequestContext. FORM scope fallback used to retrieve parameter '" & arguments.name & "' - see Issue 39.");
			}
		}
		// *** end workarounds ***

        if (isNull(orig)) return "";
        var clean = "";
        try {
            clean = variables.ESAPI.validator().getValidInput("HTTP parameter name: " & arguments.name, orig, arguments.regexName, arguments.maxLength, arguments.allowNull);
        }
        catch (org.owasp.esapi.errors.ValidationException ex) {
            // already logged
        }
        return clean;
    }

    /**
     * Returns the parameter map from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @return A {@code Map} containing scrubbed parameter names / value pairs.
     */
    public struct function getParameterMap() {
        var map = getHttpServletRequest().getParameterMap();
        var cleanMap = {};
        for (var name in map) {
            try {
                var cleanName = variables.ESAPI.validator().getValidInput("HTTP parameter name: " & name, name, "HTTPParameterName", 100, true);

                var value = map[name];
                var cleanValues = [];
                for (var j = 1; j <= arrayLen(value); j++) {
                    var cleanValue = variables.ESAPI.validator().getValidInput("HTTP parameter value: " & value[j], value[j], "HTTPParameterValue", 2000, true);
                    cleanValues[j] = cleanValue;
                }
                cleanMap.put(cleanName, cleanValues);
            }
            catch (org.owasp.esapi.errors.ValidationException e) {
                // already logged
            }
        }
        return cleanMap;
    }

    /**
     * Returns the enumeration of parameter names from the HttpServletRequest
     * after canonicalizing and filtering out any dangerous characters.
     * @return An {@code Enumeration} of properly "scrubbed" parameter names.
     */
    public array function getParameterNames() {
        var v = [];
        var en = getHttpServletRequest().getParameterNames();
        while (en.hasMoreElements()) {
            try {
                var name = en.nextElement();
                var clean = variables.ESAPI.validator().getValidInput("HTTP parameter name: " & name, name, "HTTPParameterName", 150, true);
                v.add(clean);
            }
            catch (org.owasp.esapi.errors.ValidationException e) {
                // already logged
            }
        }
        return v;
    }

    /**
     * Returns the array of matching parameter values from the
     * HttpServletRequest after canonicalizing and filtering out any dangerous
     * characters.
     * @param name The parameter name
     * @return An array of matching "scrubbed" parameter values or
     * <code>null</code> if the parameter does not exist.
     */
    public array function getParameterValues(required string name) {
        var values = getHttpServletRequest().getParameterValues(javaCast("string", arguments.name));
        var newValues = "";

		if(isNull(values)) return [];

        newValues = [];
        for (var value in values) {
            try {
                var cleanValue = variables.ESAPI.validator().getValidInput("HTTP parameter value: " & value, value, "HTTPParameterValue", 2000, true);
                newValues.add(cleanValue);
            } catch (org.owasp.esapi.errors.ValidationException e) {
                variables.logger.warning(variables.logger.SECURITY_FAILURE, "Skipping bad parameter");
            }
        }
        return newValues;
    }

    /**
     * Returns the path info from the HttpServletRequest after canonicalizing
     * and filtering out any dangerous characters.
     * @return Returns any extra path information, appropriately scrubbed,
     *         associated with the URL the client sent when it made this request.
     */
    public string function getPathInfo() {
        var path = getHttpServletRequest().getPathInfo();
		if (isNull(path)) return;
        var clean = "";
        try {
            clean = variables.ESAPI.validator().getValidInput("HTTP path: " & path, path, "HTTPPath", 150, true);
        } catch (org.owasp.esapi.errors.ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Returns any extra path information, appropriate scrubbed,
     *         after the servlet name but before the query string, and
     *         translates it to a real path.
     */
    public string function getPathTranslated() {
        return getHttpServletRequest().getPathTranslated();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Returns the name and version of the protocol the request uses in
     *       the form protocol/majorVersion.minorVersion, for example, HTTP/1.1.
     */
    public string function getProtocol() {
        return getHttpServletRequest().getProtocol();
    }

    /**
     * Returns the query string from the HttpServletRequest after canonicalizing
     * and filtering out any dangerous characters.
     * @return The scrubbed query string is returned.
     */
    public string function getQueryString() {
        var querystring = getHttpServletRequest().getQueryString();
        if (isNull(querystring)) {
        	querystring = "";
        }
        var clean = "";
        try {
            clean = variables.ESAPI.validator().getValidInput("HTTP query string: " & querystring, querystring, "HTTPQueryString", 2000, true);
        } catch (org.owasp.esapi.errors.ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Same as HttpServletRequest, no security changes required. Note that this
     * reader may contain attacks and the developer is responsible for
     * canonicalizing, validating, and encoding any data from this stream.
     * @return aA {@code BufferedReader} containing the body of the request.
     * @throws IOException If an input error occurred while reading the request
     *                     body (e.g., premature EOF).
     */
    public function getReader() {
        return getHttpServletRequest().getReader();
    }

    // CHECKME: Should this be deprecated since ServletRequest.getRealPath(String)
    //          is deprecated? Should use ServletContext.getRealPath(String) instead.
    /**
     * Same as HttpServletRequest, no security changes required.
     * @param path A virtual path on a web or application server; e.g., "/index.htm".
     * @return Returns a String containing the real path for a given virtual path.
     * @deprecated in servlet spec 2.1. Use {@link javax.servlet.ServletContext#getRealPath(String)} instead.
     */
    public string function getRealPath(required string path) {
        return getHttpServletRequest().getRealPath(javaCast("string", arguments.path));
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Returns the IP address of the client or last proxy that sent the request.
     */
    public string function getRemoteAddr() {
        return getHttpServletRequest().getRemoteAddr();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return The remote host
     */
    public string function getRemoteHost() {
        return getHttpServletRequest().getRemoteHost();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return The remote port
     */
    public numeric function getRemotePort() {
        return getHttpServletRequest().getRemotePort();
    }

    /**
     * Returns the name of the variables.ESAPI user associated with this getHttpServletRequest().
     * @return Returns the fully qualified name of the client or the last proxy
     *         that sent the request
     */
    public string function getRemoteUser() {
        return variables.ESAPI.authenticator().getCurrentUser().getAccountName();
    }

    /**
     * Checks to make sure the path to forward to is within the WEB-INF
     * directory and then returns the dispatcher. Otherwise returns null.
     * @param path The path to create a request dispatcher for
     * @return A {@code RequestDispatcher} object that acts as a wrapper for the
     *         resource at the specified path, or null if the servlet container
     *         cannot return a {@code RequestDispatcher}.
     */
    public function getRequestDispatcher(required string path) {
        if (arguments.path.startsWith(variables.allowableContentRoot)) {
            return getHttpServletRequest().getRequestDispatcher(javaCast("string", arguments.path));
        }
        return;
    }

    /**
     * Returns the URI from the HttpServletRequest after canonicalizing and
     * filtering out any dangerous characters. Code must be very careful not to
     * depend on the value of a requested session id reported by the user.
     * @return The requested Session ID
     */
    public string function getRequestedSessionId() {
        var id = getHttpServletRequest().getRequestedSessionId();
        var clean = "";
        try {
            clean = variables.ESAPI.validator().getValidInput("Requested cookie: " & id, id, "HTTPJSESSIONID", 50, false);
        } catch (org.owasp.esapi.errors.ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Returns the URI from the HttpServletRequest after canonicalizing and
     * filtering out any dangerous characters.
     * @return The current request URI
     */
    public string function getRequestURI() {
        var uri = getHttpServletRequest().getRequestURI();
        var clean = "";
        try {
            clean = variables.ESAPI.validator().getValidInput("HTTP URI: " & uri, uri, "HTTPURI", 2000, false);
        } catch (org.owasp.esapi.errors.ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Returns the URL from the HttpServletRequest after canonicalizing and
     * filtering out any dangerous characters.
     * @return The currect request URL
     */
    public function getRequestURL() {
        var httpUrl = getHttpServletRequest().getRequestURL().toString();
        var clean = "";
        try {
            clean = variables.ESAPI.validator().getValidInput("HTTP URL: " & httpUrl, httpUrl, "HTTPURL", 2000, false);
        }
        catch (org.owasp.esapi.errors.ValidationException e) {
            // already logged
        }
        return createObject("java", "java.lang.StringBuffer").init(clean);
    }

    /**
     * Returns the scheme from the HttpServletRequest after canonicalizing and
     * filtering out any dangerous characters.
     * @return The scheme of the current request
     */
    public string function getScheme() {
        var scheme = getHttpServletRequest().getScheme();
        var clean = "";
        try {
            clean = variables.ESAPI.validator().getValidInput("HTTP scheme: " & scheme, scheme, "HTTPScheme", 10, false);
        } catch (org.owasp.esapi.errors.ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Returns the server name (host header) from the HttpServletRequest after
     * canonicalizing and filtering out any dangerous characters.
     * @return The local server name
     */
    public string function getServerName() {
        var name = getHttpServletRequest().getServerName();
        var clean = "";
        try {
            clean = variables.ESAPI.validator().getValidInput("HTTP server name: " & name, name, "HTTPServerName", 100, false);
        } catch (org.owasp.esapi.errors.ValidationException e) {
            // already logged
        }
        return clean;
    }

    /**
     * Returns the server port (after the : in the host header) from the
     * HttpServletRequest after parsing and checking the range 0-65536.
     * @return The local server port
     */
	public numeric function getServerPort() {
		var port = getHttpServletRequest().getServerPort();
		if ( port < 0 || port > 65535 ) {
			variables.logger.warning( variables.logger.SECURITY_FAILURE, "HTTP server port out of range: " & port );
			port = 0;
		}
		return port;
	}


    /**
     * Returns the server path from the HttpServletRequest after canonicalizing
     * and filtering out any dangerous characters.
     * @return The servlet path
     */
    public string function getServletPath() {
        var path = getHttpServletRequest().getServletPath();
        var clean = "";
        try {
            clean = variables.ESAPI.validator().getValidInput("HTTP servlet path: " & path, path, "HTTPServletPath", 100, false);
        } catch (org.owasp.esapi.errors.ValidationException e) {
            // already logged
        }
        return clean;
    }


    /**
     * Returns a session, creating it if necessary.
     * @param create Create a new session if one doesn't exist
     * @return The current session
     */
    public function getSession(boolean create) {
		if (structKeyExists(arguments, "create")) {
			return new SafeSession(variables.ESAPI, getHttpServletRequest().getSession(javaCast("boolean", arguments.create)));
		}
		else {
			return new SafeSession(variables.ESAPI, getHttpServletRequest().getSession());
		}
    }

    /**
     * Returns the variables.ESAPI User associated with this getHttpServletRequest().
     * @return The variables.ESAPI User
     */
    public function getUserPrincipal() {
        return variables.ESAPI.authenticator().getCurrentUser();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return if requested session id is from a cookie
     */
    public boolean function isRequestedSessionIdFromCookie() {
        return getHttpServletRequest().isRequestedSessionIdFromCookie();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Whether the requested session id is from the URL
     */
    public boolean function isRequestedSessionIdFromURL() {
        return getHttpServletRequest().isRequestedSessionIdFromURL();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Whether the requested session id is valid
     */
    public boolean function isRequestedSessionIdValid() {
        return getHttpServletRequest().isRequestedSessionIdValid();
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @return Whether the current request is secure
     */
    public boolean function isSecure() {
        try {
            variables.ESAPI.httpUtilities().assertSecureChannel();
        } catch (AccessControlException e) {
            return false;
        }
        return true;
    }

    /**
     * Returns true if the variables.ESAPI User associated with this request has the
     * specified role.
     * @param role The role to check
     * @return Whether the current user is in the passed role
     */
    public boolean function isUserInRole(required string role) {
        return variables.ESAPI.authenticator().getCurrentUser().isInRole(arguments.role);
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @param name The attribute name
     */
    public void function removeAttribute(required string name) {
        getHttpServletRequest().removeAttribute(javaCast("string", arguments.name));
    }

    /**
     * Same as HttpServletRequest, no security changes required.
     * @param name The attribute name
     * @param o The attribute value
     */
    public void function setAttribute(required string name, required o) {
        getHttpServletRequest().setAttribute(javaCast("string", arguments.name), arguments.o);
    }

    /**
     * Sets the character encoding scheme to the variables.ESAPI configured encoding scheme.
     * @param enc The encoding scheme
     * @throws UnsupportedEncodingException
     */
    public void function setCharacterEncoding(required string enc) {
        getHttpServletRequest().setCharacterEncoding(variables.ESAPI.securityConfiguration().getCharacterEncoding());
    }

    public string function getAllowableContentRoot() {
        return allowableContentRoot;
    }

    public void function setAllowableContentRoot(required string allowableContentRoot) {
        variables.allowableContentRoot = arguments.allowableContentRoot.startsWith( "/" ) ? arguments.allowableContentRoot : "/" & arguments.allowableContentRoot;
    }

    // do any of these need cleansing?

    public boolean function authenticate(required response) {
		return getHttpServletRequest().authenticate(arguments.response);
    }

    public void function login(required string username, required string password) {
    	return getHttpServletRequest().login(javaCast("string", arguments.username), javaCast("string", arguments.password));
    }

    public void function logout() {
    	return getHttpServletRequest().logout();
    }

    public boolean function isAsyncStarted() {
    	return getHttpServletRequest().isAsyncStarted();
    }

    public boolean function isAsyncSupported() {
    	return getHttpServletRequest().isAsyncSupported();
    }

    public function getPart() {
    	return getHttpServletRequest().getPart();
    }

    public function getParts() {
    	return getHttpServletRequest().getParts();
    }

    public function getDispatcherType() {
    	return getHttpServletRequest().getDispatcherType();
    }

    public function getServletContext() {
    	return getHttpServletRequest().getServletContext();
    }

    public function startAsync(servletRequest, servletResponse) {
    	return getHttpServletRequest().startAsync(arguments.servletRequest, arguments.servletResponse);
    }

	public function getAsyncContext() {
		return getHttpServletRequest().getAsyncContext();
	}

}
