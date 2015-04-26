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
import "org.owasp.esapi.errors.IntrusionException";

/**
 * This response wrapper simply overrides unsafe methods in the
 * HttpServletResponse API with safe versions.
 */
component implements="org.owasp.esapi.HttpResponse" extends="org.owasp.esapi.util.Object" {

	variables.ESAPI = "";
	variables.logger = "";

	variables.httpResponse = "";

	this.SC_CONTINUE = 100;
	this.SC_SWITCHING_PROTOCOLS = 101;
	this.SC_OK = 200;
	this.SC_CREATED = 201;
	this.SC_ACCEPTED = 202;
	this.SC_NON_AUTHORITATIVE_INFORMATION = 203;
	this.SC_NO_CONTENT = 204;
	this.SC_RESET_CONTENT = 205;
	this.SC_PARTIAL_CONTENT = 206;
	this.SC_MULTIPLE_CHOICES = 300;
	this.SC_MOVED_PERMANENTLY = 301;
	this.SC_MOVED_TEMPORARILY = 302;
	this.SC_FOUND = 302;
	this.SC_SEE_OTHER = 303;
	this.SC_NOT_MODIFIED = 304;
	this.SC_USE_PROXY = 305;
	this.SC_TEMPORARY_REDIRECT = 307;
	this.SC_BAD_REQUEST = 400;
	this.SC_UNAUTHORIZED = 401;
	this.SC_PAYMENT_REQUIRED = 402;
	this.SC_FORBIDDEN = 403;
	this.SC_NOT_FOUND = 404;
	this.SC_METHOD_NOT_ALLOWED = 405;
	this.SC_NOT_ACCEPTABLE = 406;
	this.SC_PROXY_AUTHENTICATION_REQUIRED = 407;
	this.SC_REQUEST_TIMEOUT = 408;
	this.SC_CONFLICT = 409;
	this.SC_GONE = 410;
	this.SC_LENGTH_REQUIRED = 411;
	this.SC_PRECONDITION_FAILED = 412;
	this.SC_REQUEST_ENTITY_TOO_LARGE = 413;
	this.SC_REQUEST_URI_TOO_LONG = 414;
	this.SC_UNSUPPORTED_MEDIA_TYPE = 415;
	this.SC_REQUESTED_RANGE_NOT_SATISFIABLE = 416;
	this.SC_EXPECTATION_FAILED = 417;
	this.SC_INTERNAL_SERVER_ERROR = 500;
	this.SC_NOT_IMPLEMENTED = 501;
	this.SC_BAD_GATEWAY = 502;
	this.SC_SERVICE_UNAVAILABLE = 503;
	this.SC_GATEWAY_TIMEOUT = 504;
	this.SC_HTTP_VERSION_NOT_SUPPORTED = 505;

    /**
     * Construct a safe response that overrides the default response methods
     * with safer versions.
     *
     * @param response
     */
    public org.owasp.esapi.HttpResponse function init(required org.owasp.esapi.ESAPI ESAPI, httpResponse) {
    	variables.ESAPI = arguments.ESAPI;
    	variables.logger = variables.ESAPI.getLogger(getMetaData(this).fullName);

    	if (structKeyExists(arguments, "httpResponse")) {
    		variables.httpResponse = arguments.httpResponse;
    	}
    	return this;
    }

    private function getHttpServletResponse() {
    	if (!isObject(variables.httpResponse)) {
    		//variables.httpResponse = getPageContext().getResponse();
    	}
    	return variables.httpResponse;
    }

    /**
     * Add a cookie to the response after ensuring that there are no encoded or
     * illegal characters in the name and name and value. This method also sets
     * the secure and HttpOnly flags on the cookie. This implementation uses a
     * custom "set-cookie" header instead of using Java's cookie interface which
     * doesn't allow the use of HttpOnly.
     * @param cookie
     */
    public void function addCookie(required httpCookie) {
        var name = arguments.httpCookie.getName();
        var value = arguments.httpCookie.getValue();
        var maxAge = arguments.httpCookie.getMaxAge();
        var domain = arguments.httpCookie.getDomain();
        var path = arguments.httpCookie.getPath();
        var secure = arguments.httpCookie.getSecure();

        // validate the name and value
        var errors = {};
        var cookieName = variables.ESAPI.validator().getValidInput("cookie name", name, "HTTPCookieName", 50, false, true, errors);
        var cookieValue = variables.ESAPI.validator().getValidInput("cookie value", value, "HTTPCookieValue", variables.ESAPI.securityConfiguration().getMaxHttpHeaderSize(), false, true, errors);

		var cookieParams = {
			name: cookieName,
			value: cookieValue,
			maxAge: maxAge
		};
		if (isDefined("domain")) cookieParams.domain = domain;
		if (isDefined("path")) cookieParams.path = path;
		if (isDefined("secure")) cookieParams.secure = secure;

        // if there are no errors, then just set a cookie header
        if (structCount(errors) == 0) {
            var httpHeader = createCookieHeader(argumentCollection=cookieParams);
            this.addHeader("Set-Cookie", httpHeader);
            return;
        }

        var mode = variables.ESAPI.securityConfiguration().getUnsafeCookieMode();

        // if there was an error
        if (mode == "skip") {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Attempt to add unsafe data to cookie (skip mode). Skipping cookie and continuing.");
            return;
        }

        // add the original cookie to the response and continue
        if (mode == "log") {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Attempt to add unsafe data to cookie (log mode). Adding unsafe cookie anyway and continuing.");
            getHttpServletResponse().addCookie(httpCookie);
            return;
        }

        // create a sanitized cookie header and continue
        if (mode == "sanitize") {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Attempt to add unsafe data to cookie (sanitize mode). Sanitizing cookie and continuing.");
            var httpHeader = createCookieHeader(argumentCollection=cookieParams);
            this.addHeader("Set-Cookie", httpHeader);
            return;
        }

        // throw an exception if necessary or add original cookie header
        raiseException(new IntrusionException(variables.ESAPI, "Security error", "Attempt to add unsafe data to cookie (throw mode)"));
    }

    private string function createCookieHeader(required string name, required string value, required numeric maxAge, string domain, string path, boolean secure) {
        // create the special cookie header instead of creating a Java cookie
        // Set-Cookie:<name>=<value>[; <name>=<value>][; expires=<date>][;
        // domain=<domain_name>][; path=<some_path>][; secure][;HttpOnly
        var httpHeader = arguments.name & "=" & arguments.value;
        httpHeader &= "; Max-Age=" & arguments.maxAge;
        if (structKeyExists(arguments, "domain")) {
            httpHeader &= "; Domain=" & arguments.domain;
        }
        if (structKeyExists(arguments, "path")) {
            httpHeader &= "; Path=" & arguments.path;
        }
        if ((structKeyExists(arguments, "secure") && arguments.secure) || variables.ESAPI.securityConfiguration().getForceSecureCookies() ) {
			httpHeader &= "; Secure";
        }
        if ( variables.ESAPI.securityConfiguration().getForceHttpOnlyCookies() ) {
			httpHeader &= "; HttpOnly";
        }
        return httpHeader;
    }

    /**
     * Add a cookie to the response after ensuring that there are no encoded or
     * illegal characters in the name.
     * @param name
     * @param date
     */
    public void function addDateHeader(required string name, required numeric date) {
        try {
            var safeName = variables.ESAPI.validator().getValidInput("safeSetDateHeader", arguments.name, "HTTPHeaderName", 20, false);
            getHttpServletResponse().addDateHeader(javaCast("string", safeName), javaCast("long", arguments.date));
        } catch (org.owasp.esapi.errors.ValidationException e) {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Attempt to set invalid date header name denied", e);
        }
    }

    /**
     * Add a header to the response after ensuring that there are no encoded or
     * illegal characters in the name and name and value. This implementation
     * follows the following recommendation: "A recipient MAY replace any linear
     * white space with a single SP before interpreting the field value or
     * forwarding the message downstream."
     * http://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html#sec2.2
     * @param name
     * @param value
     */
    public void function addHeader(required string name, required string value) {
    	var StringUtilities = createObject("java", "org.owasp.esapi.StringUtilities");
        try {
            // TODO: make stripping a global config
            var strippedName = StringUtilities.stripControls(arguments.name);
            var strippedValue = StringUtilities.stripControls(arguments.value);
            var safeName = variables.ESAPI.validator().getValidInput("addHeader", strippedName, "HTTPHeaderName", 20, false);
            var safeValue = variables.ESAPI.validator().getValidInput("addHeader", strippedValue, "HTTPHeaderValue", variables.ESAPI.securityConfiguration().getMaxHttpHeaderSize(), false);
            getHttpServletResponse().setHeader(javaCast("string", safeName), javaCast("string", safeValue));
        } catch (org.owasp.esapi.errors.ValidationException e) {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Attempt to add invalid header denied", e);
        }
    }

    /**
     * Add an int header to the response after ensuring that there are no
     * encoded or illegal characters in the name and name.
     * @param name
     * @param value
     */
    public void function addIntHeader(required string name, required numeric value) {
        try {
            var safeName = variables.ESAPI.validator().getValidInput("safeSetDateHeader", arguments.name, "HTTPHeaderName", 20, false);
            getHttpServletResponse().addIntHeader(javaCast("string", safeName), javaCast("int", arguments.value));
        } catch (org.owasp.esapi.errors.ValidationException e) {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Attempt to set invalid int header name denied", e);
        }
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     * @param name
     * @return
     */
    public boolean function containsHeader(required string name) {
        return getHttpServletResponse().containsHeader(javaCast("string", arguments.name));
    }

    /**
     * Return the URL without any changes, to prevent disclosure of the
     * Session ID The default implementation of this method can add the
     * Session ID to the URL if support for cookies is not detected. This
     * exposes the Session ID credential in bookmarks, referer headers, server
     * logs, and more.
     *
     * @param url
     * @return original url
     */
    public string function encodeRedirectURL(required string url) {
        return arguments.url;
    }

    /**
     * Return the URL without any changes, to prevent disclosure of the
     * Session ID The default implementation of this method can add the
     * Session ID to the URL if support for cookies is not detected. This
     * exposes the Session ID credential in bookmarks, referer headers, server
     * logs, and more.
     *
     * @param url
     * @return original url
     */
    public string function encodeURL(required string url) {
        return arguments.url;
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     * @throws IOException
     */
    public void function flushBuffer() {
        getHttpServletResponse().flushBuffer();
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     * @return
     */
    public numeric function getBufferSize() {
        return getHttpServletResponse().getBufferSize();
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     * @return
     */
    public string function getCharacterEncoding() {
        return getHttpServletResponse().getCharacterEncoding();
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     * @return
     */
    public string function getContentType() {
        return getHttpServletResponse().getContentType();
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     * @return
     */
    public function getLocale() {
        return getHttpServletResponse().getLocale();
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     * @return
     * @throws IOException
     */
    public function getOutputStream() {
        return getHttpServletResponse().getOutputStream();
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     * @return
     * @throws IOException
     */
    public function getWriter() {
        return getHttpServletResponse().getWriter();
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     * @return
     */
    public boolean function isCommitted() {
        return getHttpServletResponse().isCommitted();
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     */
    public void function reset() {
        getHttpServletResponse().reset();
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     */
    public void function resetBuffer() {
        getHttpServletResponse().resetBuffer();
    }

    /**
     * Override the error code with a 200 in order to confound attackers using
     * automated scanners. The message is canonicalized and filtered for
     * dangerous characters.
     * @param sc
     * @param msg
     * @throws IOException
     */
    public void function sendError(required numeric sc, string msg=getHTTPMessage(arguments.sc)) {
        getHttpServletResponse().sendError(javaCast("int", this.SC_OK), javaCast("string", variables.ESAPI.encoder().encodeForHTML(arguments.msg)));
    }

    /**
     * This method generates a redirect response that can only be used to
     * redirect the browser to safe locations, as configured in the ESAPI
     * security configuration. This method does not that redirect requests can
     * be modified by attackers, so do not rely information contained within
     * redirect requests, and do not include sensitive information in a
     * redirect.
     * @param location
     * @throws IOException
     */
    public void function sendRedirect(required string location) {
        if (!variables.ESAPI.validator().isValidRedirectLocation("Redirect", arguments.location, false)) {
            variables.logger.fatal(variables.Logger.SECURITY_FAILURE, "Bad redirect location: " & arguments.location);
            raiseException(createObject("java", "java.io.IOException").init("Redirect failed"));
        }
        getHttpServletResponse().sendRedirect(javaCast("string", arguments.location));
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     * @param size
     */
    public void function setBufferSize(required numeric size) {
        getHttpServletResponse().setBufferSize(javaCast("int", arguments.size));
    }

    /**
     * Sets the character encoding to the ESAPI configured encoding.
     * @param charset
     */
    public void function setCharacterEncoding(required string charset) {
        getHttpServletResponse().setCharacterEncoding(javaCast("string", variables.ESAPI.securityConfiguration().getCharacterEncoding()));
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     * @param len
     */
    public void function setContentLength(required numeric len) {
        getHttpServletResponse().setContentLength(javaCast("int", arguments.len));
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     * @param type
     */
    public void function setContentType(required string type) {
        getHttpServletResponse().setContentType(javaCast("string", arguments.type));
    }

    /**
     * Add a date header to the response after ensuring that there are no
     * encoded or illegal characters in the name.
     * @param name
     * @param date
     */
    public void function setDateHeader(required string name, required numeric date) {
        try {
            var safeName = variables.ESAPI.validator().getValidInput("safeSetDateHeader", arguments.name, "HTTPHeaderName", 20, false);
            getHttpServletResponse().setDateHeader(javaCast("string", safeName), javaCast("long", arguments.date));
        } catch (org.owasp.esapi.errors.ValidationException ex) {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Attempt to set invalid date header name denied", ex);
        }
    }

    /**
     * Add a header to the response after ensuring that there are no encoded or
     * illegal characters in the name and value. "A recipient MAY replace any
     * linear white space with a single SP before interpreting the field value
     * or forwarding the message downstream."
     * http://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html#sec2.2
     * @param name
     * @param value
     */
    public void function setHeader(required string name, required string value) {
    	var StringUtilities = createObject("java", "org.owasp.esapi.StringUtilities");
        try {
            var strippedName = StringUtilities.stripControls(arguments.name);
            var strippedValue = StringUtilities.stripControls(arguments.value);
            var safeName = variables.ESAPI.validator().getValidInput("setHeader", strippedName, "HTTPHeaderName", 20, false);
            var safeValue = variables.ESAPI.validator().getValidInput("setHeader", strippedValue, "HTTPHeaderValue", variables.ESAPI.securityConfiguration().getMaxHttpHeaderSize(), false);
            getHttpServletResponse().setHeader(javaCast("string", safeName), javaCast("string", safeValue));
        } catch (org.owasp.esapi.errors.ValidationException e) {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Attempt to set invalid header denied", e);
        }
    }

    /**
     * Add an int header to the response after ensuring that there are no
     * encoded or illegal characters in the name.
     * @param name
     * @param value
     */
    public void function setIntHeader(required string name, required numeric value) {
        try {
            var safeName = variables.ESAPI.validator().getValidInput("safeSetDateHeader", arguments.name, "HTTPHeaderName", 20, false);
            getHttpServletResponse().setIntHeader(javaCast("string", safeName), javaCast("int", arguments.value));
        } catch (org.owasp.esapi.errors.ValidationException e) {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Attempt to set invalid int header name denied", e);
        }
    }

    /**
     * Same as HttpServletResponse, no security changes required.
     * @param loc
     */
    public void function setLocale(required loc) {
        // TODO investigate the character set issues here
        getHttpServletResponse().setLocale(arguments.loc);
    }


    /**
     * Override the status code with a 200 in order to confound attackers using
     * automated scanners. The message is canonicalized and filtered for
     * dangerous characters.
     * @param sc
     * @param sm
     * @deprecated In Servlet spec 2.1.
     */
    public void function setStatus(required numeric sc, string sm=this.SC_OK) {
        try {
            // setStatus is deprecated so use sendError instead
            sendError(this.SC_OK, arguments.sm);
        } catch (java.io.IOException e) {
			variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Attempt to set response status failed", e);
        }
    }

    /**
     * returns a text message for the HTTP response code
     */
    private string function getHTTPMessage(required numeric sc) {
        return "HTTP error code: " & arguments.sc;
    }

    public string function getHeader(required string name) {
    	return getHttpServletResponse().getHeader(javaCast("string", arguments.name));
    }

    public function getHeaderNames() {
		return getHttpServletResponse().getHeaderNames();
    }

	public function getHeaders(required string name) {
		return getHttpServletResponse().getHeaderNames(javaCast("string", arguments.name));
	}

	public numeric function getStatus() {
		return getHttpServletResponse().getStatus();
	}

}