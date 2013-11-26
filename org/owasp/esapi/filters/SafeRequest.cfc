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
<cfcomponent implements="org.owasp.esapi.util.HttpServletRequest" extends="org.owasp.esapi.util.Object" output="false" hint="This request wrapper simply overrides unsafe methods in the HttpServletRequest API with safe versions that return canonicalized data where possible. The wrapper returns a safe value when a validation error is detected, including stripped or empty strings.">

	<cfscript>
		variables.ESAPI = "";
		variables.httpRequest = "";
		variables.logger = "";
	</cfscript>

	<cffunction access="public" returntype="SafeRequest" name="init" output="false"
	            hint="Construct a safe request that overrides the default request methods with safer versions.">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" name="httpRequest"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.logger = variables.ESAPI.getLogger("SafeRequest");

			variables.httpRequest = arguments.httpRequest;

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getHttpServletRequest" output="false">

		<cfscript>
			return variables.httpRequest;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getAttribute" output="false" hint="Same as HttpServletRequest, no security changes required.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return variables.httpRequest.getAttribute(arguments.name);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getAttributeNames" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getAttributeNames();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getAuthType" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getAuthType();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getCharacterEncoding();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getContentLength" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getContentLength();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getContentType" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getContentType();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getContextPath" output="false"
	            hint="Returns the context path from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var path = variables.httpRequest.getContextPath();
			var clean = "";
			try {
				clean = variables.ESAPI.validator().getValidInput("HTTP context path: " & path, path, "HTTPContextPath", 150, false);
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getCookies" output="false"
	            hint="Returns the array of Cookies from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			// CF8 requires 'var' at the top
			var cookies = "";
			var newCookies = "";
			var i = "";
			var c = "";
			var name = "";
			var value = "";
			var maxAge = "";
			var domain = "";
			var path = "";
			var n = "";

			cookies = variables.httpRequest.getCookies();
			newCookies = [];
			if(isDefined("cookies") && !isNull(cookies)) {
				for(i = 1; i <= arrayLen(cookies); i++) {
					c = cookies[i];

					// build a new clean cookie
					try {
						// get data from original cookie
						name = variables.ESAPI.validator().getValidInput("Cookie name: " & c.getName(), c.getName(), "HTTPCookieName", 150, true);
						value = variables.ESAPI.validator().getValidInput("Cookie value: " & c.getValue(), c.getValue(), "HTTPCookieValue", 1000, true);
						maxAge = c.getMaxAge();
						domain = c.getDomain();
						path = c.getPath();

						n = newJava("javax.servlet.http.Cookie").init(name, value);
						n.setMaxAge(maxAge);

						if(isDefined("domain") && !isNull(domain)) {
							n.setDomain(variables.ESAPI.validator().getValidInput("Cookie domain: " & domain, domain, "HTTPHeaderValue", 200, false));
						}
						if(isDefined("path") && !isNull(path)) {
							n.setPath(variables.ESAPI.validator().getValidInput("Cookie path: " & path, path, "HTTPHeaderValue", 200, false));
						}
						newCookies.add(n);
					}
					catch(org.owasp.esapi.errors.ValidationException e) {
						variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Skipping bad cookie: " & c.getName() & "=" & c.getValue(), e);
					}
				}
			}
			return newCookies;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Date" name="getDateHeader" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return variables.httpRequest.getDateHeader(arguments.name);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getHeader" output="false"
	            hint="Returns the named header from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			var value = variables.httpRequest.getHeader(arguments.name);
			var clean = "";
			if (isDefined("value") && !isNull(value)) {
				try {
					clean = variables.ESAPI.validator().getValidInput("HTTP header value: " & value, value, "HTTPHeaderValue", variables.ESAPI.validator().MAX_HTTPHEADER_VALUE_LENGTH, true);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					// already logged
				}
			}
			return clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getHeaderNames" output="false"
	            hint="Returns the enumeration of header names from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			// CF8 requires 'var' at the top
			var v = "";
			var en = "";
			var name = "";
			var clean = "";

			v = [];
			en = variables.httpRequest.getHeaderNames();
			while(en.hasMoreElements()) {
				try {
					name = en.nextElement();
					clean = variables.ESAPI.validator().getValidInput("HTTP header name: " & name, name, "HTTPHeaderName", variables.ESAPI.validator().MAX_HTTPHEADER_NAME_LENGTH, true);
					v.add(clean);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					// already logged
				}
			}
			return v;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getHeaders" output="false"
	            hint="Returns the enumeration of headers from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var v = "";
			var en = "";
			var value = "";
			var clean = "";

			v = [];
			en = variables.httpRequest.getHeaders(arguments.name);
			while(en.hasMoreElements()) {
				try {
					value = en.nextElement();
					clean = variables.ESAPI.validator().getValidInput("HTTP header value (" & arguments.name & "): " & value, value, "HTTPHeaderValue", variables.ESAPI.validator().MAX_HTTPHEADER_VALUE_LENGTH, true);
					v.add(clean);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					// already logged
				}
			}
			return v;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getInputStream" output="false" hint="Same as HttpServletRequest, no security changes required. Note that this input stream may contain attacks and the developer is responsible for canonicalizing, validating, and encoding any data from this stream.">

		<cfscript>
			return variables.httpRequest.getInputStream();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getIntHeader" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return variables.httpRequest.getIntHeader(arguments.name);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLocalAddr" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getLocalAddr();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getLocaleData" output="false" hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getLocale();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getLocales" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getLocales();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLocalName" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getLocalName();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getLocalPort" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getLocalPort();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getMethod" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getMethod();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getParameter" output="false"
	            hint="Returns the named parameter from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var params = "";
			var orig = "";
			var clean = "";

			// https://github.com/damonmiller/esapi4cf/issues/39
			// Railo workaround for getParameter always returning null
			//orig = variables.httpRequest.getParameter(arguments.name);
			params = variables.httpRequest.getParameterMap();
			if (structKeyExists(params, arguments.name)) {
				orig = params[arguments.name];
				// CF8 cannot handle a method call and array index reference on same line
				orig = orig[1];
			}
			// end workaround

			if(!(isDefined("orig") && !isNull(orig))) {
				orig = "";
			}
			clean = "";
			try {
				clean = variables.ESAPI.validator().getValidInput("HTTP parameter name: " & arguments.name, orig, "HTTPParameterValue", variables.ESAPI.validator().MAX_PARAMETER_VALUE_LENGTH, true);
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Struct" name="getParameterMap" output="false"
	            hint="Returns the parameter map from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			// CF8 requires 'var' at the top
			var map = "";
			var cleanMap = "";
			var i = "";
			var entry = "";
			var name = "";
			var cleanName = "";
			var value = "";
			var cleanValues = "";
			var j = "";
			var cleanValue = "";

			map = variables.httpRequest.getParameterMap();
			cleanMap = {};
			i = map.entrySet().iterator();
			while(i.hasNext()) {
				try {
					entry = i.next();
					name = entry.getKey();
					cleanName = variables.ESAPI.validator().getValidInput("HTTP parameter name: " & name, name, "HTTPParameterName", variables.ESAPI.validator().MAX_PARAMETER_NAME_LENGTH, true);

					value = entry.getValue();
					cleanValues = [];
					for(j = 1; j <= arrayLen(value); j++) {
						cleanValue = variables.ESAPI.validator().getValidInput("HTTP parameter value: " & value[j], value[j], "HTTPParameterValue", variables.ESAPI.validator().MAX_PARAMETER_VALUE_LENGTH, true);
						cleanValues[j] = cleanValue;
					}
					cleanMap.put(cleanName, cleanValues);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					// already logged
				}
			}
			return cleanMap;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getParameterNames" output="false"
	            hint="Returns the enumeration of parameter names from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			// CF8 requires 'var' at the top
			var v = "";
			var en = "";
			var i = 0;
			var name = "";
			var clean = "";

			v = [];
			en = variables.httpRequest.getParameterNames();
			while (en.hasMoreElements()) {
				try {
					name = en.nextElement();
					clean = variables.ESAPI.validator().getValidInput("HTTP parameter name: " & name, name, "HTTPParameterName", variables.ESAPI.validator().MAX_PARAMETER_NAME_LENGTH, true);
					v.add(clean);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					// already logged
				}
			}
			return v;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getParameterValues" output="false"
	            hint="Returns the array of matching parameter values from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var values = "";
			var newValues = "";
			var i = 0;
			var value = "";
			var cleanValue = "";

			values = variables.httpRequest.getParameterValues(arguments.name);
			newValues = [];
			if(isDefined("values") && !isNull(values)) {
				for(i = 1; i <= arrayLen(values); i++) {
					try {
						value = values[i];
						cleanValue = variables.ESAPI.validator().getValidInput("HTTP parameter value: " & value, value, "HTTPParameterValue", variables.ESAPI.validator().MAX_PARAMETER_VALUE_LENGTH, true);
						newValues.add(cleanValue);
					}
					catch(org.owasp.esapi.errors.ValidationException e) {
						variables.logger.warning(Logger.SECURITY, false, "Skipping bad parameter");
					}
				}
			}
			return newValues;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getPathInfo" output="false"
	            hint="Returns the path info from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			// CF8 requires 'var' at the top
			var path = "";
			var clean = "";

			path = variables.httpRequest.getPathInfo();
			if(!(isDefined("path") && !isNull(path))) {
				path = "";
			}
			clean = "";
			try {
				clean = variables.ESAPI.validator().getValidInput("HTTP path: " & path, path, "HTTPPath", 150, false);
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getPathTranslated" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getPathTranslated();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getProtocol" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getProtocol();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getQueryString" output="false"
	            hint="Returns the query string from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			// CF8 requires 'var' at the top
			var queryString = "";
			var clean = "";

			queryString = variables.httpRequest.getQueryString();
			if(!(isDefined("queryString") && !isNull(queryString))) {
				queryString = "";
			}
			clean = "";
			try {
				clean = variables.ESAPI.validator().getValidInput("HTTP query string: " & queryString, queryString, "HTTPQueryString", 2000, false);
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getReader" output="false" hint="Same as HttpServletRequest, no security changes required. Note that this reader may contain attacks and the developer is responsible for canonicalizing, validating, and encoding any data from this stream.">

		<cfscript>
			return variables.httpRequest.getReader();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRealPath" output="false"
	            hint="Same as HttpServletRequest, no security changes required. @deprecated as {@link HttpServletRequest##getRealPath(String)} is.">
		<cfargument required="true" type="String" name="path"/>

		<cfscript>
			return variables.httpRequest.getRealPath(arguments.path);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRemoteAddr" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getRemoteAddr();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRemoteHost" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getRemoteHost();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getRemotePort" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.getRemotePort();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRemoteUser" output="false"
	            hint="Returns the name of the ESAPI user associated with this request.">

		<cfscript>
			return variables.ESAPI.authenticator().getCurrentUser().getAccountName();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getRequestDispatcher" output="false" hint="Checks to make sure the path to forward to is within the WEB-INF directory and then returns the dispatcher. Otherwise returns null.">
		<cfargument required="true" type="String" name="path"/>

		<cfscript>
			// FIXME: not redirecting correctly
			//if(arguments.path.startsWith( "WEB-INF" )) {
			return variables.httpRequest.getRequestDispatcher(arguments.path);
			//}
			//return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRequestedSessionId" output="false"
	            hint="Returns the URI from the HttpServletRequest after canonicalizing and filtering out any dangerous characters. Code must be very careful not to depend on the value of a requested session id reported by the user.">

		<cfscript>
			var id = variables.httpRequest.getRequestedSessionId();
			var clean = "";
			try {
				clean = variables.ESAPI.validator().getValidInput("Requested cookie: " & id, id, "HTTPJSESSIONID", 50, false);
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRequestURI" output="false"
	            hint="Returns the URI from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var uri = variables.httpRequest.getRequestURI();
			var clean = "";
			try {
				clean = variables.ESAPI.validator().getValidInput("HTTP URI: " & uri, uri, "HTTPURI", 2000, false);
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getRequestURL" output="false" hint="Returns the URL from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var requestUrl = variables.httpRequest.getRequestURL().toString();
			var clean = "";
			try {
				clean = variables.ESAPI.validator().getValidInput("HTTP URL: " & requestUrl, requestUrl, "HTTPURL", 2000, false);
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return newJava("java.lang.StringBuffer").init(clean);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getScheme" output="false"
	            hint="Returns the scheme from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var scheme = variables.httpRequest.getScheme();
			var clean = "";
			try {
				clean = variables.ESAPI.validator().getValidInput("HTTP scheme: " & scheme, scheme, "HTTPScheme", 10, false);
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getServerName" output="false"
	            hint="Returns the server name (host header) from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var name = variables.httpRequest.getServerName();
			var clean = "";
			try {
				clean = variables.ESAPI.validator().getValidInput("HTTP server name: " & name, name, "HTTPServerName", 100, false);
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getServerPort" output="false"
	            hint="Returns the server port (after the : in the host header) from the HttpServletRequest after parsing and checking the range 0-65536.">

		<cfscript>
			var port = variables.httpRequest.getServerPort();
			if(port < 0 || port > inputBaseN("FFFF", 16)) {
				variables.logger.warning(Logger.SECURITY, false, "HTTP server port out of range: " & port);
				port = 0;
			}
			return port;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getServletPath" output="false"
	            hint="Returns the server path from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var path = variables.httpRequest.getServletPath();
			var clean = "";
			try {
				clean = variables.ESAPI.validator().getValidInput("HTTP servlet path: " & path, path, "HTTPServletPath", 100, false);
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getSession" output="false" hint="Returns a session, creating it if necessary, and sets the HttpOnly flag on the JSESSIONID cookie.">
		<cfargument required="false" type="boolean" name="create"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var httpSession = "";
			var safeSession = "";
			var user = "";
			var httpCookie = "";
			var httpResponse = "";

			if(structKeyExists(arguments, "create")) {
				httpSession = getHttpServletRequest().getSession(arguments.create);
				if(!(isDefined("httpSession") && !isNull(httpSession) && (isStruct(httpSession) || isObject(httpSession)))) {
					return "";
				}
				safeSession = createObject("component", "org.owasp.esapi.filters.SafeSession").init(variables.ESAPI, httpSession);
			}
			else {
				httpSession = getHttpServletRequest().getSession();
				safeSession = createObject("component", "org.owasp.esapi.filters.SafeSession").init(variables.ESAPI, httpSession);
				user = variables.ESAPI.authenticator().getCurrentUser();
				user.addSession(safeSession);
			}

			// send a new cookie header with HttpOnly on first and second responses
			// NOTE: DO NOT attempt an httpUtilities.getCookie() at this point - can cause a stack overflow exception
			isHttpOnly = safeSession.getAttribute("HTTP_ONLY");
			if(!isDefined("isHttpOnly") || isNull(isHttpOnly)) {
				safeSession.setAttribute("HTTP_ONLY", "set");
				httpCookie = newJava("javax.servlet.http.Cookie").init("JSESSIONID", safeSession.getId());
				httpCookie.setMaxAge(-1);// session cookie
				httpCookie.setPath("/");
				httpResponse = variables.ESAPI.currentResponse();
				if(isObject(httpResponse)) {
					variables.ESAPI.currentResponse().addCookie(httpCookie);
				}
			}
			return safeSession;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getUserPrincipal" output="false" hint="Returns the ESAPI User associated with this request.">

		<cfscript>
			return variables.ESAPI.authenticator().getCurrentUser();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdFromCookie" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.isRequestedSessionIdFromCookie();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdFromURL" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.isRequestedSessionIdFromURL();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdValid" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return variables.httpRequest.isRequestedSessionIdValid();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isSecure" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			// TODO Check request method to see if this is vulnerable
			return variables.httpRequest.isSecure();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="hasUserInRole" output="false"
	            hint="Returns true if the ESAPI User associated with this request has the specified role.">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			return variables.ESAPI.authenticator().getCurrentUser().isInRole(arguments.role);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeAttribute" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			variables.httpRequest.removeAttribute(arguments.name);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAttribute" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" name="o"/>

		<cfscript>
			variables.httpRequest.setAttribute(arguments.name, arguments.o);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCharacterEncoding" output="false"
	            hint="Sets the character encoding scheme to the ESAPI configured encoding scheme.">
		<cfargument required="true" type="String" name="enc"/>

		<cfscript>
			variables.httpRequest.setCharacterEncoding(variables.ESAPI.securityConfiguration().getCharacterEncoding());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isUserInRoleData" output="false">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			variables.httpRequest.isUserInRole(arguments.role);
		</cfscript>

	</cffunction>

</cfcomponent>