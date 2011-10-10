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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.HttpServletRequest" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.logger = "";
		instance.request = "";

		instance.allowableContentRoot = "WEB-INF";
	</cfscript>
 
	<cffunction access="public" returntype="SecurityWrapperRequest" name="init" output="false" hint="Construct a safe request that overrides the default request methods with safer versions.">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="any" name="request" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("SecurityWrapperRequest");
			instance.request = arguments.request;

    		return this;
    	</cfscript> 
	</cffunction>


	<cffunction access="package" returntype="any" name="getHttpServletRequest" output="false" hint="javax.servlet.http.HttpServletRequest">
		<cfscript>
    		return instance.request;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getAttribute" output="false" hint="The attribute value">
		<cfargument type="String" name="name" required="true" hint="The attribute name">
		<cfscript>
			local.result = getHttpServletRequest().getAttribute(name);
			if (!isNull(local.result)) {
				return local.result;
			}
			else {
				return "";
			}
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Array" name="getAttributeNames" output="false" hint="An Enumeration of attribute names.">
		<cfscript>
			local.v = [];
			local.en = getHttpServletRequest().getAttributeNames();
			for (local.name in local.en) {
				local.v.add(local.name);
			}
			return local.v;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getAuthType" output="false" hint="The authentication type">
		<cfscript>
        	return getHttpServletRequest().getAuthType();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false" hint="The character-encoding for this HttpServletRequest">
		<cfscript>
        	return getHttpServletRequest().getCharacterEncoding();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getContentLength" output="false" hint="The content-length for this HttpServletRequest">
		<cfscript>
        	return getHttpServletRequest().getContentLength();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getContentType" output="false" hint="The content-type for this HttpServletRequest">
		<cfscript>
        	return getHttpServletRequest().getContentType();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getContextPath" output="false" hint="Returns the context path from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfscript>
	        local.path = getHttpServletRequest().getContextPath();

			// return empty String for the ROOT context
			if (isNull(local.path) || trim(local.path == "")) {
				return "";
			}

	        local.clean = "";
	        try {
	            local.clean = instance.ESAPI.validator().getValidInput("HTTP context path: " & local.path, local.path, "HTTPContextPath", 150, false);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return local.clean;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Array" name="getCookies" output="false" hint="Returns the array of Cookies from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfscript>
	        local.cookies = getHttpServletRequest().getCookies();
	        if (isNull(local.cookies)) return [];

	        local.newCookies = [];
	        for (local.i = 1; local.i <= arrayLen(local.cookies); local.i++) {
				local.c = local.cookies[local.i];
	            // build a new clean cookie
	            try {
	                // get data from original cookie
	                local.name = instance.ESAPI.validator().getValidInput("Cookie name: " & local.c.getName(), local.c.getName(), "HTTPCookieName", 150, true);
	                local.value = instance.ESAPI.validator().getValidInput("Cookie value: " & local.c.getValue(), local.c.getValue(), "HTTPCookieValue", 1000, true);
	                local.maxAge = local.c.getMaxAge();
	                local.domain = local.c.getDomain();
	                local.path = local.c.getPath();

	                local.n = createObject("java", "javax.servlet.http.Cookie").init(local.name, local.value);
	                local.n.setMaxAge(local.maxAge);

	                if (!isNull(local.domain)) {
	                    local.n.setDomain(instance.ESAPI.validator().getValidInput("Cookie domain: " & local.domain, local.domain, "HTTPHeaderValue", 200, false));
	                }
	                if (!isNull(local.path)) {
	                    local.n.setPath(instance.ESAPI.validator().getValidInput("Cookie path: " & local.path, local.path, "HTTPHeaderValue", 200, false));
	                }
	                local.newCookies.add(local.n);
	            } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	                instance.logger.warning(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Skipping bad cookie: " & local.c.getName() & "=" & local.c.getValue(), e );
	            }
	        }
	        return local.newCookies;
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getDateHeader" output="false" hint="a long value representing the date specified in the header expressed as the number of milliseconds since January 1, 1970 GMT, or -1 if the named header was not included with the request.">
		<cfargument type="String" name="name" required="true" hint="Specifies the name of the HTTP request header; e.g., If-Modified-Since.">
		<cfscript>
        	return getHttpServletRequest().getDateHeader(arguments.name);
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getHeader" output="false" hint="Returns the named header from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument type="String" name="name" required="true">
		<cfscript>
	        local.value = getHttpServletRequest().getHeader(arguments.name);
	        local.clean = "";
	        try {
				if (!isNull(local.value)) {
	            	local.clean = instance.ESAPI.validator().getValidInput("HTTP header value: " & local.value, local.value, "HTTPHeaderValue", 150, true);
				}
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return local.clean;
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Array" name="getHeaderNames" output="false" hint="Returns the enumeration of header names from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfscript>
	        local.v = [];
	        local.en = getHttpServletRequest().getHeaderNames();
	        for (local.name in local.en) {
	            try {
	                local.clean = instance.ESAPI.validator().getValidInput("HTTP header name: " & local.name, local.name, "HTTPHeaderName", 150, true);
	                local.v.add(local.clean);
	            } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	                // already logged
	            }
	        }
	        return local.v;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Array" name="getHeaders" output="false" hint="Returns the enumeration of headers from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument type="String" name="name" required="true" hint="The name of an HTTP request header.">
		<cfscript>
	        local.v = [];
	        local.en = getHttpServletRequest().getHeaders(arguments.name);
	        while (local.en.hasMoreElements()) {
	            try {
	                local.value = local.en.nextElement();
	                local.clean = instance.ESAPI.validator().getValidInput("HTTP header value (" & arguments.name & "): " & local.value, local.value, "HTTPHeaderValue", 150, true);
	                local.v.add(local.clean);
	            } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	                // already logged
	            }
	        }
	        return local.v;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getInputStream" output="false" hint="The javax.servlet.ServletInputStream associated with this HttpServletRequest. Note that this input stream may contain attacks and the developer is responsible for canonicalizing, validating, and encoding any data from this stream.">
		<cfscript>
        	return getHttpServletRequest().getInputStream();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getIntHeader" output="false" hint="Returns the value of the specified request header as an int.">
		<cfargument type="String" name="name" required="true" hint="The name of an HTTP request header.">
		<cfscript>
        	return getHttpServletRequest().getIntHeader(arguments.name);
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getLocalAddr" output="false" hint="A String containing the IP address on which the request was received.">
		<cfscript>
			// JRun's J2EE does not support this
        	//return getHttpServletRequest().getLocalAddr();
        	// FIXME: CF "Zeus" will use Tomcat's J2EE
        	return getRemoteAddr();
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getLocale" output="false" hint="java.util.Locale: The preferred Locale for the client.">
		<cfscript>
        	return getHttpServletRequest().getLocale();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Array" name="getLocales" output="false" hint="An Enumeration of preferred Locale objects for the client.">
		<cfscript>
        	return getHttpServletRequest().getLocales();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getLocalName" output="false" hint="A String containing the host name of the IP on which the request was received.">
		<cfscript>
        	return getHttpServletRequest().getLocalName();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getLocalPort" output="false" hint="Returns the Internet Protocol (IP) port number of the interface on which the request was received.">
		<cfscript>
			// JRun's J2EE does not support this
        	//return getHttpServletRequest().getLocalPort();
        	// FIXME: CF "Zeus" will use Tomcat's J2EE
        	return getServerPort();
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getMethod" output="false" hint="Returns the name of the HTTP method with which this request was made.">
		<cfscript>
        	return getHttpServletRequest().getMethod();
       	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getParameter" output="false" hint="Returns the named parameter from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument type="String" name="name" required="true" hint="The parameter name for the request">
		<cfscript>
	        local.orig = getHttpServletRequest().getParameter(arguments.name);

	        if (isNull(local.orig)) {
	        	return "";
			}

	        local.clean = "";
	        try {
	            local.clean = instance.ESAPI.validator().getValidInput("HTTP parameter name: " & arguments.name, local.orig, "HTTPParameterValue", 2000, true);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return local.clean;
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Struct" name="getParameterMap" output="false" hint="Returns the parameter map from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfscript>
	        local.map = getHttpServletRequest().getParameterMap();
	        local.cleanMap = {};
	        local.i = local.map.entrySet().iterator();
	        while (local.i.hasNext()) {
	            try {
	                local.e = local.i.next();
	                local.name = local.e.getKey();
	                local.cleanName = instance.ESAPI.validator().getValidInput("HTTP parameter name: " & local.name, local.name, "HTTPParameterName", 100, true);

	                local.value = local.e.getValue();
	                local.cleanValues = [];
	                for (local.j = 1; local.j <= arrayLen(local.value); local.j++) {
	                    local.cleanValue = instance.ESAPI.validator().getValidInput("HTTP parameter value: " & local.value[local.j], local.value[local.j], "HTTPParameterValue", 2000, true);
	                    local.cleanValues[local.j] = local.cleanValue;
	                }
	                local.cleanMap.put(local.cleanName, local.cleanValues);
	            } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	                // already logged
	            }
	        }
	        return local.cleanMap;
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Array" name="getParameterNames" output="false" hint="Returns the enumeration of parameter names from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfscript>
	        local.v = [];
	        local.en = getHttpServletRequest().getParameterNames();
	        for (local.name in local.en) {
	            try {
	                local.clean = instance.ESAPI.validator().getValidInput("HTTP parameter name: " & local.name, local.name, "HTTPParameterName", 150, true);
	                local.v.add(local.clean);
	            } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	                // already logged
	            }
	        }
	        return local.v;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Array" name="getParameterValues" output="false" hint="Returns the array of matching parameter values from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument type="String" name="name" required="true" hint="The parameter name">
		<cfscript>
			local.values = getHttpServletRequest().getParameterValues(arguments.name);

			if (isNull(local.values)) {
				return [];
			}
			local.newValues = [];
			for (local.value in local.values) {
				try {
					local.cleanValue = instance.ESAPI.validator().getValidInput("HTTP parameter value: " & local.value, local.value, "HTTPParameterValue", 2000, true);
					local.newValues.add(local.cleanValue);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					instance.logger.warning(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Skipping bad parameter");
				}
			}
			return local.newValues;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getPathInfo" output="false" hint="Returns the path info from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfscript>
	        local.path = getHttpServletRequest().getPathInfo();
			if (isNull(local.path)) return "";
	        local.clean = "";
	        try {
	            local.clean = instance.ESAPI.validator().getValidInput("HTTP path: " & local.path, local.path, "HTTPPath", 150, true);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return local.clean;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getPathTranslated" output="false" hint="Returns any extra path information, appropriate scrubbed, after the servlet name but before the query string, and translates it to a real path.">
		<cfscript>
        	return getHttpServletRequest().getPathTranslated();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getProtocol" output="false" hint="Returns the name and version of the protocol the request uses in the form protocol/majorVersion.minorVersion, for example, HTTP/1.1.">
		<cfscript>
        	return getHttpServletRequest().getProtocol();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getQueryString" output="false" hint="Returns the query string from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfscript>
	        local.query = getHttpServletRequest().getQueryString();
	        local.clean = "";
	        try {
	            local.clean = instance.ESAPI.validator().getValidInput("HTTP query string: " & local.query, local.query, "HTTPQueryString", 2000, true);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return local.clean;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getReader" output="false" hint="A java.io.BufferedReader containing the body of the request. Note that this reader may contain attacks and the developer is responsible for canonicalizing, validating, and encoding any data from this stream.">
		<cfscript>
        	return getHttpServletRequest().getReader();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getRemoteAddr" output="false" hint="Returns the IP address of the client or last proxy that sent the request.">
		<cfscript>
        	return getHttpServletRequest().getRemoteAddr();
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getRemoteHost" output="false" hint="The remote host">
		<cfscript>
       		return getHttpServletRequest().getRemoteHost();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getRemotePort" output="false" hint="The remote port">
		<cfscript>
        	return getHttpServletRequest().getRemotePort();
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getRemoteUser" output="false" hint="Returns the name of the ESAPI user associated with this getHttpServletRequest().">
		<cfscript>
        	return instance.ESAPI.authenticator().getCurrentUser().getAccountName();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getRequestDispatcher" output="false" hint="java.servlet.RequestDispatcher: Checks to make sure the path to forward to is within the WEB-INF directory and then returns the dispatcher. Otherwise returns null.">
		<cfargument type="String" name="path" required="true" hint="The path to create a request dispatcher for">
		<cfscript>
	        if (arguments.path.startsWith(instance.allowableContentRoot)) {
	            return getHttpServletRequest().getRequestDispatcher(arguments.path);
	        }
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getRequestedSessionId" output="false" hint="Returns the SessionId from the HttpServletRequest after canonicalizing and filtering out any dangerous characters. Code must be very careful not to depend on the value of a requested session id reported by the user.">
		<cfscript>
	        local.id = createObject("java", "org.owasp.esapi.StringUtilities").replaceNull(getHttpServletRequest().getRequestedSessionId(), "");
	        local.clean = "";
	        try {
	            local.clean = instance.ESAPI.validator().getValidInput("Requested cookie: " & local.id, local.id, "HTTPJSESSIONID", 50, false);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return local.clean;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getRequestURI" output="false" hint="Returns the URI from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfscript>
	        local.uri = getHttpServletRequest().getRequestURI();
	        local.clean = "";
	        try {
	            local.clean = instance.ESAPI.validator().getValidInput("HTTP URI: " & local.uri, local.uri, "HTTPURI", 2000, false);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return local.clean;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getRequestURL" output="false" hint="java.lang.StringBuffer: The currect request URL">
		<cfscript>
	        local.url = getHttpServletRequest().getRequestURL().toString();
	        local.clean = "";
	        try {
	            local.clean = instance.ESAPI.validator().getValidInput("HTTP URL: " & local.url, local.url, "HTTPURL", 2000, false);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return createObject("java", "java.lang.StringBuffer").init(local.clean);
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getScheme" output="false" hint="Returns the scheme from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfscript>
	        local.scheme = getHttpServletRequest().getScheme();
	        local.clean = "";
	        try {
	            local.clean = instance.ESAPI.validator().getValidInput("HTTP scheme: " & local.scheme, local.scheme, "HTTPScheme", 10, false);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return local.clean;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getServerName" output="false" hint="Returns the server name (host header) from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfscript>
	        local.name = getHttpServletRequest().getServerName();
	        local.clean = "";
	        try {
	            local.clean = instance.ESAPI.validator().getValidInput("HTTP server name: " & local.name, local.name, "HTTPServerName", 100, false);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return local.clean;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getServerPort" output="false" hint="Returns the server port (after the : in the host header) from the HttpServletRequest after parsing and checking the range 0-65536.">
		<cfscript>
			local.port = getHttpServletRequest().getServerPort();
			if ( local.port < 0 || local.port > 65536 ) {
				instance.logger.warning( createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "HTTP server port out of range: " & local.port );
				local.port = 0;
			}
			return local.port;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getServletPath" output="false" hint="Returns the server path from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfscript>
	        local.path = getHttpServletRequest().getServletPath();
	        local.clean = "";
	        try {
	            local.clean = instance.ESAPI.validator().getValidInput("HTTP servlet path: " & local.path, local.path, "HTTPServletPath", 100, false);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return local.clean;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getSession" output="false" hint="cfesapi.org.owasp.esapi.HttpSession: Returns a session, creating it if necessary, and sets the HttpOnly flag on the Session ID cookie.">
		<cfargument type="boolean" name="create" required="false">
		<cfscript>
			if (structKeyExists(arguments, 'create')) {
				local.jsession = getHttpServletRequest().getSession(arguments.create);
			}
			else {
				local.jsession = getHttpServletRequest().getSession();
			}

			if (isNull(local.jsession)) {
				return;
			}

			local.session = createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapperSession").init(instance.ESAPI, local.jsession);

			// send a new cookie header with HttpOnly on first and second responses
		    if (instance.ESAPI.securityConfiguration().getForceHttpOnlySession()) {
		        /*
		         * FIXME
		         * Upon the initial request that sets the Session ID by the CF engine, the below code will get executed.
		         * The problem is, both the cookie we set below and the cookie set by the CF engine are sent in the response.
		         * The CF engine cookie seems to always be the one picked up by the browser.
		         * Subsequent requests will not run this code because of the conditional around the HTTP_ONLY session attribute.
		         * If you comment out the conditional, the correct cookie is sent on subsequent requests.
		         *
		         * ISSUES
		         * 1) The code in its current state will never set the HttpOnly state of the Session ID cookie.
		         * 2) Removing the conditional allows the HttpOnly to be set on subsequent requests, but what about our initial request?
		         * 3) Removing the conditional also causes the same cookie to be set multiple times per request depending on how many
		         *		times this method is called. This bloats our response headers.
		         *
		         * Thoughts???
		         */
		        if (local.session.getAttribute("HTTP_ONLY") == "") {
					local.session.setAttribute("HTTP_ONLY", "set");
					local.cookie = createObject("java", "javax.servlet.http.Cookie").init(instance.ESAPI.securityConfiguration().getHttpSessionIdName(), local.session.getId());
					local.cookie.setPath( getHttpServletRequest().getContextPath() );
					local.cookie.setMaxAge(-1); // session cookie
		            local.response = instance.ESAPI.currentResponse();
		            if (!isNull(local.response)) {
		                instance.ESAPI.currentResponse().addCookie(local.cookie);
		            }
		        }
		    }
	        return local.session;
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getUserPrincipal" output="false" hint="Returns the ESAPI User associated with this getHttpServletRequest().">
		<cfscript>
        	return instance.ESAPI.authenticator().getCurrentUser();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdFromCookie" output="false" hint="if requested session id is from a cookie">
		<cfscript>
        	return getHttpServletRequest().isRequestedSessionIdFromCookie();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdFromURL" output="false" hint="Whether the requested session id is from the URL">
		<cfscript>
        	return getHttpServletRequest().isRequestedSessionIdFromURL();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdValid" output="false" hint="Whether the requested session id is valid">
		<cfscript>
        	return getHttpServletRequest().isRequestedSessionIdValid();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isSecure" output="false" hint="Whether the current request is secure">
		<cfscript>
	        try {
	            instance.ESAPI.httpUtilities().assertSecureChannel();
	        } catch (cfesapi.org.owasp.esapi.errors.AccessControlException e) {
	            return false;
	        }
	        return true;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isUserInRole" output="false" hint="Returns true if the ESAPI User associated with this request has the specified role.">
		<cfargument type="String" name="role" required="true" hint="The role to check">
		<cfscript>
        	return instance.ESAPI.authenticator().getCurrentUser().isInRole(arguments.role);
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="removeAttribute" output="false" hint="The attribute name">
		<cfargument type="String" name="name" required="true">
		<cfscript>
        	getHttpServletRequest().removeAttribute(arguments.name);
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setAttribute" output="false">
		<cfargument type="String" name="name" required="true" hint="The attribute name">
		<cfargument type="any" name="o" required="true" hint="The attribute value">
		<cfscript>
        	getHttpServletRequest().setAttribute(name, o);
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setCharacterEncoding" output="false" hint="Sets the character encoding scheme to the ESAPI configured encoding scheme.">
		<cfargument type="String" name="enc" required="true" hint="The encoding scheme">
		<cfscript>
        	getHttpServletRequest().setCharacterEncoding(instance.ESAPI.securityConfiguration().getCharacterEncoding());
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getAllowableContentRoot" output="false">
		<cfscript>
       		return instance.allowableContentRoot;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setAllowableContentRoot" output="false">
		<cfargument type="String" name="allowableContentRoot" required="true">
		<cfscript>
       		instance.allowableContentRoot = arguments.allowableContentRoot.startsWith( "/" ) ? arguments.allowableContentRoot : "/" & arguments.allowableContentRoot;
    	</cfscript> 
	</cffunction>


</cfcomponent>
