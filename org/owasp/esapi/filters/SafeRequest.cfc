<!---
 * OWASP Enterprise Security API (ESAPI) This file is part of the Open Web
 * Application Security Project (OWASP) Enterprise Security API (ESAPI) project.
 * For details, please see <a
 * href="http://www.owasp.org/index.php/ESAPI">http://
 * www.owasp.org/index.php/ESAPI</a>. Copyright (c) 2007 - The OWASP Foundation
 * The ESAPI is published by OWASP under the BSD license. You should read and
 * accept the LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect
 *         Security</a>
 * @created 2007
 --->
<cfcomponent implements="cfesapi.org.owasp.esapi.HttpServletRequest" extends="cfesapi.org.owasp.esapi.util.Object" output="false" hint="This request wrapper simply overrides unsafe methods in the HttpServletRequest API with safe versions that return canonicalized data where possible. The wrapper returns a safe value when a validation error is detected, including stripped or empty strings.">

	<cfscript>
		instance.ESAPI = "";
		instance.request = "";
		instance.logger = "";
	</cfscript>

	<cffunction access="public" returntype="SafeRequest" name="init" output="false"
	            hint="Construct a safe request that overrides the default request methods with safer versions.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" name="request"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger( "SafeRequest" );

			instance.request = arguments.request;

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getHttpServletRequest" output="false">

		<cfscript>
			return instance.request;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getAttribute" output="false" hint="Same as HttpServletRequest, no security changes required.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return instance.request.getAttribute( arguments.name );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getAttributeNames" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getAttributeNames();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getAuthType" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getAuthType();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getCharacterEncoding();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getContentLength" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getContentLength();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getContentType" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getContentType();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getContextPath" output="false"
	            hint="Returns the context path from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var local = {};
			local.path = instance.request.getContextPath();
			local.clean = "";
			try {
				local.clean = instance.ESAPI.validator().getValidInput( "HTTP context path: " & local.path, local.path, "HTTPContextPath", 150, false );
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getCookies" output="false"
	            hint="Returns the array of Cookies from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var local = {};
			local.cookies = instance.request.getCookies();
			local.newCookies = [];
			if (structKeyExists(local, "cookies")) {
				for(local.i = 1; local.i <= arrayLen( local.cookies ); local.i++) {
					local.c = local.cookies[local.i];

					// build a new clean cookie
					try {
						// get data from original cookie
						local.name = instance.ESAPI.validator().getValidInput( "Cookie name: " & local.c.getName(), local.c.getName(), "HTTPCookieName", instance.ESAPI.validator().MAX_PARAMETER_NAME_LENGTH, true );
						local.value = instance.ESAPI.validator().getValidInput( "Cookie value: " & local.c.getValue(), local.c.getValue(), "HTTPCookieValue", instance.ESAPI.validator().MAX_PARAMETER_VALUE_LENGTH, true );
						local.maxAge = local.c.getMaxAge();
						local.domain = local.c.getDomain();
						local.path = local.c.getPath();

						local.n = getJava( "javax.servlet.http.Cookie" ).init( local.name, local.value );
						local.n.setMaxAge( local.maxAge );

						if(structKeyExists( local, "domain" )) {
							local.n.setDomain( instance.ESAPI.validator().getValidInput( "Cookie domain: " & local.domain, local.domain, "HTTPHeaderValue", instance.ESAPI.validator().MAX_PARAMETER_VALUE_LENGTH, false ) );
						}
						if(structKeyExists( local, "path" )) {
							local.n.setPath( instance.ESAPI.validator().getValidInput( "Cookie path: " & local.path, local.path, "HTTPHeaderValue", instance.ESAPI.validator().MAX_PARAMETER_VALUE_LENGTH, false ) );
						}
						local.newCookies.add( local.n );
					}
					catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
						instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Skipping bad cookie: " & local.c.getName() & "=" & local.c.getValue(), e );
					}
				}
			}
			return local.newCookies;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Date" name="getDateHeader" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return instance.request.getDateHeader( arguments.name );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getHeader" output="false"
	            hint="Returns the named header from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			var local = {};
			local.value = instance.request.getHeader( arguments.name );
			local.clean = "";
			try {
				local.clean = instance.ESAPI.validator().getValidInput( "HTTP header value: " & local.value, local.value, "HTTPHeaderValue", instance.ESAPI.validator().MAX_PARAMETER_VALUE_LENGTH, true );
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return local.clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getHeaderNames" output="false"
	            hint="Returns the enumeration of header names from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var local = {};
			local.v = [];
			local.en = instance.request.getHeaderNames();
			while(local.en.hasMoreElements()) {
				try {
					local.name = local.en.nextElement();
					local.clean = instance.ESAPI.validator().getValidInput( "HTTP header name: " & local.name, local.name, "HTTPHeaderName", instance.ESAPI.validator().MAX_PARAMETER_NAME_LENGTH, true );
					local.v.add( local.clean );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					// already logged
				}
			}
			return local.v;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getHeaders" output="false"
	            hint="Returns the enumeration of headers from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			var local = {};
			local.v = [];
			local.en = instance.request.getHeaders( arguments.name );
			while (local.en.hasMoreElements()) {
				try {
					local.value = local.en.nextElement();
					local.clean = instance.ESAPI.validator().getValidInput( "HTTP header value (" & arguments.name & "): " & local.value, local.value, "HTTPHeaderValue", instance.ESAPI.validator().MAX_PARAMETER_VALUE_LENGTH, true );
					local.v.add( local.clean );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					// already logged
				}
			}
			return local.v;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getInputStream" output="false" hint="Same as HttpServletRequest, no security changes required. Note that this input stream may contain attacks and the developer is responsible for canonicalizing, validating, and encoding any data from this stream.">

		<cfscript>
			return instance.request.getInputStream();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getIntHeader" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return instance.request.getIntHeader( arguments.name );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLocalAddr" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getLocalAddr();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getLocaleData" output="false" hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getLocale();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getLocales" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getLocales();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLocalName" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getLocalName();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getLocalPort" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getLocalPort();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getMethod" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getMethod();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getParameter" output="false"
	            hint="Returns the named parameter from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			var local = {};
			local.orig = instance.request.getParameter( arguments.name );
			if (!structKeyExists(local, "orig")) {
				local.orig = "";
			}
			local.clean = "";
			try {
				local.clean = instance.ESAPI.validator().getValidInput( "HTTP parameter name: " & arguments.name, local.orig, "HTTPParameterValue", instance.ESAPI.validator().MAX_PARAMETER_VALUE_LENGTH, true );
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return local.clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Struct" name="getParameterMap" output="false"
	            hint="Returns the parameter map from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var local = {};
			local.map = instance.request.getParameterMap();
			local.cleanMap = {};
			local.i = local.map.entrySet().iterator();
			while(local.i.hasNext()) {
				try {
					local.e = local.i.next();
					local.name = local.e.getKey();
					local.cleanName = instance.ESAPI.validator().getValidInput( "HTTP parameter name: " & local.name, local.name, "HTTPParameterName", instance.ESAPI.validator().MAX_PARAMETER_NAME_LENGTH, true );

					local.value = local.e.getValue();
					local.cleanValues = [];
					for(local.j = 1; local.j <= arrayLen( local.value ); local.j++) {
						local.cleanValue = instance.ESAPI.validator().getValidInput( "HTTP parameter value: " & local.value[local.j], local.value[local.j], "HTTPParameterValue", instance.ESAPI.validator().MAX_PARAMETER_VALUE_LENGTH, true );
						local.cleanValues[local.j] = local.cleanValue;
					}
					local.cleanMap.put( local.cleanName, local.cleanValues );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					// already logged
				}
			}
			return local.cleanMap;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getParameterNames" output="false"
	            hint="Returns the enumeration of parameter names from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var local = {};
			local.v = [];
			local.en = instance.request.getParameterNames();
			for(local.i = 1; local.i <= arrayLen( local.en ); local.i++) {
				try {
					local.name = local.en[local.i];
					local.clean = instance.ESAPI.validator().getValidInput( "HTTP parameter name: " & local.name, local.name, "HTTPParameterName", instance.ESAPI.validator().MAX_PARAMETER_NAME_LENGTH, true );
					local.v.add( local.clean );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					// already logged
				}
			}
			return local.v;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getParameterValues" output="false"
	            hint="Returns the array of matching parameter values from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			var local = {};
			local.values = instance.request.getParameterValues( arguments.name );
			local.newValues = [];
			if(structKeyExists( local, "values" )) {
				for(local.i = 1; local.i <= arrayLen( local.values ); local.i++) {
					try {
						local.value = local.values[local.i];
						local.cleanValue = instance.ESAPI.validator().getValidInput( "HTTP parameter value: " & local.value, local.value, "HTTPParameterValue", instance.ESAPI.validator().MAX_PARAMETER_VALUE_LENGTH, true );
						local.newValues.add( local.cleanValue );
					}
					catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
						instance.logger.warning( Logger.SECURITY, false, "Skipping bad parameter" );
					}
				}
			}
			return local.newValues;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getPathInfo" output="false"
	            hint="Returns the path info from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var local = {};
			local.path = instance.request.getPathInfo();
			if (!structKeyExists(local, "path")) {
				local.path = "";
			}
			local.clean = "";
			try {
				local.clean = instance.ESAPI.validator().getValidInput( "HTTP path: " & local.path, local.path, "HTTPPath", 150, false );
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return local.clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getPathTranslated" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getPathTranslated();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getProtocol" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getProtocol();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getQueryString" output="false"
	            hint="Returns the query string from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var local = {};
			local.query = instance.request.getQueryString();
			if (!structKeyExists(local, "query")) {
				local.query = "";
			}
			local.clean = "";
			try {
				local.clean = instance.ESAPI.validator().getValidInput( "HTTP query string: " & local.query, local.query, "HTTPQueryString", 2000, true );
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return local.clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getReader" output="false" hint="Same as HttpServletRequest, no security changes required. Note that this reader may contain attacks and the developer is responsible for canonicalizing, validating, and encoding any data from this stream.">

		<cfscript>
			return instance.request.getReader();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRealPath" output="false"
	            hint="Same as HttpServletRequest, no security changes required. @deprecated as {@link HttpServletRequest##getRealPath(String)} is.">
		<cfargument required="true" type="String" name="path"/>

		<cfscript>
			return instance.request.getRealPath( arguments.path );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRemoteAddr" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getRemoteAddr();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRemoteHost" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getRemoteHost();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getRemotePort" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.getRemotePort();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRemoteUser" output="false"
	            hint="Returns the name of the ESAPI user associated with this request.">

		<cfscript>
			return instance.ESAPI.authenticator().getCurrentUser().getAccountName();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getRequestDispatcher" output="false" hint="Checks to make sure the path to forward to is within the WEB-INF directory and then returns the dispatcher. Otherwise returns null.">
		<cfargument required="true" type="String" name="path"/>

		<cfscript>
			// FIXME: not redirecting correctly
			//if(arguments.path.startsWith( "WEB-INF" )) {
				return instance.request.getRequestDispatcher( arguments.path );
			//}
			//return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRequestedSessionId" output="false"
	            hint="Returns the URI from the HttpServletRequest after canonicalizing and filtering out any dangerous characters. Code must be very careful not to depend on the value of a requested session id reported by the user.">

		<cfscript>
			var local = {};
			local.id = instance.request.getRequestedSessionId();
			local.clean = "";
			try {
				local.clean = instance.ESAPI.validator().getValidInput( "Requested cookie: " & local.id, local.id, "HTTPJSESSIONID", 50, false );
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return local.clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRequestURI" output="false"
	            hint="Returns the URI from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var local = {};
			local.uri = instance.request.getRequestURI();
			local.clean = "";
			try {
				local.clean = instance.ESAPI.validator().getValidInput( "HTTP URI: " & local.uri, local.uri, "HTTPURI", 2000, false );
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return local.clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getRequestURL" output="false" hint="Returns the URL from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var local = {};
			local.url = instance.request.getRequestURL().toString();
			local.clean = "";
			try {
				local.clean = instance.ESAPI.validator().getValidInput( "HTTP URL: " & local.url, local.url, "HTTPURL", 2000, false );
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return getJava( "java.lang.StringBuffer" ).init( local.clean );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getScheme" output="false"
	            hint="Returns the scheme from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var local = {};
			local.scheme = instance.request.getScheme();
			local.clean = "";
			try {
				local.clean = instance.ESAPI.validator().getValidInput( "HTTP scheme: " & local.scheme, local.scheme, "HTTPScheme", 10, false );
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return local.clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getServerName" output="false"
	            hint="Returns the server name (host header) from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var local = {};

			local.name = instance.request.getServerName();
			local.clean = "";
			try {
				local.clean = instance.ESAPI.validator().getValidInput( "HTTP server name: " & local.name, local.name, "HTTPServerName", 100, false );
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return local.clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getServerPort" output="false"
	            hint="Returns the server port (after the : in the host header) from the HttpServletRequest after parsing and checking the range 0-65536.">

		<cfscript>
			var local = {};

			local.port = instance.request.getServerPort();
			if(local.port < 0 || local.port > inputBaseN( "FFFF", 16 )) {
				instance.logger.warning( Logger.SECURITY, false, "HTTP server port out of range: " & local.port );
				local.port = 0;
			}
			return local.port;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getServletPath" output="false"
	            hint="Returns the server path from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">

		<cfscript>
			var local = {};

			local.path = instance.request.getServletPath();
			local.clean = "";
			try {
				local.clean = instance.ESAPI.validator().getValidInput( "HTTP servlet path: " & local.path, local.path, "HTTPServletPath", 100, false );
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				// already logged
			}
			return local.clean;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getSession" output="false" hint="Returns a session, creating it if necessary, and sets the HttpOnly flag on the JSESSIONID cookie.">
		<cfargument required="false" type="boolean" name="create"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "create" )) {
				local.jsession = getHttpServletRequest().getSession( arguments.create );
				if( !(structKeyExists( local, "jsession" ) && ( isStruct(local.jsession) || isObject(local.jsession) ) )) {
					return "";
				}
				local.session = createObject( "component", "cfesapi.org.owasp.esapi.filters.SafeSession" ).init( instance.ESAPI, local.jsession );
			}
			else {
				local.jsession = getHttpServletRequest().getSession();
				local.session = createObject( "component", "cfesapi.org.owasp.esapi.filters.SafeSession" ).init( instance.ESAPI, local.jsession );
				local.user = instance.ESAPI.authenticator().getCurrentUser();
				local.user.addSession( local.session );
			}

			// send a new cookie header with HttpOnly on first and second responses
			if(local.session.getAttribute( "HTTP_ONLY" ) == "") {
				local.session.setAttribute( "HTTP_ONLY", "set" );
				local.cookie = getJava( "javax.servlet.http.Cookie" ).init( "JSESSIONID", local.session.getId() );
				local.cookie.setMaxAge( -1 );// session cookie
				local.response = instance.ESAPI.currentResponse();
				if(isObject( local.response )) {
					instance.ESAPI.currentResponse().addCookie( local.cookie );
				}
			}

			return local.session;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getUserPrincipal" output="false" hint="Returns the ESAPI User associated with this request.">

		<cfscript>
			return instance.ESAPI.authenticator().getCurrentUser();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdFromCookie" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.isRequestedSessionIdFromCookie();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdFromURL" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.isRequestedSessionIdFromURL();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdValid" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			return instance.request.isRequestedSessionIdValid();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isSecure" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">

		<cfscript>
			// TODO Check request method to see if this is vulnerable
			return instance.request.isSecure();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="hasUserInRole" output="false"
	            hint="Returns true if the ESAPI User associated with this request has the specified role.">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			return instance.ESAPI.authenticator().getCurrentUser().isInRole( arguments.role );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeAttribute" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			instance.request.removeAttribute( arguments.name );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAttribute" output="false"
	            hint="Same as HttpServletRequest, no security changes required.">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" name="o"/>

		<cfscript>
			instance.request.setAttribute( arguments.name, arguments.o );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCharacterEncoding" output="false"
	            hint="Sets the character encoding scheme to the ESAPI configured encoding scheme.">
		<cfargument required="true" type="String" name="enc"/>

		<cfscript>
			instance.request.setCharacterEncoding( instance.ESAPI.securityConfiguration().getCharacterEncoding() );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isUserInRoleData" output="false">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			instance.request.isUserInRole( arguments.role );
		</cfscript>

	</cffunction>

</cfcomponent>