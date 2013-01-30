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
<cfcomponent implements="esapi4cf.org.owasp.esapi.HttpServletResponse" extends="esapi4cf.org.owasp.esapi.util.Object" output="false" hint="This response wrapper simply overrides unsafe methods in the HttpServletResponse API with safe versions.">

	<cfscript>
		instance.ESAPI = "";
		instance.response = "";
		instance.logger = "";
	</cfscript>

	<cffunction access="public" returntype="esapi4cf.org.owasp.esapi.HttpServletResponse" name="init" output="false"
	            hint="Construct a safe response that overrides the default response methods with safer versions.">
		<cfargument required="true" type="esapi4cf.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" name="response"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger( "SafeResponse" );

			instance.response = arguments.response;

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getHttpServletResponse" output="false">

		<cfscript>
			return instance.response;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addCookie" output="false"
	            hint="Add a cookie to the response after ensuring that there are no encoded or illegal characters in the name and name and value. This method also sets the secure and HttpOnly flags on the cookie.">
		<cfargument required="true" name="cookie"/>

		<cfscript>
			var local = {};
			local.name = arguments.cookie.getName();
			local.value = arguments.cookie.getValue();
			local.maxAge = arguments.cookie.getMaxAge();
			local.domain = arguments.cookie.getDomain();
			local.path = arguments.cookie.getPath();
			addSafeCookie( argumentCollection=local );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addSafeCookie" output="false"
	            hint="Add a cookie to the response after ensuring that there are no encoded or illegal characters in the name and name and value. This method also sets the secure and HttpOnly flags on the cookie.">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="String" name="value"/>
		<cfargument required="true" type="numeric" name="maxAge"/>
		<cfargument type="String" name="domain"/>
		<cfargument type="String" name="path"/>

		<cfscript>
			var local = {};
			try {
				local.cookieName = instance.ESAPI.validator().getValidInput( "safeAddCookie", arguments.name, "HTTPCookieName", 50, false );
				local.cookieValue = instance.ESAPI.validator().getValidInput( "safeAddCookie", arguments.value, "HTTPCookieValue", 5000, false );

				// create the special cookie header
				// Set-Cookie:<name>=<value>[; <name>=<value>][; expires=<date>][;
				// domain=<domain_name>][; path=<some_path>][; secure][;HttpOnly
				local.header = local.cookieName & "=" & local.cookieValue;
				if(arguments.maxAge != -1)
					local.header &= "; Max-Age=" & arguments.maxAge;
				if(structKeyExists( arguments, "domain" ))
					local.header &= "; Domain=" & arguments.domain;
				if(structKeyExists( arguments, "path" ))
					local.header &= "; Path=" & arguments.path;
				local.header &= "; Secure; HttpOnly";
				instance.response.addHeader( "Set-Cookie", local.header );
			}
			catch(esapi4cf.org.owasp.esapi.errors.ValidationException e) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Attempt to set invalid cookie denied", e );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addDateHeader" output="false"
	            hint="Add a cookie to the response after ensuring that there are no encoded or illegal characters in the name.">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="Date" name="date"/>

		<cfscript>
			var local = {};
			try {
				local.safeName = instance.ESAPI.validator().getValidInput( "safeSetDateHeader", arguments.name, "HTTPHeaderName", 20, false );
				instance.response.addDateHeader( local.safeName, arguments.date );
			}
			catch(esapi4cf.org.owasp.esapi.errors.ValidationException e) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Attempt to set invalid date header name denied", e );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addHeader" output="false"
	            hint="Add a header to the response after ensuring that there are no encoded or illegal characters in the name and name and value. This implementation follows the following recommendation: 'A recipient MAY replace any linear white space with a single SP before interpreting the field value or forwarding the message downstream.' http://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html##sec2.2">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="String" name="value"/>

		<cfscript>
			var local = {};
			try {
				// TODO: make stripping a global config
				local.strippedName = getJava("org.owasp.esapi.StringUtilities").stripControls( arguments.name );
				local.strippedValue = getJava("org.owasp.esapi.StringUtilities").stripControls( arguments.value );
				local.safeName = instance.ESAPI.validator().getValidInput( "addHeader", local.strippedName, "HTTPHeaderName", 20, false );
				local.safeValue = instance.ESAPI.validator().getValidInput( "addHeader", local.strippedValue, "HTTPHeaderValue", 500, false );
				instance.response.setHeader( local.safeName, local.safeValue );
			}
			catch(esapi4cf.org.owasp.esapi.errors.ValidationException e) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Attempt to add invalid header denied", e );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addIntHeader" output="false"
	            hint="Add an int header to the response after ensuring that there are no encoded or illegal characters in the name and name.">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="numeric" name="value"/>

		<cfscript>
			var local = {};
			try {
				local.safeName = instance.ESAPI.validator().getValidInput( "safeSetDateHeader", arguments.name, "HTTPHeaderName", 20, false );
				instance.response.addIntHeader( local.safeName, arguments.value );
			}
			catch(esapi4cf.org.owasp.esapi.errors.ValidationException e) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Attempt to set invalid int header name denied", e );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="containsHeader" output="false"
	            hint="Same as HttpServletResponse, no security changes required.">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return instance.response.containsHeader( arguments.name );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeRedirectURL" output="false"
	            hint="Return the URL without any changes, to prevent disclosure of the JSESSIONID The default implementation of this method can add the JSESSIONID to the URL if support for cookies is not detected. This exposes the JSESSIONID credential in bookmarks, referer headers, server logs, and more.">
		<cfargument required="true" type="String" name="url"/>

		<cfscript>
			return arguments.url;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeURL" output="false"
	            hint="Return the URL without any changes, to prevent disclosure of the JSESSIONID The default implementation of this method can add the JSESSIONID to the URL if support for cookies is not detected. This exposes the JSESSIONID credential in bookmarks, referer headers, server logs, and more.">
		<cfargument required="true" type="String" name="url"/>

		<cfscript>
			return arguments.url;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="flushBuffer" output="false"
	            hint="Same as HttpServletResponse, no security changes required.">

		<cfscript>
			instance.response.flushBuffer();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getBufferSize" output="false"
	            hint="Same as HttpServletResponse, no security changes required.">

		<cfscript>
			return instance.response.getBufferSize();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false"
	            hint="Same as HttpServletResponse, no security changes required.">

		<cfscript>
			return instance.response.getCharacterEncoding();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getContentType" output="false"
	            hint="Same as HttpServletResponse, no security changes required.">

		<cfscript>
			return instance.response.getContentType();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getLocaleData" output="false" hint="Same as HttpServletResponse, no security changes required.">

		<cfscript>
			return instance.response.getLocale();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getOutputStream" output="false" hint="Same as HttpServletResponse, no security changes required.">

		<cfscript>
			return instance.response.getOutputStream();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getWriter" output="false" hint="Same as HttpServletResponse, no security changes required.">

		<cfscript>
			return instance.response.getWriter();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isCommitted" output="false"
	            hint="Same as HttpServletResponse, no security changes required.">

		<cfscript>
			return instance.response.isCommitted();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="reset" output="false"
	            hint="Same as HttpServletResponse, no security changes required.">

		<cfscript>
			instance.response.reset();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="resetBuffer" output="false"
	            hint="Same as HttpServletResponse, no security changes required.">

		<cfscript>
			instance.response.resetBuffer();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="sendError" output="false"
	            hint="Override the error code with a 200 in order to confound attackers using automated scanners. The message is canonicalized and filtered for dangerous characters.">
		<cfargument required="true" type="numeric" name="sc"/>
		<cfargument required="false" type="String" name="msg"/>

		<cfscript>
			if(structKeyExists( arguments, "msg" )) {
				instance.response.sendError( HttpServletResponse.SC_OK, instance.ESAPI.encoder().encodeForHTML( arguments.msg ) );
			}
			else {
				instance.response.sendError( HttpServletResponse.SC_OK, getHTTPMessage( arguments.sc ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="sendRedirect" output="false"
	            hint="This method generates a redirect response that can only be used to redirect the browser to safe locations, as configured in the ESAPI security configuration. This method does not that redirect requests can be modified by attackers, so do not rely information contained within redirect requests, and do not include sensitive information in a redirect.">
		<cfargument required="true" type="String" name="location"/>

		<cfscript>
			if(!instance.ESAPI.validator().isValidRedirectLocation( "Redirect", arguments.location, false )) {
				instance.logger.fatal( getSecurity("SECURITY_FAILURE"), false, "Bad redirect location: " & arguments.location );
				throwException( getJava( "java.io.IOException" ).init( "Redirect failed" ) );
			}
			instance.response.sendRedirect( arguments.location );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setBufferSize" output="false"
	            hint="Same as HttpServletResponse, no security changes required.">
		<cfargument required="true" type="numeric" name="size"/>

		<cfscript>
			instance.response.setBufferSize( arguments.size );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCharacterEncoding" output="false"
	            hint="Sets the character encoding scheme to the ESAPI configured encoding scheme.">
		<cfargument required="true" type="String" name="charset"/>

		<cfscript>
			// Note: This overrides the provided character set and replaces it with the safe encoding scheme set in ESAPI.properties.
			instance.response.setCharacterEncoding( instance.ESAPI.securityConfiguration().getCharacterEncoding() );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setContentLength" output="false"
	            hint="Same as HttpServletResponse, no security changes required.">
		<cfargument required="true" type="numeric" name="len"/>

		<cfscript>
			instance.response.setContentLength( arguments.len );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setContentType" output="false"
	            hint="Same as HttpServletResponse, no security changes required.">
		<cfargument required="true" type="String" name="type"/>

		<cfscript>
			instance.response.setContentType( arguments.type );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setDateHeader" output="false"
	            hint="Add a date header to the response after ensuring that there are no encoded or illegal characters in the name.">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="Date" name="date"/>

		<cfscript>
			var local = {};
			try {
				local.safeName = instance.ESAPI.validator().getValidInput( "safeSetDateHeader", arguments.name, "HTTPHeaderName", 20, false );
				instance.response.setDateHeader( local.safeName, arguments.date );
			}
			catch(esapi4cf.org.owasp.esapi.errors.ValidationException e) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Attempt to set invalid date header name denied", e );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setHeader" output="false"
	            hint="Add a header to the response after ensuring that there are no encoded or illegal characters in the name and value. 'A recipient MAY replace any linear white space with a single SP before interpreting the field value or forwarding the message downstream.' http://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html##sec2.2">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="String" name="value"/>

		<cfscript>
			var local = {};
			try {
				local.strippedName = getJava("org.owasp.esapi.StringUtilities").stripControls( arguments.name );
				local.strippedValue = getJava("org.owasp.esapi.StringUtilities").stripControls( arguments.value );
				local.safeName = instance.ESAPI.validator().getValidInput( "setHeader", local.strippedName, "HTTPHeaderName", 20, false );
				local.safeValue = instance.ESAPI.validator().getValidInput( "setHeader", local.strippedValue, "HTTPHeaderValue", 500, false );
				instance.response.setHeader( local.safeName, local.safeValue );
			}
			catch(esapi4cf.org.owasp.esapi.errors.ValidationException e) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Attempt to set invalid header denied", e );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setIntHeader" output="false"
	            hint="Add an int header to the response after ensuring that there are no encoded or illegal characters in the name.">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="numeric" name="value"/>

		<cfscript>
			var local = {};
			try {
				local.safeName = instance.ESAPI.validator().getValidInput( "safeSetDateHeader", arguments.name, "HTTPHeaderName", 20, false );
				instance.response.setIntHeader( local.safeName, arguments.value );
			}
			catch(esapi4cf.org.owasp.esapi.errors.ValidationException e) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Attempt to set invalid int header name denied", e );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLocaleData" output="false"
	            hint="Same as HttpServletResponse, no security changes required.">
		<cfargument required="true" name="loc"/>

		<cfscript>
			// TODO investigate the character set issues here
			instance.response.setLocale( arguments.loc );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setStatus" output="false"
	            hint="Override the status code with a 200 in order to confound attackers using automated scanners. The message is canonicalized and filtered for dangerous characters.">
		<cfargument required="true" type="numeric" name="sc"/>
		<cfargument required="false" type="String" name="sm"/>

		<cfscript>
			if(structKeyExists( arguments, "sm" )) {
				try {
					// setStatus is deprecated so use sendError instead
					sendError( HttpServletResponse.SC_OK, arguments.sm );
				}
				catch(java.io.IOException e) {
					instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Attempt to set response status failed", e );
				}
			}
			else {
				instance.response.setStatus( HttpServletResponse.SC_OK );
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="getHTTPMessage" output="false"
	            hint="returns a text message for the HTTP response code">
		<cfargument required="true" type="numeric" name="sc"/>

		<cfscript>
			return "HTTP error code: " & arguments.sc;
		</cfscript>

	</cffunction>

</cfcomponent>