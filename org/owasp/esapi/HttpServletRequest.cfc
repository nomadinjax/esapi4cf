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
<cfinterface>

	<cffunction access="public" returntype="String" name="getAuthType" output="false" hint="The authentication type">
	</cffunction>


	<cffunction access="public" returntype="String" name="getContextPath" output="false" hint="Returns the context path from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getCookies" output="false" hint="Returns the array of Cookies from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getDateHeader" output="false" hint="a long value representing the date specified in the header expressed as the number of milliseconds since January 1, 1970 GMT, or -1 if the named header was not included with the request.">
		<cfargument type="String" name="name" required="true" hint="Specifies the name of the HTTP request header; e.g., If-Modified-Since.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getHeader" output="false" hint="Returns the named header from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument type="String" name="name" required="true">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getHeaderNames" output="false" hint="Returns the enumeration of header names from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getHeaders" output="false" hint="Returns the enumeration of headers from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument type="String" name="name" required="true" hint="The name of an HTTP request header.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getIntHeader" output="false" hint="Returns the value of the specified request header as an int.">
		<cfargument type="String" name="name" required="true" hint="The name of an HTTP request header.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getMethod" output="false" hint="Returns the name of the HTTP method with which this request was made.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getPathInfo" output="false" hint="Returns the path info from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getPathTranslated" output="false" hint="Returns any extra path information, appropriate scrubbed, after the servlet name but before the query string, and translates it to a real path.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getQueryString" output="false" hint="Returns the query string from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getRemoteUser" output="false" hint="Returns the name of the ESAPI user associated with this getHttpServletRequest().">
	</cffunction>


	<cffunction access="public" returntype="String" name="getRequestedSessionId" output="false" hint="Returns the SessionId from the HttpServletRequest after canonicalizing and filtering out any dangerous characters. Code must be very careful not to depend on the value of a requested session id reported by the user.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getRequestURI" output="false" hint="Returns the URI from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
	</cffunction>


	<cffunction access="public" returntype="any" name="getRequestURL" output="false" hint="java.lang.StringBuffer: The currect request URL">
	</cffunction>


	<cffunction access="public" returntype="String" name="getServletPath" output="false" hint="Returns the server path from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
	</cffunction>


	<cffunction access="public" returntype="any" name="getSession" output="false" hint="cfesapi.org.owasp.esapi.HttpSession: Returns a session, creating it if necessary, and sets the HttpOnly flag on the JSESSIONID cookie.">
		<cfargument type="boolean" name="create" required="false">
	</cffunction>


	<cffunction access="public" returntype="any" name="getUserPrincipal" output="false" hint="Returns the ESAPI User associated with this getHttpServletRequest().">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdFromCookie" output="false" hint="if requested session id is from a cookie">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdFromURL" output="false" hint="Whether the requested session id is from the URL">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdValid" output="false" hint="Whether the requested session id is valid">
	</cffunction>

	<!--- RAILO ERROR: The name [isUserInRole] is already used by a Build in Function

		<cffunction access="public" returntype="boolean" name="isUserInRole" output="false" hint="Returns true if the ESAPI User associated with this request has the specified role.">
		<cfargument type="String" name="role" required="true" hint="The role to check">
		</cffunction>

		--->
	<!--- javax.servlet.ServletRequest --->

	<cffunction access="public" returntype="any" name="getAttribute" output="false" hint="The attribute value">
		<cfargument type="String" name="name" required="true" hint="The attribute name">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getAttributeNames" output="false" hint="An Enumeration of attribute names.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false" hint="The character-encoding for this HttpServletRequest">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getContentLength" output="false" hint="The content-length for this HttpServletRequest">
	</cffunction>


	<cffunction access="public" returntype="String" name="getContentType" output="false" hint="The content-type for this HttpServletRequest">
	</cffunction>


	<cffunction access="public" returntype="any" name="getInputStream" output="false" hint="The javax.servlet.ServletInputStream associated with this HttpServletRequest. Note that this input stream may contain attacks and the developer is responsible for canonicalizing, validating, and encoding any data from this stream.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getLocalAddr" output="false" hint="A String containing the IP address on which the request was received.">
	</cffunction>

	<!--- RAILO ERROR: 	The name [getLocale] is already used by a Build in Function

		<cffunction access="public" returntype="any" name="getLocale" output="false" hint="java.util.Locale: The preferred Locale for the client.">
		</cffunction>

		--->

	<cffunction access="public" returntype="Array" name="getLocales" output="false" hint="An Enumeration of preferred Locale objects for the client.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getLocalName" output="false" hint="A String containing the host name of the IP on which the request was received.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getLocalPort" output="false" hint="Returns the Internet Protocol (IP) port number of the interface on which the request was received.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getParameter" output="false" hint="Returns the named parameter from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument type="String" name="name" required="true" hint="The parameter name for the request">
	</cffunction>


	<cffunction access="public" returntype="Struct" name="getParameterMap" output="false" hint="Returns the parameter map from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getParameterNames" output="false" hint="Returns the enumeration of parameter names from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getParameterValues" output="false" hint="Returns the array of matching parameter values from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument type="String" name="name" required="true" hint="The parameter name">
	</cffunction>


	<cffunction access="public" returntype="String" name="getProtocol" output="false" hint="Returns the name and version of the protocol the request uses in the form protocol/majorVersion.minorVersion, for example, HTTP/1.1.">
	</cffunction>


	<cffunction access="public" returntype="any" name="getReader" output="false" hint="A java.io.BufferedReader containing the body of the request. Note that this reader may contain attacks and the developer is responsible for canonicalizing, validating, and encoding any data from this stream.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getRemoteAddr" output="false" hint="Returns the IP address of the client or last proxy that sent the request.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getRemoteHost" output="false" hint="The remote host">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getRemotePort" output="false" hint="The remote port">
	</cffunction>


	<cffunction access="public" returntype="any" name="getRequestDispatcher" output="false" hint="java.servlet.RequestDispatcher: Checks to make sure the path to forward to is within the WEB-INF directory and then returns the dispatcher. Otherwise returns null.">
		<cfargument type="String" name="path" required="true" hint="The path to create a request dispatcher for">
	</cffunction>


	<cffunction access="public" returntype="String" name="getScheme" output="false" hint="Returns the scheme from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getServerName" output="false" hint="Returns the server name (host header) from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getServerPort" output="false" hint="Returns the server port (after the : in the host header) from the HttpServletRequest after parsing and checking the range 0-65536.">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isSecure" output="false" hint="Whether the current request is secure">
	</cffunction>


	<cffunction access="public" returntype="void" name="removeAttribute" output="false" hint="The attribute name">
		<cfargument type="String" name="name" required="true">
	</cffunction>


	<cffunction access="public" returntype="void" name="setAttribute" output="false">
		<cfargument type="String" name="name" required="true" hint="The attribute name">
		<cfargument type="any" name="o" required="true" hint="The attribute value">
	</cffunction>


	<cffunction access="public" returntype="void" name="setCharacterEncoding" output="false" hint="Sets the character encoding scheme to the ESAPI configured encoding scheme.">
		<cfargument type="String" name="enc" required="true" hint="The encoding scheme">
	</cffunction>

</cfinterface>
