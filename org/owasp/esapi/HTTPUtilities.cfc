<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfinterface hint="The HTTPUtilities interface is a collection of methods that provide additional security related to HTTP requests, responses, sessions, cookies, headers, and logging.">

	<cffunction access="public" returntype="void" name="assertSecureRequest" output="false"
	            hint="Ensures that the current request uses SSL and POST to protect any sensitive parameters in the querystring from being sniffed or logged. For example, this method should be called from any method that uses sensitive data from a web form. This method uses {@link HTTPUtilities##getCurrentRequest()} to obtain the current {@link HttpServletRequest} object">
		<cfargument required="true" name="httpRequest"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="addCSRFToken" output="false"
	            hint="Adds the current user's CSRF token (see User.getCSRFToken()) to the URL for purposes of preventing CSRF attacks. This method should be used on all URLs to be put into all links and forms the application generates.">
		<cfargument required="true" type="String" name="href" hint="the URL to which the CSRF token will be appended"/>

	</cffunction>

	<cffunction access="public" name="getCookie" output="false" hint="Get the first cookie with the matching name.">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" type="String" name="name"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCSRFToken" output="false"
	            hint="Returns the current user's CSRF token. If there is no current user then return null.">
	</cffunction>

	<cffunction access="public" name="changeSessionIdentifier" output="false" hint="Invalidate the old session after copying all of its contents to a newly created session with a new session id. Note that this is different from logging out and creating a new session identifier that does not contain the existing session contents. Care should be taken to use this only when the existing session does not contain hazardous contents. This method uses {@link HTTPUtilities##getCurrentRequest()} to obtain the current {@link HttpSession} object">
		<cfargument required="true" name="httpRequest"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="verifyCSRFToken" output="false"
	            hint="Checks the CSRF token in the URL (see User.getCSRFToken()) against the user's CSRF token and throws an IntrusionException if it is missing.">
		<cfargument required="true" name="httpRequest"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="decryptHiddenField" output="false"
	            hint="Decrypts an encrypted hidden field value and returns the cleartext. If the field does not decrypt properly, an IntrusionException is thrown to indicate tampering.">
		<cfargument required="true" type="String" name="encrypted" hint="hidden field value to decrypt"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="setRememberToken" output="false"
	            hint="Set a cookie containing the current User's remember me token for automatic authentication. The use of remember me tokens is generally not recommended, but this method will help do it as safely as possible. The user interface should strongly warn the user that this should only be enabled on computers where no other users will have access. Implementations should save the user's remember me data in an encrypted cookie and send it to the user. Any old remember me cookie should be destroyed first. Setting this cookie should keep the user logged in until the maxAge passes, the password is changed, or the cookie is deleted. If the cookie exists for the current user, it should automatically be used by ESAPI to log the user in, if the data is valid and not expired. The ESAPI reference implementation, DefaultHTTPUtilities.setRememberToken() implements all these suggestions. The username can be retrieved with: User username = ESAPI.authenticator().getCurrentUser();">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" name="httpResponse"/>
		<cfargument required="true" type="String" name="password" hint="the user's password"/>
		<cfargument required="true" type="numeric" name="maxAge" hint="the length of time that the token should be valid for in relative seconds"/>
		<cfargument required="true" type="String" name="domain" hint="the domain to restrict the token to or null"/>
		<cfargument required="true" type="String" name="path" hint="the path to restrict the token to or null"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="encryptHiddenField" output="false"
	            hint="Encrypts a hidden field value for use in HTML.">
		<cfargument required="true" type="String" name="value" hint="the cleartext value of the hidden field"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="encryptQueryString" output="false"
	            hint="Takes a querystring (everything after the question mark in the URL) and returns an encrypted string containing the parameters.">
		<cfargument required="true" type="String" name="query" hint="the querystring to encrypt"/>

	</cffunction>

	<cffunction access="public" returntype="Struct" name="decryptQueryString" output="false"
	            hint="Takes an encrypted querystring and returns a Map containing the original parameters.">
		<cfargument required="true" type="String" name="encrypted" hint="the encrypted querystring to decrypt"/>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getSafeFileUploads" output="false"
	            hint="Extract uploaded files from a multipart HTTP requests. Implementations must check the content to ensure that it is safe before making a permanent copy on the local filesystem. Checks should include length and content checks, possibly virus checking, and path and name checks. Refer to the file checking methods in Validator for more information. This method uses {@link HTTPUtilities##getCurrentRequest()} to obtain the {@link HttpServletRequest} object">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" name="tempDir" hint="the temporary directory"/>
		<cfargument required="true" name="finalDir" hint="the final directory"/>

	</cffunction>

	<cffunction access="public" returntype="Struct" name="decryptStateFromCookie" output="false"
	            hint="Retrieves a map of data from a cookie encrypted with encryptStateInCookie().">
		<cfargument required="true" name="httpRequest"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="killAllCookies" output="false"
	            hint="Kill all cookies received in the last request from the browser. Note that new cookies set by the application in this response may not be killed by this method.">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" name="httpResponse"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="killCookie" output="false"
	            hint="Kills the specified cookie by setting a new cookie that expires immediately. Note that this method does not delete new cookies that are being set by the application for this response.">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" name="httpResponse"/>
		<cfargument required="true" type="String" name="name"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="encryptStateInCookie" output="false"
	            hint="Stores a Map of data in an encrypted cookie. Generally the session is a better place to store state information, as it does not expose it to the user at all. If there is a requirement not to use sessions, or the data should be stored across sessions (for a long time), the use of encrypted cookies is an effective way to prevent the exposure.">
		<cfargument required="true" name="httpResponse"/>
		<cfargument required="true" type="Struct" name="cleartext"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="safeSendForward" output="false"
	            hint="This method performs a forward to any resource located inside the WEB-INF directory. Forwarding to publicly accessible resources can be dangerous, as the request will have already passed the URL based access control check. This method ensures that you can only forward to non-publicly accessible resources.">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" name="httpResponse"/>
		<cfargument required="true" type="String" name="context" hint="A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in."/>
		<cfargument required="true" type="String" name="location" hint="the URL to forward to"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setSafeContentType" output="false"
	            hint="Set the content type character encoding header on every HttpServletResponse in order to limit the ways in which the input data can be represented. This prevents malicious users from using encoding and multi-byte escape sequences to bypass input validation routines. Implementations of this method should set the content type header to a safe value for your environment. The default is text/html; charset=UTF-8 character encoding, which is the default in early versions of HTML and HTTP. See RFC 2047 (http://ds.internic.net/rfc/rfc2045.txt) for more information about character encoding and MIME. The DefaultHTTPUtilities reference implementation sets the content type as specified.">
		<cfargument required="true" name="httpResponse" hint="The servlet response to set the content type for."/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setNoCacheHeaders" output="false"
	            hint="Set headers to protect sensitive information against being cached in the browser. Developers should make this call for any HTTP responses that contain any sensitive data that should not be cached within the browser or any intermediate proxies or caches. Implementations should set headers for the expected browsers. The safest approach is to set all relevant headers to their most restrictive setting. These include: Cache-Control: no-store; Cache-Control: no-cache; Cache-Control: must-revalidate; Expires: -1. Note that the header 'pragma: no-cache' is only useful in HTTP requests, not HTTP responses. So even though there are many articles recommending the use of this header, it is not helpful for preventing browser caching. This method uses {@link HTTPUtilities##getCurrentResponse()} to obtain the {@link HttpServletResponse} object">
		<cfargument required="true" name="httpResponse"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCurrentHTTP" output="false"
	            hint="Stores the current HttpRequest and HttpResponse so that they may be readily accessed throughout ESAPI (and elsewhere)">
		<cfargument required="true" name="httpRequest" hint="the current request"/>
		<cfargument required="true" name="httpResponse" hint="the current response"/>

	</cffunction>

	<cffunction access="public" returntype="org.owasp.esapi.filters.SafeRequest" name="getCurrentRequest" output="false"
	            hint="Retrieves the current HttpServletRequest">
	</cffunction>

	<cffunction access="public" returntype="org.owasp.esapi.filters.SafeResponse" name="getCurrentResponse" output="false"
	            hint="Retrieves the current HttpServletResponse">
	</cffunction>

	<cffunction access="public" returntype="String" name="logHTTPRequest" output="false"
	            hint="Format the Source IP address, URL, URL parameters, and all form parameters into a string suitable for the log file. The list of parameters to obfuscate should be specified in order to prevent sensitive information from being logged. If a null list is provided, then all parameters will be logged. If HTTP request logging is done in a central place, the parameterNamesToObfuscate could be made a configuration parameter. We include it here in case different parts of the application need to obfuscate different parameters. This method uses {@link HTTPUtilities##getCurrentResponse()} to obtain the {@link HttpServletResponse} object">
		<cfargument required="true" name="httpRequest"/>
		<cfargument required="true" type="org.owasp.esapi.Logger" name="logger" hint="the logger to write the request to"/>
		<cfargument type="Array" name="parameterNamesToObfuscate" hint="the sensitive parameters"/>

	</cffunction>

</cfinterface>