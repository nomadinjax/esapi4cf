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
 * The HTTPUtilities interface is a collection of methods that provide additional security related to HTTP requests,
 * responses, sessions, cookies, headers, and logging.
 */
interface {

	/**
     * Add a cookie to the response after ensuring that there are no encoded or
     * illegal characters in the name and name and value. This method also sets
     * the secure and HttpOnly flags on the cookie.
     *
     * @param cookie
     */
    public void function addCookie(required httpCookie, httpResponse);

	/**
     * Adds the current user's CSRF token (see User.getCSRFToken()) to the URL for purposes of preventing CSRF attacks.
     * This method should be used on all URLs to be put into all links and forms the application generates.
     *
     * @param href the URL to which the CSRF token will be appended
     * @return the updated URL with the CSRF token parameter added
     */
    public string function addCSRFToken(required string href);

    /**
     * Add a header to the response after ensuring that there are no encoded or
     * illegal characters in the name and name and value. This implementation
     * follows the following recommendation: "A recipient MAY replace any linear
     * white space with a single SP before interpreting the field value or
     * forwarding the message downstream."
     * http://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html#sec2.2
     *
     * @param name
     * @param value
     */
    public void function addHeader(required string name, required string value, httpResponse=getCurrentResponse());

	/**
	 * Ensures that the request uses both SSL and POST to protect any sensitive parameters
	 * in the querystring from being sniffed, logged, bookmarked, included in referer header, etc...
	 * This method should be called for any request that contains sensitive data from a web form.
     *
     * @param request
     * @throws AccessControlException if security constraints are not met
	 */
    public void function assertSecureRequest(httpRequest);

	/**
	 * Ensures the use of SSL to protect any sensitive parameters in the request and
	 * any sensitive data in the response. This method should be called for any request
	 * that contains sensitive data from a web form or will result in sensitive data in the
	 * response page.
     *
     * @param request
     * @throws AccessControlException if security constraints are not met
	 */
    public void function assertSecureChannel(httpRequest);

	/**
     * Invalidate the existing session after copying all of its contents to a newly created session with a new session id.
     * Note that this is different from logging out and creating a new session identifier that does not contain the
     * existing session contents. Care should be taken to use this only when the existing session does not contain
     * hazardous contents.
     *
     * @param request
     * @return the new HttpSession with a changed id
     * @throws AuthenticationException the exception
     */
    public function changeSessionIdentifier(httpRequest);

    /**
	 * Clears the current HttpRequest and HttpResponse associated with the current thread.
     *
	 * @see ESAPI#clearCurrent()
	 */
    public void function clearCurrent();

    /**
	 * Decrypts an encrypted hidden field value and returns the cleartext. If the field does not decrypt properly,
	 * an IntrusionException is thrown to indicate tampering.
     *
	 * @param encrypted hidden field value to decrypt
	 * @return decrypted hidden field value stored as a String
	 */
	public string function decryptHiddenField(required string encrypted);

    /**
	 * Takes an encrypted querystring and returns a Map containing the original parameters.
     *
	 * @param encrypted the encrypted querystring to decrypt
	 * @return a Map object containing the decrypted querystring
	 * @throws EncryptionException
	 */
    public struct function decryptQueryString(required string encrypted);

    /**
     * Retrieves a map of data from a cookie encrypted with encryptStateInCookie().
     *
     * @param request
     * @return a map containing the decrypted cookie state value
	 * @throws EncryptionException
     */
    public struct function decryptStateFromCookie(httpRequest);

    /**
     * Encrypts a hidden field value for use in HTML.
     *
     * @param value the cleartext value of the hidden field
     * @return the encrypted value of the hidden field
     * @throws EncryptionException
     */
	public string function encryptHiddenField(required string value);

	/**
	 * Takes a querystring (everything after the question mark in the URL) and returns an encrypted string containing the parameters.
     *
	 * @param query the querystring to encrypt
	 * @return encrypted querystring stored as a String
	 * @throws EncryptionException
	 */
	public string function encryptQueryString(required string queryString);

    /**
     * Stores a Map of data in an encrypted cookie. Generally the session is a better
     * place to store state information, as it does not expose it to the user at all.
     * If there is a requirement not to use sessions, or the data should be stored
     * across sessions (for a long time), the use of encrypted cookies is an effective
     * way to prevent the exposure.
     *
     * @param response
     * @param cleartext
     * @throws EncryptionException
     */
    public void function encryptStateInCookie(required struct cleartext, httpResponse);

	/**
     * A safer replacement for getCookies() in HttpServletRequest that returns the canonicalized
     * value of the named cookie after "global" validation against the
     * general type defined in ESAPI.properties. This should not be considered a replacement for
     * more specific validation.
     *
     * @param request
     * @param name
     * @return the requested cookie value
     */
	public string function getCookie(required string name, httpRequest);

    /**
     * Returns the current user's CSRF token. If there is no current user then return null.
     *
     * @return the current users CSRF token
     */
    public string function getCSRFToken();

	/**
     * Retrieves the current HttpServletRequest
     *
     * @return the current request
     */
    public function getCurrentRequest();

	/**
     * Retrieves the current HttpServletResponse
     *
     * @return the current response
     */
    public function getCurrentResponse();

    /**
     * Extract uploaded files from a multipart HTTP requests. Implementations must check the content to ensure that it
     * is safe before making a permanent copy on the local filesystem. Checks should include length and content checks,
     * possibly virus checking, and path and name checks. Refer to the file checking methods in Validator for more
     * information.
     * <p/>
	 * This method uses {@link HTTPUtilities#getCurrentRequest()} to obtain the {@link HttpServletRequest} object
     *
     * @param request
     * @return List of new File objects from upload
     * @throws ValidationException if the file fails validation
     */
    public array function getFileUploads(uploadDir, array allowedExtensions, httpRequest);

    /**
     * A safer replacement for getHeader() in HttpServletRequest that returns the canonicalized
     * value of the named header after "global" validation against the
     * general type defined in ESAPI.properties. This should not be considered a replacement for
     * more specific validation.
     *
     * @param request
     * @param name
     * @return the requested header value
     */
	public string function getHeader(required string name, httpRequest);

    /**
     * A safer replacement for getParameter() in HttpServletRequest that returns the canonicalized
     * value of the named parameter after "global" validation against the
     * general type defined in ESAPI.properties. This should not be considered a replacement for
     * more specific validation.
     *
     * @param request
     * @param name
     * @return the requested parameter value
     */
    public string function getParameter(required string name, httpRequest);

    /**
     * Kill all cookies received in the last request from the browser. Note that new cookies set by the application in
     * this response may not be killed by this method.
     *
     * @param request
     * @param response
     */
    public void function killAllCookies(httpRequest, httpResponse);

    /**
     * Kills the specified cookie by setting a new cookie that expires immediately. Note that this
     * method does not delete new cookies that are being set by the application for this response.
     *
     * @param request
     * @param name
     * @param response
     */
    public void function killCookie(required string name, httpRequest, httpResponse);

    /**
     * Format the Source IP address, URL, URL parameters, and all form
     * parameters into a string suitable for the log file. The list of parameters to
     * obfuscate should be specified in order to prevent sensitive information
     * from being logged. If a null list is provided, then all parameters will
     * be logged. If HTTP request logging is done in a central place, the
     * parameterNamesToObfuscate could be made a configuration parameter. We
     * include it here in case different parts of the application need to obfuscate
     * different parameters.
     *
     * @param request
     * @param logger the logger to write the request to
     * @param parameterNamesToObfuscate the sensitive parameters
     */
    public void function logHTTPRequest(httpRequest, logger, array parameterNamesToObfuscate);

    /**
     * This method performs a forward to any resource located inside the WEB-INF directory. Forwarding to
     * publicly accessible resources can be dangerous, as the request will have already passed the URL
     * based access control check. This method ensures that you can only forward to non-publicly
     * accessible resources.
     *
     * @param request
     * @param response
     * @param location the URL to forward to, including parameters
     * @throws AccessControlException
     * @throws ServletException
     * @throws IOException
     */
    public void function sendForward(required string location, httpRequest, httpResponse);


    /**
     * This method performs a forward to any resource located inside the WEB-INF directory. Forwarding to
     * publicly accessible resources can be dangerous, as the request will have already passed the URL
     * based access control check. This method ensures that you can only forward to non-publicly
     * accessible resources.
     *
     * @param response
     * @param location the URL to forward to, including parameters
     * @throws AccessControlException
     * @throws ServletException
     * @throws IOException
     */
    public void function sendRedirect(required string location, httpResponse);

     /**
	 * Set the content type character encoding header on every HttpServletResponse in order to limit
	 * the ways in which the input data can be represented. This prevents
	 * malicious users from using encoding and multi-byte escape sequences to
	 * bypass input validation routines.
     * <p/>
	 * Implementations of this method should set the content type header to a safe value for your environment.
     * The default is text/html; charset=UTF-8 character encoding, which is the default in early
	 * versions of HTML and HTTP. See RFC 2047 (http://ds.internic.net/rfc/rfc2045.txt) for more
	 * information about character encoding and MIME.
     * <p/>
	 * The DefaultHTTPUtilities reference implementation sets the content type as specified.
     *
     * @param response The servlet response to set the content type for.
     */
    public void function setContentType(httpResponse);

    /**
     * Stores the current HttpRequest and HttpResponse so that they may be readily accessed throughout
     * ESAPI (and elsewhere)
     *
     * @param request  the current request
     * @param response the current response
     */
    public void function setCurrentHTTP(required httpRequest, required httpResponse);


    /**
     * Add a header to the response after ensuring that there are no encoded or
     * illegal characters in the name and value. "A recipient MAY replace any
     * linear white space with a single SP before interpreting the field value
     * or forwarding the message downstream."
     * http://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html#sec2.2
     *
     * @param name
     * @param value
     */
    public void function setHeader(required string name, required string value, httpResponse);


    /**
     * Set headers to protect sensitive information against being cached in the browser. Developers should make this
     * call for any HTTP responses that contain any sensitive data that should not be cached within the browser or any
     * intermediate proxies or caches. Implementations should set headers for the expected browsers. The safest approach
     * is to set all relevant headers to their most restrictive setting. These include:
     * <p/>
     * <PRE>
     * Cache-Control: no-store<BR>
     * Cache-Control: no-cache<BR>
     * Cache-Control: must-revalidate<BR>
     * Expires: -1<BR>
     * </PRE>
     * <p/>
     * Note that the header "pragma: no-cache" is intended only for use in HTTP requests, not HTTP responses. However, Microsoft has chosen to
     * directly violate the standards, so we need to include that header here. For more information, please refer to the relevant standards:
     * <UL>
     * <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.1">HTTP/1.1 Cache-Control "no-cache"</a>
     * <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9.2">HTTP/1.1 Cache-Control "no-store"</a>
     * <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.32">HTTP/1.0 Pragma "no-cache"</a>
     * <LI><a href="http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.21">HTTP/1.0 Expires</a>
     * <LI><a href="http://support.microsoft.com/kb/937479">IE6 Caching Issues</a>
     * <LI><a href="http://support.microsoft.com/kb/234067">Microsoft directly violates specification for pragma: no-cache</a>
     * <LI><a href="https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Mozilla_networking_preferences#Cache">Firefox browser.cache.disk_cache_ssl</a>
     * <LI><a href="https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Mozilla_networking_preferences">Mozilla</a>
     * </UL>
     *
     * @param response
     */
    public void function setNoCacheHeaders(httpResponse);

    /**
	 * Set a cookie containing the current User's remember me token for automatic authentication. The use of remember me tokens
	 * is generally not recommended, but this method will help do it as safely as possible. The user interface should strongly warn
     * the user that this should only be enabled on computers where no other users will have access.
     * <p/>
     * Implementations should save the user's remember me data in an encrypted cookie and send it to the user.
     * Any old remember me cookie should be destroyed first. Setting this cookie should keep the user
	 * logged in until the maxAge passes, the password is changed, or the cookie is deleted.
	 * If the cookie exists for the current user, it should automatically be used by ESAPI to
     * log the user in, if the data is valid and not expired.
     * <p/>
	 * The ESAPI reference implementation, DefaultHTTPUtilities.setRememberToken() implements all these suggestions.
     * <p/>
     * The username can be retrieved with: User username = ESAPI.authenticator().getCurrentUser();
     *
     * @param request
     * @param password the user's password
     * @param response
     * @param maxAge the length of time that the token should be valid for in relative seconds
	 * @param domain the domain to restrict the token to or null
	 * @param path the path to restrict the token to or null
	 * @return encrypted "Remember Me" token stored as a String
	 */
    public string function setRememberToken(required string password, required numeric maxAge, required string domain, required string path, httpRequest, httpResponse);


    /**
     * Checks the CSRF token in the URL (see User.getCSRFToken()) against the user's CSRF token and
	 * throws an IntrusionException if it is missing.
     *
     * @param request
     * @throws IntrusionException if CSRF token is missing or incorrect
	 */
    public void function verifyCSRFToken(httpRequest);

    /**
     * Gets a typed attribute from the passed in session. This method has the same
     * responsibility as {link #getSessionAttribute(String} however only it references
     * the passed in session and thus performs slightly better since it does not need
     * to return to the Thread to get the {@link HttpSession} associated with the current
     * thread.
     *
     * @param session
     *          The session to retrieve the attribute from
     * @param key
     *          The key that references the requested object
     * @param <T>
     *          The implied type of object expected
     * @return  The requested object
     */
    public function getSessionAttribute(required string key, httpSession);

    /**
     * Gets a typed attribute from the {@link HttpServletRequest} associated
     * with the passed in request. If the attribute on the request is not of the implied
     * type, a ClassCastException will be thrown back to the caller.
     *
     * @param request The request to retrieve the attribute from
     * @param key The key that references the request attribute.
     * @param <T> The implied type of the object expected
     * @return The requested object
     */
    public function getRequestAttribute(required string key, httpRequest);

}
