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
interface {

  /* javax.servlet.http.HttpServletRequest */

  public boolean function authenticate(required response);

  public string function getAuthType();

  public string function getContextPath();

  public array function getCookies();

  public numeric function getDateHeader(required string name);

  public string function getHeader(required string name);

  public array function getHeaderNames();

  public function getHeaders(required string name);

  public numeric function getIntHeader(required string name);

  public string function getMethod();

  public function getPart();

  public function getParts();

  public string function getPathInfo();

  public string function getPathTranslated();

  public string function getQueryString();

  public string function getRemoteUser();

  public string function getRequestedSessionId();

  public string function getRequestURI();

  public function getRequestURL();

  public string function getServletPath();

  public function getSession(boolean create);

  public function getUserPrincipal();

  public boolean function isRequestedSessionIdFromCookie();

  public boolean function isRequestedSessionIdFromURL();

  public boolean function isRequestedSessionIdValid();

  public boolean function isUserInRole(required string role);

  public void function login(required string username, required string password);

  public void function logout();

  /* javax.servlet.ServletRequest */

  public function getAsyncContext();

  public function getAttribute(required string name);

  public function getAttributeNames();

  public string function getCharacterEncoding();

  public numeric function getContentLength();

  public string function getContentType();

  public function getDispatcherType();

  public function getInputStream();

  public string function getLocalAddr();

  public function getLocale();

  public function getLocales();

  public string function getLocalName();

  public function getLocalPort();

  public string function getParameter(required string name, boolean allowNull, numeric maxLength, string regexName, boolean canonicalize);

  public struct function getParameterMap();

  public array function getParameterNames();

  public array function getParameterValues(required string name);

  public string function getProtocol();

  public function getReader();

  public string function getRealPath(required string path);

  public string function getRemoteAddr();

  public string function getRemoteHost();

  public numeric function getRemotePort();

  public function getRequestDispatcher(required string path);

  public string function getScheme();

  public string function getServerName();

  public numeric function getServerPort();

  public function getServletContext();

  public boolean function isAsyncStarted();

  public boolean function isAsyncSupported();

  public boolean function isSecure();

  public void function removeAttribute(required string name);

  public void function setAttribute(required string name, required o);

  public void function setCharacterEncoding(required string enc);

  public function startAsync(servletRequest, servletResponse);

}