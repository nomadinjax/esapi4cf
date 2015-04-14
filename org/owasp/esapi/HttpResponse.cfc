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

  /* javax.servlet.http.HttpServletResponse */

  public void function addCookie(required httpCookie);

  public void function addDateHeader(required string name, required numeric date);

  public void function addHeader(required string name, required string value);

  public void function addIntHeader(required string name, required numeric value);

  public boolean function containsHeader(required string name);

  public string function encodeRedirectURL(required string url);

  public string function encodeURL(required string url);

  public string function getHeader(required string name);

  public function getHeaderNames();

  public function getHeaders(required string name);

  public numeric function getStatus();

  public void function sendError(required numeric sc, string msg);

  public void function sendRedirect(required string location);

  public void function setDateHeader(required string name, required numeric date);

  public void function setHeader(required string name, required string value);

  public void function setIntHeader(required string name, required numeric value);

  public void function setStatus(required numeric sc, string sm);

  /* javax.servlet.ServletResponse */

  public void function flushBuffer();

  public numeric function getBufferSize();

  public string function getCharacterEncoding();

  public string function getContentType();

  public function getLocale();

  public function getOutputStream();

  public function getWriter();

  public boolean function isCommitted();

  public void function reset();

  public void function resetBuffer();

  public void function setBufferSize(required numeric size);

  public void function setCharacterEncoding(required string charset);

  public void function setContentLength(required numeric len);

  public void function setContentType(required string type);

  public void function setLocale(required loc);

}