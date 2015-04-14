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

	public function getAttribute(required string name);

	public array function getAttributeNames();

	public numeric function getCreationTime();

	public string function getId();

	public numeric function getLastAccessedTime();

	public numeric function getMaxInactiveInterval();

	public function getServletContext();

	public function getSessionContext();

	public function getValue(required string name);

	public array function getValueNames();

	public void function invalidate();

	public boolean function isNew();

	public void function putValue(required string name, required value);

	public void function removeAttribute(required string name);

	public void function removeValue(required string name);

	public void function setAttribute(required string name, required value);

	public void function setMaxInactiveInterval(required numeric interval);

}