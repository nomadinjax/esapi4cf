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
component implements="org.owasp.esapi.HttpSession" extends="org.owasp.esapi.util.Object" {

	variables.httpSession = "";

	public org.owasp.esapi.HttpSession function init(required org.owasp.esapi.ESAPI ESAPI, httpSession) {
    	variables.ESAPI = arguments.ESAPI;
    	if (structKeyExists(arguments, "httpSession")) {
    		variables.httpSession = arguments.httpSession;
    	}
    	return this;
    }

    private function getHttpServletSession() {
    	if (!isObject(variables.httpSession)) {
    		variables.httpSession = getPageContext().getRequest().getSession(true);
    	}
    	return variables.httpSession;
    }

	public function getAttribute(required string name) {
		var persistence = getPersistedScope();
		if (structKeyExists(persistence.data, arguments.name)) {
			return persistence.data[arguments.name];
		}
		return "";
	}

	public array function getAttributeNames() {
		var persistence = getPersistedScope();
		return listToArray(structKeyList(persistence.data));
	}

	public numeric function getCreationTime() {
		return getHttpServletSession().getCreationTime();
	}

	public string function getId() {
		return getHttpServletSession().getId();
	}

	public numeric function getLastAccessedTime() {
		return getHttpServletSession().getLastAccessedTime();
	}

	public numeric function getMaxInactiveInterval() {
		return getHttpServletSession().getMaxInactiveInterval();
	}

	public function getServletContext() {
		return getHttpServletSession().getServletContext();
	}

	public function getSessionContext() {
		return getHttpServletSession().getSessionContext();
	}

	/**
	 * Deprecated in favor of getAttribute(name).
	 */
	public function getValue(required string name) {
		return this.getAttribute(arguments.name);
	}

	/**
	 * Deprecated in favor of getAttributeNames().
	 */
	public array function getValueNames() {
		return this.getAttributeNames();
	}

	public void function invalidate() {
		/*try {
			sessionInvalidate();
		}
		catch (expression e) {
			// expected when session scope was not enabled
		}
		try {
			getHttpServletSession().invalidate();
		}
		catch (expression e) {}*/
		var persistence = getPersistedScope();
		structClear(persistence);
	}

	public boolean function isNew() {
		return getHttpServletSession().isNew();
	}

	/**
	 * Deprecated in favor of setAttribute(name, value).
	 */
	public void function putValue(required string name, required value) {
		this.setAttribute(arguments.name, arguments.value);
	}

	public void function removeAttribute(required string name) {
		var persistence = getPersistedScope();
		structDelete(persistence.data, arguments.name);
	}

	/**
	 * Deprecated in favor of removeAttribute(name).
	 */
	public void function removeValue(required string name) {
		this.removeAttribute(arguments.name);
	}

	public void function setAttribute(required string name, required value) {
		var persistence = getPersistedScope();
		persistence.data[arguments.name] = arguments.value;
	}

	public void function setMaxInactiveInterval(required numeric interval) {
		getHttpServletSession().setMaxInactiveInterval(javaCast("int", arguments.interval));
	}

	// private methods

	private function getPersistedScope() {
		// web apps maintain state between requests
		if (getApplicationMetaData().sessionManagement) {
			return {scope: "session", data: session};
		}
		// REST apps are stateless so use psuedo-session object in request scope
		// in order to avoid conflicts with true request scope variables
		if (!structKeyExists(request, "SessionFacade")) {
			request["SessionFacade"] = {};
		}
		return {scope: "request", data: request["SessionFacade"]};
	}

}