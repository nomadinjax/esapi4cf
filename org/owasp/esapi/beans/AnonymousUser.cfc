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
 * The ANONYMOUS user is used to represent an unidentified user. Since there is
 * always a real user, the ANONYMOUS user is better than using null to represent
 * this.
 */
component implements="org.owasp.esapi.User" extends="org.owasp.esapi.util.Object" {

	// defaults
	variables.csrfToken = "";
	variables.sessions = [];
	variables.Locale = "";

	public AnonymousUser function init(required org.owasp.esapi.ESAPI ESAPI) {
		variables.ESAPI = arguments.ESAPI;

		return this;
	}

	public void function addRole(required string role) {
		anonymousAccessFailure();
	}

	public void function addRoles(required array newRoles) {
		anonymousAccessFailure();
	}

	public void function changePassword(required string oldPassword, required string newPassword1, required string newPassword2) {
		anonymousAccessFailure();
	}

	public void function disable() {
		anonymousAccessFailure();
	}

	public void function enable() {
		anonymousAccessFailure();
	}

	public function getAccountId() {
		return 0;
	}

	public string function getAccountName() {
		return variables.ESAPI.getResource().getString("User.anonymousAccountName");
	}

	public string function getCSRFToken() {
		return variables.csrfToken;
	}

	public date function getExpirationTime() {
		return createObject("java", "java.util.Date").init(javaCast("long", createObject("java", "java.lang.Long").MAX_VALUE));
	}

	public numeric function getFailedLoginCount() {
		return 0;
	}

	public date function getLastFailedLoginTime() {
		return createObject("java", "java.util.Date").init(javaCast("long", 0));
	}

	public string function getLastHostAddress() {
		var httpRequest = variables.ESAPI.currentRequest();
		if (!isNull(httpRequest) && isObject(httpRequest)) {
			var remoteAddr = httpRequest.getRemoteAddr();
			if (!isNull(remoteAddr)) {
				return remoteAddr;
			}
		}
		return "unknown";
	}

	public date function getLastLoginTime() {
		return createObject("java", "java.util.Date").init(javaCast("long", 0));
	}

	public date function getLastPasswordChangeTime() {
		return createObject("java", "java.util.Date").init(javaCast("long", 0));
	}

	public array function getRoles() {
		return [];
	}

	public string function getScreenName() {
		return variables.ESAPI.getResource().getString("User.anonymousAccountName");
	}

	public void function addSession(required s) {
	}

	public void function removeSession(required s) {
	}

	public array function getSessions() {
		return variables.sessions;
	}

	public void function incrementFailedLoginCount() {
		anonymousAccessFailure();
	}

	public boolean function isAnonymous() {
		return true;
	}

	public boolean function isEnabled() {
		return false;
	}

	public boolean function isExpired() {
		return false;
	}

	public boolean function isInRole(required string role) {
		return false;
	}

	public boolean function isLocked() {
		return false;
	}

	public boolean function isLoggedIn() {
		return false;
	}

	public boolean function isSessionAbsoluteTimeout(httpRequest) {
		return false;
	}

	public boolean function isSessionTimeout(httpRequest) {
		return false;
	}

	public void function lock() {
		anonymousAccessFailure();
	}

	public void function loginWithPassword(required string password, httpRequest, httpResponse) {
		anonymousAccessFailure();
	}

	public void function logout(httpRequest, httpResponse) {
		anonymousAccessFailure();
	}

	public void function removeRole(required string role) {
		anonymousAccessFailure();
	}

	public string function resetCSRFToken() {
		variables.csrfToken = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		return variables.csrfToken;
	}

	public void function setAccountName(required string accountName) {
		anonymousAccessFailure();
	}

	public void function setExpirationTime(required date expirationTime) {
		anonymousAccessFailure();
	}

	public void function setRoles(required array roles) {
		anonymousAccessFailure();
	}

	public void function setScreenName(required string screenName) {
		anonymousAccessFailure();
	}

	public void function unlock() {
		anonymousAccessFailure();
	}

	public boolean function verifyPassword(required string password) {
		anonymousAccessFailure();
	}

	public void function setLastFailedLoginTime(required date lastFailedLoginTime) {
		anonymousAccessFailure();
	}

	public void function setLastLoginTime(required date lastLoginTime) {
		anonymousAccessFailure();
	}

	public void function setLastHostAddress(required string remoteHost) {
		anonymousAccessFailure();
	}

	public void function setLastPasswordChangeTime(required date lastPasswordChangeTime) {
		anonymousAccessFailure();
	}

	public struct function getEventMap() {
		anonymousAccessFailure();
	}

	public function getLocale() {
		return variables.Locale;
	}

	public void function setLocale(required Locale) {
		variables.Locale = arguments.Locale;
	}

	// private methods

	private void function anonymousAccessFailure() {
		raiseException(createObject("java", "java.lang.RuntimeException").init("Invalid operation for the anonymous user"));
	}

}