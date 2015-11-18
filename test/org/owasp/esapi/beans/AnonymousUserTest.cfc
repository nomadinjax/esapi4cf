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

component extends="test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	public void function testAllMethods() {
		// create a user to test Anonymous
		var accountName = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var instance = variables.ESAPI.authenticator();
		var password = instance.generateStrongPassword();

		// Probably could skip the assignment here, but maybe someone had
		// future plans to use this. So will just suppress warning for now.
		var user = instance.createUser(accountName, password, password);

		var userAnonymous = instance.getAnonymousUserInstance();

		// test the rest of the Anonymous user
		try { userAnonymous.addRole(""); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.addRoles([]); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.changePassword("", "", ""); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.disable(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.enable(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.getAccountId(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.getAccountName(); } catch( java.lang.RuntimeException e ) {}
		//try { userAnonymous.getName(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.getCSRFToken(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.getExpirationTime(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.getFailedLoginCount(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.getLastFailedLoginTime(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.getLastLoginTime(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.getLastPasswordChangeTime(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.getRoles(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.getScreenName(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.addSession(""); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.removeSession(""); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.incrementFailedLoginCount(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.isAnonymous(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.isEnabled(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.isExpired(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.isInRole(""); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.isLocked(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.isLoggedIn(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.isSessionAbsoluteTimeout(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.isSessionTimeout(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.lock(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.loginWithPassword(""); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.logout(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.removeRole(""); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.resetCSRFToken(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.setAccountName(""); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.setExpirationTime(now()); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.setRoles([]); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.setScreenName(""); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.unlock(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.verifyPassword(""); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.setLastFailedLoginTime(now()); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.setLastLoginTime(now()); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.setLastHostAddress(""); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.setLastPasswordChangeTime(now()); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.getEventMap(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.getLocale(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.setLocale(""); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.getAccountName(); } catch( java.lang.RuntimeException e ) {}
		try { userAnonymous.getAccountName(); } catch( java.lang.RuntimeException e ) {}
	}
}


