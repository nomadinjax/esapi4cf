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
component UserTest extends="cfesapi.test.org.owasp.esapi.lang.TestCase" {

	// imports
	DefaultEncoder = createObject("java", "org.owasp.esapi.reference.DefaultEncoder");

	public void function setUp() {
		// delete the users.txt file as running all these tests just once creates tons of users
		// the more users, the longer the tests take
		filePath = expandPath("/cfesapi/esapi/configuration/esapi/users.txt");
		if(fileExists(filePath)) {
			try {
				fileDelete(filePath);
			}
			catch(Any e) {
			}
		}
	
		instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();
	}
	
	public void function tearDown() {
		instance.ESAPI = "";
	}
	
	public void function testAllMethods() {
		// create a user to test Anonymous
		local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		local.authenticator = instance.ESAPI.authenticator();
		local.password = local.authenticator.generateStrongPassword();
		local.user = local.authenticator.createUser(local.accountName, local.password, local.password);
	
		// test the rest of the Anonymous user
		User.ANONYMOUS = new cfesapi.org.owasp.esapi.User$ANONYMOUS(instance.ESAPI);
		try {
			User.ANONYMOUS.addRole("");
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.addRoles([]);
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.changePassword("", "", "");
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.disable();
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.enable();
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.getAccountId();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.getAccountName();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.getName();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.getCSRFToken();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.getExpirationTime();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.getFailedLoginCount();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.getLastFailedLoginTime();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.getLastLoginTime();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.getLastPasswordChangeTime();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.getRoles();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.getScreenName();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.addSession("");
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.removeSession("");
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.incrementFailedLoginCount();
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.isAnonymous();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.isEnabled();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.isExpired();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.isInRole("");
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.isLocked();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.isLoggedIn();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.isSessionAbsoluteTimeout();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.isSessionTimeout();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.lock();
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.loginWithPassword(password="");
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.logout();
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.removeRole("");
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.resetCSRFToken();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.setAccountName("");
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.setExpirationTime(now());
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.setRoles([]);
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.setScreenName("");
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.unlock();
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.verifyPassword("");
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.setLastFailedLoginTime(now());
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.setLastLoginTime(now());
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.setLastHostAddress("");
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.setLastPasswordChangeTime(now());
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.getEventMap();
			fail("");
		}
		catch(java.lang.RuntimeException e) {
		}
		try {
			User.ANONYMOUS.getLocale();
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
		try {
			User.ANONYMOUS.setLocale("");
		}
		catch(java.lang.RuntimeException e) {
			fail("");
		}
	}
	
}