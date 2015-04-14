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
 * The Class UserTest.
 */
component extends="esapi4cf.test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	clearUserFile();

	/**
	 * Creates the test user.
	 *
	 * @param password
	 *            the password
	 *
	 * @return the user
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	private org.owasp.esapi.beans.AuthenticatedUser function createTestUser(required string password) {
		var username = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var e = callStackGet();
		variables.System.out.println("Creating user " & username & " for " & e[2]["function"]);
		var user = variables.ESAPI.authenticator().createUser(username, arguments.password, arguments.password);
		return user;
	}

	/**
	 * Test of testAddRole method, of class org.owasp.esapi.User.
	 *
	 * @exception Exception
	 * 				any Exception thrown by testing addRole()
	 */
	public void function testAddRole() {
		variables.System.out.println("addRole");
		var instance = variables.ESAPI.authenticator();
		var accountName = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var password = variables.ESAPI.authenticator().generateStrongPassword();
		var role = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_LOWERS);
		var user = instance.createUser(accountName, password, password);
		user.addRole(role);
		assertTrue(user.isInRole(role));
		assertFalse(user.isInRole("ridiculous"));
	}

	/**
	 * Test of addRoles method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testAddRoles() {
		variables.System.out.println("addRoles");
		var instance = variables.ESAPI.authenticator();
		var oldPassword = instance.generateStrongPassword();
		var user = createTestUser(oldPassword);
		var set = [];
		set.add("rolea");
		set.add("roleb");
		user.addRoles(set);
		assertTrue(user.isInRole("rolea"));
		assertTrue(user.isInRole("roleb"));
		assertFalse(user.isInRole("ridiculous"));
	}

	/**
	 * Test of changePassword method, of class org.owasp.esapi.User.
	 *
	 * @throws Exception
	 *             the exception
	 */
	public void function testChangePassword() {
		variables.System.out.println("changePassword");
		var instance = variables.ESAPI.authenticator();
		var oldPassword = "Password12!@";
		var user = createTestUser(oldPassword);
		variables.System.out.println("Hash of " & oldPassword & " = " & instance.getHashedPassword(user));
		var password1 = "SomethingElse34##$";
		user.changePassword(oldPassword, password1, password1);
		variables.System.out.println("Hash of " & password1 & " = " & instance.getHashedPassword(user));
		assertTrue(user.verifyPassword(password1));
		var password2 = "YetAnother56%^";
		user.changePassword(password1, password2, password2);
		variables.System.out.println("Hash of " & password2 & " = " & instance.getHashedPassword(user));
		try {
			user.changePassword(password2, password1, password1);
			fail("Shouldn't be able to reuse a password");
		} catch( org.owasp.esapi.errors.AuthenticationCredentialsException e ) {
			// expected
		}
		assertTrue(user.verifyPassword(password2));
		assertFalse(user.verifyPassword("badpass"));
	}

	/**
	 * Test of disable method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testDisable() {
		variables.System.out.println("disable");
		var instance = variables.ESAPI.authenticator();
		var oldPassword = instance.generateStrongPassword();
		var user = createTestUser(oldPassword);
		user.enable();
		assertTrue(user.isEnabled());
		user.disable();
		assertFalse(user.isEnabled());
	}

	/**
	 * Test of enable method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testEnable() {
		variables.System.out.println("enable");
		var instance = variables.ESAPI.authenticator();
		var oldPassword = instance.generateStrongPassword();
		var user = createTestUser(oldPassword);
		user.enable();
		assertTrue(user.isEnabled());
		user.disable();
		assertFalse(user.isEnabled());
	}

	/**
	 * Test of failedLoginCount lockout, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 * @throws EncryptionException
	 *             any EncryptionExceptions thrown by testing failedLoginLockout()
	 */
	public void function testFailedLoginLockout() {
		variables.System.out.println("failedLoginLockout");
		var user = createTestUser("failedLoginLockout");
		user.enable();
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);

		user.loginWithPassword("failedLoginLockout");

		try {
    		user.loginWithPassword("ridiculous");
		} catch( org.owasp.esapi.errors.AuthenticationLoginException e ) {
    		// expected
    	}
 		variables.System.out.println("FAILED: " & user.getFailedLoginCount());
		assertFalse(user.isLocked());

		try {
    		user.loginWithPassword("ridiculous");
		} catch( org.owasp.esapi.errors.AuthenticationLoginException e ) {
    		// expected
    	}
		variables.System.out.println("FAILED: " & user.getFailedLoginCount());
		assertFalse(user.isLocked());

		try {
    		user.loginWithPassword("ridiculous");
		} catch( org.owasp.esapi.errors.AuthenticationLoginException e ) {
    		// expected
    	}
		variables.System.out.println("FAILED: " & user.getFailedLoginCount());
		assertTrue(user.isLocked());
	}

	/**
	 * Test of getAccountName method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testGetAccountName() {
		variables.System.out.println("getAccountName");
		var user = createTestUser("getAccountName");
		var accountName = variables.ESAPI.randomizer().getRandomString(7, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		user.setAccountName(accountName);
		assertEquals(accountName.toLowerCase(), user.getAccountName());
		assertFalse("ridiculous" == user.getAccountName());
	}

	/**
	 * Test get last failed login time.
	 *
	 * @throws Exception
	 *             the exception
	 */
	public void function testGetLastFailedLoginTime() {
		variables.System.out.println("getLastLoginTime");
		var instance = variables.ESAPI.authenticator();
		var oldPassword = instance.generateStrongPassword();
		var user = createTestUser(oldPassword);

		try {
    		user.loginWithPassword("ridiculous");
		} catch( org.owasp.esapi.errors.AuthenticationLoginException e ) {
    		// expected
    	}
		var llt1 = user.getLastFailedLoginTime();
		sleep(100); // need a short delay to separate attempts
		try {
    		user.loginWithPassword("ridiculous");
		} catch( org.owasp.esapi.errors.AuthenticationLoginException e ) {
    		// expected
    	}
		var llt2 = user.getLastFailedLoginTime();
		assertTrue(llt1.before(llt2));
	}

	/**
	 * Test get last login time.
	 *
	 * @throws Exception
	 *             the exception
	 */
	public void function testGetLastLoginTime() {
		variables.System.out.println("getLastLoginTime");
		var instance = variables.ESAPI.authenticator();
		var oldPassword = instance.generateStrongPassword();
		var user = createTestUser(oldPassword);
		user.verifyPassword(oldPassword);
		var llt1 = user.getLastLoginTime();
		sleep(10); // need a short delay to separate attempts
		user.verifyPassword(oldPassword);
		var llt2 = user.getLastLoginTime();
		assertTrue(llt1.before(llt2));
	}

	/**
	 * Test getLastPasswordChangeTime method, of class org.owasp.esapi.User.
	 *
	 * @throws Exception
	 *             the exception
	 */
	public void function testGetLastPasswordChangeTime() {
		variables.System.out.println("getLastPasswordChangeTime");
		var user = createTestUser("getLastPasswordChangeTime");
		var t1 = user.getLastPasswordChangeTime();
		sleep(10); // need a short delay to separate attempts
		var newPassword = variables.ESAPI.authenticator().generateStrongPassword(user, "getLastPasswordChangeTime");
		user.changePassword("getLastPasswordChangeTime", newPassword, newPassword);
		var t2 = user.getLastPasswordChangeTime();
		assertTrue(t2.after(t1));
	}

	/**
	 * Test of getRoles method, of class org.owasp.esapi.User.
     *
     * @throws Exception
     */
	public void function testGetRoles() {
		variables.System.out.println("getRoles");
		var instance = variables.ESAPI.authenticator();
		var accountName = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var password = variables.ESAPI.authenticator().generateStrongPassword();
		var role = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_LOWERS);
		var user = instance.createUser(accountName, password, password);
		user.addRole(role);
		var roles = user.getRoles();
		assertTrue(roles.size() > 0);
	}

	/**
	 * Test of getScreenName method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testGetScreenName() {
		variables.System.out.println("getScreenName");
		var user = createTestUser("getScreenName");
		var screenName = variables.ESAPI.randomizer().getRandomString(7, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		user.setScreenName(screenName);
		assertEquals(screenName, user.getScreenName());
		assertFalse("ridiculous" == user.getScreenName());
	}

    /**
     *
     * @throws org.owasp.esapi.errors.AuthenticationException
     */
    public void function testGetSessions() {
        variables.System.out.println("getSessions");
        var instance = variables.ESAPI.authenticator();
        var accountName = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
        var password = variables.ESAPI.authenticator().generateStrongPassword();
        var user = instance.createUser(accountName, password, password);
        var httpSession1 = createObject("java", "org.owasp.esapi.http.MockHttpSession").init();
        user.addSession( httpSession1 );
        var httpSession2 = createObject("java", "org.owasp.esapi.http.MockHttpSession").init();
        user.addSession( httpSession2 );
        var httpSession3 = createObject("java", "org.owasp.esapi.http.MockHttpSession").init();
        user.addSession( httpSession3 );
        var httpSessions = user.getSessions();
        var i = httpSessions.iterator();
        while ( i.hasNext() ) {
            var s = i.next();
            variables.System.out.println( ">>>" & s.getId() );
        }
        assertTrue(httpSessions.size() == 3);
	}


    /**
     *
     */
    public void function testAddSession() {
	    // TODO
	}

    /**
     *
     */
    public void function testRemoveSession() {
	    // TODO
	}

	/**
	 * Test of incrementFailedLoginCount method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testIncrementFailedLoginCount() {
		variables.System.out.println("incrementFailedLoginCount");
		var user = createTestUser("incrementFailedLoginCount");
		user.enable();
		assertEquals(0, user.getFailedLoginCount());
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
		try {
			user.loginWithPassword("ridiculous");
		} catch (org.owasp.esapi.errors.AuthenticationLoginException e) {
			// expected
		}
		assertEquals(1, user.getFailedLoginCount());
		try {
			user.loginWithPassword("ridiculous");
		} catch (org.owasp.esapi.errors.AuthenticationLoginException e) {
			// expected
		}
		assertEquals(2, user.getFailedLoginCount());
		try {
			user.loginWithPassword("ridiculous");
		} catch (org.owasp.esapi.errors.AuthenticationLoginException e) {
			// expected
		}
		assertEquals(3, user.getFailedLoginCount());
		try {
			user.loginWithPassword("ridiculous");
		} catch (org.owasp.esapi.errors.AuthenticationLoginException e) {
			// expected
		}
		assertTrue(user.isLocked());
	}

	/**
	 * Test of isEnabled method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testIsEnabled() {
		variables.System.out.println("isEnabled");
		var user = createTestUser("isEnabled");
		user.disable();
		assertFalse(user.isEnabled());
		user.enable();
		assertTrue(user.isEnabled());
	}



	/**
	 * Test of isInRole method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testIsInRole() {
		variables.System.out.println("isInRole");
		var user = createTestUser("isInRole");
		var role = "TestRole";
		assertFalse(user.isInRole(role));
		user.addRole(role);
		assertTrue(user.isInRole(role));
		assertFalse(user.isInRole("Ridiculous"));
	}

	/**
	 * Test of isLocked method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testIsLocked() {
		variables.System.out.println("isLocked");
		var user = createTestUser("isLocked");
		user.lock();
		assertTrue(user.isLocked());
		user.unlock();
		assertFalse(user.isLocked());
	}

	/**
	 * Test of isSessionAbsoluteTimeout method, of class
	 * org.owasp.esapi.IntrusionDetector.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testIsSessionAbsoluteTimeout() {
		variables.System.out.println("isSessionAbsoluteTimeout");
		var instance = variables.ESAPI.authenticator();
		var oldPassword = instance.generateStrongPassword();
		var user = createTestUser(oldPassword);
		var rightNow = variables.System.currentTimeMillis();
		// setup httpRequest and httpResponse
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
		var httpSession = httpRequest.getSession();

		// set session creation -3 hours (default is 2 hour timeout)
		httpSession.setCreationTime( rightNow - (1000 * 60 * 60 * 3) );
		assertTrue(user.isSessionAbsoluteTimeout());

		// set session creation -1 hour (default is 2 hour timeout)
		httpSession.setCreationTime( rightNow - (1000 * 60 * 60 * 1) );
		assertFalse(user.isSessionAbsoluteTimeout());
	}

	/**
	 * Test of isSessionTimeout method, of class
	 * org.owasp.esapi.IntrusionDetector.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testIsSessionTimeout() {
		variables.System.out.println("isSessionTimeout");
		var instance = variables.ESAPI.authenticator();
		var oldPassword = instance.generateStrongPassword();
		var user = createTestUser(oldPassword);
		var rightNow = variables.System.currentTimeMillis();
		// setup httpRequest and httpResponse
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
		var httpSession = httpRequest.getSession();

		// set creation -30 mins (default is 20 min timeout)
		httpSession.setAccessedTime( rightNow - 1000 * 60 * 30 );
		assertTrue(user.isSessionTimeout());

		// set creation -1 hour (default is 20 min timeout)
		httpSession.setAccessedTime( rightNow - 1000 * 60 * 10 );
		assertFalse(user.isSessionTimeout());
	}

	/**
	 * Test of lockAccount method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testLock() {
		variables.System.out.println("lock");
		var instance = variables.ESAPI.authenticator();
		var oldPassword = instance.generateStrongPassword();
		var user = createTestUser(oldPassword);
		user.lock();
		assertTrue(user.isLocked());
		user.unlock();
		assertFalse(user.isLocked());
	}

	/**
	 * Test of loginWithPassword method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testLoginWithPassword() {
		variables.System.out.println("loginWithPassword");
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		var httpSession = httpRequest.getSession();
		assertFalse(httpSession.getInvalidated());
		var user = createTestUser("loginWithPassword");
		user.enable();
		user.loginWithPassword("loginWithPassword", httpRequest, httpResponse);
		assertTrue(user.isLoggedIn());
		user.logout(httpRequest, httpResponse);
		assertFalse(user.isLoggedIn());
		assertFalse(user.isLocked());
		try {
			user.loginWithPassword("ridiculous");
		} catch (org.owasp.esapi.errors.AuthenticationLoginException e) {
			// expected
		}
		assertFalse(user.isLoggedIn());
		try {
			user.loginWithPassword("ridiculous");
		} catch (org.owasp.esapi.errors.AuthenticationLoginException e) {
			// expected
		}
		try {
			user.loginWithPassword("ridiculous");
		} catch (org.owasp.esapi.errors.AuthenticationLoginException e) {
			// expected
		}
		assertTrue(user.isLocked());
		user.unlock();
		assertTrue(user.getFailedLoginCount() == 0);
	}


	/**
	 * Test of logout method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testLogout() {
		variables.System.out.println("logout");
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		var httpSession = httpRequest.getSession();
		assertFalse(httpSession.getInvalidated());
		var instance = variables.ESAPI.authenticator();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
		var oldPassword = instance.generateStrongPassword();
		var user = createTestUser(oldPassword);
		user.enable();
		variables.System.out.println(user.getLastLoginTime());
		user.loginWithPassword(oldPassword);
		assertTrue(user.isLoggedIn());
		// get new session after user logs in
		httpSession = httpRequest.getSession();
		assertFalse(httpSession.getInvalidated());
		user.logout(httpRequest, httpResponse);
		assertFalse(user.isLoggedIn());
		assertTrue(httpSession.getInvalidated());
	}

	/**
	 * Test of testRemoveRole method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testRemoveRole() {
		variables.System.out.println("removeRole");
		var role = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_LOWERS);
		var user = createTestUser("removeRole");
		user.addRole(role);
		assertTrue(user.isInRole(role));
		user.removeRole(role);
		assertFalse(user.isInRole(role));
	}

	/**
	 * Test of testResetCSRFToken method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testResetCSRFToken() {
		variables.System.out.println("resetCSRFToken");
		var user = createTestUser("resetCSRFToken");
        var token1 = user.resetCSRFToken();
        var token2 = user.resetCSRFToken();
        assertFalse( token1.equals( token2 ) );
	}

	/**
	 * Test of setAccountName method, of class org.owasp.esapi.User.
     *
     * @throws AuthenticationException
     */
	public void function testSetAccountName() {
		variables.System.out.println("setAccountName");
		var user = createTestUser("setAccountName");
		var accountName = variables.ESAPI.randomizer().getRandomString(7, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		user.setAccountName(accountName);
		assertEquals(accountName.toLowerCase(), user.getAccountName());
		assertFalse("ridiculous" == user.getAccountName());
	}

	/**
	 * Test of setExpirationTime method, of class org.owasp.esapi.User.
     *
     * @throws Exception
     */
	public void function testSetExpirationTime() {
		var longAgo = createObject("java", "java.util.Date").init(javaCast("long", 0));
		var rightNow = now();
		assertTrue(longAgo.before(rightNow), "new Date(0) returned " & longAgo & " which is considered before new Date() " & rightNow & ". Please report this output to the email list or as a issue");
		var password=variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var user = createTestUser(password);
		user.setExpirationTime(longAgo);
		assertTrue( user.isExpired() );
	}


	/**
	 * Test of setRoles method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testSetRoles() {
		variables.System.out.println("setRoles");
		var user = createTestUser("setRoles");
		user.addRole("user");
		assertTrue(user.isInRole("user"));
		var set = [];
		set.add("rolea");
		set.add("roleb");
		user.setRoles(set);
		assertFalse(user.isInRole("user"));
		assertTrue(user.isInRole("rolea"));
		assertTrue(user.isInRole("roleb"));
		assertFalse(user.isInRole("ridiculous"));
	}

	/**
	 * Test of setScreenName method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testSetScreenName() {
		variables.System.out.println("setScreenName");
		var user = createTestUser("setScreenName");
		var screenName = variables.ESAPI.randomizer().getRandomString(7, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		user.setScreenName(screenName);
		assertEquals(screenName, user.getScreenName());
		assertFalse("ridiculous" == user.getScreenName());
	}

	/**
	 * Test of unlockAccount method, of class org.owasp.esapi.User.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testUnlock() {
		variables.System.out.println("unlockAccount");
		var instance = variables.ESAPI.authenticator();
		var oldPassword = instance.generateStrongPassword();
		var user = createTestUser(oldPassword);
		user.lock();
		assertTrue(user.isLocked());
		user.unlock();
		assertFalse(user.isLocked());
	}

}