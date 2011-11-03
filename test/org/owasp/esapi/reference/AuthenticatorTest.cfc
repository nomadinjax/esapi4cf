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
/**
 * The Class AuthenticatorTest.
 */
component AuthenticatorTest extends="cfesapi.test.org.owasp.esapi.lang.TestCase" {

	instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();

	/**
	 * {@inheritDoc}
	 *
	 * @throws Exception
	 */
	
	public void function setUp() {
		structClear(session);
		structClear(request);
		cleanUpUsers();
	}
	
	/**
	 * {@inheritDoc}
	 *
	 * @throws Exception
	 */
	
	public void function tearDown() {
		structClear(session);
		structClear(request);
	}
	
	/**
	 * Test of createAccount method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 * @throws EncryptionException
	 */
	
	public void function testCreateUser() {
		newJava("java.lang.System").out.println("createUser");
		local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		local.authenticator = instance.ESAPI.authenticator();
		local.password = local.authenticator.generateStrongPassword();
		local.user = local.authenticator.createUser(local.accountName, local.password, local.password);
		assertTrue(local.user.verifyPassword(local.password));
		try {
			local.authenticator.createUser(local.accountName, local.password, local.password);// duplicate user
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException e) {
			// success
		}
		try {
			local.authenticator.createUser(instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS), "password1", "password2");// don't match
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			local.authenticator.createUser(instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS), "weak1", "weak1");// weak password
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			local.authenticator.createUser("", "weak1", "weak1");// null username
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException e) {
			// success
		}
		try {
			local.authenticator.createUser(instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS), "", "");// null password
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			local.uName = "ea234kEknr";//sufficiently random password that also works as a username
			local.authenticator.createUser(local.uName, local.uName, local.uName);// using username as password
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
	}
	
	/**
	 * Test of generateStrongPassword method, of class
	 * org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	
	public void function testGenerateStrongPassword() {
		newJava("java.lang.System").out.println("generateStrongPassword");
		local.authenticator = instance.ESAPI.authenticator();
		local.oldPassword = "iiiiiiiiii";// i is not allowed in passwords - this prevents failures from containing pieces of old password
		local.newPassword = "";
		local.username = "FictionalEsapiUser";
		local.user = new cfesapi.org.owasp.esapi.reference.DefaultUser(instance.ESAPI, local.username);
		for(local.i = 0; local.i < 100; local.i++) {
			try {
				local.newPassword = local.authenticator.generateStrongPassword();
				local.authenticator.verifyPasswordStrength(local.oldPassword, local.newPassword, local.user);
			}
			catch(cfesapi.org.owasp.esapi.errors.AuthenticationException e) {
				newJava("java.lang.System").out.println("  FAILED >> " & local.newPassword & " : " & e.getLogMessage());
				fail();
			}
		}
		try {
			local.authenticator.verifyPasswordStrength("test56^$test", "abcdx56^$sl", local.user);
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// expected
		}
	}
	
	/**
	 * Test of getCurrentUser method, of class org.owasp.esapi.Authenticator.
	 * 
	 *
	 * @throws Exception
	 */
	
	public void function testGetCurrentUser() {
		newJava("java.lang.System").out.println("getCurrentUser");
		local.authenticator = instance.ESAPI.authenticator();
		local.username1 = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		local.username2 = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		local.user1 = local.authenticator.createUser(local.username1, "getCurrentUser", "getCurrentUser");
		local.user2 = local.authenticator.createUser(local.username2, "getCurrentUser", "getCurrentUser");
		local.user1.enable();
		local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.response = new cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse();
		instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
		local.user1.loginWithPassword(password="getCurrentUser");
		local.currentUser = local.authenticator.getCurrentUser();
		assertEquals(local.currentUser, local.user1);
		local.authenticator.setCurrentUser(user=local.user2);
		assertFalse(local.currentUser.getAccountName() == local.user2.getAccountName());
	
		/* TODO: make this work too!
		Runnable echo = new Runnable() {
		    private int count = 1;
		    private boolean result = false;
		    public void run() {
		        Authenticator auth = instance.ESAPI.authenticator();
		        User a = null;
		        try {
		            String password = auth.generateStrongPassword();
		            local.accountName = "TestAccount" & count++;
		            a = auth.getUser(local.accountName);
		            if ( a != null ) {
		                auth.removeUser(local.accountName);
		            }
		            a = auth.createUser(local.accountName, password, password);
		            auth.setCurrentUser(a);
		        } catch (cfesapi.org.owasp.esapi.errors.AuthenticationException e) {
		            e.printStackTrace();
		        }
		        User b = auth.getCurrentUser();
		        result &= a.equals(b);
		    }
		};
		ThreadGroup tg = new ThreadGroup("test");
		for ( int i = 0; i<10; i++ ) {
		    new Thread( tg, echo ).start();
		}
		while (tg.activeCount() > 0 ) {
		    Thread.sleep(100);
		}*/
	}
	
	/**
	 * Test of getUser method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	
	public void function testGetUser() {
		newJava("java.lang.System").out.println("getUser");
		local.authenticator = instance.ESAPI.authenticator();
		local.password = local.authenticator.generateStrongPassword();
		local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		local.authenticator.createUser(local.accountName, local.password, local.password);
		assertTrue(isObject(local.authenticator.getUserByAccountName(local.accountName)));
		assertFalse(isObject(local.authenticator.getUserByAccountName(instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS))));
	}
	
	/**
	 *
	 * @throws org.owasp.esapi.errors.AuthenticationException
	 */
	
	public void function testGetUserFromRememberToken() {
		newJava("java.lang.System").out.println("getUserFromRememberToken");
		local.authenticator = instance.ESAPI.authenticator();
		local.authenticator.logout();// in case anyone is logged in
		local.password = local.authenticator.generateStrongPassword();
		local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		local.user = local.authenticator.createUser(local.accountName, local.password, local.password);
		local.user.enable();
		local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.response = new cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse();
		instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
	
		newJava("java.lang.System").out.println("getUserFromRememberToken - expecting failure");
		local.request.setCookie(instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME, "ridiculous");
		try {
			local.authenticator.login(local.request, local.response);// wrong cookie will fail
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// expected
		}
		
		newJava("java.lang.System").out.println("getUserFromRememberToken - expecting success");
		local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
		instance.ESAPI.authenticator().setCurrentUser(local.user);
		local.newToken = instance.ESAPI.httpUtilities().setRememberToken(local.request, local.response, local.password, 10000, "test.com", local.request.getContextPath());
		local.request.setCookie(instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME, local.newToken);
		local.user.logout();// logout the current user so we can log them in with the remember cookie
		local.test2 = local.authenticator.login(local.request, local.response);
		assertSame(local.user, local.test2);
	}
	
	/**
	 * Test get user from session.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	
	public void function testGetUserFromSession() {
		newJava("java.lang.System").out.println("getUserFromSession");
		local.authenticator = instance.ESAPI.authenticator();
		local.authenticator.logout();// in case anyone is logged in
		local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		local.password = local.authenticator.generateStrongPassword();
		local.user = local.authenticator.createUser(local.accountName, local.password, local.password);
		local.user.enable();
		local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.request.addParameter("username", local.accountName);
		local.request.addParameter("password", local.password);
		local.response = new cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse();
		instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
		local.authenticator.login(local.request, local.response);
		local.test = local.authenticator.getUserFromSession();
		assertEquals(local.user, local.test);
	}
	
	/**
	 * Test get user names.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	
	public void function testGetUserNames() {
		newJava("java.lang.System").out.println("getUserNames");
		local.authenticator = instance.ESAPI.authenticator();
		local.password = local.authenticator.generateStrongPassword();
		local.testnames = ["", "", "", "", "", "", "", "", "", ""];
		for(local.i = 1; local.i <= arrayLen(local.testnames); local.i++) {
			local.testnames[local.i] = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		}
		for(local.i = 1; local.i <= arrayLen(local.testnames); local.i++) {
			local.authenticator.createUser(local.testnames[local.i], local.password, local.password);
		}
		local.names = local.authenticator.getUserNames();
		for(local.i = 1; local.i <= arrayLen(local.testnames); local.i++) {
			assertTrue(local.names.contains(local.testnames[local.i].toLowerCase()));
		}
	}
	
	/**
	 * Test of hashPassword method, of class org.owasp.esapi.Authenticator.
	 *
	 * @throws EncryptionException
	 */
	
	public void function testHashPassword() {
		newJava("java.lang.System").out.println("hashPassword");
		local.username = "Jeff";
		local.password = "test";
		local.authenticator = instance.ESAPI.authenticator();
		local.result1 = local.authenticator.hashPassword(local.password, local.username);
		local.result2 = local.authenticator.hashPassword(local.password, local.username);
		assertTrue(local.result1.equals(local.result2));
	}
	
	/**
	 * Test of login method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	
	public void function testLogin() {
		newJava("java.lang.System").out.println("login");
		local.authenticator = instance.ESAPI.authenticator();
		local.username = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		local.password = local.authenticator.generateStrongPassword();
		local.user = local.authenticator.createUser(local.username, local.password, local.password);
		local.user.enable();
		local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.request.addParameter("username", local.username);
		local.request.addParameter("password", local.password);
		local.response = new cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse();
		local.test = local.authenticator.login(local.request, local.response);
		assertTrue(local.test.isLoggedIn());
	}
	
	/**
	 * Test of removeAccount method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws Exception
	 *             the exception
	 */
	
	public void function testRemoveUser() {
		newJava("java.lang.System").out.println("removeUser");
		local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		local.authenticator = instance.ESAPI.authenticator();
		local.password = local.authenticator.generateStrongPassword();
		local.authenticator.createUser(local.accountName, local.password, local.password);
		assertTrue(local.authenticator.exists(local.accountName));
		local.authenticator.removeUser(local.accountName);
		assertFalse(local.authenticator.exists(local.accountName));
	}
	
	/**
	 * Test of saveUsers method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws Exception
	 *             the exception
	 */
	
	public void function testSaveUsers() {
		newJava("java.lang.System").out.println("saveUsers");
		local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		local.authenticator = instance.ESAPI.authenticator();
		local.password = local.authenticator.generateStrongPassword();
		local.authenticator.createUser(local.accountName, local.password, local.password);
		local.authenticator.saveUsers();
		assertTrue(isObject(local.authenticator.getUserByAccountName(local.accountName)));
		local.authenticator.removeUser(local.accountName);
		assertFalse(isObject(local.authenticator.getUserByAccountName(local.accountName)));
	}
	
	/**
	 * Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	
	public void function testSetCurrentUser() {
		newJava("java.lang.System").out.println("setCurrentUser");
		local.authenticator = instance.ESAPI.authenticator();
		local.user1 = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_UPPERS);
		local.user2 = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_UPPERS);
		local.userOne = local.authenticator.createUser(local.user1, "getCurrentUser", "getCurrentUser");
		local.userOne.enable();
		local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.response = new cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse();
		instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
		local.userOne.loginWithPassword(password="getCurrentUser");
		local.currentUser = local.authenticator.getCurrentUser();
		assertEquals(local.currentUser, local.userOne);
		local.userTwo = local.authenticator.createUser(local.user2, "getCurrentUser", "getCurrentUser");
		local.authenticator.setCurrentUser(local.userTwo);
		assertFalse(local.currentUser.getAccountName() == local.userTwo.getAccountName());
	
		/* TODO: make this work too!
		Runnable echo = new Runnable() {
		    private int count = 1;
		    public void run() {
		        User u=null;
		        try {
		            local.password = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		            u = local.authenticator.createUser("test" & count++, local.password, local.password);
		            local.authenticator.setCurrentUser(u);
		            instance.ESAPI.getLogger("test").info( Logger.SECURITY_SUCCESS, "Got current user" );
		            // instance.ESAPI.authenticator().removeUser( u.getAccountName() );
		        } catch (cfesapi.org.owasp.esapi.errors.AuthenticationException e) {
		            e.printStackTrace();
		        }
		    }
		};
		for ( int i = 0; i<10; i++ ) {
		    new Thread( echo ).start();
		}*/
	}
	
	/**
	 * Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	
	public void function testSetCurrentUserWithRequest() {
		newJava("java.lang.System").out.println("setCurrentUser(req,resp)");
		local.authenticator = instance.ESAPI.authenticator();
		local.authenticator.logout();// in case anyone is logged in
		local.password = local.authenticator.generateStrongPassword();
		local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		local.user = local.authenticator.createUser(local.accountName, local.password, local.password);
		local.user.enable();
		local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
		local.request.addParameter("username", local.accountName);
		local.request.addParameter("password", local.password);
		local.response = new cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse();
		local.authenticator.login(local.request, local.response);
		assertEquals(local.user, local.authenticator.getCurrentUser());
		try {
			local.user.disable();
			local.authenticator.login(local.request, local.response);
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationLoginException e) {
			// expected
		}
		try {
			local.user.enable();
			local.user.lock();
			local.authenticator.login(local.request, local.response);
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationLoginException e) {
			// expected
		}
		try {
			local.user.unlock();
			local.user.setExpirationTime(newJava("java.util.Date").init());
			local.authenticator.login(local.request, local.response);
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationLoginException e) {
			// expected
		}
	}
	
	/**
	 * Test of validatePasswordStrength method, of class
	 * org.owasp.esapi.Authenticator.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	
	public void function testValidatePasswordStrength() {
		newJava("java.lang.System").out.println("validatePasswordStrength");
		local.authenticator = instance.ESAPI.authenticator();
	
		local.username = "FictionalEsapiUser";
		local.user = new cfesapi.org.owasp.esapi.reference.DefaultUser(instance.ESAPI, local.username);
	
		// should fail
		try {
			local.authenticator.verifyPasswordStrength("password", "jeff", local.user);
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			local.authenticator.verifyPasswordStrength("diff123bang", "same123string", local.user);
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			local.authenticator.verifyPasswordStrength("password", "JEFF", local.user);
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			local.authenticator.verifyPasswordStrength("password", "1234", local.user);
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			local.authenticator.verifyPasswordStrength("password", "password", local.user);
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			local.authenticator.verifyPasswordStrength("password", "-1", local.user);
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			local.authenticator.verifyPasswordStrength("password", "password123", local.user);
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			local.authenticator.verifyPasswordStrength("password", "test123", local.user);
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		//jtm - 11/16/2010 - fix for bug http://code.google.com/p/owasp-esapi-java/issues/detail?id=108
		try {
			local.authenticator.verifyPasswordStrength("password", "FictionalEsapiUser", local.user);
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			local.authenticator.verifyPasswordStrength("password", "FICTIONALESAPIUSER", local.user);
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		
		// should pass
		local.authenticator.verifyPasswordStrength("password", "jeffJEFF12!", local.user);
		local.authenticator.verifyPasswordStrength("password", "super calif ragil istic", local.user);
		local.authenticator.verifyPasswordStrength("password", "TONYTONYTONYTONY", local.user);
		local.authenticator.verifyPasswordStrength("password", local.authenticator.generateStrongPassword(), local.user);
	
		// chrisisbeef - Issue 65 - http://code.google.com/p/owasp-esapi-java/issues/detail?id=65
		local.authenticator.verifyPasswordStrength("password", "b!gbr0ther", local.user);
	}
	
	/**
	 * Test of exists method, of class org.owasp.esapi.Authenticator.
	 * 
	 * @throws Exception
	 *             the exception
	 */
	
	public void function testExists() {
		newJava("java.lang.System").out.println("exists");
		local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
		local.authenticator = instance.ESAPI.authenticator();
		local.password = local.authenticator.generateStrongPassword();
		local.authenticator.createUser(local.accountName, local.password, local.password);
		assertTrue(local.authenticator.exists(local.accountName));
		local.authenticator.removeUser(local.accountName);
		assertFalse(local.authenticator.exists(local.accountName));
	}
	
	/**
	 * Test of main method, of class org.owasp.esapi.Authenticator.
	 * @throws Exception
	 */
	/* NOTE: do we need this test?
	public void function testMain() {
	    newJava("java.lang.System").out.println("Authenticator Main");
	    local.authenticator = instance.ESAPI.authenticator();
	    local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
	    local.password = local.authenticator.generateStrongPassword();
	    local.role = "test";
	    
	    // test wrong parameters - missing role parameter
	    local.badargs = [ local.accountName, local.password ];
	    FileBasedAuthenticator.main( local.badargs );
	    // load users since the new user was added in another instance
	    local.authenticator.loadUsersImmediately();
	    local.u1 = local.authenticator.getUser(local.accountName);
	    assertNull( local.u1 );
	
	    // test good parameters
	    local.args = [ local.accountName, local.password, local.role ];
	    FileBasedAuthenticator.main(local.args);
	    // load users since the new user was added in another instance
	    local.authenticator.loadUsersImmediately();
	    local.u2 = local.authenticator.getUser(local.accountName);
	    assertNotNull( local.u2 );
	    assertTrue( local.u2.isInRole(local.role));
	    assertEquals( local.authenticator.hashPassword(local.password, local.accountName), local.authenticator.getHashedPassword(local.u2) );
	} */
}