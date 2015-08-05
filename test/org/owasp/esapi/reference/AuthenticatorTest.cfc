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
import "org.owasp.esapi.beans.SafeRequest";
import "org.owasp.esapi.beans.SafeResponse";

/**
 * The Class AuthenticatorTest.
 */
component extends="esapi4cf.test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	public void function beforeTests() {
		super.beforeTests();
		clearUserFile();
	}

	variables.testForNull = false;
	if (server.coldfusion.productName == "Railo" || server.coldfusion.productName == "Lucee") {
		variables.testForNull = true;
	}

	/**
	 * Test of createAccount method, of class org.owasp.esapi.Authenticator.
	 *
	 * @throws AuthenticationException
     *             the authentication exception
     * @throws EncryptionException
	 */
	public void function testCreateUser() {
		variables.System.out.println("createUser");
		var accountName = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var instance = variables.ESAPI.authenticator();
		var password = instance.generateStrongPassword();
		var user = instance.createUser(accountName, password, password);
		assertTrue(user.verifyPassword(password));
        try {
            instance.createUser(accountName, password, password); // duplicate user
            fail("");
        } catch (org.owasp.esapi.errors.AuthenticationAccountsException e) {
            // success
        }
        try {
            instance.createUser(variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS), "password1", "password2"); // don't match
            fail();
        } catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {
            // success
        }
        try {
            instance.createUser(variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS), "weak1", "weak1");  // weak password
            fail("");
        } catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {
            // success
        }
        if (variables.testForNull) {
	        try {
	            instance.createUser(javaCast("null", ""), "weak1", "weak1");  // null username
	            fail("");
	        } catch (org.owasp.esapi.errors.AuthenticationAccountsException e) {
	            // success
	        }
	        try {
	            instance.createUser(variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS), javaCast("null", ""), javaCast("null", ""));  // null password
	            fail("");
	        } catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {
	            // success
	        }
        }
        try {
        	var uName = "ea234kEknr";	//sufficiently random password that also works as a username
            instance.createUser(uName, uName, uName);  // using username as password
            fail("");
        } catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {
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
		variables.System.out.println("generateStrongPassword");
		var instance = variables.ESAPI.authenticator();
		var oldPassword = "iiiiiiiiii";  // i is not allowed in passwords - this prevents failures from containing pieces of old password
		var newPassword = "";
		var username = "FictionalEsapiUser";
		var user = instance.getAuthenticatedUserInstance(username);
		for (var i = 0; i < 100; i++) {
            try {
                newPassword = instance.generateStrongPassword();
                instance.verifyPasswordStrength(user, newPassword, oldPassword);
            } catch( AuthenticationException e ) {
            	variables.System.out.println( "  FAILED >> " & newPassword & " : " & e.getLogMessage());
                fail();
            }
		}
		try {
			instance.verifyPasswordStrength(user, "abcdx56^$sl", "test56^$test" );
		} catch( org.owasp.esapi.errors.AuthenticationCredentialsException e ) {
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
		variables.System.out.println("getCurrentUser");
        var instance = variables.ESAPI.authenticator();
		var username1 = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var username2 = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var user1 = instance.createUser(username1, "getCurrentUser", "getCurrentUser");
		var user2 = instance.createUser(username2, "getCurrentUser", "getCurrentUser");
		user1.enable();
	    var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
        variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
		user1.loginWithPassword("getCurrentUser");
		var currentUser = instance.getCurrentUser();
		assertEquals( currentUser.getAccountName(), user1.getAccountName() );
		assertSame( currentUser, user1 );
		instance.setCurrentUser( user2 );
		assertFalse( currentUser.getAccountName() == user2.getAccountName() );

		var threadName = getMetaData().name & "-testGetCurrentUser";
        for (var i=0; i<10; i++) {
        	thread action="run" name="#threadName#_#i#" {
    			thread.returnValue = false;
    			var instance = variables.ESAPI.authenticator();
    			var a = "";
    			try {
    				var password = instance.generateStrongPassword();
    				var accountName = "TestAccount" & listLast(thread.name, "_");
    				a = instance.getUserByAccountName(accountName);
    				if(!isNull(a) && isObject(a)) {
    					instance.removeUser(accountName);
    				}
    				a = instance.createUser(accountName, password, password);
    				instance.setCurrentUser(a);
    			}
    			catch(org.owasp.esapi.errors.AuthenticationException e) {
    				e.printStackTrace();
    			}
    			catch(org.owasp.esapi.errors.AuthenticationAccountsException e) {
    				e.printStackTrace();
    			}
    			catch(org.owasp.esapi.errors.AuthenticationCredentialsException e) {
    				e.printStackTrace();
    			}
    			var b = instance.getCurrentUser();
    			thread.returnValue = a.isEquals(b);
        	}
		}

		// join threads and loop results for any failures
		thread action="join" name="#structKeyList(cfthread)#";
		for (var key in cfthread) {
			if (structKeyExists(cfthread[key], "error")) {
				assertTrue(cfthread[key].returnValue, cfthread[key].error.message);
			}
			else {
				assertTrue(cfthread[key].returnValue);
			}
		}
	}

	/**
	 * Test of getUser method, of class org.owasp.esapi.Authenticator.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testGetUserByAccountName() {
		variables.System.out.println("getUser");
        var instance = variables.ESAPI.authenticator();
		var password = instance.generateStrongPassword();
		var accountName = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		instance.createUser(accountName, password, password);
		assertFalse(isNull(instance.getUserByAccountName( accountName )));
		assertTrue(isNull(instance.getUserByAccountName( variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS) )));
	}

    /**
     *
     * @throws org.owasp.esapi.errors.AuthenticationException
     */
    public void function testGetUserFromRememberToken() {
		variables.System.out.println("getUserFromRememberToken");
        var instance = variables.ESAPI.authenticator();
        instance.logout();  // in case anyone is logged in
		var password = instance.generateStrongPassword();
		var accountName = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var user = instance.createUser(accountName, password, password);
		user.enable();
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);

		variables.System.out.println("getUserFromRememberToken - expecting failure");
		httpRequest.setCookie( variables.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME, "ridiculous" );
		try {
			instance.login( httpRequest, httpResponse );  // wrong cookie will fail
		} catch( org.owasp.esapi.errors.AuthenticationCredentialsException e ) {
			// expected
		}

		variables.System.out.println("getUserFromRememberToken - expecting success");
		httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
		variables.ESAPI.authenticator().setCurrentUser(user);
		var path = httpRequest.getContextPath();
		if (isNull(path)) {
			path = "";
		}
		var newToken = variables.ESAPI.httpUtilities().setRememberToken(password, 10000, "test.com", path, httpRequest, httpResponse);
		httpRequest.setCookie( variables.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME, newToken );
        user.logout(httpRequest, httpResponse);  // logout the current user so we can log them in with the remember cookie
		var test2 = instance.login( httpRequest, httpResponse );
		assertSame( user, test2 );
	}



	/**
	 * Test get user from session.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testGetUserFromSession() {
		variables.System.out.println("getUserFromSession");
        var instance = variables.ESAPI.authenticator();
        instance.logout();  // in case anyone is logged in
		var accountName = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var password = instance.generateStrongPassword();
		var user = instance.createUser(accountName, password, password);
		user.enable();
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		httpRequest.addParameter("username", accountName);
		httpRequest.addParameter("password", password);
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		variables.ESAPI.httpUtilities().setCurrentHTTP( httpRequest, httpResponse );
		instance.login(httpRequest, httpResponse);
		var test = instance.getUserFromSession(httpRequest);
		assertSame( user, test );
	}

	/**
	 * Test get user names.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testGetUserNames() {
		variables.System.out.println("getUserNames");
        var instance = variables.ESAPI.authenticator();
		var password = instance.generateStrongPassword();
		var testnames = [];
		for(var i=1;i<=10;i++) {
			testnames[i] = variables.ESAPI.randomizer().getRandomString(8,variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		}
		for(var i=1;i<=10;i++) {
			instance.createUser(testnames[i], password, password);
		}
		var names = instance.getUserNames();
		for(var i=1;i<=10;i++) {
			assertTrue(names.contains(testnames[i].toLowerCase()));
		}
	}

	/**
	 * Test of hashPassword method, of class org.owasp.esapi.Authenticator.
     *
     * @throws EncryptionException
     */
	public void function testHashPassword() {
		variables.System.out.println("hashPassword");
		var username = "Jeff";
		var password = "test";
        var instance = variables.ESAPI.authenticator();
		var result1 = instance.hashPassword(password, username);
		var result2 = instance.hashPassword(password, username);
		assertTrue(result1.equals(result2));
	}

	/**
	 * Test of login method, of class org.owasp.esapi.Authenticator.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testLogin() {
		variables.System.out.println("login");
        var instance = variables.ESAPI.authenticator();
        var username = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var password = instance.generateStrongPassword();
		var user = instance.createUser(username, password, password);
		user.enable();
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		httpRequest.addParameter("username", username);
		httpRequest.addParameter("password", password);
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		var test = instance.login(httpRequest, httpResponse);
		assertTrue(test.isLoggedIn());
	}

	/**
	 * Test of removeAccount method, of class org.owasp.esapi.Authenticator.
	 *
	 * @throws Exception
	 *             the exception
	 */
	public void function testRemoveUser() {
		variables.System.out.println("removeUser");
		var accountName = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
        var instance = variables.ESAPI.authenticator();
		var password = instance.generateStrongPassword();
		instance.createUser(accountName, password, password);
		assertTrue( instance.exists(accountName));
		instance.removeUser(accountName);
		assertFalse( instance.exists(accountName));
	}

	/**
	 * Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.
	 *
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
	public void function testSetCurrentUser() {
		variables.System.out.println("setCurrentUser");
        var instance = variables.ESAPI.authenticator();
		var user1 = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_UPPERS);
		var user2 = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_UPPERS);
		var userOne = instance.createUser(user1, "getCurrentUser", "getCurrentUser");
		userOne.enable();
	    var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
		userOne.loginWithPassword("getCurrentUser");
		var currentUser = instance.getCurrentUser();
		assertEquals( currentUser, userOne );
		var userTwo = instance.createUser(user2, "getCurrentUser", "getCurrentUser");
		instance.setCurrentUser( userTwo );
		assertFalse( currentUser.getAccountName() == userTwo.getAccountName() );

		/*Runnable echo = new Runnable() {
			private int count = 1;
			public void run() {
				User u=null;
				try {
					String password = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
					u = instance.createUser("test" & count++, password, password);
					instance.setCurrentUser(u);
					variables.ESAPI.getLogger("test").info( Logger.SECURITY_SUCCESS, "Got current user" );
					// variables.ESAPI.authenticator().removeUser( u.getAccountName() );
				} catch (AuthenticationException e) {
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
		variables.System.out.println("setCurrentUser(req,resp)");
        var instance = variables.ESAPI.authenticator();
        instance.logout();  // in case anyone is logged in
		var password = instance.generateStrongPassword();
		var accountName = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
		var user = instance.createUser(accountName, password, password);
		user.enable();
		var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
		httpRequest.addParameter("username", accountName);
		httpRequest.addParameter("password", password);
		var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
		instance.login( httpRequest, httpResponse );
		assertEquals( user, instance.getCurrentUser() );
		try {
			user.disable();
			instance.login( httpRequest, httpResponse );
		} catch( org.owasp.esapi.errors.AuthenticationLoginException e ) {
			// expected
		}
		try {
			user.enable();
			user.lock();
			instance.login( httpRequest, httpResponse );
		} catch( org.owasp.esapi.errors.AuthenticationLoginException e ) {
			// expected
		}
		try {
			user.unlock();
			user.setExpirationTime( now() );
			instance.login( httpRequest, httpResponse );
		} catch( org.owasp.esapi.errors.AuthenticationLoginException e ) {
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
		variables.System.out.println("validatePasswordStrength");
        var instance = variables.ESAPI.authenticator();

        var username = "FictionalEsapiUser";
		var user = instance.getAuthenticatedUserInstance(username);

		// should fail
		try {
			instance.verifyPasswordStrength(user, "jeff", "password");
			fail("");
		} catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength(user, "same123string", "diff123bang");
			fail("");
		} catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength(user, "JEFF", "password");
			fail("");
		} catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength(user, "1234", "password");
			fail("");
		} catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength(user, "password", "password");
			fail("");
		} catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength(user, "-1", "password");
			fail("");
		} catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength(user, "password123", "password");
			fail("");
		} catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength(user, "test123", "password");
			fail("");
		} catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		//jtm - 11/16/2010 - fix for bug http://code.google.com/p/owasp-esapi-java/issues/detail?id=108
		try {
			instance.verifyPasswordStrength(user, "FictionalEsapiUser", "password");
			fail("");
		} catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}
		try {
			instance.verifyPasswordStrength(user, "FICTIONALESAPIUSER", "password");
			fail("");
		} catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {
			// success
		}

		// should pass
		instance.verifyPasswordStrength(user, "jeffJEFF12!", "password");
		instance.verifyPasswordStrength(user, "super calif ragil istic", "password" );
		instance.verifyPasswordStrength(user, "TONYTONYTONYTONY", "password");
		instance.verifyPasswordStrength(user, instance.generateStrongPassword(), "password");

        // chrisisbeef - Issue 65 - http://code.google.com/p/owasp-esapi-java/issues/detail?id=65
        instance.verifyPasswordStrength(user, "b!gbr0ther", "password");
	}

	/**
	 * Test of exists method, of class org.owasp.esapi.Authenticator.
	 *
	 * @throws Exception
	 *             the exception
	 */
	public void function testExists() {
		variables.System.out.println("exists");
		var accountName = variables.ESAPI.randomizer().getRandomString(8, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
        var instance = variables.ESAPI.authenticator();
		var password = instance.generateStrongPassword();
		instance.createUser(accountName, password, password);
		assertTrue(instance.exists(accountName));
		instance.removeUser(accountName);
		assertFalse(instance.exists(accountName));
	}

}
