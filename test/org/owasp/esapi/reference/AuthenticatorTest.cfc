<cfcomponent extends="cfesapi.test.org.owasp.esapi.TestCase" output="false">

	<cfscript>
		System = createObject("java", "java.lang.System");
		DefaultEncoder = createObject("java", "org.owasp.esapi.Encoder");

		instance.ESAPI = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			structClear(session);
			structClear(request);

			instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="tearDown" output="false">
		<cfscript>
			instance.ESAPI = "";

			structClear(session);
			structClear(request);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreateUser" output="false" hint="Test of createAccount method, of class org.owasp.esapi.Authenticator.">
		<cfscript>
			System.out.println("createUser");
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.instance = instance.ESAPI.authenticator();
			local.password = local.instance.generateStrongPassword();
			local.user = local.instance.createUser(local.accountName, local.password, local.password);
			assertTrue(local.user.verifyPassword(local.password));
	        try {
	            local.instance.createUser(local.accountName, local.password, local.password); // duplicate user
	            fail();
	        } catch (cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException e) {
	            // success
	        }
	        try {
	            local.instance.createUser(instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS), "password1", "password2"); // don't match
	            fail();
	        } catch (cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException e) {
	            // success
	        }
	        try {
	            local.instance.createUser(instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS), "weak1", "weak1");  // weak password
	            fail();
	        } catch (cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
	            // success
	        }
	        try {
	            local.instance.createUser("", "weak1", "weak1");  // null username
	            fail();
	        } catch (cfesapi.org.owasp.esapi.errors.AuthenticationAccountsException e) {
	            // success
	        }
	        try {
	            local.instance.createUser(instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS), "", "");  // null password
	            fail();
	        } catch (cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
	            // success
	        }
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGenerateStrongPassword" output="false" hint="Test of generateStrongPassword method, of class org.owasp.esapi.Authenticator.">
		<cfscript>
			System.out.println("generateStrongPassword");
			local.instance = instance.ESAPI.authenticator();
			local.oldPassword = "iiiiiiiiii";  // i is not allowed in passwords - this prevents failures from containing pieces of old password
			local.newPassword = "";
			for (local.i = 0; local.i < 100; local.i++) {
	            try {
	                newPassword = local.instance.generateStrongPassword();
	                local.instance.verifyPasswordStrength(local.oldPassword, local.newPassword);
	            } catch( cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e ) {
	            	System.out.println( "  FAILED >> " & local.newPassword & " : " & e.getLogMessage());
	                fail();
	            }
			}
			try {
				local.instance.verifyPasswordStrength("test56^$test", "abcdx56^$sl" );
			} catch( cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e ) {
				// expected
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetCurrentUser" output="false" hint="Test of getCurrentUser method, of class org.owasp.esapi.Authenticator.">
		<cfscript>
			System.out.println("getCurrentUser");
	        local.instance = instance.ESAPI.authenticator();
			local.username1 = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.username2 = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.user1 = local.instance.createUser(local.username1, "getCurrentUser", "getCurrentUser");
			local.user2 = local.instance.createUser(local.username2, "getCurrentUser", "getCurrentUser");
			local.user1.enable();
		    local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.response = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse").init();
	        instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			local.user1.loginWithPassword(password="getCurrentUser");
			local.currentUser = local.instance.getCurrentUser();
			assertEquals( local.currentUser, local.user1 );
			local.instance.setCurrentUser( user=local.user2 );
			assertFalse( local.currentUser.getAccountName() == local.user2.getAccountName() );

			/*Runnable echo = new Runnable() {
				private int count = 1;
	            private boolean result = false;
				public void run() {
			        Authenticator auth = ESAPI.authenticator();
					User a = null;
					try {
						String password = auth.generateStrongPassword();
						String accountName = "TestAccount" + count++;
						a = auth.getUserByAccountName(accountName);
						if ( a != null ) {
							auth.removeUser(accountName);
						}
						a = auth.createUser(accountName, password, password);
						auth.setCurrentUser(a);
					} catch (AuthenticationException e) {
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
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetUser" output="false" hint="Test of getUser method, of class org.owasp.esapi.Authenticator.">
		<cfscript>
			System.out.println("getUser");
	        local.instance = instance.ESAPI.authenticator();
			local.password = local.instance.generateStrongPassword();
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.instance.createUser(local.accountName, local.password, local.password);
			assertTrue(isObject(local.instance.getUserByAccountName( local.accountName )));
			assertFalse(isObject(local.instance.getUserByAccountName( instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS) )));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetUserFromRememberToken" output="false">
		<cfscript>
			System.out.println("getUserFromRememberToken");
	        local.instance = instance.ESAPI.authenticator();
	        local.instance.logout();  // in case anyone is logged in
			local.password = local.instance.generateStrongPassword();
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.user = local.instance.createUser(local.accountName, local.password, local.password);
			local.user.enable();
		    local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.response = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse").init();
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);

			System.out.println("getUserFromRememberToken - expecting failure");
			local.request.setCookie( instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME, "ridiculous" );
			//try {
				local.instance.getUserFromRememberToken( local.request, local.response );  // wrong cookie will fail
			//} catch( AuthenticationException e ) {
				// expected
			//}

			System.out.println("getUserFromRememberToken - expecting success");
		    local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			instance.ESAPI.authenticator().setCurrentUser(local.user);
			local.newToken = instance.ESAPI.httpUtilities().setRememberToken(local.request, local.response, local.password, 10000, "test.com", local.request.getContextPath() );
			local.request.setCookie( instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME, local.newToken );
	        local.user.logout();  // logout the current user so we can log them in with the remember cookie
			local.test2 = local.instance.getUserFromRememberToken( local.request, local.response );
			assertSame( local.user, local.test2 );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetUserFromSession" output="false" hint="Test get user from session.">
		<cfscript>
			System.out.println("getUserFromSession");
	        local.instance = instance.ESAPI.authenticator();
	        local.instance.logout();  // in case anyone is logged in
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.instance.generateStrongPassword();
			local.user = local.instance.createUser(local.accountName, local.password, local.password);
			local.user.enable();
			local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.request.addParameter("username", local.accountName);
			local.request.addParameter("password", local.password);
			local.response = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse").init();
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, local.response );
			local.instance.login( local.request, local.response);
			local.test = local.instance.getUserFromSession();
			assertEquals( local.user, local.test );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetUserNames" output="false" hint="Test get user names.">
		<cfscript>
			System.out.println("getUserNames");
	        local.instance = instance.ESAPI.authenticator();
			local.password = local.instance.generateStrongPassword();
			local.testnames = ["", "", "", "", "", "", "", "", "", ""];
			for(local.i=1;local.i<=arrayLen(local.testnames);local.i++) {
				local.testnames[local.i] = instance.ESAPI.randomizer().getRandomString(8,DefaultEncoder.CHAR_ALPHANUMERICS);
			}
			for(local.i=1;local.i<=arrayLen(local.testnames);local.i++) {
				local.instance.createUser(local.testnames[local.i], local.password, local.password);
			}
			local.names = local.instance.getUserNames();
			for(local.i=1;local.i<=arrayLen(local.testnames);local.i++) {
				assertTrue(local.names.contains(local.testnames[local.i].toLowerCase()));
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testHashPassword" output="false" hint="Test of hashPassword method, of class org.owasp.esapi.Authenticator.">
		<cfscript>
			System.out.println("hashPassword");
			local.username = "Jeff";
			local.password = "test";
	        local.instance = instance.ESAPI.authenticator();
			local.result1 = local.instance.hashPassword(local.password, local.username);
			local.result2 = local.instance.hashPassword(local.password, local.username);
			assertTrue(local.result1.equals(local.result2));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testLogin" output="false" hint="Test of login method, of class org.owasp.esapi.Authenticator.">
		<cfscript>
			System.out.println("login");
	        local.instance = instance.ESAPI.authenticator();
	        local.username = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.instance.generateStrongPassword();
			local.user = local.instance.createUser(local.username, local.password, local.password);
			local.user.enable();
			local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.request.addParameter("username", local.username);
			local.request.addParameter("password", local.password);
			local.response = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse").init();
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, local.response );
			local.test = local.instance.login( local.request, local.response);
			assertTrue( local.test.isLoggedIn() );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testRemoveUser" output="false" hint="Test of removeAccount method, of class org.owasp.esapi.Authenticator.">
		<cfscript>
			System.out.println("removeUser");
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
	        local.instance = instance.ESAPI.authenticator();
			local.password = local.instance.generateStrongPassword();
			local.instance.createUser(local.accountName, local.password, local.password);
			assertTrue( local.instance.exists(local.accountName));
			local.instance.removeUser(local.accountName);
			assertFalse( local.instance.exists(local.accountName));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testSaveUsers" output="false" hint="Test of saveUsers method, of class org.owasp.esapi.Authenticator.">
		<cfscript>
			System.out.println("saveUsers");
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
	        local.instance = instance.ESAPI.authenticator();
			local.password = local.instance.generateStrongPassword();
			local.instance.createUser(local.accountName, local.password, local.password);
			local.instance.saveUsers();
			assertTrue( isObject(local.instance.getUserByAccountName(local.accountName)) );
			local.instance.removeUser(local.accountName);
			assertFalse( isObject(local.instance.getUserByAccountName(local.accountName)) );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testSetCurrentUser" output="false" hint="Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.">
		<cfscript>
			System.out.println("setCurrentUser");
	        local.instance = instance.ESAPI.authenticator();
			local.user1 = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_UPPERS);
			local.user2 = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_UPPERS);
			local.userOne = local.instance.createUser(local.user1, "getCurrentUser", "getCurrentUser");
			local.userOne.enable();
		    local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.response = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse").init();
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			local.userOne.loginWithPassword(password="getCurrentUser");
			local.currentUser = local.instance.getCurrentUser();
			assertEquals( local.currentUser, local.userOne );
			local.userTwo = local.instance.createUser(local.user2, "getCurrentUser", "getCurrentUser");
			local.instance.setCurrentUser( user=local.userTwo );
			assertFalse( local.currentUser.getAccountName() == local.userTwo.getAccountName() );

			/*Runnable echo = new Runnable() {
				private int count = 1;
				public void run() {
					User u=null;
					try {
						String password = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
						u = instance.createUser("test" + count++, password, password);
						instance.setCurrentUser(u);
						instance.ESAPI.getLogger("test").info( Logger.SECURITY_SUCCESS, "Got current user" );
						// instance.ESAPI.authenticator().removeUser( u.getAccountName() );
					} catch (AuthenticationException e) {
						e.printStackTrace();
					}
				}
			};
			for ( int i = 0; i<10; i++ ) {
				new Thread( echo ).start();
			}*/
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testSetCurrentUserWithRequest" output="false" hint="Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.">
		<cfscript>
			System.out.println("setCurrentUser(req,resp)");
	        local.instance = instance.ESAPI.authenticator();
	        local.instance.logout();  // in case anyone is logged in
			local.password = local.instance.generateStrongPassword();
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.user = local.instance.createUser(local.accountName, local.password, local.password);
			local.user.enable();
		    local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			local.request.addParameter("username", local.accountName);
			local.request.addParameter("password", local.password);
			local.response = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse").init();
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			local.instance.login( local.request, local.response );
			assertEquals( local.user, local.instance.getCurrentUser() );
			try {
				local.user.disable();
				local.instance.login( local.request, local.response );
			} catch( cfesapi.org.owasp.esapi.errors.AuthenticationLoginException e ) {
				// expected
			}
			try {
				local.user.enable();
				local.user.lock();
				local.instance.login( local.request, local.response );
			} catch( cfesapi.org.owasp.esapi.errors.AuthenticationLoginException e ) {
				// expected
			}
			try {
				local.user.unlock();
				local.user.setExpirationTime( createObject("java", "java.util.Date").init() );
				local.instance.login( local.request, local.response );
			} catch( cfesapi.org.owasp.esapi.errors.AuthenticationLoginException e ) {
				// expected
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testValidatePasswordStrength" output="false" hint="Test of validatePasswordStrength method, of class org.owasp.esapi.Authenticator.">
		<cfscript>
			System.out.println("validatePasswordStrength");
	        local.instance = instance.ESAPI.authenticator();

			// should fail
			try {
				local.instance.verifyPasswordStrength("password", "jeff");
				fail();
			} catch (cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.instance.verifyPasswordStrength("diff123bang", "same123string");
				fail();
			} catch (cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.instance.verifyPasswordStrength("password", "JEFF");
				fail();
			} catch (cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.instance.verifyPasswordStrength("password", "1234");
				fail();
			} catch (cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.instance.verifyPasswordStrength("password", "password");
				fail();
			} catch (cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.instance.verifyPasswordStrength("password", "-1");
				fail();
			} catch (cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.instance.verifyPasswordStrength("password", "password123");
				fail();
			} catch (cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.instance.verifyPasswordStrength("password", "test123");
				fail();
			} catch (cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}

			// should pass
			local.instance.verifyPasswordStrength("password", "jeffJEFF12!");
			local.instance.verifyPasswordStrength("password", "super calif ragil istic");
			local.instance.verifyPasswordStrength("password", "TONYTONYTONYTONY");
			local.instance.verifyPasswordStrength("password", local.instance.generateStrongPassword());

	        // chrisisbeef - Issue 65 - http://code.google.com/p/owasp-esapi-java/issues/detail?id=65
	        local.instance.verifyPasswordStrength("password", "b!gbr0ther");
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testExists" output="false" hint="Test of exists method, of class org.owasp.esapi.Authenticator.">
		<cfscript>
			System.out.println("exists");
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
	        local.instance = instance.ESAPI.authenticator();
			local.password = local.instance.generateStrongPassword();
			local.instance.createUser(local.accountName, local.password, local.password);
			assertTrue(local.instance.exists(local.accountName));
			local.instance.removeUser(local.accountName);
			assertFalse(local.instance.exists(local.accountName));
		</cfscript>
	</cffunction>


</cfcomponent>
