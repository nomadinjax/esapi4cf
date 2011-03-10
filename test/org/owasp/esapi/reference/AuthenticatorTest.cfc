<cfcomponent extends="cfesapi.test.org.owasp.esapi.TestCase" output="false">

	<cfscript>
		instance.ESAPI = "";

		System = createObject("java", "java.lang.System");
		DefaultEncoder = javaLoader().create("org.owasp.esapi.Encoder");
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
			local.user1.loginWithPassword("getCurrentUser");
			local.currentUser = local.instance.getCurrentUser();
			assertEquals( local.currentUser, local.user1 );
			local.instance.setCurrentUser( local.user2 );
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
						a = auth.getUser(accountName);
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
			assertTrue(isObject(local.instance.getUser( local.accountName )));
			assertFalse(isObject(local.instance.getUser( instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS) )));
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
			try {
				local.instance.login( local.request, local.response );  // wrong cookie will fail
			} catch( cfesapi.org.owasp.esapi.errors.AuthenticationException e ) {
				// expected
			}

			System.out.println("getUserFromRememberToken - expecting success");
		    local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest").init();
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			instance.ESAPI.authenticator().setCurrentUser(local.user);
			local.newToken = instance.ESAPI.httpUtilities().setRememberToken(local.request, local.response, local.password, 10000, "test.com", local.request.getContextPath() );
			local.request.setCookie( instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME, local.newToken );
	        local.user.logout();  // logout the current user so we can log them in with the remember cookie
			local.test2 = local.instance.login( local.request, local.response );
			assertSame( local.user, local.test2 );
		</cfscript>
	</cffunction>


</cfcomponent>
