<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 --->
<cfcomponent extends="esapi4cf.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		instance.ESAPI = createObject( "component", "esapi4cf.org.owasp.esapi.ESAPI" ).init();
		clearUserFile();
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			structClear( session );
			structClear( request );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testCreateUser" output="false"
	            hint="Test of createAccount method, of class org.owasp.esapi.Authenticator.">

		<cfscript>
			var local = {};

			System.out.println( "createUser" );
			local.accountName = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.authenticator = instance.ESAPI.authenticator();
			local.password = local.authenticator.generateStrongPassword();
			local.user = local.authenticator.createUser( local.accountName, local.password, local.password );
			assertTrue( local.user.verifyPassword( local.password ) );
			try {
				local.authenticator.createUser( local.accountName, local.password, local.password );// duplicate user
				fail("");
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationAccountsException e) {
				// success
			}
			try {
				local.authenticator.createUser( instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS ), "password1", "password2" );// don't match
				fail("");
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.authenticator.createUser( instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS ), "weak1", "weak1" );// weak password
				fail("");
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.authenticator.createUser( "", "weak1", "weak1" );// null username
				fail("");
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationAccountsException e) {
				// success
			}
			try {
				local.authenticator.createUser( instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS ), "", "" );// null password
				fail("");
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGenerateStrongPassword" output="false"
	            hint="Test of generateStrongPassword method, of class org.owasp.esapi.Authenticator.">

		<cfscript>
			var local = {};

			System.out.println( "generateStrongPassword" );
			local.authenticator = instance.ESAPI.authenticator();
			local.oldPassword = "iiiiiiiiii";// i is not allowed in passwords - this prevents failures from containing pieces of old password
			local.newPassword = "";
			for(local.i = 0; local.i < 100; local.i++) {
				try {
					local.newPassword = local.authenticator.generateStrongPassword();
					local.authenticator.verifyPasswordStrength( local.oldPassword, local.newPassword );
				}
				catch(esapi4cf.org.owasp.esapi.errors.AuthenticationException e) {
					System.out.println( "  FAILED >> " & local.newPassword & " : " & e.getLogMessage() );
					fail("");
				}
			}
			try {
				local.authenticator.verifyPasswordStrength( "test56^$test", "abcdx56^$sl" );
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetCurrentUser" output="false"
	            hint="Test of getCurrentUser method, of class org.owasp.esapi.Authenticator.">

		<cfscript>
			var local = {};

			System.out.println( "getCurrentUser" );
			local.authenticator = instance.ESAPI.authenticator();
			local.username1 = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.username2 = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.user1 = local.authenticator.createUser( local.username1, "getCurrentUser", "getCurrentUser" );
			local.user2 = local.authenticator.createUser( local.username2, "getCurrentUser", "getCurrentUser" );
			local.user1.enable();
			local.request = createObject( "component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.response = createObject( "component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();;
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, local.response );
			local.user1.loginWithPassword( "getCurrentUser" );
			local.currentUser = local.authenticator.getCurrentUser();
			assertEquals( local.currentUser, local.user1 );
			local.authenticator.setCurrentUser( local.user2 );
			assertFalse( local.currentUser.getAccountName() == local.user2.getAccountName() );

			/* TODO: make runnable
			Runnable echo = new Runnable() {
			    private int count = 1;
			    private boolean result = false;
			    public void run() {
			        Authenticator instance = instance.ESAPI.authenticator();
			        User a = null;
			        try {
			            String password = instance.generateStrongPassword();
			            String accountName = "TestAccount" + count++;
			            a = instance.getUser(accountName);
			            if ( a != null ) {
			                instance.removeUser(accountName);
			            }
			            a = instance.createUser(accountName, password, password);
			            instance.setCurrentUser(a);
			        } catch (esapi4cf.org.owasp.esapi.errors.AuthenticationException e) {
			            e.printStackTrace();
			        }
			        User b = instance.getCurrentUser();
			        result &= a.equals(b);
			    }
			};
			ThreadGroup tg = new ThreadGroup("test");
			for ( int i = 0; i<10; i++ ) {
			    new Thread( tg, echo ).start();
			}
			while (tg.activeCount() > 0 ) {
			    Thread.sleep(100);
			} */
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetUser" output="false"
	            hint="Test of getUser method, of class org.owasp.esapi.Authenticator.">

		<cfscript>
			var local = {};

			System.out.println( "getUser" );
			local.authenticator = instance.ESAPI.authenticator();
			local.password = local.authenticator.generateStrongPassword();
			local.accountName = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.authenticator.createUser( local.accountName, local.password, local.password );
			assertTrue( isObject( local.authenticator.getUserByAccountName( local.accountName ) ) );
			assertFalse( isObject( local.authenticator.getUserByAccountName( instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS ) ) ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetUserFromRememberToken" output="false">

		<cfscript>
			var local = {};

			System.out.println( "getUserFromRememberToken" );
			local.authenticator = instance.ESAPI.authenticator();
			local.authenticator.logout();// in case anyone is logged in
			local.password = local.authenticator.generateStrongPassword();
			local.accountName = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.user = local.authenticator.createUser( local.accountName, local.password, local.password );
			local.user.enable();
			local.request = createObject( "component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.response = createObject( "component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();;
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, local.response );

			local.request.setCookie( instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME, "ridiculous" );
			try {
				local.authenticator.login( instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse() );// wrong cookie will fail
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// expected
			}

			local.request = createObject( "component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, local.response );
			instance.ESAPI.authenticator().setCurrentUser( local.user );
			local.newToken = instance.ESAPI.httpUtilities().setRememberToken( instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse(), local.password, 10000, "test.com", local.request.getContextPath() );
			local.request.setCookie( instance.ESAPI.httpUtilities().REMEMBER_TOKEN_COOKIE_NAME, local.newToken );
			local.test2 = local.authenticator.login( instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse() );
			assertEquals( local.user.getAccountName(), local.test2.getAccountName() );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetUserFromSession" output="false"
	            hint="Test get user from session.">

		<cfscript>
			var local = {};

			System.out.println( "getUserFromSession" );
			local.authenticator = instance.ESAPI.authenticator();
			local.authenticator.logout();// in case anyone is logged in
			local.accountName = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.password = local.authenticator.generateStrongPassword();
			local.user = local.authenticator.createUser( local.accountName, local.password, local.password );
			local.user.enable();
			local.request = createObject( "component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.request.addParameter( "username", local.accountName );
			local.request.addParameter( "password", local.password );
			local.response = createObject( "component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();;
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, local.response );
			local.authenticator.login( instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse() );
			local.test = local.authenticator.getUserFromSession();
			assertEquals( local.user, local.test );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetUserNames" output="false"
	            hint="Test get user names.">

		<cfscript>
			var local = {};

			System.out.println( "getUserNames" );
			local.authenticator = instance.ESAPI.authenticator();
			local.password = local.authenticator.generateStrongPassword();
			local.testnames = [];
			arrayResize( local.testnames, 10 );
			for(local.i = 1; local.i <= arrayLen( local.testnames ); local.i++) {
				local.testnames[local.i] = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			}
			for(local.i = 1; local.i <= arrayLen( local.testnames ); local.i++) {
				local.authenticator.createUser( local.testnames[local.i], local.password, local.password );
			}
			local.names = local.authenticator.getUserNames();
			for(local.i = 1; local.i <= arrayLen( local.testnames ); local.i++) {
				assertTrue( local.names.contains( local.testnames[local.i].toLowerCase() ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testHashPassword" output="false"
	            hint="Test of hashPassword method, of class org.owasp.esapi.Authenticator.">

		<cfscript>
			var local = {};

			System.out.println( "hashPassword" );
			local.username = "Jeff";
			local.password = "test";
			local.authenticator = instance.ESAPI.authenticator();
			local.result1 = local.authenticator.hashPassword( local.password, local.username );
			local.result2 = local.authenticator.hashPassword( local.password, local.username );
			assertTrue( local.result1.equals( local.result2 ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testLogin" output="false"
	            hint="Test of login method, of class org.owasp.esapi.Authenticator.">

		<cfscript>
			var local = {};

			System.out.println( "login" );
			local.authenticator = instance.ESAPI.authenticator();
			local.username = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.password = local.authenticator.generateStrongPassword();
			local.user = local.authenticator.createUser( local.username, local.password, local.password );
			local.user.enable();
			local.request = createObject( "component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.request.addParameter( "username", local.username );
			local.request.addParameter( "password", local.password );
			local.response = createObject( "component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			local.test = local.authenticator.login( instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse() );
			assertTrue( local.test.isLoggedIn() );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testRemoveUser" output="false"
	            hint="Test of removeAccount method, of class org.owasp.esapi.Authenticator.">

		<cfscript>
			var local = {};

			System.out.println( "removeUser" );
			local.accountName = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.authenticator = instance.ESAPI.authenticator();
			local.password = local.authenticator.generateStrongPassword();
			local.authenticator.createUser( local.accountName, local.password, local.password );
			assertTrue( local.authenticator.exists( local.accountName ) );
			local.authenticator.removeUser( local.accountName );
			assertFalse( local.authenticator.exists( local.accountName ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSaveUsers" output="false"
	            hint="Test of saveUsers method, of class org.owasp.esapi.Authenticator.">

		<cfscript>
			var local = {};

			System.out.println( "saveUsers" );
			local.accountName = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.authenticator = instance.ESAPI.authenticator();
			local.password = local.authenticator.generateStrongPassword();
			local.authenticator.createUser( local.accountName, local.password, local.password );
			local.authenticator.saveUsers();
			assertTrue( isObject( local.authenticator.getUserByAccountName( local.accountName ) ) );
			local.authenticator.removeUser( local.accountName );
			assertFalse( isObject( local.authenticator.getUserByAccountName( local.accountName ) ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSetCurrentUser" output="false"
	            hint="Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.">

		<cfscript>
			var local = {};

			System.out.println( "setCurrentUser" );
			local.authenticator = instance.ESAPI.authenticator();
			local.user1 = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_UPPERS );
			local.user2 = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_UPPERS );
			local.userOne = local.authenticator.createUser( local.user1, "getCurrentUser", "getCurrentUser" );
			local.userOne.enable();
			local.request = createObject( "component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.response = createObject( "component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();;
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, local.response );
			local.userOne.loginWithPassword( "getCurrentUser" );
			local.currentUser = local.authenticator.getCurrentUser();
			assertEquals( local.currentUser, local.userOne );
			local.userTwo = local.authenticator.createUser( local.user2, "getCurrentUser", "getCurrentUser" );
			local.authenticator.setCurrentUser( local.userTwo );
			assertFalse( local.currentUser.getAccountName() == local.userTwo.getAccountName() );

			/* TODO make this work
			Runnable echo = new Runnable() {
			    private int count = 1;
			    public void run() {
			        User u=null;
			        try {
			            String password = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			            u = instance.createUser("test" + count++, password, password);
			            instance.setCurrentUser(u);
			            ESAPI.getLogger("test").info( Logger.SECURITY, true, "Got current user" );
			            // ESAPI.authenticator().removeUser( u.getAccountName() );
			        } catch (esapi4cf.org.owasp.esapi.errors.AuthenticationException e) {
			            e.printStackTrace();
			        }
			    }
			};
			for ( int i = 0; i<10; i++ ) {
			    new Thread( echo ).start();
			} */
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSetCurrentUserWithRequest" output="false"
	            hint="Test of setCurrentUser method, of class org.owasp.esapi.Authenticator.">

		<cfscript>
			var local = {};

			System.out.println( "setCurrentUser(req,resp)" );
			local.authenticator = instance.ESAPI.authenticator();
			local.authenticator.logout();// in case anyone is logged in
			local.password = local.authenticator.generateStrongPassword();
			local.accountName = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.user = local.authenticator.createUser( local.accountName, local.password, local.password );
			local.user.enable();
			local.request = createObject( "component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.request.addParameter( "username", local.accountName );
			local.request.addParameter( "password", local.password );
			local.response = createObject( "component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			local.authenticator.login( instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse() );
			assertEquals( local.user, local.authenticator.getCurrentUser() );
			try {
				local.user.disable();
				local.authenticator.login( instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse() );
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected
			}
			try {
				local.user.enable();
				local.user.lock();
				local.authenticator.login( instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse() );
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected
			}
			try {
				local.user.unlock();
				local.user.setExpirationTime( getJava( "java.util.Date" ).init() );
				local.authenticator.login( instance.ESAPI.currentRequest(), instance.ESAPI.currentResponse() );
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected`
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testValidatePasswordStrength" output="false"
	            hint="Test of validatePasswordStrength method, of class org.owasp.esapi.Authenticator.">

		<cfscript>
			var local = {};

			System.out.println( "validatePasswordStrength" );
			local.authenticator = instance.ESAPI.authenticator();

			// should fail
			try {
				local.authenticator.verifyPasswordStrength( "password", "jeff" );
				fail("");
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.authenticator.verifyPasswordStrength( "diff123bang", "same123string" );
				fail("");
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.authenticator.verifyPasswordStrength( "password", "JEFF" );
				fail("");
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.authenticator.verifyPasswordStrength( "password", "1234" );
				fail("");
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.authenticator.verifyPasswordStrength( "password", "password" );
				fail("");
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.authenticator.verifyPasswordStrength( "password", "-1" );
				fail("");
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.authenticator.verifyPasswordStrength( "password", "password123" );
				fail("");
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}
			try {
				local.authenticator.verifyPasswordStrength( "password", "test123" );
				fail("");
			}
			catch(esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// success
			}

			// should pass
			local.authenticator.verifyPasswordStrength( "password", "jeffJEFF12!" );
			local.authenticator.verifyPasswordStrength( "password", "super calif ragil istic" );
			local.authenticator.verifyPasswordStrength( "password", "TONYTONYTONYTONY" );
			local.authenticator.verifyPasswordStrength( "password", local.authenticator.generateStrongPassword() );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testExists" output="false"
	            hint="Test of exists method, of class org.owasp.esapi.Authenticator.">

		<cfscript>
			var local = {};

			System.out.println( "exists" );
			local.accountName = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
			local.authenticator = instance.ESAPI.authenticator();
			local.password = local.authenticator.generateStrongPassword();
			local.authenticator.createUser( local.accountName, local.password, local.password );
			assertTrue( local.authenticator.exists( local.accountName ) );
			local.authenticator.removeUser( local.accountName );
			assertFalse( local.authenticator.exists( local.accountName ) );
		</cfscript>

	</cffunction>

	<!---
	<cffunction access="public" returntype="void" name="testMain" output="false"
	            hint="Test of main method, of class org.owasp.esapi.Authenticator.">

	    <cfscript>
	        var local = {};
	        System.out.println( "Authenticator Main" );
	        local.authenticator = instance.ESAPI.authenticator();
	        local.accountName = instance.ESAPI.randomizer().getRandomString( 8, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
	        local.password = local.authenticator.generateStrongPassword();
	        local.role = "test";

	        // test wrong parameters - missing role parameter
	        local.badargs = [local.accountName, local.password];
	        FileBasedAuthenticator.main( local.badargs );
	        // load users since the new user was added in another instance
	        local.authenticator.loadUsersImmediately();
	        local.u1 = local.authenticator.getUser( local.accountName );
	        assertNull( local.u1 );

	        // test good parameters
	        local.args = [local.accountName, local.password, local.role];
	        FileBasedAuthenticator.main( local.args );
	        // load users since the new user was added in another instance
	        local.authenticator.loadUsersImmediately();
	        local.u2 = local.authenticator.getUser( local.accountName );
	        assertNotNull( local.u2 );
	        assertTrue( local.u2.isInRole( local.role ) );
	        assertEquals( local.authenticator.hashPassword( local.password, local.accountName ), local.authenticator.getHashedPassword( local.u2 ) );
	    </cfscript>

	</cffunction>
	--->
</cfcomponent>