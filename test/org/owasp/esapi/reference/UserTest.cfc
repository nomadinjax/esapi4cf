<!---
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
--->
<cfcomponent extends="esapi4cf.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		clearUserFile();
	</cfscript>

	<cffunction access="private" returntype="org.owasp.esapi.reference.DefaultUser" name="createTestUser" output="false"
	            hint="Creates the test user.">
		<cfargument required="true" type="String" name="password" hint="the password"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";

			var username = request.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			var ex = createObject("java", "java.lang.Exception").init();
			st = ex.getStackTrace();
			System.out.println("Creating user " & username & " for " & st[1].getMethodName());
			user = request.ESAPI.authenticator().createUser(username, arguments.password, arguments.password);
			return user;
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testAddRole" output="false"
	            hint="Test of testAddRole method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = request.ESAPI.authenticator();
			var accountName = request.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			var password = request.ESAPI.authenticator().generateStrongPassword();
			var role = request.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_LOWERS);
			var user = instance.createUser(accountName, password, password);

			System.out.println("addRole");
			user.addRole(role);
			assertTrue(user.isInRole(role));
			assertFalse(user.isInRole("ridiculous"));
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testAddRoles" output="false"
	            hint="Test of addRoles method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = request.ESAPI.authenticator();
			var oldPassword = instance.generateStrongPassword();
			var user = createTestUser(oldPassword);
			var set = [];

			System.out.println("addRoles");
			set.add("rolea");
			set.add("roleb");
			user.addRoles(set);
			assertTrue(user.isInRole("rolea"));
			assertTrue(user.isInRole("roleb"));
			assertFalse(user.isInRole("ridiculous"));
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testChangePassword" output="false"
	            hint="Test of changePassword method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var oldPassword = "";
			var user = "";
			var password1 = "";
			var password2 = "";

			System.out.println("changePassword");
			instance = request.ESAPI.authenticator();
			oldPassword = "Password12!@";
			user = createTestUser(oldPassword);
			System.out.println("Hash of " & oldPassword & " = " & instance.getHashedPassword(user));
			password1 = "SomethingElse34##$";
			user.changePassword(oldPassword, password1, password1);
			System.out.println("Hash of " & password1 & " = " & instance.getHashedPassword(user));
			assertTrue(user.verifyPassword(password1));
			password2 = "YetAnother56%^";
			user.changePassword(password1, password2, password2);
			System.out.println("Hash of " & password2 & " = " & instance.getHashedPassword(user));
			try {
				user.changePassword(password2, password1, password1);
				fail("Shouldn't be able to reuse a password");
			}
			catch(org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				// expected
			}
			assertTrue(user.verifyPassword(password2));
			assertFalse(user.verifyPassword("badpass"));
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testDisable" output="false"
	            hint="Test of disable method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = request.ESAPI.authenticator();
			var oldPassword = instance.generateStrongPassword();
			var user = createTestUser(oldPassword);

			System.out.println("disable");
			user.enable();
			assertTrue(user.isEnabled());
			user.disable();
			assertFalse(user.isEnabled());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testEnable" output="false"
	            hint="Test of enable method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = request.ESAPI.authenticator();
			var oldPassword = instance.generateStrongPassword();
			var user = createTestUser(oldPassword);

			System.out.println("enable");
			user.enable();
			assertTrue(user.isEnabled());
			user.disable();
			assertFalse(user.isEnabled());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testFailedLoginLockout" output="false"
	            hint="Test of failedLoginCount lockout, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var httpRequest = "";
			var httpResponse = "";

			System.out.println("failedLoginLockout");
			user = createTestUser("failedLoginLockout");
			user.enable();
			httpRequest = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest").init();
			httpResponse = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse").init();
			request.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);

			user.loginWithPassword("failedLoginLockout");

			try {
				user.loginWithPassword("ridiculous");
			}
			catch(org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected
			}
			System.out.println("FAILED: " & user.getFailedLoginCount());
			assertFalse(user.isLocked());

			try {
				user.loginWithPassword("ridiculous");
			}
			catch(org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected
			}
			System.out.println("FAILED: " & user.getFailedLoginCount());
			assertFalse(user.isLocked());

			try {
				user.loginWithPassword("ridiculous");
			}
			catch(org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected
			}
			System.out.println("FAILED: " & user.getFailedLoginCount());
			assertTrue(user.isLocked());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testGetAccountName" output="false"
	            hint="Test of getAccountName method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var user = createTestUser("getAccountName");
			var accountName = request.ESAPI.randomizer().getRandomString(7, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);

			System.out.println("getAccountName");
			user.setAccountName(accountName);
			assertEquals(accountName.toLowerCase(), user.getAccountName());
			assertFalse("ridiculous" == user.getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testGetLastFailedLoginTime" output="false"
	            hint="Test get last failed login time.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = request.ESAPI.authenticator();
			var oldPassword = instance.generateStrongPassword();
			var user = createTestUser(oldPassword);
			var httpRequest = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest").init();
			var httpResponse = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse").init();

			System.out.println("getLastLoginTime");
			request.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
			try {
				user.loginWithPassword("ridiculous");
			}
			catch(org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected
			}
			llt1 = user.getLastFailedLoginTime();
			sleep(100);// need a short delay to separate attempts
			try {
				user.loginWithPassword("ridiculous");
			}
			catch(org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected
			}
			llt2 = user.getLastFailedLoginTime();
			assertTrue(llt1.before(llt2));
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testGetLastLoginTime" output="false"
	            hint="Test get last login time.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var oldPassword = "";
			var user = "";
			var llt1 = "";
			var llt2 = "";

			System.out.println("getLastLoginTime");
			instance = request.ESAPI.authenticator();
			oldPassword = instance.generateStrongPassword();
			user = createTestUser(oldPassword);
			user.verifyPassword(oldPassword);
			llt1 = user.getLastLoginTime();
			sleep(10);// need a short delay to separate attempts
			user.verifyPassword(oldPassword);
			llt2 = user.getLastLoginTime();
			assertTrue(llt1.before(llt2));
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testGetLastPasswordChangeTime" output="false"
	            hint="Test getLastPasswordChangeTime method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var t1 = "";
			var newPassword = "";
			var t2 = "";

			System.out.println("getLastPasswordChangeTime");
			user = createTestUser("getLastPasswordChangeTime");
			t1 = user.getLastPasswordChangeTime();
			sleep(10);// need a short delay to separate attempts
			newPassword = request.ESAPI.authenticator().generateStrongPassword(user, "getLastPasswordChangeTime");
			user.changePassword("getLastPasswordChangeTime", newPassword, newPassword);
			t2 = user.getLastPasswordChangeTime();
			assertTrue(t2.after(t1));
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testGetRoles" output="false"
	            hint="Test of getRoles method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var accountName = "";
			var password = "";
			var role = "";
			var user = "";
			var roles = "";

			System.out.println("getRoles");
			instance = request.ESAPI.authenticator();
			accountName = request.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			password = request.ESAPI.authenticator().generateStrongPassword();
			role = request.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_LOWERS);
			user = instance.createUser(accountName, password, password);
			user.addRole(role);
			roles = user.getRoles();
			assertTrue(roles.size() > 0);
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testGetScreenName" output="false"
	            hint="Test of getScreenName method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var screenName = "";

			System.out.println("getScreenName");
			user = createTestUser("getScreenName");
			screenName = request.ESAPI.randomizer().getRandomString(7, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			user.setScreenName(screenName);
			assertEquals(screenName, user.getScreenName());
			assertFalse("ridiculous" == user.getScreenName());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testGetSessions" output="false"
	            hint="">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var accountName = "";
			var password = "";
			var user = "";
			var jsession1 = "";
			var session1 = "";
			var jsession2 = "";
			var session2 = "";
			var jsession3 = "";
			var session3 = "";
			var httpSessions = "";
			var i = "";
			var s = "";

			System.out.println("getSessions");
			instance = request.ESAPI.authenticator();
			accountName = request.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			password = request.ESAPI.authenticator().generateStrongPassword();
			user = instance.createUser(accountName, password, password);
			jsession1 = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpSession").init();
			session1 = createObject("component", "org.owasp.esapi.filters.SafeSession").init(request.ESAPI, jsession1);
			user.addSession(session1);
			jsession2 = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpSession").init();
			session2 = createObject("component", "org.owasp.esapi.filters.SafeSession").init(request.ESAPI, jsession1);
			user.addSession(session2);
			jsession3 = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpSession").init();
			session3 = createObject("component", "org.owasp.esapi.filters.SafeSession").init(request.ESAPI, jsession1);
			user.addSession(session3);
			httpSessions = user.getSessions();
			i = httpSessions.iterator();
			while(i.hasNext()) {
				s = i.next();
				System.out.println(">>>" & s.getId());
			}
			assertTrue(httpSessions.size() == 3);
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testAddSession" output="false">

		<cfscript>
			// TODO
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testRemoveSession" output="false">

		<cfscript>
			// TODO
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testIncrementFailedLoginCount" output="false"
	            hint="Test of incrementFailedLoginCount method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var httpRequest = "";
			var httpResponse = "";

			System.out.println("incrementFailedLoginCount");
			user = createTestUser("incrementFailedLoginCount");
			user.enable();
			assertEquals(0, user.getFailedLoginCount());
			httpRequest = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest").init();
			httpResponse = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse").init();
			request.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
			try {
				user.loginWithPassword("ridiculous");
			}
			catch(org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected
			}
			assertEquals(1, user.getFailedLoginCount());
			try {
				user.loginWithPassword("ridiculous");
			}
			catch(org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected
			}
			assertEquals(2, user.getFailedLoginCount());
			try {
				user.loginWithPassword("ridiculous");
			}
			catch(org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected
			}
			assertEquals(3, user.getFailedLoginCount());
			try {
				user.loginWithPassword("ridiculous");
			}
			catch(org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected
			}
			assertTrue(user.isLocked());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testIsEnabled" output="false"
	            hint="Test of isEnabled method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";

			System.out.println("isEnabled");
			user = createTestUser("isEnabled");
			user.disable();
			assertFalse(user.isEnabled());
			user.enable();
			assertTrue(user.isEnabled());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testIsInRole" output="false"
	            hint="Test of isInRole method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var role = "";

			System.out.println("isInRole");
			user = createTestUser("isInRole");
			role = "TestRole";
			assertFalse(user.isInRole(role));
			user.addRole(role);
			assertTrue(user.isInRole(role));
			assertFalse(user.isInRole("Ridiculous"));
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testIsLocked" output="false"
	            hint="Test of isLocked method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";

			System.out.println("isLocked");
			user = createTestUser("isLocked");
			user.lock();
			assertTrue(user.isLocked());
			user.unlock();
			assertFalse(user.isLocked());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testIsSessionAbsoluteTimeout" output="false"
	            hint="Test of isSessionAbsoluteTimeout method, of class org.owasp.esapi.IntrusionDetector.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var oldPassword = "";
			var user = "";
			var timestamp = "";
			var httpRequest = "";
			var httpResponse = "";
			var httpSession = "";

			System.out.println("isSessionAbsoluteTimeout");
			instance = request.ESAPI.authenticator();
			oldPassword = instance.generateStrongPassword();
			user = createTestUser(oldPassword);
			timestamp = System.currentTimeMillis();
			// setup request and response
			httpRequest = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest").init();
			httpResponse = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse").init();
			request.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
			httpSession = httpRequest.getSession();

			// set session creation -3 hours (default is 2 hour timeout)
			httpSession.setCreationTime(javaCast("long", timestamp - (1000 * 60 * 60 * 3)));
			assertTrue(user.isSessionAbsoluteTimeout());

			// set session creation -1 hour (default is 2 hour timeout)
			httpSession.setCreationTime(javaCast("long", timestamp - (1000 * 60 * 60 * 1)));
			assertFalse(user.isSessionAbsoluteTimeout());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testIsSessionTimeout" output="false"
	            hint="Test of isSessionTimeout method, of class org.owasp.esapi.IntrusionDetector.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var oldPassword = "";
			var user = "";
			var timestamp = "";
			var httpRequest = "";
			var httpResponse = "";
			var httpSession = "";

			System.out.println("isSessionTimeout");
			instance = request.ESAPI.authenticator();
			oldPassword = instance.generateStrongPassword();
			user = createTestUser(oldPassword);
			timestamp = System.currentTimeMillis();
			// setup request and response
			httpRequest = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest").init();
			httpResponse = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse").init();
			request.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
			httpSession = httpRequest.getSession();

			// set creation -30 mins (default is 20 min timeout)
			httpSession.setAccessedTime(timestamp - 1000 * 60 * 30);
			assertTrue(user.isSessionTimeout());

			// set creation -1 hour (default is 20 min timeout)
			httpSession.setAccessedTime(timestamp - 1000 * 60 * 10);
			assertFalse(user.isSessionTimeout());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testLock" output="false"
	            hint="Test of lockAccount method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var oldPassword = "";
			var user = "";

			System.out.println("lock");
			instance = request.ESAPI.authenticator();
			oldPassword = instance.generateStrongPassword();
			user = createTestUser(oldPassword);
			user.lock();
			assertTrue(user.isLocked());
			user.unlock();
			assertFalse(user.isLocked());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testLoginWithPassword" output="false"
	            hint="Test of loginWithPassword method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var httpRequest = "";
			var httpResponse = "";
			var httpSession = "";
			var user = "";

			System.out.println("loginWithPassword");
			httpRequest = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest").init();
			httpResponse = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse").init();
			request.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
			httpSession = httpRequest.getSession();
			assertFalse(httpSession.getInvalidated());
			user = createTestUser("loginWithPassword");
			user.enable();
			user.loginWithPassword("loginWithPassword");
			assertTrue(user.isLoggedIn());
			user.logout();
			assertFalse(user.isLoggedIn());
			assertFalse(user.isLocked());
			try {
				user.loginWithPassword("ridiculous");
			}
			catch(org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected
			}
			assertFalse(user.isLoggedIn());
			try {
				user.loginWithPassword("ridiculous");
			}
			catch(org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected
			}
			try {
				user.loginWithPassword("ridiculous");
			}
			catch(org.owasp.esapi.errors.AuthenticationLoginException e) {
				// expected
			}
			assertTrue(user.isLocked());
			user.unlock();
			assertTrue(user.getFailedLoginCount() == 0);
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testLogout" output="false"
	            hint="Test of logout method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var httpRequest = "";
			var httpResponse = "";
			var httpSession = "";
			var instance = "";
			var oldPassword = "";
			var user = "";

			System.out.println("logout");
			httpRequest = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest").init();
			httpResponse = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse").init();
			httpSession = httpRequest.getSession();
			assertFalse(httpSession.getInvalidated());
			instance = request.ESAPI.authenticator();
			request.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
			oldPassword = instance.generateStrongPassword();
			user = createTestUser(oldPassword);
			user.enable();
			System.out.println(user.getLastLoginTime());
			user.loginWithPassword(password=oldPassword);
			assertTrue(user.isLoggedIn());
			// get new session after user logs in
			httpSession = httpRequest.getSession();
			assertFalse(httpSession.getInvalidated());
			user.logout();
			assertFalse(user.isLoggedIn());
			assertTrue(httpSession.getInvalidated());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testRemoveRole" output="false"
	            hint="Test of testRemoveRole method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var role = "";
			var user = "";

			System.out.println("removeRole");
			role = request.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_LOWERS);
			user = createTestUser("removeRole");
			user.addRole(role);
			assertTrue(user.isInRole(role));
			user.removeRole(role);
			assertFalse(user.isInRole(role));
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testResetCSRFToken" output="false"
	            hint="Test of testResetCSRFToken method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var user = createTestUser("resetCSRFToken");
			var token1 = user.resetCSRFToken();
			var token2 = user.resetCSRFToken();

			System.out.println("resetCSRFToken");
			assertFalse(token1.equals(token2));
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testSetAccountName" output="false"
	            hint="Test of setAccountName method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var user = createTestUser("setAccountName");
			var accountName = request.ESAPI.randomizer().getRandomString(7, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);

			System.out.println("setAccountName");
			user.setAccountName(accountName);
			assertEquals(accountName.toLowerCase(), user.getAccountName());
			assertFalse("ridiculous" == user.getAccountName());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testSetExpirationTime" output="false"
	            hint="Test of setExpirationTime method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var password = request.ESAPI.randomizer().getRandomString(8, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			var user = createTestUser(password);

			System.out.println("setAccountName");
			user.setExpirationTime(createObject("java", "java.util.Date").init(javaCast("long", 0)));
			assertTrue(user.isExpired());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testSetRoles" output="false"
	            hint="Test of setRoles method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var set = "";

			System.out.println("setRoles");
			user = createTestUser("setRoles");
			user.addRole("user");
			assertTrue(user.isInRole("user"));
			set = [];
			set.add("rolea");
			set.add("roleb");
			user.setRoles(set);
			assertFalse(user.isInRole("user"));
			assertTrue(user.isInRole("rolea"));
			assertTrue(user.isInRole("roleb"));
			assertFalse(user.isInRole("ridiculous"));
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testSetScreenName" output="false"
	            hint="Test of setScreenName method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var user = createTestUser("setScreenName");
			var screenName = request.ESAPI.randomizer().getRandomString(7, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);

			System.out.println("setScreenName");
			user.setScreenName(screenName);
			assertEquals(screenName, user.getScreenName());
			assertFalse("ridiculous" == user.getScreenName());
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="testUnlock" output="false"
	            hint="Test of unlockAccount method, of class org.owasp.esapi.User.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = request.ESAPI.authenticator();
			var oldPassword = instance.generateStrongPassword();
			var user = createTestUser(oldPassword);

			System.out.println("unlockAccount");
			user.lock();
			assertTrue(user.isLocked());
			user.unlock();
			assertFalse(user.isLocked());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSerialization" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var serializedUser = "";
			var deserializedUser = "";

			// test AnonymousUser
			user = request.ESAPI.authenticator().getCurrentUser();
			assertTrue(isInstanceOf(user, "org.owasp.esapi.User"), "Instance of AnonymousUser failed.");

			serializedUser = objectSave(user);
			assertTrue(isBinary(serializedUser), "Serialization of AnonymousUser failed.");

			deserializedUser = objectLoad(serializedUser);
			// NOTE: CFC exists but instanceOf fails ???
			//assertTrue(isInstanceOf(deserializedUser, "org.owasp.esapi.User$ANONYMOUS"), "Deserialization of AnonymousUser failed.");
			assertEquals(user.getAccountId(), deserializedUser.getAccountId(), "AnonymousUser accountId failed to persist.");
			assertEquals(user.getAccountName(), deserializedUser.getAccountName(), "AnonymousUser accountName failed to persist.");

			// test DefaultUser
			user = createTestUser(request.ESAPI.authenticator().generateStrongPassword());
			assertTrue(isInstanceOf(user, "org.owasp.esapi.User"), "Instance of DefaultUser failed.");

			serializedUser = objectSave(user);
			assertTrue(isBinary(serializedUser), "Serialization of DefaultUser failed.");

			deserializedUser = objectLoad(serializedUser);
			// NOTE: CFC exists but instanceOf fails ???
			//assertTrue(isInstanceOf(deserializedUser, "org.owasp.esapi.reference.DefaultUser"), "Deserialization of DefaultUser failed.");
			assertEquals(user.getAccountId(), deserializedUser.getAccountId(), "DefaultUser accountId failed to persist.");
			assertEquals(user.getAccountName(), deserializedUser.getAccountName(), "DefaultUser accountName failed to persist.");
		</cfscript>
	</cffunction>

</cfcomponent>