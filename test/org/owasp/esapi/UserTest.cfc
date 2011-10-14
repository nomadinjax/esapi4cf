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
		if (fileExists(filePath)) {
			try {
				fileDelete(filePath);
			}
			catch (Any e) {}
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
		try { User.ANONYMOUS.addRole(""); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.addRoles([]); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.changePassword("", "", ""); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.disable(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.enable(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getAccountId(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getAccountName(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getName(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getCSRFToken(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getExpirationTime(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getFailedLoginCount(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getLastFailedLoginTime(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getLastLoginTime(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getLastPasswordChangeTime(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getRoles(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getScreenName(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.addSession(""); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.removeSession(""); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.incrementFailedLoginCount(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.isAnonymous(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.isEnabled(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.isExpired(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.isInRole(""); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.isLocked(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.isLoggedIn(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.isSessionAbsoluteTimeout(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.isSessionTimeout(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.lock(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.loginWithPassword(""); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.logout(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.removeRole(""); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.resetCSRFToken(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.setAccountName(""); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.setExpirationTime(now()); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.setRoles([]); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.setScreenName(""); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.unlock(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.verifyPassword(""); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.setLastFailedLoginTime(now()); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.setLastLoginTime(now()); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.setLastHostAddress(""); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.setLastPasswordChangeTime(now()); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getEventMap(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getLocale(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.setLocale(""); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getAccountName(); } catch( java.lang.RuntimeException e ) {}
		try { User.ANONYMOUS.getAccountName(); } catch( java.lang.RuntimeException e ) {}
	}
	
}