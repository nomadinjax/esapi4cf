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
 * The Class AccessControllerTest.
 */
component AccessControllerTest extends="cfesapi.test.org.owasp.esapi.lang.TestCase" {

	instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();

	/**
	 * {@inheritDoc}
	 *
	 * @throws Exception
	 */
	
	public void function setUp() {
		cleanUpUsers();
	
		local.authenticator = instance.ESAPI.authenticator();
		local.password = local.authenticator.generateStrongPassword();
	
		// create a user with the "user" role for this test
		local.alice = local.authenticator.getUserByAccountName("testuser1");
		if(!isObject(local.alice)) {
			local.alice = local.authenticator.createUser("testuser1", local.password, local.password);
		}
		local.alice.addRole("user");
	
		// create a user with the "admin" role for this test
		local.bob = local.authenticator.getUserByAccountName("testuser2");
		if(!isObject(local.bob)) {
			local.bob = local.authenticator.createUser("testuser2", local.password, local.password);
		}
		local.bob.addRole("admin");
	
		// create a user with the "user" and "admin" roles for this test
		local.mitch = local.authenticator.getUserByAccountName("testuser3");
		if(!isObject(local.mitch)) {
			local.mitch = local.authenticator.createUser("testuser3", local.password, local.password);
		}
		local.mitch.addRole("admin");
		local.mitch.addRole("user");
	}
	
	/**
	 * {@inheritDoc}
	 *
	 * @throws Exception
	 */
	
	public void function tearDown() {
		// none
	}
	
	/**
	 *
	 */
	
	public void function testMatchRule() {
		local.user = new cfesapi.org.owasp.esapi.User$ANONYMOUS(instance.ESAPI);
		instance.ESAPI.authenticator().setCurrentUser(local.user);
		assertFalse(instance.ESAPI.accessController().isAuthorizedForURL("/nobody"));
	}
	
	/**
	 * Test of isAuthorizedForURL method, of class
	 * org.owasp.esapi.AccessController.
	 *
	 * @throws Exception
	 */
	
	public void function testIsAuthorizedForURL() {
		newJava("java.lang.System").out.println("isAuthorizedForURL");
		local.accessController = instance.ESAPI.accessController();
		local.auth = instance.ESAPI.authenticator();
	
		local.auth.setCurrentUser(local.auth.getUserByAccountName("testuser1"));
		assertFalse(local.accessController.isAuthorizedForURL("/nobody"));
		assertFalse(local.accessController.isAuthorizedForURL("/test/admin"));
		assertTrue(local.accessController.isAuthorizedForURL("/test/user"));
		assertTrue(local.accessController.isAuthorizedForURL("/test/all"));
		assertFalse(local.accessController.isAuthorizedForURL("/test/none"));
		assertTrue(local.accessController.isAuthorizedForURL("/test/none/test.gif"));
		assertFalse(local.accessController.isAuthorizedForURL("/test/none/test.exe"));
		assertTrue(local.accessController.isAuthorizedForURL("/test/none/test.png"));
		assertFalse(local.accessController.isAuthorizedForURL("/test/moderator"));
		assertTrue(local.accessController.isAuthorizedForURL("/test/profile"));
		assertFalse(local.accessController.isAuthorizedForURL("/upload"));
	
		local.auth.setCurrentUser(local.auth.getUserByAccountName("testuser2"));
		assertFalse(local.accessController.isAuthorizedForURL("/nobody"));
		assertTrue(local.accessController.isAuthorizedForURL("/test/admin"));
		assertFalse(local.accessController.isAuthorizedForURL("/test/user"));
		assertTrue(local.accessController.isAuthorizedForURL("/test/all"));
		assertFalse(local.accessController.isAuthorizedForURL("/test/none"));
		assertTrue(local.accessController.isAuthorizedForURL("/test/none/test.png"));
		assertFalse(local.accessController.isAuthorizedForURL("/test/moderator"));
		assertTrue(local.accessController.isAuthorizedForURL("/test/profile"));
		assertFalse(local.accessController.isAuthorizedForURL("/upload"));
	
		local.auth.setCurrentUser(local.auth.getUserByAccountName("testuser3"));
		assertFalse(local.accessController.isAuthorizedForURL("/nobody"));
		assertTrue(local.accessController.isAuthorizedForURL("/test/admin"));
		assertTrue(local.accessController.isAuthorizedForURL("/test/user"));
		assertTrue(local.accessController.isAuthorizedForURL("/test/all"));
		assertFalse(local.accessController.isAuthorizedForURL("/test/none"));
		assertTrue(local.accessController.isAuthorizedForURL("/test/none/test.png"));
		assertFalse(local.accessController.isAuthorizedForURL("/test/moderator"));
		assertTrue(local.accessController.isAuthorizedForURL("/test/profile"));
		assertFalse(local.accessController.isAuthorizedForURL("/upload"));
	
		try {
			local.accessController.assertAuthorizedForURL("/test/admin");
			local.accessController.assertAuthorizedForURL("/nobody");
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
			// expected
		}
	}
	
	/**
	 * Test of isAuthorizedForFunction method, of class
	 * org.owasp.esapi.AccessController.
	 */
	
	public void function testIsAuthorizedForFunction() {
		newJava("java.lang.System").out.println("isAuthorizedForFunction");
		local.accessController = instance.ESAPI.accessController();
		local.auth = instance.ESAPI.authenticator();
	
		local.auth.setCurrentUser(local.auth.getUserByAccountName("testuser1"));
		assertTrue(local.accessController.isAuthorizedForFunction("/FunctionA"));
		assertFalse(local.accessController.isAuthorizedForFunction("/FunctionAdeny"));
		assertFalse(local.accessController.isAuthorizedForFunction("/FunctionB"));
		assertFalse(local.accessController.isAuthorizedForFunction("/FunctionBdeny"));
		assertTrue(local.accessController.isAuthorizedForFunction("/FunctionC"));
		assertFalse(local.accessController.isAuthorizedForFunction("/FunctionCdeny"));
	
		local.auth.setCurrentUser(local.auth.getUserByAccountName("testuser2"));
		assertFalse(local.accessController.isAuthorizedForFunction("/FunctionA"));
		assertFalse(local.accessController.isAuthorizedForFunction("/FunctionAdeny"));
		assertTrue(local.accessController.isAuthorizedForFunction("/FunctionB"));
		assertFalse(local.accessController.isAuthorizedForFunction("/FunctionBdeny"));
		assertTrue(local.accessController.isAuthorizedForFunction("/FunctionD"));
		assertFalse(local.accessController.isAuthorizedForFunction("/FunctionDdeny"));
	
		local.auth.setCurrentUser(local.auth.getUserByAccountName("testuser3"));
		assertTrue(local.accessController.isAuthorizedForFunction("/FunctionA"));
		assertFalse(local.accessController.isAuthorizedForFunction("/FunctionAdeny"));
		assertTrue(local.accessController.isAuthorizedForFunction("/FunctionB"));
		assertFalse(local.accessController.isAuthorizedForFunction("/FunctionBdeny"));
		assertTrue(local.accessController.isAuthorizedForFunction("/FunctionC"));
		assertFalse(local.accessController.isAuthorizedForFunction("/FunctionCdeny"));
	
		try {
			local.accessController.assertAuthorizedForFunction("/FunctionA");
			local.accessController.assertAuthorizedForFunction("/FunctionDdeny");
			fail("");
		}
		catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
			// expected
		}
	}
	
	/**
	 * Test of isAuthorizedForData method, of class
	 * org.owasp.esapi.AccessController.
	 */
	
	public void function testIsAuthorizedForData() {
		newJava("java.lang.System").out.println("isAuthorizedForData");
		local.accessController = instance.ESAPI.accessController();
		local.auth = instance.ESAPI.authenticator();
	
		local.adminR = "";
		local.adminRW = "";
		local.userW = "";
		local.userRW = "";
		local.anyR = "";
		local.userAdminR = "";
		local.userAdminRW = "";
		local.undefined = "";
	
		try {
			local.adminR = newJava("java.util.ArrayList");
			local.adminRW = newJava("java.lang.Math");
			local.userW = newJava("java.util.Date");
			local.userRW = newJava("java.lang.String");
			local.anyR = newJava("java.io.BufferedReader");
			local.userAdminR = newJava("java.util.Random");
			local.userAdminRW = newJava("java.awt.event.MouseWheelEvent");
			local.undefined = newJava("java.io.FileWriter");
		}
		catch(java.lang.ClassNotFoundException cnf) {
			newJava("java.lang.System").out.println("CLASS NOT FOUND.");
			cnf.printStackTrace();
		}
		//test User
		local.auth.setCurrentUser(local.auth.getUserByAccountName("testuser1"));
		assertTrue(local.accessController.isAuthorizedForData("read", local.userRW));
		assertFalse(local.accessController.isAuthorizedForData("read", local.undefined));
		assertFalse(local.accessController.isAuthorizedForData("write", local.undefined));
		assertFalse(local.accessController.isAuthorizedForData("read", local.userW));
		assertFalse(local.accessController.isAuthorizedForData("read", local.adminRW));
		assertTrue(local.accessController.isAuthorizedForData("write", local.userRW));
		assertTrue(local.accessController.isAuthorizedForData("write", local.userW));
		assertFalse(local.accessController.isAuthorizedForData("write", local.anyR));
		assertTrue(local.accessController.isAuthorizedForData("read", local.anyR));
		assertTrue(local.accessController.isAuthorizedForData("read", local.userAdminR));
		assertTrue(local.accessController.isAuthorizedForData("write", local.userAdminRW));
	
		//test Admin
		local.auth.setCurrentUser(local.auth.getUserByAccountName("testuser2"));
		assertTrue(local.accessController.isAuthorizedForData("read", local.adminRW));
		assertFalse(local.accessController.isAuthorizedForData("read", local.undefined));
		assertFalse(local.accessController.isAuthorizedForData("write", local.undefined));
		assertFalse(local.accessController.isAuthorizedForData("read", local.userRW));
		assertTrue(local.accessController.isAuthorizedForData("write", local.adminRW));
		assertFalse(local.accessController.isAuthorizedForData("write", local.anyR));
		assertTrue(local.accessController.isAuthorizedForData("read", local.anyR));
		assertTrue(local.accessController.isAuthorizedForData("read", local.userAdminR));
		assertTrue(local.accessController.isAuthorizedForData("write", local.userAdminRW));
	
		//test User/Admin
		local.auth.setCurrentUser(local.auth.getUserByAccountName("testuser3"));
		assertTrue(local.accessController.isAuthorizedForData("read", local.userRW));
		assertFalse(local.accessController.isAuthorizedForData("read", local.undefined));
		assertFalse(local.accessController.isAuthorizedForData("write", local.undefined));
		assertFalse(local.accessController.isAuthorizedForData("read", local.userW));
		assertTrue(local.accessController.isAuthorizedForData("read", local.adminR));
		assertTrue(local.accessController.isAuthorizedForData("write", local.userRW));
		assertTrue(local.accessController.isAuthorizedForData("write", local.userW));
		assertFalse(local.accessController.isAuthorizedForData("write", local.anyR));
		assertTrue(local.accessController.isAuthorizedForData("read", local.anyR));
		assertTrue(local.accessController.isAuthorizedForData("read", local.userAdminR));
		assertTrue(local.accessController.isAuthorizedForData("write", local.userAdminRW));
		try {
			local.accessController.assertAuthorizedForData("read", local.userRW);
			local.accessController.assertAuthorizedForData("write", local.adminR);
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
			// expected
		}
	}
	
	/**
	 * Test of isAuthorizedForFile method, of class
	 * org.owasp.esapi.AccessController.
	 */
	
	public void function testIsAuthorizedForFile() {
		newJava("java.lang.System").out.println("isAuthorizedForFile");
		local.accessController = instance.ESAPI.accessController();
		local.auth = instance.ESAPI.authenticator();
	
		local.auth.setCurrentUser(auth.getUserByAccountName("testuser1"));
		assertTrue(local.accessController.isAuthorizedForFile("/Dir/File1"));
		assertFalse(local.accessController.isAuthorizedForFile("/Dir/File2"));
		assertTrue(local.accessController.isAuthorizedForFile("/Dir/File3"));
		assertFalse(local.accessController.isAuthorizedForFile("/Dir/ridiculous"));
	
		local.auth.setCurrentUser(auth.getUserByAccountName("testuser2"));
		assertFalse(local.accessController.isAuthorizedForFile("/Dir/File1"));
		assertTrue(local.accessController.isAuthorizedForFile("/Dir/File2"));
		assertTrue(local.accessController.isAuthorizedForFile("/Dir/File4"));
		assertFalse(local.accessController.isAuthorizedForFile("/Dir/ridiculous"));
	
		local.auth.setCurrentUser(auth.getUserByAccountName("testuser3"));
		assertTrue(local.accessController.isAuthorizedForFile("/Dir/File1"));
		assertTrue(local.accessController.isAuthorizedForFile("/Dir/File2"));
		assertFalse(local.accessController.isAuthorizedForFile("/Dir/File5"));
		assertFalse(local.accessController.isAuthorizedForFile("/Dir/ridiculous"));
	
		try {
			local.accessController.assertAuthorizedForFile("/Dir/File1");
			local.accessController.assertAuthorizedForFile("/Dir/File6");
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
			// expected
		}
	}
	
	/**
	 * Test of isAuthorizedForService method, of class
	 * org.owasp.esapi.AccessController.
	 */
	
	public void function testIsAuthorizedForService() {
		newJava("java.lang.System").out.println("isAuthorizedForService");
		local.accessController = instance.ESAPI.accessController();
		local.auth = instance.ESAPI.authenticator();
	
		local.auth.setCurrentUser(auth.getUserByAccountName("testuser1"));
		assertTrue(local.accessController.isAuthorizedForService("/services/ServiceA"));
		assertFalse(local.accessController.isAuthorizedForService("/services/ServiceB"));
		assertTrue(local.accessController.isAuthorizedForService("/services/ServiceC"));
	
		assertFalse(local.accessController.isAuthorizedForService("/test/ridiculous"));
	
		local.auth.setCurrentUser(auth.getUserByAccountName("testuser2"));
		assertFalse(local.accessController.isAuthorizedForService("/services/ServiceA"));
		assertTrue(local.accessController.isAuthorizedForService("/services/ServiceB"));
		assertFalse(local.accessController.isAuthorizedForService("/services/ServiceF"));
		assertFalse(local.accessController.isAuthorizedForService("/test/ridiculous"));
	
		local.auth.setCurrentUser(auth.getUserByAccountName("testuser3"));
		assertTrue(local.accessController.isAuthorizedForService("/services/ServiceA"));
		assertTrue(local.accessController.isAuthorizedForService("/services/ServiceB"));
		assertFalse(local.accessController.isAuthorizedForService("/services/ServiceE"));
		assertFalse(local.accessController.isAuthorizedForService("/test/ridiculous"));
	
		try {
			local.accessController.assertAuthorizedForService("/services/ServiceD");
			local.accessController.assertAuthorizedForService("/test/ridiculous");
			fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
			// expected
		}
	}
	
}