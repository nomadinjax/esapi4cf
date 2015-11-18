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
 * The Class AccessControllerTest.
 */
component extends="test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	/**
	 * Instantiates a new access controller test.
	 *
	 * @param testName
     *            the test name
     * @throws Exception
	 */
	public void function setUp() {
		var authenticator = variables.ESAPI.authenticator();
		var password = authenticator.generateStrongPassword();

		// create a user with the "user" role for this test
		var alice = authenticator.getUserByAccountName("testuser1");
		if (isNull(alice)) {
			alice = authenticator.createUser( "testuser1", password, password);
		}
		alice.addRole("user");

		// create a user with the "admin" role for this test
		var bob = authenticator.getUserByAccountName("testuser2");
		if (isNull(bob)) {
			bob = authenticator.createUser( "testuser2", password, password);
		}
		bob.addRole("admin");

		// create a user with the "user" and "admin" roles for this test
		var mitch = authenticator.getUserByAccountName("testuser3");
		if (isNull(mitch)) {
			mitch = authenticator.createUser( "testuser3", password, password);
		}
		mitch.addRole("admin");
		mitch.addRole("user");
	}

    /**
     *
     */
    public void function testMatchRule() {
		variables.ESAPI.authenticator().setCurrentUser(null);
		assertFalse(variables.ESAPI.accessController().isAuthorizedForURL("/nobody"));
	}

	/**
	 * Test of isAuthorizedForURL method, of class
	 * org.owasp.esapi.AccessController.
     *
     * @throws Exception
     */
	public void function testIsAuthorizedForURL() {
		System.out.println("isAuthorizedForURL");
		var instance = variables.ESAPI.accessController();
		var auth = variables.ESAPI.authenticator();

		auth.setCurrentUser( auth.getUser("testuser1") );
		assertFalse(instance.isAuthorizedForURL("/nobody"));
		assertFalse(instance.isAuthorizedForURL("/test/admin"));
		assertTrue(instance.isAuthorizedForURL("/test/user"));
		assertTrue(instance.isAuthorizedForURL("/test/all"));
		assertFalse(instance.isAuthorizedForURL("/test/none"));
		assertTrue(instance.isAuthorizedForURL("/test/none/test.gif"));
		assertFalse(instance.isAuthorizedForURL("/test/none/test.exe"));
		assertTrue(instance.isAuthorizedForURL("/test/none/test.png"));
		assertFalse(instance.isAuthorizedForURL("/test/moderator"));
		assertTrue(instance.isAuthorizedForURL("/test/profile"));
		assertFalse(instance.isAuthorizedForURL("/upload"));

		auth.setCurrentUser( auth.getUser("testuser2") );
		assertFalse(instance.isAuthorizedForURL("/nobody"));
		assertTrue(instance.isAuthorizedForURL("/test/admin"));
		assertFalse(instance.isAuthorizedForURL("/test/user"));
		assertTrue(instance.isAuthorizedForURL("/test/all"));
		assertFalse(instance.isAuthorizedForURL("/test/none"));
		assertTrue(instance.isAuthorizedForURL("/test/none/test.png"));
		assertFalse(instance.isAuthorizedForURL("/test/moderator"));
		assertTrue(instance.isAuthorizedForURL("/test/profile"));
		assertFalse(instance.isAuthorizedForURL("/upload"));

		auth.setCurrentUser( auth.getUser("testuser3") );
		assertFalse(instance.isAuthorizedForURL("/nobody"));
		assertTrue(instance.isAuthorizedForURL("/test/admin"));
		assertTrue(instance.isAuthorizedForURL("/test/user"));
		assertTrue(instance.isAuthorizedForURL("/test/all"));
		assertFalse(instance.isAuthorizedForURL("/test/none"));
		assertTrue(instance.isAuthorizedForURL("/test/none/test.png"));
		assertFalse(instance.isAuthorizedForURL("/test/moderator"));
		assertTrue(instance.isAuthorizedForURL("/test/profile"));
		assertFalse(instance.isAuthorizedForURL("/upload"));

		try {
			instance.assertAuthorizedForURL("/test/admin");
			instance.assertAuthorizedForURL( "/nobody" );
			fail();
		} catch ( AccessControlException e ) {
			// expected
		}
	}

	/**
	 * Test of isAuthorizedForFunction method, of class
	 * org.owasp.esapi.AccessController.
	 */
	public void function testIsAuthorizedForFunction() {
		System.out.println("isAuthorizedForFunction");
		var instance = variables.ESAPI.accessController();
		var auth = variables.ESAPI.authenticator();

		auth.setCurrentUser( auth.getUser("testuser1") );
		assertTrue(instance.isAuthorizedForFunction("/FunctionA"));
		assertFalse(instance.isAuthorizedForFunction("/FunctionAdeny"));
		assertFalse(instance.isAuthorizedForFunction("/FunctionB"));
		assertFalse(instance.isAuthorizedForFunction("/FunctionBdeny"));
		assertTrue(instance.isAuthorizedForFunction("/FunctionC"));
		assertFalse(instance.isAuthorizedForFunction("/FunctionCdeny"));

		auth.setCurrentUser( auth.getUser("testuser2") );
		assertFalse(instance.isAuthorizedForFunction("/FunctionA"));
		assertFalse(instance.isAuthorizedForFunction("/FunctionAdeny"));
		assertTrue(instance.isAuthorizedForFunction("/FunctionB"));
		assertFalse(instance.isAuthorizedForFunction("/FunctionBdeny"));
		assertTrue(instance.isAuthorizedForFunction("/FunctionD"));
		assertFalse(instance.isAuthorizedForFunction("/FunctionDdeny"));

		auth.setCurrentUser( auth.getUser("testuser3") );
		assertTrue(instance.isAuthorizedForFunction("/FunctionA"));
		assertFalse(instance.isAuthorizedForFunction("/FunctionAdeny"));
		assertTrue(instance.isAuthorizedForFunction("/FunctionB"));
		assertFalse(instance.isAuthorizedForFunction("/FunctionBdeny"));
		assertTrue(instance.isAuthorizedForFunction("/FunctionC"));
		assertFalse(instance.isAuthorizedForFunction("/FunctionCdeny"));

		try {
			instance.assertAuthorizedForFunction("/FunctionA");
			instance.assertAuthorizedForFunction( "/FunctionDdeny" );
			fail();
		} catch ( AccessControlException e ) {
			// expected
		}
	}

	/**
	 * Test of isAuthorizedForData method, of class
	 * org.owasp.esapi.AccessController.
	 */
	public void function testIsAuthorizedForData() {
		System.out.println("isAuthorizedForData");
		var instance = variables.ESAPI.accessController();
		var auth = variables.ESAPI.authenticator();

		var adminR = null;
		var adminRW = null;
		var userW = null;
		var userRW = null;
		var anyR = null;
		var userAdminR = null;
		var userAdminRW = null;
		var undefined = null;

		try{
			adminR = Class.forName("java.util.ArrayList");
			adminRW = Class.forName("java.lang.Math");
			userW = Class.forName("java.util.Date");
			userRW = Class.forName("java.lang.String");
			anyR = Class.forName("java.io.BufferedReader");
			userAdminR = Class.forName("java.util.Random");
			userAdminRW = Class.forName("java.awt.event.MouseWheelEvent");
			undefined = Class.forName("java.io.FileWriter");

		}catch(ClassNotFoundException cnf){
			System.out.println("CLASS NOT FOUND.");
			cnf.printStackTrace();
		}
		//test User
		auth.setCurrentUser( auth.getUser("testuser1") );
		assertTrue(instance.isAuthorizedForData("read", userRW));
		assertFalse(instance.isAuthorizedForData("read", undefined));
		assertFalse(instance.isAuthorizedForData("write", undefined));
		assertFalse(instance.isAuthorizedForData("read", userW));
		assertFalse(instance.isAuthorizedForData("read", adminRW));
		assertTrue(instance.isAuthorizedForData("write", userRW));
		assertTrue(instance.isAuthorizedForData("write", userW));
		assertFalse(instance.isAuthorizedForData("write", anyR));
		assertTrue(instance.isAuthorizedForData("read", anyR));
		assertTrue(instance.isAuthorizedForData("read", userAdminR));
		assertTrue(instance.isAuthorizedForData("write", userAdminRW));

		//test Admin
		auth.setCurrentUser( auth.getUser("testuser2") );
		assertTrue(instance.isAuthorizedForData("read", adminRW));
		assertFalse(instance.isAuthorizedForData("read", undefined));
		assertFalse(instance.isAuthorizedForData("write", undefined));
		assertFalse(instance.isAuthorizedForData("read", userRW));
		assertTrue(instance.isAuthorizedForData("write", adminRW));
		assertFalse(instance.isAuthorizedForData("write", anyR));
		assertTrue(instance.isAuthorizedForData("read", anyR));
		assertTrue(instance.isAuthorizedForData("read", userAdminR));
		assertTrue(instance.isAuthorizedForData("write", userAdminRW));

		//test User/Admin
		auth.setCurrentUser( auth.getUser("testuser3") );
		assertTrue(instance.isAuthorizedForData("read", userRW));
		assertFalse(instance.isAuthorizedForData("read", undefined));
		assertFalse(instance.isAuthorizedForData("write", undefined));
		assertFalse(instance.isAuthorizedForData("read", userW));
		assertTrue(instance.isAuthorizedForData("read", adminR));
		assertTrue(instance.isAuthorizedForData("write", userRW));
		assertTrue(instance.isAuthorizedForData("write", userW));
		assertFalse(instance.isAuthorizedForData("write", anyR));
		assertTrue(instance.isAuthorizedForData("read", anyR));
		assertTrue(instance.isAuthorizedForData("read", userAdminR));
		assertTrue(instance.isAuthorizedForData("write", userAdminRW));
		try {
			instance.assertAuthorizedForData("read", userRW);
			instance.assertAuthorizedForData( "write", adminR );
			fail();
		} catch ( AccessControlException e ) {
			// expected
		}

	}

	/**
	 * Test of isAuthorizedForFile method, of class
	 * org.owasp.esapi.AccessController.
	 */
	public void function testIsAuthorizedForFile() {
		System.out.println("isAuthorizedForFile");
		var instance = variables.ESAPI.accessController();
		var auth = variables.ESAPI.authenticator();

		auth.setCurrentUser( auth.getUser("testuser1") );
		assertTrue(instance.isAuthorizedForFile("/Dir/File1"));
		assertFalse(instance.isAuthorizedForFile("/Dir/File2"));
		assertTrue(instance.isAuthorizedForFile("/Dir/File3"));
		assertFalse(instance.isAuthorizedForFile("/Dir/ridiculous"));

		auth.setCurrentUser( auth.getUser("testuser2") );
		assertFalse(instance.isAuthorizedForFile("/Dir/File1"));
		assertTrue(instance.isAuthorizedForFile("/Dir/File2"));
		assertTrue(instance.isAuthorizedForFile("/Dir/File4"));
		assertFalse(instance.isAuthorizedForFile("/Dir/ridiculous"));

		auth.setCurrentUser( auth.getUser("testuser3") );
		assertTrue(instance.isAuthorizedForFile("/Dir/File1"));
		assertTrue(instance.isAuthorizedForFile("/Dir/File2"));
		assertFalse(instance.isAuthorizedForFile("/Dir/File5"));
		assertFalse(instance.isAuthorizedForFile("/Dir/ridiculous"));

		try {
			instance.assertAuthorizedForFile("/Dir/File1");
			instance.assertAuthorizedForFile( "/Dir/File6" );
			fail();
		} catch ( AccessControlException e ) {
			// expected
		}
	}

	/**
	 * Test of isAuthorizedForService method, of class
	 * org.owasp.esapi.AccessController.
	 */
	public void function testIsAuthorizedForService() {
		System.out.println("isAuthorizedForService");
		var instance = variables.ESAPI.accessController();
		var auth = variables.ESAPI.authenticator();

		auth.setCurrentUser( auth.getUser("testuser1") );
		assertTrue(instance.isAuthorizedForService("/services/ServiceA"));
		assertFalse(instance.isAuthorizedForService("/services/ServiceB"));
		assertTrue(instance.isAuthorizedForService("/services/ServiceC"));

		assertFalse(instance.isAuthorizedForService("/test/ridiculous"));

		auth.setCurrentUser( auth.getUser("testuser2") );
		assertFalse(instance.isAuthorizedForService("/services/ServiceA"));
		assertTrue(instance.isAuthorizedForService("/services/ServiceB"));
		assertFalse(instance.isAuthorizedForService("/services/ServiceF"));
		assertFalse(instance.isAuthorizedForService("/test/ridiculous"));

		auth.setCurrentUser( auth.getUser("testuser3") );
		assertTrue(instance.isAuthorizedForService("/services/ServiceA"));
		assertTrue(instance.isAuthorizedForService("/services/ServiceB"));
		assertFalse(instance.isAuthorizedForService("/services/ServiceE"));
		assertFalse(instance.isAuthorizedForService("/test/ridiculous"));

		try {
			instance.assertAuthorizedForService("/services/ServiceD");
			instance.assertAuthorizedForService( "/test/ridiculous" );
			fail();
		} catch ( AccessControlException e ) {
			// expected
		}
	}

}
