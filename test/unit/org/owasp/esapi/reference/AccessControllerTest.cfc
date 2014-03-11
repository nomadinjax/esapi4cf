<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfcomponent extends="esapi4cf.test.unit.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		clearUserFile();

		variables.origResDir = "";
	</cfscript>

	<cffunction access="private" returntype="void" name="initUsers" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var alice = "";
			var bob = "";
			var mitch = "";

			// FIXME: this should probably be changed to be part of setUp()
			var authenticator = request.ESAPI.authenticator();
			var password = authenticator.generateStrongPassword();

			// create a user with the "user" role for this test
			alice = authenticator.getUserByAccountName("testuser1");
			if(!isObject(alice)) {
				alice = authenticator.createUser("testuser1", password, password);
			}
			alice.addRole("user");

			// create a user with the "admin" role for this test
			bob = authenticator.getUserByAccountName("testuser2");
			if(!isObject(bob)) {
				bob = authenticator.createUser("testuser2", password, password);
			}
			bob.addRole("admin");

			// create a user with the "user" and "admin" roles for this test
			mitch = authenticator.getUserByAccountName("testuser3");
			if(!isObject(mitch)) {
				mitch = authenticator.createUser("testuser3", password, password);
			}
			mitch.addRole("admin");
			mitch.addRole("user");
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="checkDir" output="false"
	            hint="Check that a file exists and is a directory.">
		<cfargument required="true" type="String" name="dir" hint="The file to check."/>
		<cfargument required="true" type="String" name="prefix" hint="The prefix for the exception message thrown if dir does not exist or is not a directory."/>

		<cfscript>
			if(!directoryExists(arguments.dir))
				throw(object=createObject("java", "java.lang.IllegalStateException").init(arguments.prefix & " does not exist (was " & arguments.dir & ')'));
			//if(!arguments.dir.isDirectory())
			//    throw(object=createObject("java", "java.lang.IllegalStateException" ).init( arguments.prefix & " is not a directory (was " & arguments.dir.getPath() & ')' ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var basedir = "";
			var basedirFile = "";
			var srcDir = "";
			var testDir = "";
			var resDir = "";

			super.setUp();

			initUsers();

			basedirFile = expandPath("../../../../");
			srcDir = "";
			testDir = "";
			resDir = "";

			//if(isNull(basedir))
			//	throw(object=createObject("java", "java.lang.IllegalStateException").init("The basedir system property used to find the resource directory is not set"));
			checkDir((basedirFile), "The basedir system property defines a base directory that");
			srcDir = expandPath("/org");
			checkDir((srcDir), "The src directory");
			basedirFile = "";
			testDir = expandPath("/esapi4cf/test/unit");
			checkDir((testDir), "The test directory");
			srcDir = "";
			resDir = testDir & "/resources";
			checkDir((resDir), "The resources directory");
			testDir = "";
			variables.origResDir = request.ESAPI.securityConfiguration().getResourceDirectory();

			request.ESAPI.securityConfiguration().setResourceDirectory(resDir);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="tearDown" output="false">

		<cfscript>
			request.ESAPI.securityConfiguration().setResourceDirectory(variables.origResDir);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testMatchRule" output="false">

		<cfscript>
			//request.ESAPI.authenticator().setCurrentUser( "" );
			request.ESAPI.authenticator().clearCurrent();
			assertFalse(request.ESAPI.accessController().isAuthorizedForURL("/nobody"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsAuthorizedForURL" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var auth = "";

			System.out.println("isAuthorizedForURL");
			instance = request.ESAPI.accessController();
			auth = request.ESAPI.authenticator();

			auth.setCurrentUser(auth.getUserByAccountName("testuser1"));
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

			auth.setCurrentUser(auth.getUserByAccountName("testuser2"));
			assertFalse(instance.isAuthorizedForURL("/nobody"));
			assertTrue(instance.isAuthorizedForURL("/test/admin"));
			assertFalse(instance.isAuthorizedForURL("/test/user"));
			assertTrue(instance.isAuthorizedForURL("/test/all"));
			assertFalse(instance.isAuthorizedForURL("/test/none"));
			assertTrue(instance.isAuthorizedForURL("/test/none/test.png"));
			assertFalse(instance.isAuthorizedForURL("/test/moderator"));
			assertTrue(instance.isAuthorizedForURL("/test/profile"));
			assertFalse(instance.isAuthorizedForURL("/upload"));

			auth.setCurrentUser(auth.getUserByAccountName("testuser3"));
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
				instance.assertAuthorizedForURL("/nobody");
				fail();
			}
			catch(org.owasp.esapi.errors.AccessControlException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsAuthorizedForFunction" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var auth = "";

			System.out.println("isAuthorizedForFunction");
			instance = request.ESAPI.accessController();
			auth = request.ESAPI.authenticator();

			auth.setCurrentUser(auth.getUserByAccountName("testuser1"));
			assertTrue(instance.isAuthorizedForFunction("/FunctionA"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionAdeny"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionB"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionBdeny"));
			assertTrue(instance.isAuthorizedForFunction("/FunctionC"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionCdeny"));

			auth.setCurrentUser(auth.getUserByAccountName("testuser2"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionA"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionAdeny"));
			assertTrue(instance.isAuthorizedForFunction("/FunctionB"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionBdeny"));
			assertTrue(instance.isAuthorizedForFunction("/FunctionD"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionDdeny"));

			auth.setCurrentUser(auth.getUserByAccountName("testuser3"));
			assertTrue(instance.isAuthorizedForFunction("/FunctionA"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionAdeny"));
			assertTrue(instance.isAuthorizedForFunction("/FunctionB"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionBdeny"));
			assertTrue(instance.isAuthorizedForFunction("/FunctionC"));
			assertFalse(instance.isAuthorizedForFunction("/FunctionCdeny"));

			try {
				instance.assertAuthorizedForFunction("/FunctionA");
				instance.assertAuthorizedForFunction("/FunctionDdeny");
				fail();
			}
			catch(org.owasp.esapi.errors.AccessControlException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsAuthorizedForData" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var auth = "";
			var adminR = "";
			var adminRW = "";
			var userW = "";
			var userRW = "";
			var anyR = "";
			var userAdminR = "";
			var userAdminRW = "";
			var undefined = "";

			System.out.println("isAuthorizedForData");
			instance = request.ESAPI.accessController();
			auth = request.ESAPI.authenticator();

			try {
				adminR = createObject("java", "java.util.ArrayList");
				adminRW = createObject("java", "java.lang.Math");
				userW = createObject("java", "java.util.Date");
				userRW = createObject("java", "java.lang.String");
				anyR = createObject("java", "java.io.BufferedReader");
				userAdminR = createObject("java", "java.util.Random");
				userAdminRW = createObject("java", "java.awt.event.MouseWheelEvent");
				undefined = createObject("java", "java.io.FileWriter");
			}
			catch(java.lang.ClassNotFoundException cnf) {
				System.out.println("CLASS NOT FOUND.");
				cnf.printStackTrace();
			}
			//test User
			auth.setCurrentUser(auth.getUserByAccountName("testuser1"));
			//assertTrue( instance.isAuthorizedForData( "read", userRW ) );
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
			auth.setCurrentUser(auth.getUserByAccountName("testuser2"));
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
			auth.setCurrentUser(auth.getUserByAccountName("testuser3"));
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
				instance.assertAuthorizedForData("write", adminR);
				fail();
			}
			catch(org.owasp.esapi.errors.AccessControlException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsAuthorizedForFile" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var auth = "";

			System.out.println("isAuthorizedForFile");
			instance = request.ESAPI.accessController();
			auth = request.ESAPI.authenticator();

			auth.setCurrentUser(auth.getUserByAccountName("testuser1"));
			assertTrue(instance.isAuthorizedForFile("/Dir/File1"));
			assertFalse(instance.isAuthorizedForFile("/Dir/File2"));
			assertTrue(instance.isAuthorizedForFile("/Dir/File3"));
			assertFalse(instance.isAuthorizedForFile("/Dir/ridiculous"));

			auth.setCurrentUser(auth.getUserByAccountName("testuser2"));
			assertFalse(instance.isAuthorizedForFile("/Dir/File1"));
			assertTrue(instance.isAuthorizedForFile("/Dir/File2"));
			assertTrue(instance.isAuthorizedForFile("/Dir/File4"));
			assertFalse(instance.isAuthorizedForFile("/Dir/ridiculous"));

			auth.setCurrentUser(auth.getUserByAccountName("testuser3"));
			assertTrue(instance.isAuthorizedForFile("/Dir/File1"));
			assertTrue(instance.isAuthorizedForFile("/Dir/File2"));
			assertFalse(instance.isAuthorizedForFile("/Dir/File5"));
			assertFalse(instance.isAuthorizedForFile("/Dir/ridiculous"));

			try {
				instance.assertAuthorizedForFile("/Dir/File1");
				instance.assertAuthorizedForFile("/Dir/File6");
				fail();
			}
			catch(org.owasp.esapi.errors.AccessControlException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsAuthorizedForBackendService" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var auth = "";

			System.out.println("isAuthorizedForBackendService");
			instance = request.ESAPI.accessController();
			auth = request.ESAPI.authenticator();

			auth.setCurrentUser(auth.getUserByAccountName("testuser1"));
			assertTrue(instance.isAuthorizedForService("/services/ServiceA"));
			assertFalse(instance.isAuthorizedForService("/services/ServiceB"));
			assertTrue(instance.isAuthorizedForService("/services/ServiceC"));

			assertFalse(instance.isAuthorizedForService("/test/ridiculous"));

			auth.setCurrentUser(auth.getUserByAccountName("testuser2"));
			assertFalse(instance.isAuthorizedForService("/services/ServiceA"));
			assertTrue(instance.isAuthorizedForService("/services/ServiceB"));
			assertFalse(instance.isAuthorizedForService("/services/ServiceF"));
			assertFalse(instance.isAuthorizedForService("/test/ridiculous"));

			auth.setCurrentUser(auth.getUserByAccountName("testuser3"));
			assertTrue(instance.isAuthorizedForService("/services/ServiceA"));
			assertTrue(instance.isAuthorizedForService("/services/ServiceB"));
			assertFalse(instance.isAuthorizedForService("/services/ServiceE"));
			assertFalse(instance.isAuthorizedForService("/test/ridiculous"));

			try {
				instance.assertAuthorizedForService("/services/ServiceD");
				instance.assertAuthorizedForService("/test/ridiculous");
				fail();
			}
			catch(org.owasp.esapi.errors.AccessControlException e) {
				// expected
			}
		</cfscript>

	</cffunction>

</cfcomponent>