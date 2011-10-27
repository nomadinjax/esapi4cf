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
<cfcomponent extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false">

	<cfscript>
		instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();
	</cfscript>
 
	<cffunction access="public" returntype="void" name="testMatchRule" output="false">
		<cfscript>
			instance.ESAPI.authenticator().setCurrentUser(user=new cfesapi.org.owasp.esapi.User$ANONYMOUS(instance.ESAPI));
			assertFalse(instance.ESAPI.accessController().isAuthorizedForURL("/nobody"));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsAuthorizedForURL" output="false" hint="Test of isAuthorizedForURL method, of class org.owasp.esapi.AccessController.">
		<cfscript>
			newJava("java.lang.System").out.println("isAuthorizedForURL");
			local.accessController = instance.ESAPI.accessController();
			local.auth = instance.ESAPI.authenticator();

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user1 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user1.setRoles(["user"]);

			local.auth.setCurrentUser( user=local.user1 );
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

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user2 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user2.setRoles(["admin"]);

			local.auth.setCurrentUser( user=local.user2 );
			assertFalse(local.accessController.isAuthorizedForURL("/nobody"));
			assertTrue(local.accessController.isAuthorizedForURL("/test/admin"));
			assertFalse(local.accessController.isAuthorizedForURL("/test/user"));
			assertTrue(local.accessController.isAuthorizedForURL("/test/all"));
			assertFalse(local.accessController.isAuthorizedForURL("/test/none"));
			assertTrue(local.accessController.isAuthorizedForURL("/test/none/test.png"));
			assertFalse(local.accessController.isAuthorizedForURL("/test/moderator"));
			assertTrue(local.accessController.isAuthorizedForURL("/test/profile"));
			assertFalse(local.accessController.isAuthorizedForURL("/upload"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user3 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user3.setRoles(["user","admin"]);

			local.auth.setCurrentUser( user=local.user3 );
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
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				fail();
			}
			try {
				local.accessController.assertAuthorizedForURL( "/nobody" );
				fail();
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				// expected
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsAuthorizedForFunction" output="false" hint="Test of isAuthorizedForFunction method, of class org.owasp.esapi.AccessController.">
		<cfscript>
			newJava("java.lang.System").out.println("isAuthorizedForFunction");
			local.accessController = instance.ESAPI.accessController();
			local.auth = instance.ESAPI.authenticator();

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user1 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user1.setRoles(["user"]);

			local.auth.setCurrentUser( user=local.user1 );
			assertTrue(local.accessController.isAuthorizedForFunction("/FunctionA"));
			assertFalse(local.accessController.isAuthorizedForFunction("/FunctionAdeny"));
			assertFalse(local.accessController.isAuthorizedForFunction("/FunctionB"));
			assertFalse(local.accessController.isAuthorizedForFunction("/FunctionBdeny"));
			assertTrue(local.accessController.isAuthorizedForFunction("/FunctionC"));
			assertFalse(local.accessController.isAuthorizedForFunction("/FunctionCdeny"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user2 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user2.setRoles(["admin"]);

			local.auth.setCurrentUser( user=local.user2 );
			assertFalse(local.accessController.isAuthorizedForFunction("/FunctionA"));
			assertFalse(local.accessController.isAuthorizedForFunction("/FunctionAdeny"));
			assertTrue(local.accessController.isAuthorizedForFunction("/FunctionB"));
			assertFalse(local.accessController.isAuthorizedForFunction("/FunctionBdeny"));
			assertTrue(local.accessController.isAuthorizedForFunction("/FunctionD"));
			assertFalse(local.accessController.isAuthorizedForFunction("/FunctionDdeny"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user3 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user3.setRoles(["user","admin"]);

			local.auth.setCurrentUser( user=local.user3 );
			assertTrue(local.accessController.isAuthorizedForFunction("/FunctionA"));
			assertFalse(local.accessController.isAuthorizedForFunction("/FunctionAdeny"));
			assertTrue(local.accessController.isAuthorizedForFunction("/FunctionB"));
			assertFalse(local.accessController.isAuthorizedForFunction("/FunctionBdeny"));
			assertTrue(local.accessController.isAuthorizedForFunction("/FunctionC"));
			assertFalse(local.accessController.isAuthorizedForFunction("/FunctionCdeny"));

			try {
				local.accessController.assertAuthorizedForFunction("/FunctionA");
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				fail("");
			}

			try {
				local.accessController.assertAuthorizedForFunction( "/FunctionDdeny" );
				fail("");
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				// expected
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsAuthorizedForData" output="false" hint="Test of isAuthorizedForData method, of class org.owasp.esapi.AccessController.">
		<cfscript>
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

			try{
				local.adminR = newJava("java.util.ArrayList");
				local.adminRW = newJava("java.lang.Math");
				local.userW = newJava("java.util.Date");
				local.userRW = newJava("java.lang.String");
				local.anyR = newJava("java.io.BufferedReader");
				local.userAdminR = newJava("java.util.Random");
				local.userAdminRW = newJava("java.awt.event.MouseWheelEvent");
				local.undefined = newJava("java.io.FileWriter");

			}catch(ClassNotFoundException cnf){
				newJava("java.lang.System").out.println("CLASS NOT FOUND.");
				cnf.printStackTrace();
			}
			//test User
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user1 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user1.setRoles(["user"]);

			local.auth.setCurrentUser( user=local.user1 );
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
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user2 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user2.setRoles(["admin"]);

			local.auth.setCurrentUser( user=local.user2 );
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
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user3 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user3.setRoles(["user","admin"]);

			local.auth.setCurrentUser( user=local.user3 );
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
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				fail();
			}
			try {
				local.accessController.assertAuthorizedForData( "write", local.adminR );
				fail();
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				// expected
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsAuthorizedForFile" output="false" hint="Test of isAuthorizedForFile method, of class org.owasp.esapi.AccessController.">
		<cfscript>
			newJava("java.lang.System").out.println("isAuthorizedForFile");
			local.accessController = instance.ESAPI.accessController();
			local.auth = instance.ESAPI.authenticator();

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user1 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user1.setRoles(["user"]);

			local.auth.setCurrentUser( user=local.user1 );
			assertTrue(local.accessController.isAuthorizedForFile("/Dir/File1"));
			assertFalse(local.accessController.isAuthorizedForFile("/Dir/File2"));
			assertTrue(local.accessController.isAuthorizedForFile("/Dir/File3"));
			assertFalse(local.accessController.isAuthorizedForFile("/Dir/ridiculous"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user2 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user2.setRoles(["admin"]);

			local.auth.setCurrentUser( user=local.user2 );
			assertFalse(local.accessController.isAuthorizedForFile("/Dir/File1"));
			assertTrue(local.accessController.isAuthorizedForFile("/Dir/File2"));
			assertTrue(local.accessController.isAuthorizedForFile("/Dir/File4"));
			assertFalse(local.accessController.isAuthorizedForFile("/Dir/ridiculous"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user3 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user3.setRoles(["user","admin"]);

			local.auth.setCurrentUser( user=local.user3 );
			assertTrue(local.accessController.isAuthorizedForFile("/Dir/File1"));
			assertTrue(local.accessController.isAuthorizedForFile("/Dir/File2"));
			assertFalse(local.accessController.isAuthorizedForFile("/Dir/File5"));
			assertFalse(local.accessController.isAuthorizedForFile("/Dir/ridiculous"));

			try {
				local.accessController.assertAuthorizedForFile("/Dir/File1");
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				fail();
			}
			try {
				local.accessController.assertAuthorizedForFile( "/Dir/File6" );
				fail();
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				// expected
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsAuthorizedForService" output="false" hint="Test of isAuthorizedForService method, of class org.owasp.esapi.AccessController.">
		<cfscript>
			newJava("java.lang.System").out.println("isAuthorizedForService");
			local.accessController = instance.ESAPI.accessController();
			local.auth = instance.ESAPI.authenticator();

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user1 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user1.setRoles(["user"]);

			local.auth.setCurrentUser( user=local.user1 );
			assertTrue(local.accessController.isAuthorizedForService("/services/ServiceA"));
			assertFalse(local.accessController.isAuthorizedForService("/services/ServiceB"));
			assertTrue(local.accessController.isAuthorizedForService("/services/ServiceC"));
			assertFalse(local.accessController.isAuthorizedForService("/test/ridiculous"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user2 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user2.setRoles(["admin"]);

			local.auth.setCurrentUser( user=local.user2 );
			assertFalse(local.accessController.isAuthorizedForService("/services/ServiceA"));
			assertTrue(local.accessController.isAuthorizedForService("/services/ServiceB"));
			assertFalse(local.accessController.isAuthorizedForService("/services/ServiceF"));
			assertFalse(local.accessController.isAuthorizedForService("/test/ridiculous"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, newJava("org.owasp.esapi.Encoder").CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user3 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user3.setRoles(["user","admin"]);

			local.auth.setCurrentUser( user=local.user3 );
			assertTrue(local.accessController.isAuthorizedForService("/services/ServiceA"));
			assertTrue(local.accessController.isAuthorizedForService("/services/ServiceB"));
			assertFalse(local.accessController.isAuthorizedForService("/services/ServiceE"));
			assertFalse(local.accessController.isAuthorizedForService("/test/ridiculous"));

			try {
				local.accessController.assertAuthorizedForService("/services/ServiceD");
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				fail();
			}
			try {
				local.accessController.assertAuthorizedForService( "/test/ridiculous" );
				fail();
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				// expected
			}
		</cfscript> 
	</cffunction>


</cfcomponent>
