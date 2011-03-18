<cfcomponent extends="cfesapi.test.org.owasp.esapi.TestCase" output="false">

	<cfscript>
		System = createObject("java", "java.lang.System");
		DefaultEncoder = javaLoader().create("org.owasp.esapi.Encoder");

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


	<cffunction access="public" returntype="void" name="testMatchRule" output="false">
		<cfscript>
			instance.ESAPI.authenticator().setCurrentUser(user=createObject("component", "cfesapi.org.owasp.esapi.reference.AnonymousUser"));
			assertFalse(instance.ESAPI.accessController().isAuthorizedForURL("/nobody"));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsAuthorizedForURL" output="false" hint="Test of isAuthorizedForURL method, of class org.owasp.esapi.AccessController.">
		<cfscript>
			System.out.println("isAuthorizedForURL");
			local.instance = instance.ESAPI.accessController();
			local.auth = instance.ESAPI.authenticator();

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user1 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user1.setRoles(["user"]);

			local.auth.setCurrentUser( user=local.user1 );
			assertFalse(local.instance.isAuthorizedForURL("/nobody"));
			assertFalse(local.instance.isAuthorizedForURL("/test/admin"));
			assertTrue(local.instance.isAuthorizedForURL("/test/user"));
			assertTrue(local.instance.isAuthorizedForURL("/test/all"));
			assertFalse(local.instance.isAuthorizedForURL("/test/none"));
			assertTrue(local.instance.isAuthorizedForURL("/test/none/test.gif"));
			assertFalse(local.instance.isAuthorizedForURL("/test/none/test.exe"));
			assertTrue(local.instance.isAuthorizedForURL("/test/none/test.png"));
			assertFalse(local.instance.isAuthorizedForURL("/test/moderator"));
			assertTrue(local.instance.isAuthorizedForURL("/test/profile"));
			assertFalse(local.instance.isAuthorizedForURL("/upload"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user2 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user2.setRoles(["admin"]);

			local.auth.setCurrentUser( user=local.user2 );
			assertFalse(local.instance.isAuthorizedForURL("/nobody"));
			assertTrue(local.instance.isAuthorizedForURL("/test/admin"));
			assertFalse(local.instance.isAuthorizedForURL("/test/user"));
			assertTrue(local.instance.isAuthorizedForURL("/test/all"));
			assertFalse(local.instance.isAuthorizedForURL("/test/none"));
			assertTrue(local.instance.isAuthorizedForURL("/test/none/test.png"));
			assertFalse(local.instance.isAuthorizedForURL("/test/moderator"));
			assertTrue(local.instance.isAuthorizedForURL("/test/profile"));
			assertFalse(local.instance.isAuthorizedForURL("/upload"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user3 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user3.setRoles(["user","admin"]);

			local.auth.setCurrentUser( user=local.user3 );
			assertFalse(local.instance.isAuthorizedForURL("/nobody"));
			assertTrue(local.instance.isAuthorizedForURL("/test/admin"));
			assertTrue(local.instance.isAuthorizedForURL("/test/user"));
			assertTrue(local.instance.isAuthorizedForURL("/test/all"));
			assertFalse(local.instance.isAuthorizedForURL("/test/none"));
			assertTrue(local.instance.isAuthorizedForURL("/test/none/test.png"));
			assertFalse(local.instance.isAuthorizedForURL("/test/moderator"));
			assertTrue(local.instance.isAuthorizedForURL("/test/profile"));
			assertFalse(local.instance.isAuthorizedForURL("/upload"));

			try {
				local.instance.assertAuthorizedForURL("/test/admin");
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				fail();
			}
			try {
				local.instance.assertAuthorizedForURL( "/nobody" );
				fail();
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				// expected
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsAuthorizedForFunction" output="false" hint="Test of isAuthorizedForFunction method, of class org.owasp.esapi.AccessController.">
		<cfscript>
			System.out.println("isAuthorizedForFunction");
			local.instance = instance.ESAPI.accessController();
			local.auth = instance.ESAPI.authenticator();

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user1 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user1.setRoles(["user"]);

			local.auth.setCurrentUser( user=local.user1 );
			assertTrue(local.instance.isAuthorizedForFunction("/FunctionA"));
			assertFalse(local.instance.isAuthorizedForFunction("/FunctionAdeny"));
			assertFalse(local.instance.isAuthorizedForFunction("/FunctionB"));
			assertFalse(local.instance.isAuthorizedForFunction("/FunctionBdeny"));
			assertTrue(local.instance.isAuthorizedForFunction("/FunctionC"));
			assertFalse(local.instance.isAuthorizedForFunction("/FunctionCdeny"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user2 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user2.setRoles(["admin"]);

			local.auth.setCurrentUser( user=local.user2 );
			assertFalse(local.instance.isAuthorizedForFunction("/FunctionA"));
			assertFalse(local.instance.isAuthorizedForFunction("/FunctionAdeny"));
			assertTrue(local.instance.isAuthorizedForFunction("/FunctionB"));
			assertFalse(local.instance.isAuthorizedForFunction("/FunctionBdeny"));
			assertTrue(local.instance.isAuthorizedForFunction("/FunctionD"));
			assertFalse(local.instance.isAuthorizedForFunction("/FunctionDdeny"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user3 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user3.setRoles(["user","admin"]);

			local.auth.setCurrentUser( user=local.user3 );
			assertTrue(local.instance.isAuthorizedForFunction("/FunctionA"));
			assertFalse(local.instance.isAuthorizedForFunction("/FunctionAdeny"));
			assertTrue(local.instance.isAuthorizedForFunction("/FunctionB"));
			assertFalse(local.instance.isAuthorizedForFunction("/FunctionBdeny"));
			assertTrue(local.instance.isAuthorizedForFunction("/FunctionC"));
			assertFalse(local.instance.isAuthorizedForFunction("/FunctionCdeny"));

			try {
				local.instance.assertAuthorizedForFunction("/FunctionA");
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				fail("");
			}

			try {
				local.instance.assertAuthorizedForFunction( "/FunctionDdeny" );
				fail("");
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				// expected
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsAuthorizedForData" output="false" hint="Test of isAuthorizedForData method, of class org.owasp.esapi.AccessController.">
		<cfscript>
			System.out.println("isAuthorizedForData");
			local.instance = instance.ESAPI.accessController();
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
				local.adminR = createObject("java", "java.util.ArrayList");
				local.adminRW = createObject("java", "java.lang.Math");
				local.userW = createObject("java", "java.util.Date");
				local.userRW = createObject("java", "java.lang.String");
				local.anyR = createObject("java", "java.io.BufferedReader");
				local.userAdminR = createObject("java", "java.util.Random");
				local.userAdminRW = createObject("java", "java.awt.event.MouseWheelEvent");
				local.undefined = createObject("java", "java.io.FileWriter");

			}catch(ClassNotFoundException cnf){
				System.out.println("CLASS NOT FOUND.");
				cnf.printStackTrace();
			}
			//test User
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user1 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user1.setRoles(["user"]);

			local.auth.setCurrentUser( user=local.user1 );
			assertTrue(local.instance.isAuthorizedForData("read", local.userRW));
			assertFalse(local.instance.isAuthorizedForData("read", local.undefined));
			assertFalse(local.instance.isAuthorizedForData("write", local.undefined));
			assertFalse(local.instance.isAuthorizedForData("read", local.userW));
			assertFalse(local.instance.isAuthorizedForData("read", local.adminRW));
			assertTrue(local.instance.isAuthorizedForData("write", local.userRW));
			assertTrue(local.instance.isAuthorizedForData("write", local.userW));
			assertFalse(local.instance.isAuthorizedForData("write", local.anyR));
			assertTrue(local.instance.isAuthorizedForData("read", local.anyR));
			assertTrue(local.instance.isAuthorizedForData("read", local.userAdminR));
			assertTrue(local.instance.isAuthorizedForData("write", local.userAdminRW));

			//test Admin
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user2 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user2.setRoles(["admin"]);

			local.auth.setCurrentUser( user=local.user2 );
			assertTrue(local.instance.isAuthorizedForData("read", local.adminRW));
			assertFalse(local.instance.isAuthorizedForData("read", local.undefined));
			assertFalse(local.instance.isAuthorizedForData("write", local.undefined));
			assertFalse(local.instance.isAuthorizedForData("read", local.userRW));
			assertTrue(local.instance.isAuthorizedForData("write", local.adminRW));
			assertFalse(local.instance.isAuthorizedForData("write", local.anyR));
			assertTrue(local.instance.isAuthorizedForData("read", local.anyR));
			assertTrue(local.instance.isAuthorizedForData("read", local.userAdminR));
			assertTrue(local.instance.isAuthorizedForData("write", local.userAdminRW));

			//test User/Admin
			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user3 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user3.setRoles(["user","admin"]);

			local.auth.setCurrentUser( user=local.user3 );
			assertTrue(local.instance.isAuthorizedForData("read", local.userRW));
			assertFalse(local.instance.isAuthorizedForData("read", local.undefined));
			assertFalse(local.instance.isAuthorizedForData("write", local.undefined));
			assertFalse(local.instance.isAuthorizedForData("read", local.userW));
			assertTrue(local.instance.isAuthorizedForData("read", local.adminR));
			assertTrue(local.instance.isAuthorizedForData("write", local.userRW));
			assertTrue(local.instance.isAuthorizedForData("write", local.userW));
			assertFalse(local.instance.isAuthorizedForData("write", local.anyR));
			assertTrue(local.instance.isAuthorizedForData("read", local.anyR));
			assertTrue(local.instance.isAuthorizedForData("read", local.userAdminR));
			assertTrue(local.instance.isAuthorizedForData("write", local.userAdminRW));
			try {
				local.instance.assertAuthorizedForData("read", local.userRW);
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				fail();
			}
			try {
				local.instance.assertAuthorizedForData( "write", local.adminR );
				fail();
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				// expected
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsAuthorizedForFile" output="false" hint="Test of isAuthorizedForFile method, of class org.owasp.esapi.AccessController.">
		<cfscript>
			System.out.println("isAuthorizedForFile");
			local.instance = instance.ESAPI.accessController();
			local.auth = instance.ESAPI.authenticator();

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user1 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user1.setRoles(["user"]);

			local.auth.setCurrentUser( user=local.user1 );
			assertTrue(local.instance.isAuthorizedForFile("/Dir/File1"));
			assertFalse(local.instance.isAuthorizedForFile("/Dir/File2"));
			assertTrue(local.instance.isAuthorizedForFile("/Dir/File3"));
			assertFalse(local.instance.isAuthorizedForFile("/Dir/ridiculous"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user2 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user2.setRoles(["admin"]);

			local.auth.setCurrentUser( user=local.user2 );
			assertFalse(local.instance.isAuthorizedForFile("/Dir/File1"));
			assertTrue(local.instance.isAuthorizedForFile("/Dir/File2"));
			assertTrue(local.instance.isAuthorizedForFile("/Dir/File4"));
			assertFalse(local.instance.isAuthorizedForFile("/Dir/ridiculous"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user3 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user3.setRoles(["user","admin"]);

			local.auth.setCurrentUser( user=local.user3 );
			assertTrue(local.instance.isAuthorizedForFile("/Dir/File1"));
			assertTrue(local.instance.isAuthorizedForFile("/Dir/File2"));
			assertFalse(local.instance.isAuthorizedForFile("/Dir/File5"));
			assertFalse(local.instance.isAuthorizedForFile("/Dir/ridiculous"));

			try {
				local.instance.assertAuthorizedForFile("/Dir/File1");
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				fail();
			}
			try {
				local.instance.assertAuthorizedForFile( "/Dir/File6" );
				fail();
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				// expected
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsAuthorizedForService" output="false" hint="Test of isAuthorizedForService method, of class org.owasp.esapi.AccessController.">
		<cfscript>
			System.out.println("isAuthorizedForService");
			local.instance = instance.ESAPI.accessController();
			local.auth = instance.ESAPI.authenticator();

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user1 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user1.setRoles(["user"]);

			local.auth.setCurrentUser( user=local.user1 );
			assertTrue(local.instance.isAuthorizedForService("/services/ServiceA"));
			assertFalse(local.instance.isAuthorizedForService("/services/ServiceB"));
			assertTrue(local.instance.isAuthorizedForService("/services/ServiceC"));
			assertFalse(local.instance.isAuthorizedForService("/test/ridiculous"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user2 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user2.setRoles(["admin"]);

			local.auth.setCurrentUser( user=local.user2 );
			assertFalse(local.instance.isAuthorizedForService("/services/ServiceA"));
			assertTrue(local.instance.isAuthorizedForService("/services/ServiceB"));
			assertFalse(local.instance.isAuthorizedForService("/services/ServiceF"));
			assertFalse(local.instance.isAuthorizedForService("/test/ridiculous"));

			local.accountName = instance.ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			local.password = local.auth.generateStrongPassword();
			local.user3 = local.auth.createUser(local.accountName, local.password, local.password);
			local.user3.setRoles(["user","admin"]);

			local.auth.setCurrentUser( user=local.user3 );
			assertTrue(local.instance.isAuthorizedForService("/services/ServiceA"));
			assertTrue(local.instance.isAuthorizedForService("/services/ServiceB"));
			assertFalse(local.instance.isAuthorizedForService("/services/ServiceE"));
			assertFalse(local.instance.isAuthorizedForService("/test/ridiculous"));

			try {
				local.instance.assertAuthorizedForService("/services/ServiceD");
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				fail();
			}
			try {
				local.instance.assertAuthorizedForService( "/test/ridiculous" );
				fail();
			} catch ( cfesapi.org.owasp.esapi.errors.AccessControlException e ) {
				// expected
			}
		</cfscript>
	</cffunction>


</cfcomponent>
