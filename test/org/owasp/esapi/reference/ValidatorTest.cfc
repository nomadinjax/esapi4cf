<cfcomponent extends="cfesapi.test.org.owasp.esapi.TestCase" output="false">

	<cfscript>
		instance.ESAPI = "";

		static.PREFERRED_ENCODING = "UTF-8";
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


	<cffunction access="public" returntype="void" name="testAddRule" output="false">
		<cfscript>
			local.validator = instance.ESAPI.validator();
			local.rule = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.StringValidationRule").init(instance.ESAPI, "ridiculous");
			local.validator.addRule(local.rule);
			assertEquals(local.rule, local.validator.getRule("ridiculous"));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetRule" output="false">
		<cfscript>
			local.validator = instance.ESAPI.validator();
			local.rule = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.StringValidationRule").init(instance.ESAPI, "rule");
			local.validator.addRule(local.rule);
			assertEquals(local.rule, local.validator.getRule("rule"));
			assertFalse(local.rule.toString() == local.validator.getRule("ridiculous").toString());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidCreditCard" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("getValidCreditCard");
			local.instance = instance.ESAPI.validator();
			local.errors = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");

			assertTrue(local.instance.isValidCreditCard("cctest1", "1234 9876 0000 0008", false));
			assertTrue(local.instance.isValidCreditCard("cctest2", "1234987600000008", false));
			assertFalse(local.instance.isValidCreditCard("cctest3", "12349876000000081", false));
			assertFalse(local.instance.isValidCreditCard("cctest4", "4417 1234 5678 9112", false));

			local.instance.getValidCreditCard("cctest5", "1234 9876 0000 0008", false, local.errors);
			assertEquals(0, local.errors.size());
			local.instance.getValidCreditCard("cctest6", "1234987600000008", false, local.errors);
			assertEquals(0, local.errors.size());
			local.instance.getValidCreditCard("cctest7", "12349876000000081", false, local.errors);
			assertEquals(1, local.errors.size());
			local.instance.getValidCreditCard("cctest8", "4417 1234 5678 9112", false, local.errors);
			assertEquals(2, local.errors.size());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidDate" output="false">
		<cfscript>
			DateFormat = createObject("java", "java.text.DateFormat");
			Locale = createObject("java", "java.util.Locale");

			createObject("java", "java.lang.System").out.println("getValidDate");
			local.instance = instance.ESAPI.validator();
			local.errors = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");
			assertTrue(local.instance.getValidDate("datetest1", "June 23, 1967", DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.US), false) != "");
			local.instance.getValidDate("datetest2", "freakshow", DateFormat.getDateInstance(), false, local.errors);
			assertEquals(1, local.errors.size());

			// TODO: This test case fails due to an apparent bug in SimpleDateFormat
			local.instance.getValidDate("test", "June 32, 2008", DateFormat.getDateInstance(), false, local.errors);
			// assertEquals( 2, local.errors.size() );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidDirectoryPath" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("getValidDirectoryPath");
			local.instance = instance.ESAPI.validator();
			local.errors = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");
			// find a directory that exists
			local.parent = createObject("java", "java.io.File").init("/");
			local.path = instance.ESAPI.securityConfiguration().getResourceFile("ESAPI.properties").getParentFile().getCanonicalPath();
			local.instance.getValidDirectoryPath("dirtest1", local.path, local.parent, true, local.errors);
			assertEquals(0, local.errors.size());
			local.instance.getValidDirectoryPath("dirtest2", "", local.parent, false, local.errors);
			assertEquals(1, local.errors.size());
			local.instance.getValidDirectoryPath("dirtest3", "ridicul%00ous", local.parent, false, local.errors);
			assertEquals(2, local.errors.size());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidDouble" output="false">
		<cfscript>
			Double = createObject("java", "java.lang.Double");

			createObject("java", "java.lang.System").out.println("getValidDouble");
			local.instance = instance.ESAPI.validator();
			local.errors = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");
			local.instance.getValidDouble("dtest1", "1.0", 0, 20, true, local.errors);
			assertEquals(0, local.errors.size());
			local.instance.getValidDouble("dtest2", "", 0, 20, true, local.errors);
			assertEquals(0, local.errors.size());
			local.instance.getValidDouble("dtest3", "", 0, 20, false, local.errors);
			assertEquals(1, local.errors.size());
			local.instance.getValidDouble("dtest4", "ridiculous", 0, 20, true, local.errors);
			assertEquals(2, local.errors.size());
			local.instance.getValidDouble("dtest5", "" & (Double.MAX_VALUE), 0, 20, true, local.errors);
			assertEquals(3, local.errors.size());
			local.instance.getValidDouble("dtest6", "" & (Double.MAX_VALUE & .00001), 0, 20, true, local.errors);
			assertEquals(4, local.errors.size());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidFileContent" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("getValidFileContent");
			local.instance = instance.ESAPI.validator();
			local.errors = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");
			local.bytes = "";
			try {
			   local.bytes = createObject("java", "java.lang.String").init("12345").getBytes(static.PREFERRED_ENCODING);
			}
			catch (java.io.UnsupportedEncodingException e) {
			   fail(static.PREFERRED_ENCODING & " not a supported encoding?!?!!");
			}
			local.instance.getValidFileContent("test", local.bytes, 5, true, local.errors);
			assertEquals(0, local.errors.size());
			local.instance.getValidFileContent("test", local.bytes, 4, true, local.errors);
			assertEquals(1, local.errors.size());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidFileName" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("getValidFileName");
			local.instance = instance.ESAPI.validator();
			local.errors = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");
			local.testName = "aspe%20ct.jar";
			assertEquals(local.testName, local.instance.getValidFileName("test", local.testName, instance.ESAPI.securityConfiguration().getAllowedFileExtensions(), false, local.errors), "Percent encoding is not changed");
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidInput" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("getValidInput");
			local.instance = instance.ESAPI.validator();
			local.errors = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");
			// local.instance.getValidInput(String, String, String, int, boolean, ValidationErrorList)
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidInteger" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("getValidInteger");
			local.instance = instance.ESAPI.validator();
			local.errors = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");
			// local.instance.getValidInteger(String, String, int, int, boolean, ValidationErrorList)
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidListItem" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("getValidListItem");
			local.instance = instance.ESAPI.validator();
			local.errors = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");
			// local.instance.getValidListItem(String, String, List, ValidationErrorList)
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidNumber" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("getValidNumber");
			local.instance = instance.ESAPI.validator();
			local.errors = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");
			// local.instance.getValidNumber(String, String, long, long, boolean, ValidationErrorList)
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidRedirectLocation" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("getValidRedirectLocation");
			local.instance = instance.ESAPI.validator();
			local.errors = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");
			// local.instance.getValidRedirectLocation(String, String, boolean, ValidationErrorList)
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidSafeHTML" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("getValidSafeHTML");
			local.instance = instance.ESAPI.validator();
			local.errors = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");

			// new school test case setup
			local.rule = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.HTMLValidationRule").init(instance.ESAPI, "test");
			instance.ESAPI.validator().addRule(local.rule);

			assertEquals("Test.", instance.ESAPI.validator().getRule("test").getValid("test", "Test. <script>alert(document.cookie)</script>"));

			local.test1 = "<b>Jeff</b>";
			local.result1 = local.instance.getValidSafeHTML("test", local.test1, 100, false, local.errors);
			assertEquals(local.test1, local.result1);

			local.test2 = '<a href="http://www.aspectsecurity.com">Aspect Security</a>';
			local.result2 = local.instance.getValidSafeHTML("test", local.test2, 100, false, local.errors);
			assertEquals(local.test2, local.result2);

			local.test3 = "Test. <script>alert(document.cookie)</script>";
			assertEquals("Test.", local.rule.getSafe("test", local.test3));

			assertEquals("Test. &lt;<div>load=alert()</div>", local.rule.getSafe("test", "Test. <<div on<script></script>load=alert()"));
			assertEquals("Test. <div>b</div>", local.rule.getSafe("test", "Test. <div style={xss:expression(xss)}>b</div>"));
			assertEquals("Test.", local.rule.getSafe("test", "Test. <s%00cript>alert(document.cookie)</script>"));
			assertEquals("Test. alert(document.cookie)", local.rule.getSafe("test", "Test. <s\tcript>alert(document.cookie)</script>"));
			assertEquals("Test. alert(document.cookie)", local.rule.getSafe("test", "Test. <s\tcript>alert(document.cookie)</script>"));
			// TODO: ENHANCE waiting for a way to validate text headed for an attribute for scripts
			// This would be nice to catch, but just looks like text to AntiSamy
			// assertFalse(local.instance.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
			// String result4 = local.instance.getValidSafeHTML("test", test4);
			// assertEquals("", result4);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsInvalidFilename" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("testIsInvalidFilename");
			local.instance = instance.ESAPI.validator();
			local.invalidChars = createObject("java", "java.lang.String").init('/\:*?"<>|').toCharArray();
			for (local.i = 1; local.i <= arrayLen(local.invalidChars); local.i++) {
			   assertFalse(local.instance.isValidFileName(context="test", input="as" & local.invalidChars[local.i] & "pect.jar", allowNull=false), local.invalidChars[local.i] & " is an invalid character for a filename");
			}
			assertFalse(local.instance.isValidFileName(context="test", input="", allowNull=false), "Files must have an extension");
			assertFalse(local.instance.isValidFileName(context="test.invalidExtension", input="", allowNull=false), "Files must have a valid extension");
			assertFalse(local.instance.isValidFileName(context="test", input="", allowNull=false), "Filennames cannot be the empty string");
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidDate" output="false">
		<cfscript>
			SimpleDateFormat = createObject("java", "java.text.SimpleDateFormat");

			createObject("java", "java.lang.System").out.println("isValidDate");
			local.instance = instance.ESAPI.validator();
			local.format = SimpleDateFormat.getDateInstance();
			assertTrue(local.instance.isValidDate("datetest1", "September 11, 2001", local.format, true));
			assertFalse(local.instance.isValidDate("datetest2", "", local.format, false));
			assertFalse(local.instance.isValidDate("datetest3", "", local.format, false));
   		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidDirectoryPath" output="false">
		<cfscript>
			ioFile = createObject("java", "java.io.File");

			createObject("java", "java.lang.System").out.println("isValidDirectoryPath");

			// get an encoder with a special list of codecs and make a validator out of it
			local.list = [];
			local.list.add("HTMLEntityCodec");
			local.encoder = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultEncoder").init(instance.ESAPI, local.list);
			local.instance = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultValidator").init(instance.ESAPI, local.encoder);

			local.isWindows = (createObject("java", "java.lang.System").getProperty("os.name").indexOf("Windows") != -1) ? true : false;
			local.parent = ioFile.init("/");

			if (local.isWindows) {
				local.sysRoot = ioFile.init(createObject("java", "java.lang.System").getenv("SystemRoot")).getCanonicalPath();
				// Windows paths that don't exist and thus should fail
				assertFalse(local.instance.isValidDirectoryPath("test", "c:\ridiculous", local.parent, false));
				assertFalse(local.instance.isValidDirectoryPath("test", "c:\jeff", local.parent, false));
				assertFalse(local.instance.isValidDirectoryPath("test", "c:\temp\..\etc", local.parent, false));

				// Windows paths
				assertTrue(local.instance.isValidDirectoryPath("test", "C:\", local.parent, false));                        // Windows root directory
				assertTrue(local.instance.isValidDirectoryPath("test", local.sysRoot, local.parent, false));                  // Windows always exist directory
				assertFalse(local.instance.isValidDirectoryPath("test", local.sysRoot & "\System32\cmd.exe", local.parent, false));      // Windows command shell

				// Unix specific paths should not pass
				assertFalse(local.instance.isValidDirectoryPath("test", "/tmp", local.parent, false));      // Unix Temporary directory
				assertFalse(local.instance.isValidDirectoryPath("test", "/bin/sh", local.parent, false));   // Unix Standard shell
				assertFalse(local.instance.isValidDirectoryPath("test", "/etc/config", parent, false));

				// Unix specific paths that should not exist or work
				assertFalse(local.instance.isValidDirectoryPath("test", "/etc/ridiculous", local.parent, false));
				assertFalse(local.instance.isValidDirectoryPath("test", "/tmp/../etc", local.parent, false));
			}
			else {
				// Windows paths should fail
				assertFalse(local.instance.isValidDirectoryPath("test", "c:\ridiculous", local.parent, false));
				assertFalse(local.instance.isValidDirectoryPath("test", "c:\temp\..\etc", local.parent, false));

				// Standard Windows locations should fail
				assertFalse(local.instance.isValidDirectoryPath("test", "c:\", local.parent, false));                        // Windows root directory
				assertFalse(local.instance.isValidDirectoryPath("test", "c:\Windows\temp", local.parent, false));               // Windows temporary directory
				assertFalse(local.instance.isValidDirectoryPath("test", "c:\Windows\System32\cmd.exe", local.parent, false));   // Windows command shell

				// Unix specific paths should pass
				assertTrue(local.instance.isValidDirectoryPath("test", "/", local.parent, false));         // Root directory
				assertTrue(local.instance.isValidDirectoryPath("test", "/bin", local.parent, false));      // Always exist directory

				// Unix specific paths that should not exist or work
				assertFalse(local.instance.isValidDirectoryPath("test", "/bin/sh", local.parent, false));   // Standard shell, not dir
				assertFalse(local.instance.isValidDirectoryPath("test", "/etc/ridiculous", local.parent, false));
				assertFalse(local.instance.isValidDirectoryPath("test", "/tmp/../etc", local.parent, false));
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidDouble" output="false">
		<cfscript>
			// isValidDouble(String, String, double, double, boolean)
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidFileContent" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("isValidFileContent");
			local.content = "";
			try {
			   local.content = createObject("java", "java.lang.String").init("This is some file content").getBytes(static.PREFERRED_ENCODING);
			}
			catch (java.io.UnsupportedEncodingException e) {
			   fail(static.PREFERRED_ENCODING & " not a supported encoding?!?!!!");
			}
			local.instance = instance.ESAPI.validator();
			assertTrue(local.instance.isValidFileContent("test", local.content, 100, false));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidFileName" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("isValidFileName");
			local.instance = instance.ESAPI.validator();
			assertTrue(local.instance.isValidFileName(context="test", input="aspect.jar", allowNull=false), "Simple valid filename with a valid extension");
			assertTrue(local.instance.isValidFileName(context="test", input="!@##$%^&{}[]()_+-=,.~'` abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.jar", allowNull=false), "All valid filename characters are accepted");
			assertTrue(local.instance.isValidFileName(context="test", input="aspe%20ct.jar", allowNull=false), "Legal filenames that decode to legal filenames are accepted");
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidFileUpload" output="false">
		<cfscript>
			ioFile = createObject("java", "java.io.File");

			createObject("java", "java.lang.System").out.println("isValidFileUpload");
			local.filepath = ioFile.init(createObject("java", "java.lang.System").getProperty("user.dir")).getCanonicalPath();
			local.filename = "aspect.jar";
			local.parent = ioFile.init("/").getCanonicalFile();
			local.content = "";
			try {
			   local.content = createObject("java", "java.lang.String").init("This is some file content").getBytes(static.PREFERRED_ENCODING);
			}
			catch (java.io.UnsupportedEncodingException e) {
			   fail(static.PREFERRED_ENCODING & " not a supported encoding?!?!!!");
			}
			local.instance = instance.ESAPI.validator();
			assertTrue(local.instance.isValidFileUpload("test", local.filepath, local.filename, local.parent, local.content, 100, false));

			local.filepath = "/ridiculous";
			local.filename = "aspect.jar";
			try {
			   local.content = createObject("java", "java.lang.String").init("This is some file content").getBytes(static.PREFERRED_ENCODING);
			}
			catch (java.io.UnsupportedEncodingException e) {
			   fail(static.PREFERRED_ENCODING & " not a supported encoding?!?!!!");
			}
			assertFalse(local.instance.isValidFileUpload("test", local.filepath, local.filename, local.parent, local.content, 100, false));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidHTTPRequestParameterSet" output="false">
		<cfscript>
			//		isValidHTTPRequestParameterSet(String, Set, Set)
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testisValidInput" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("isValidInput");
			local.instance = instance.ESAPI.validator();
			assertTrue(local.instance.isValidInput("test", "jeff.williams@aspectsecurity.com", "Email", 100, false));
			assertFalse(local.instance.isValidInput("test", "jeff.williams@@aspectsecurity.com", "Email", 100, false));
			assertFalse(local.instance.isValidInput("test", "jeff.williams@aspectsecurity", "Email", 100, false));
			assertTrue(local.instance.isValidInput("test", "123.168.100.234", "IPAddress", 100, false));
			assertTrue(local.instance.isValidInput("test", "192.168.1.234", "IPAddress", 100, false));
			assertFalse(local.instance.isValidInput("test", "..168.1.234", "IPAddress", 100, false));
			assertFalse(local.instance.isValidInput("test", "10.x.1.234", "IPAddress", 100, false));
			assertTrue(local.instance.isValidInput("test", "http://www.aspectsecurity.com", "URL", 100, false));
			assertFalse(local.instance.isValidInput("test", "http:///www.aspectsecurity.com", "URL", 100, false));
			assertFalse(local.instance.isValidInput("test", "http://www.aspect security.com", "URL", 100, false));
			assertTrue(local.instance.isValidInput("test", "078-05-1120", "SSN", 100, false));
			assertTrue(local.instance.isValidInput("test", "078 05 1120", "SSN", 100, false));
			assertTrue(local.instance.isValidInput("test", "078051120", "SSN", 100, false));
			assertFalse(local.instance.isValidInput("test", "987-65-4320", "SSN", 100, false));
			assertFalse(local.instance.isValidInput("test", "000-00-0000", "SSN", 100, false));
			assertFalse(local.instance.isValidInput("test", "(555) 555-5555", "SSN", 100, false));
			assertFalse(local.instance.isValidInput("test", "test", "SSN", 100, false));

			assertTrue(local.instance.isValidInput("test", "", "Email", 100, true));
			assertFalse(local.instance.isValidInput("test", "", "Email", 100, false));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidInteger" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("isValidInteger");
			local.instance = instance.ESAPI.validator();
			//testing negative range
			assertFalse(local.instance.isValidInteger("test", "-4", 1, 10, false));
			assertTrue(local.instance.isValidInteger("test", "-4", -10, 10, false));
			//testing empty value
			assertTrue(local.instance.isValidInteger("test", "", -10, 10, true));
			assertFalse(local.instance.isValidInteger("test", "", -10, 10, false));
			//testing empty string
			assertTrue(local.instance.isValidInteger("test", "", -10, 10, true));
			assertFalse(local.instance.isValidInteger("test", "", -10, 10, false));
			//testing improper range
			assertFalse(local.instance.isValidInteger("test", "50", 10, -10, false));
			//testing non-integers
			assertFalse(local.instance.isValidInteger("test", "4.3214", -10, 10, true));
			assertFalse(local.instance.isValidInteger("test", "-1.65", -10, 10, true));
			//other testing
			assertTrue(local.instance.isValidInteger("test", "4", 1, 10, false));
			assertTrue(local.instance.isValidInteger("test", "400", 1, 10000, false));
			assertTrue(local.instance.isValidInteger("test", "400000000", 1, 400000000, false));
			assertFalse(local.instance.isValidInteger("test", "4000000000000", 1, 10000, false));
			assertFalse(local.instance.isValidInteger("test", "alsdkf", 10, 10000, false));
			assertFalse(local.instance.isValidInteger("test", "--10", 10, 10000, false));
			assertFalse(local.instance.isValidInteger("test", "14.1414234x", 10, 10000, false));
			assertFalse(local.instance.isValidInteger("test", "Infinity", 10, 10000, false));
			assertFalse(local.instance.isValidInteger("test", "-Infinity", 10, 10000, false));
			assertFalse(local.instance.isValidInteger("test", "NaN", 10, 10000, false));
			assertFalse(local.instance.isValidInteger("test", "-NaN", 10, 10000, false));
			assertFalse(local.instance.isValidInteger("test", "+NaN", 10, 10000, false));
			assertFalse(local.instance.isValidInteger("test", "1e-6", -999999999, 999999999, false));
			assertFalse(local.instance.isValidInteger("test", "-1e-6", -999999999, 999999999, false));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidListItem" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("isValidListItem");
			local.instance = instance.ESAPI.validator();
			local.list = [];
			local.list.add("one");
			local.list.add("two");
			assertTrue(local.instance.isValidListItem("test", "one", local.list));
			assertFalse(local.instance.isValidListItem("test", "three", local.list));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidNumber" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("isValidNumber");
			local.instance = instance.ESAPI.validator();
			//testing negative range
			assertFalse(local.instance.isValidNumber("test", "-4", 1, 10, false));
			assertTrue(local.instance.isValidNumber("test", "-4", -10, 10, false));
			//testing empty value
			assertTrue(local.instance.isValidNumber("test", "", -10, 10, true));
			assertFalse(local.instance.isValidNumber("test", "", -10, 10, false));
			//testing empty string
			assertTrue(local.instance.isValidNumber("test", "", -10, 10, true));
			assertFalse(local.instance.isValidNumber("test", "", -10, 10, false));
			//testing improper range
			assertFalse(local.instance.isValidNumber("test", "5", 10, -10, false));
			//testing non-integers
			assertTrue(local.instance.isValidNumber("test", "4.3214", -10, 10, true));
			assertTrue(local.instance.isValidNumber("test", "-1.65", -10, 10, true));
			//other testing
			assertTrue(local.instance.isValidNumber("test", "4", 1, 10, false));
			assertTrue(local.instance.isValidNumber("test", "400", 1, 10000, false));
			assertTrue(local.instance.isValidNumber("test", "400000000", 1, 400000000, false));
			assertFalse(local.instance.isValidNumber("test", "4000000000000", 1, 10000, false));
			assertFalse(local.instance.isValidNumber("test", "alsdkf", 10, 10000, false));
			assertFalse(local.instance.isValidNumber("test", "--10", 10, 10000, false));
			assertFalse(local.instance.isValidNumber("test", "14.1414234x", 10, 10000, false));
			assertFalse(local.instance.isValidNumber("test", "Infinity", 10, 10000, false));
			assertFalse(local.instance.isValidNumber("test", "-Infinity", 10, 10000, false));
			assertFalse(local.instance.isValidNumber("test", "NaN", 10, 10000, false));
			assertFalse(local.instance.isValidNumber("test", "-NaN", 10, 10000, false));
			assertFalse(local.instance.isValidNumber("test", "+NaN", 10, 10000, false));
			assertTrue(local.instance.isValidNumber("test", "1e-6", -999999999, 999999999, false));
			assertTrue(local.instance.isValidNumber("test", "-1e-6", -999999999, 999999999, false));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidParameterSet" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("isValidParameterSet");
			local.requiredNames = [];
			local.requiredNames.add("p1");
			local.requiredNames.add("p2");
			local.requiredNames.add("p3");
			local.optionalNames = [];
			local.optionalNames.add("p4");
			local.optionalNames.add("p5");
			local.optionalNames.add("p6");
			local.request = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest");
			local.response = createObject("component", "cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse");
			local.request.addParameter("p1", "value");
			local.request.addParameter("p2", "value");
			local.request.addParameter("p3", "value");
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			local.instance = instance.ESAPI.validator();
			assertTrue(local.instance.isValidHTTPRequestParameterSet("HTTPParameters", local.request, local.requiredNames, local.optionalNames));
			local.request.addParameter("p4", "value");
			local.request.addParameter("p5", "value");
			local.request.addParameter("p6", "value");
			assertTrue(local.instance.isValidHTTPRequestParameterSet("HTTPParameters", local.request, local.requiredNames, local.optionalNames));
			local.request.removeParameter("p1");
			assertFalse(local.instance.isValidHTTPRequestParameterSet("HTTPParameters", local.request, local.requiredNames, local.optionalNames));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidPrintable" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("isValidPrintable");
			local.instance = instance.ESAPI.validator();
			assertTrue(local.instance.isValidPrintable("name", "abcDEF", 100, false));
			assertTrue(local.instance.isValidPrintable("name", "!@##R()*$;><()", 100, false));
			local.chars = [inputBaseN("60", 16), inputBaseN("FF", 16), inputBaseN("10", 16), inputBaseN("25", 16)];
			assertFalse(local.instance.isValidPrintable("name", local.chars, 100, false));
			assertFalse(local.instance.isValidPrintable("name", [inputBaseN("08", 16)], 100, false));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidRedirectLocation" output="false">
		<cfscript>
			//		isValidRedirectLocation(String, String, boolean)
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidSafeHTML" output="false">
		<cfscript>
			createObject("java", "java.lang.System").out.println("isValidSafeHTML");
			local.instance = instance.ESAPI.validator();

			assertTrue(local.instance.isValidSafeHTML("test", "<b>Jeff</b>", 100, false));
			assertTrue(local.instance.isValidSafeHTML("test", '<a href="http://www.aspectsecurity.com">Aspect Security</a>', 100, false));
			assertTrue(local.instance.isValidSafeHTML("test", "Test. <script>alert(document.cookie)</script>", 100, false));
			assertTrue(local.instance.isValidSafeHTML("test", "Test. <div style={xss:expression(xss)}>", 100, false));
			assertTrue(local.instance.isValidSafeHTML("test", "Test. <s%00cript>alert(document.cookie)</script>", 100, false));
			assertTrue(local.instance.isValidSafeHTML("test", "Test. <s\tcript>alert(document.cookie)</script>", 100, false));
			assertTrue(local.instance.isValidSafeHTML("test", "Test. <s\r\n\0cript>alert(document.cookie)</script>", 100, false));

			// TODO: waiting for a way to validate text headed for an attribute for scripts
			// This would be nice to catch, but just looks like text to AntiSamy
			// assertFalse(local.instance.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testSafeReadLine" output="false">
		<cfscript>
			ByteArrayInputStream = createObject("java", "java.io.ByteArrayInputStream");
			InputStreamReader = createObject("java", "java.io.InputStreamReader");
			BufferedReader = createObject("java", "java.io.BufferedReader");

			createObject("java", "java.lang.System").out.println("safeReadLine");

			local.bytes = "";
			try {
			   local.bytes = createObject("java", "java.lang.String").init("testString").getBytes(static.PREFERRED_ENCODING);
			}
			catch (java.io.UnsupportedEncodingException e1) {
			   fail(static.PREFERRED_ENCODING & " not a supported encoding?!?!!!");
			}
			local.s = ByteArrayInputStream.init(local.bytes);
			local.instance = instance.ESAPI.validator();
			try {
			   local.instance.safeReadLine(local.s, -1);
			   fail();
			}
			catch (cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException e) {
			   // Expected
			}
			local.s.reset();
			try {
			   local.instance.safeReadLine(local.s, 4);
			   fail();
			}
			catch (cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException e) {
			   // Expected
			}
			local.s.reset();
			try {
			   local.u = local.instance.safeReadLine(local.s, 20);
			   assertEquals("testString", local.u);
			}
			catch (cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException e) {
			   fail();
			}

			// This sub-test attempts to validate that BufferedReader.readLine() and safeReadLine() are similar in operation
			// for the nominal case
			try {
			   local.s.reset();
			   local.isr = InputStreamReader.init(local.s);
			   local.br = BufferedReader.init(local.isr);
			   local.u = local.br.readLine();
			   local.s.reset();
			   local.v = local.instance.safeReadLine(local.s, 20);
			   assertEquals(local.u, local.v);
			}
			catch (java.io.IOException e) {
			   fail();
			}
			catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
			   fail();
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIssue82_SafeString_Bad_Regex" output="false">
		<cfscript>
			local.instance = instance.ESAPI.validator();
			try {
			   local.instance.getValidInput("address", "55 main st. pasadena ak", "SafeString", 512, false);
			}
			catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
			   fail(e.getLogMessage());
			}
		</cfscript>
	</cffunction>


</cfcomponent>
