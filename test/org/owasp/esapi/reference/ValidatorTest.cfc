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

	<cffunction access="public" returntype="void" name="testIsValidCreditCard" output="false"
	            hint="Test of isValidCreditCard method, of class org.owasp.esapi.Validator.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = variables.ESAPI.validator();

			System.out.println("isValidCreditCard");
			assertTrue(instance.isValidCreditCard("test", "1234 9876 0000 0008", false));
			assertTrue(instance.isValidCreditCard("test", "1234987600000008", false));
			assertFalse(instance.isValidCreditCard("test", "12349876000000081", false));
			assertFalse(instance.isValidCreditCard("test", "4417 1234 5678 9112", false));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidInput" output="false"
	            hint="Test of isValidEmailAddress method, of class org.owasp.esapi.Validator.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = variables.ESAPI.validator();

			System.out.println("isValidInput");
			assertTrue(instance.isValidInput("test", "jeff.williams@aspectsecurity.com", "Email", 100, false));
			assertFalse(instance.isValidInput("test", "jeff.williams@@aspectsecurity.com", "Email", 100, false));
			assertFalse(instance.isValidInput("test", "jeff.williams@aspectsecurity", "Email", 100, false));
			assertTrue(instance.isValidInput("test", "123.168.100.234", "IPAddress", 100, false));
			assertTrue(instance.isValidInput("test", "192.168.1.234", "IPAddress", 100, false));
			assertFalse(instance.isValidInput("test", "..168.1.234", "IPAddress", 100, false));
			assertFalse(instance.isValidInput("test", "10.x.1.234", "IPAddress", 100, false));
			assertTrue(instance.isValidInput("test", "http://www.aspectsecurity.com", "URL", 100, false));
			assertFalse(instance.isValidInput("test", "http:///www.aspectsecurity.com", "URL", 100, false));
			assertFalse(instance.isValidInput("test", "http://www.aspect security.com", "URL", 100, false));
			assertTrue(instance.isValidInput("test", "078-05-1120", "SSN", 100, false));
			assertTrue(instance.isValidInput("test", "078 05 1120", "SSN", 100, false));
			assertTrue(instance.isValidInput("test", "078051120", "SSN", 100, false));
			assertFalse(instance.isValidInput("test", "987-65-4320", "SSN", 100, false));
			assertFalse(instance.isValidInput("test", "000-00-0000", "SSN", 100, false));
			assertFalse(instance.isValidInput("test", "(555) 555-5555", "SSN", 100, false));
			assertFalse(instance.isValidInput("test", "test", "SSN", 100, false));

			try {
				// Railo 4.1 has full NULL support
				assertTrue( instance.isValidInput( "test", javaCast("null", ""), "Email", 100, true ) );
				assertFalse( instance.isValidInput( "test", javaCast("null", ""), "Email", 100, false ) );
			}
			catch (application e) {
				// fails if NULL support is not available - just skip
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidSafeHTML" output="false"
	            hint="Test of isValidSafeHTML method, of class org.owasp.esapi.Validator.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = variables.ESAPI.validator();

			System.out.println("isValidSafeHTML");

			assertTrue(instance.isValidSafeHTML("test", "<b>Jeff</b>", 100, false));
			assertTrue(instance.isValidSafeHTML("test", '<a href="http://www.aspectsecurity.com">Aspect Security</a>', 100, false));
			assertFalse(instance.isValidSafeHTML("test", "Test. <script>alert(document.cookie)</script>", 100, false));

			// TODO: waiting for a way to validate text headed for an attribute for scripts
			// This would be nice to catch, but just looks like text to AntiSamy
			// assertFalse(instance.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetValidSafeHTML" output="false"
	            hint="Test of getValidSafeHTML method, of class org.owasp.esapi.Validator.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var test1 = "";
			var result1 = "";
			var test2 = "";
			var result2 = "";
			var test3 = "";
			var result3 = "";

			System.out.println("getValidSafeHTML");
			instance = variables.ESAPI.validator();
			test1 = "<b>Jeff</b>";
			result1 = instance.getValidSafeHTML("test", test1, 100, false);
			assertEquals(test1, result1);

			test2 = '<a href="http://www.aspectsecurity.com">Aspect Security</a>';
			result2 = instance.getValidSafeHTML("test", test2, 100, false);
			assertEquals(test2, result2);

			test3 = "Test. <script>alert(document.cookie)</script>";
			result3 = instance.getValidSafeHTML("test", test3, 100, false);
			assertEquals("Test.", result3);

			// TODO: ENHANCE waiting for a way to validate text headed for an attribute for scripts
			// This would be nice to catch, but just looks like text to AntiSamy
			// assertFalse(instance.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
			// String result4 = instance.getValidSafeHTML("test", test4);
			// assertEquals("", result4);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidListItem" output="false"
	            hint="Test of isValidListItem method, of class org.owasp.esapi.Validator.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = variables.ESAPI.validator();
			var list = [];

			System.out.println("isValidListItem");
			list.add("one");
			list.add("two");
			assertTrue(instance.isValidListItem("test", "one", list));
			assertFalse(instance.isValidListItem("test", "three", list));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidNumber" output="false"
	            hint="Test of isValidNumber method, of class org.owasp.esapi.Validator.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = variables.ESAPI.validator();

			System.out.println("isValidNumber");
			//testing negative range
			assertFalse(instance.isValidNumber("test", "-4", 1, 10, false));
			assertTrue(instance.isValidNumber("test", "-4", -10, 10, false));
			//testing null value
			try {
				// Railo 4.1 has full NULL support
				assertTrue( instance.isValidNumber( "test", javaCast("null", ""), -10, 10, true ) );
				assertFalse( instance.isValidNumber( "test", javaCast("null", ""), -10, 10, false ) );
			}
			catch (application e) {
				// fails if NULL support is not available - just skip
			}
			//testing empty string
			assertTrue(instance.isValidNumber("test", "", -10, 10, true));
			assertFalse(instance.isValidNumber("test", "", -10, 10, false));
			//testing improper range
			assertFalse(instance.isValidNumber("test", "5", 10, -10, false));
			//testing non-integers
			assertTrue(instance.isValidNumber("test", "4.3214", -10, 10, true));
			assertTrue(instance.isValidNumber("test", "-1.65", -10, 10, true));
			//other testing
			assertTrue(instance.isValidNumber("test", "4", 1, 10, false));
			assertTrue(instance.isValidNumber("test", "400", 1, 10000, false));
			assertTrue(instance.isValidNumber("test", "400000000", 1, 400000000, false));
			assertFalse(instance.isValidNumber("test", "4000000000000", 1, 10000, false));
			assertFalse(instance.isValidNumber("test", "alsdkf", 10, 10000, false));
			assertFalse(instance.isValidNumber("test", "--10", 10, 10000, false));
			assertFalse(instance.isValidNumber("test", "14.1414234x", 10, 10000, false));
			assertFalse(instance.isValidNumber("test", "Infinity", 10, 10000, false));
			assertFalse(instance.isValidNumber("test", "-Infinity", 10, 10000, false));
			assertFalse(instance.isValidNumber("test", "NaN", 10, 10000, false));
			assertFalse(instance.isValidNumber("test", "-NaN", 10, 10000, false));
			assertFalse(instance.isValidNumber("test", "+NaN", 10, 10000, false));
			assertTrue(instance.isValidNumber("test", "1e-6", -999999999, 999999999, false));
			assertTrue(instance.isValidNumber("test", "-1e-6", -999999999, 999999999, false));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidInteger" output="false"
	            hint="">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = variables.ESAPI.validator();

			System.out.println("isValidInteger");
			//testing negative range
			assertFalse(instance.isValidInteger("test", "-4", 1, 10, false));
			assertTrue(instance.isValidInteger("test", "-4", -10, 10, false));
			//testing null value
			try {
				// Railo 4.1 has full NULL support
				assertTrue(instance.isValidInteger("test", javaCast("null", ""), -10, 10, true));
				assertFalse(instance.isValidInteger("test", javaCast("null", ""), -10, 10, false));
			}
			catch (application e) {
				// fails if NULL support is not available - just skip
			}
			//testing empty string
			assertTrue(instance.isValidInteger("test", "", -10, 10, true));
			assertFalse(instance.isValidInteger("test", "", -10, 10, false));
			//testing improper range
			assertFalse(instance.isValidInteger("test", "5", 10, -10, false));
			//testing non-integers
			assertFalse(instance.isValidInteger("test", "4.3214", -10, 10, true));
			assertFalse(instance.isValidInteger("test", "-1.65", -10, 10, true));
			//other testing
			assertTrue(instance.isValidInteger("test", "4", 1, 10, false));
			assertTrue(instance.isValidInteger("test", "400", 1, 10000, false));
			assertTrue(instance.isValidInteger("test", "400000000", 1, 400000000, false));
			assertFalse(instance.isValidInteger("test", "4000000000000", 1, 10000, false));
			assertFalse(instance.isValidInteger("test", "alsdkf", 10, 10000, false));
			assertFalse(instance.isValidInteger("test", "--10", 10, 10000, false));
			assertFalse(instance.isValidInteger("test", "14.1414234x", 10, 10000, false));
			assertFalse(instance.isValidInteger("test", "Infinity", 10, 10000, false));
			assertFalse(instance.isValidInteger("test", "-Infinity", 10, 10000, false));
			assertFalse(instance.isValidInteger("test", "NaN", 10, 10000, false));
			assertFalse(instance.isValidInteger("test", "-NaN", 10, 10000, false));
			assertFalse(instance.isValidInteger("test", "+NaN", 10, 10000, false));
			assertFalse(instance.isValidInteger("test", "1e-6", -999999999, 999999999, false));
			assertFalse(instance.isValidInteger("test", "-1e-6", -999999999, 999999999, false));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetValidDate" output="false"
	            hint="Test of getValidDate method, of class org.owasp.esapi.Validator.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = variables.ESAPI.validator();
			var errors = createObject("component", "org.owasp.esapi.ValidationErrorList").init();

			System.out.println("getValidDate");
			assertTrue(instance.getValidDate("test", "June 23, 1967", newJava("java.text.DateFormat").getDateInstance(newJava("java.text.DateFormat").MEDIUM, newJava("java.util.Locale").US), false) != "");
			instance.getValidDate("test", "freakshow", newJava("java.text.DateFormat").getDateInstance(), false, errors);
			assertEquals(1, errors.size());

			// This test case fails due to an apparent bug in SimpleDateFormat
			try {
				instance.getValidDate("test", "June 32, 2008", newJava("java.text.DateFormat").getDateInstance(), false);
				// fail();
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidFileName" output="false"
	            hint="Test of isValidFileName method, of class org.owasp.esapi.Validator.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = variables.ESAPI.validator();

			System.out.println("isValidFileName");
			assertTrue(instance.isValidFileName("test", "aspect.jar", false));
			assertFalse(instance.isValidFileName("test", "", false));
			try {
				instance.isValidFileName("test", "abc/def", false);
			}
			catch(org.owasp.esapi.errors.IntrusionException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidDirectoryPath" output="false"
	            hint="Test of isValidDirectoryPath method, of class org.owasp.esapi.Validator.">

		<cfscript>
			// CF8 requires 'var' at the top
			var isWindows = iif(System.getProperty("os.name").indexOf("Windows") != -1, de(true), de(false));
			var instance = variables.ESAPI.validator();

			System.out.println("isValidDirectoryPath");

			if(isWindows) {
				// Windows paths that don't exist and thus should fail
				assertFalse(instance.isValidDirectoryPath("test", "C:\pathNotExist", false));
				assertFalse(instance.isValidDirectoryPath("test", "C:\jeff123", false));
				assertFalse(instance.isValidDirectoryPath("test", "C:\temp\..\etc", false));

				// Windows paths that should pass
				assertTrue(instance.isValidDirectoryPath("test", "C:\WINDOWS", false));
				assertTrue(instance.isValidDirectoryPath("test", "C:\WINDOWS\system32", false));

				// Windows file should exist but is not a directory and should fail
				assertFalse(instance.isValidDirectoryPath("test", "C:\WINDOWS\system32\cmd.exe", false));// Windows command shell
				// Unix specific paths should not pass
				assertFalse(instance.isValidDirectoryPath("test", "/tmp", false));// Unix Temporary directory
				assertFalse(instance.isValidDirectoryPath("test", "/bin/sh", false));// Unix Standard shell
				assertFalse(instance.isValidDirectoryPath("test", "/etc/config", false));
				assertFalse(instance.isValidDirectoryPath("test", "/", false));// Unix Root directory
				// Unix specific paths that should not exist or work
				assertFalse(instance.isValidDirectoryPath("test", "/etc/pathDoesNotExist", false));
				assertFalse(instance.isValidDirectoryPath("test", "/tmp/../etc", false));
			}
			else {
				// Windows paths should fail
				assertFalse(instance.isValidDirectoryPath("test", "c:\pathNotExist", false));
				assertFalse(instance.isValidDirectoryPath("test", "c:\temp\..\etc", false));

				// Standard Windows locations should fail
				assertFalse(instance.isValidDirectoryPath("test", "c:\", false));// Windows root directory
				assertFalse(instance.isValidDirectoryPath("test", "c:\Windows\temp", false));// Windows temporary directory
				assertFalse(instance.isValidDirectoryPath("test", "c:\Windows\System32\cmd.exe", false));// Windows command shell
				// Unix specific paths should pass
				assertTrue(instance.isValidDirectoryPath("test", "/", false));// Root directory
				assertTrue(instance.isValidDirectoryPath("test", "/bin", false));// Always exist directory
				// Unix specific paths that should not exist or work
				assertFalse(instance.isValidDirectoryPath("test", "/bin/sh", false));// Standard shell, not dir
				assertFalse(instance.isValidDirectoryPath("test", "/etc/pathDoesNotExist", false));
				assertFalse(instance.isValidDirectoryPath("test", "/tmp/../etc", false));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidPrintable" output="false"
	            hint="">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = variables.ESAPI.validator();

			System.out.println("isValidPrintable");
			assertTrue(instance.isValidPrintable("name", "abcDEF", 100, false));
			assertTrue(instance.isValidPrintable("name", "!@##R()*$;><()", 100, false));
			bytes = [inputBaseN("60", 16), inputBaseN("FF", 16), inputBaseN("10", 16), inputBaseN("25", 16)];
			assertFalse(instance.isValidPrintable("name", bytes, 100, false));
			assertFalse(instance.isValidPrintable("name", "%08", 100, false));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidFileContent" output="false"
	            hint="Test of isValidFileContent method, of class org.owasp.esapi.Validator.">

		<cfscript>
			// CF8 requires 'var' at the top
			var content = newJava("java.lang.String").init("This is some file content").getBytes();
			var instance = variables.ESAPI.validator();

			System.out.println("isValidFileContent");
			assertTrue(instance.isValidFileContent("test", content, 100, false));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidFileUpload" output="false"
	            hint="Test of isValidFileUpload method, of class org.owasp.esapi.Validator.">

		<cfscript>
			// CF8 requires 'var' at the top
			var isWindows = iif(System.getProperty("os.name").indexOf("Windows") != -1, de(true), de(false));
			var instance = variables.ESAPI.validator();
			var filepath = "";
			var filename = "";
			var content = "";

			System.out.println("isValidFileUpload");

			if(isWindows) {
				filepath = "C:\WINDOWS\system32";
				filename = "cmd.exe";
				content = newJava("java.lang.String").init("This is some file content").getBytes();
				assertTrue(instance.isValidFileUpload("test", filepath, filename, content, 100, false));
			}
			else {
				filepath = "/bin";
				filename = "aspect.jar";
				content = newJava("java.lang.String").init("Thisi is some file content").getBytes();
				assertTrue(instance.isValidFileUpload("test", filepath, filename, content, 100, false));

				// This will fail on MacOS X, as /etc is actually /private/etc
				// TODO: Fix canonicalization of symlinks on MacOS X
				filepath = "/etc";
				filename = "aspect.jar";
				content = newJava("java.lang.String").init("Thisi is some file content").getBytes();
				assertTrue(instance.isValidFileUpload("test", filepath, filename, content, 100, false));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidParameterSet" output="false"
	            hint="Test of isValidParameterSet method, of class org.owasp.esapi.Validator.">

		<cfscript>
			// CF8 requires 'var' at the top
			var requiredNames = "";
			var optionalNames = "";
			var httpRequest = "";
			var httpResponse = "";
			var instance = "";

			System.out.println("isValidParameterSet");

			requiredNames = [];
			requiredNames.add("p1");
			requiredNames.add("p2");
			requiredNames.add("p3");
			optionalNames = [];
			optionalNames.add("p4");
			optionalNames.add("p5");
			optionalNames.add("p6");
			httpRequest = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletRequest").init();
			httpResponse = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpServletResponse").init();
			httpRequest.addParameter("p1", "value");
			httpRequest.addParameter("p2", "value");
			httpRequest.addParameter("p3", "value");
			variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
			instance = variables.ESAPI.validator();
			assertTrue(instance.isValidHTTPRequestParameterSet("HTTPParameters", requiredNames, optionalNames));
			httpRequest.addParameter("p4", "value");
			httpRequest.addParameter("p5", "value");
			httpRequest.addParameter("p6", "value");
			assertTrue(instance.isValidHTTPRequestParameterSet("HTTPParameters", requiredNames, optionalNames));
			httpRequest.removeParameter("p1");
			assertFalse(instance.isValidHTTPRequestParameterSet("HTTPParameters", requiredNames, optionalNames));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSafeReadLine" output="false"
	            hint="Test safe read line.">

		<cfscript>
			// CF8 requires 'var' at the top
			var s = "";
			var instance = "";
			var u = "";

			System.out.println("safeReadLine");

			s = newJava("java.io.ByteArrayInputStream").init(newJava("java.lang.String").init("testString").getBytes());
			instance = variables.ESAPI.validator();
			try {
				instance.safeReadLine(s, -1);
				fail();
			}
			catch(org.owasp.esapi.errors.ValidationAvailabilityException e) {
				// Expected
			}
			s.reset();
			try {
				instance.safeReadLine(s, 4);
				fail();
			}
			catch(org.owasp.esapi.errors.ValidationAvailabilityException e) {
				// Expected
			}
			s.reset();
			try {
				u = instance.safeReadLine(s, 20);
				assertEquals("testString", u);
			}
			catch(org.owasp.esapi.errors.ValidationAvailabilityException e) {
				fail();
			}
		</cfscript>

	</cffunction>

</cfcomponent>