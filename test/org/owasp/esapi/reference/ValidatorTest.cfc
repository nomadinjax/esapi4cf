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
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 --->
<cfcomponent extends="cfesapi.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		System = getJava( "java.lang.System" );
		instance.ESAPI = createObject( "component", "cfesapi.org.owasp.esapi.ESAPI" ).init();
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			structClear( request );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidCreditCard" output="false"
	            hint="Test of isValidCreditCard method, of class org.owasp.esapi.Validator.">

		<cfscript>
			System.out.println( "isValidCreditCard" );
			local.validator = instance.ESAPI.validator();
			assertTrue( local.validator.isValidCreditCard( "test", "1234 9876 0000 0008", false ) );
			assertTrue( local.validator.isValidCreditCard( "test", "1234987600000008", false ) );
			assertFalse( local.validator.isValidCreditCard( "test", "12349876000000081", false ) );
			assertFalse( local.validator.isValidCreditCard( "test", "4417 1234 5678 9112", false ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidInput" output="false"
	            hint="Test of isValidEmailAddress method, of class org.owasp.esapi.Validator.">

		<cfscript>
			System.out.println( "isValidInput" );
			local.validator = instance.ESAPI.validator();
			assertTrue( local.validator.isValidInput( "test", "jeff.williams@aspectsecurity.com", "Email", 100, false ) );
			assertFalse( local.validator.isValidInput( "test", "jeff.williams@@aspectsecurity.com", "Email", 100, false ) );
			assertFalse( local.validator.isValidInput( "test", "jeff.williams@aspectsecurity", "Email", 100, false ) );
			assertTrue( local.validator.isValidInput( "test", "123.168.100.234", "IPAddress", 100, false ) );
			assertTrue( local.validator.isValidInput( "test", "192.168.1.234", "IPAddress", 100, false ) );
			assertFalse( local.validator.isValidInput( "test", "..168.1.234", "IPAddress", 100, false ) );
			assertFalse( local.validator.isValidInput( "test", "10.x.1.234", "IPAddress", 100, false ) );
			assertTrue( local.validator.isValidInput( "test", "http://www.aspectsecurity.com", "URL", 100, false ) );
			assertFalse( local.validator.isValidInput( "test", "http:///www.aspectsecurity.com", "URL", 100, false ) );
			assertFalse( local.validator.isValidInput( "test", "http://www.aspect security.com", "URL", 100, false ) );
			assertTrue( local.validator.isValidInput( "test", "078-05-1120", "SSN", 100, false ) );
			assertTrue( local.validator.isValidInput( "test", "078 05 1120", "SSN", 100, false ) );
			assertTrue( local.validator.isValidInput( "test", "078051120", "SSN", 100, false ) );
			assertFalse( local.validator.isValidInput( "test", "987-65-4320", "SSN", 100, false ) );
			assertFalse( local.validator.isValidInput( "test", "000-00-0000", "SSN", 100, false ) );
			assertFalse( local.validator.isValidInput( "test", "(555) 555-5555", "SSN", 100, false ) );
			assertFalse( local.validator.isValidInput( "test", "test", "SSN", 100, false ) );

			/* NULL test invalid for CF
			assertTrue( local.validator.isValidInput( "test", null, "Email", 100, true ) );
			assertFalse( local.validator.isValidInput( "test", null, "Email", 100, false ) );
			*/
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidSafeHTML" output="false"
	            hint="Test of isValidSafeHTML method, of class org.owasp.esapi.Validator.">

		<cfscript>
			System.out.println( "isValidSafeHTML" );
			local.validator = instance.ESAPI.validator();

			assertTrue( local.validator.isValidSafeHTML( "test", "<b>Jeff</b>", 100, false ) );
			assertTrue( local.validator.isValidSafeHTML( "test", '<a href="http://www.aspectsecurity.com">Aspect Security</a>', 100, false ) );
			assertFalse( local.validator.isValidSafeHTML( "test", "Test. <script>alert(document.cookie)</script>", 100, false ) );

			// TODO: waiting for a way to validate text headed for an attribute for scripts
			// This would be nice to catch, but just looks like text to AntiSamy
			// assertFalse(local.validator.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetValidSafeHTML" output="false"
	            hint="Test of getValidSafeHTML method, of class org.owasp.esapi.Validator.">

		<cfscript>
			System.out.println( "getValidSafeHTML" );
			local.validator = instance.ESAPI.validator();
			local.test1 = "<b>Jeff</b>";
			local.result1 = local.validator.getValidSafeHTML( "test", local.test1, 100, false );
			assertEquals( local.test1, local.result1 );

			local.test2 = '<a href="http://www.aspectsecurity.com">Aspect Security</a>';
			local.result2 = local.validator.getValidSafeHTML( "test", local.test2, 100, false );
			assertEquals( local.test2, local.result2 );

			local.test3 = "Test. <script>alert(document.cookie)</script>";
			local.result3 = local.validator.getValidSafeHTML( "test", local.test3, 100, false );
			assertEquals( "Test.", local.result3 );

			// TODO: ENHANCE waiting for a way to validate text headed for an attribute for scripts
			// This would be nice to catch, but just looks like text to AntiSamy
			// assertFalse(local.validator.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
			// String result4 = local.validator.getValidSafeHTML("test", test4);
			// assertEquals("", result4);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidListItem" output="false"
	            hint="Test of isValidListItem method, of class org.owasp.esapi.Validator.">

		<cfscript>
			System.out.println( "isValidListItem" );
			local.validator = instance.ESAPI.validator();
			local.list = [];
			local.list.add( "one" );
			local.list.add( "two" );
			assertTrue( local.validator.isValidListItem( "test", "one", local.list ) );
			assertFalse( local.validator.isValidListItem( "test", "three", local.list ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidNumber" output="false"
	            hint="Test of isValidNumber method, of class org.owasp.esapi.Validator.">

		<cfscript>
			System.out.println( "isValidNumber" );
			local.validator = instance.ESAPI.validator();
			//testing negative range
			assertFalse( local.validator.isValidNumber( "test", "-4", 1, 10, false ) );
			assertTrue( local.validator.isValidNumber( "test", "-4", -10, 10, false ) );
			/* NULL test not valid in CF
			//testing null value
			assertTrue( local.validator.isValidNumber( "test", null, -10, 10, true ) );
			assertFalse( local.validator.isValidNumber( "test", null, -10, 10, false ) );
			*/
			//testing empty string
			assertTrue( local.validator.isValidNumber( "test", "", -10, 10, true ) );
			assertFalse( local.validator.isValidNumber( "test", "", -10, 10, false ) );
			//testing improper range
			assertFalse( local.validator.isValidNumber( "test", "5", 10, -10, false ) );
			//testing non-integers
			assertTrue( local.validator.isValidNumber( "test", "4.3214", -10, 10, true ) );
			assertTrue( local.validator.isValidNumber( "test", "-1.65", -10, 10, true ) );
			//other testing
			assertTrue( local.validator.isValidNumber( "test", "4", 1, 10, false ) );
			assertTrue( local.validator.isValidNumber( "test", "400", 1, 10000, false ) );
			assertTrue( local.validator.isValidNumber( "test", "400000000", 1, 400000000, false ) );
			assertFalse( local.validator.isValidNumber( "test", "4000000000000", 1, 10000, false ) );
			assertFalse( local.validator.isValidNumber( "test", "alsdkf", 10, 10000, false ) );
			assertFalse( local.validator.isValidNumber( "test", "--10", 10, 10000, false ) );
			assertFalse( local.validator.isValidNumber( "test", "14.1414234x", 10, 10000, false ) );
			assertFalse( local.validator.isValidNumber( "test", "Infinity", 10, 10000, false ) );
			assertFalse( local.validator.isValidNumber( "test", "-Infinity", 10, 10000, false ) );
			assertFalse( local.validator.isValidNumber( "test", "NaN", 10, 10000, false ) );
			assertFalse( local.validator.isValidNumber( "test", "-NaN", 10, 10000, false ) );
			assertFalse( local.validator.isValidNumber( "test", "+NaN", 10, 10000, false ) );
			assertTrue( local.validator.isValidNumber( "test", "1e-6", -999999999, 999999999, false ) );
			assertTrue( local.validator.isValidNumber( "test", "-1e-6", -999999999, 999999999, false ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidInteger" output="false"
	            hint="">

		<cfscript>
			System.out.println( "isValidInteger" );
			local.validator = instance.ESAPI.validator();
			//testing negative range
			assertFalse( local.validator.isValidInteger( "test", "-4", 1, 10, false ) );
			assertTrue( local.validator.isValidInteger( "test", "-4", -10, 10, false ) );
			/* NULL test not valid for CF
			//testing null value
			assertTrue( local.validator.isValidInteger( "test", null, -10, 10, true ) );
			assertFalse( local.validator.isValidInteger( "test", null, -10, 10, false ) );
			*/
			//testing empty string
			assertTrue( local.validator.isValidInteger( "test", "", -10, 10, true ) );
			assertFalse( local.validator.isValidInteger( "test", "", -10, 10, false ) );
			//testing improper range
			assertFalse( local.validator.isValidInteger( "test", "5", 10, -10, false ) );
			//testing non-integers
			assertFalse( local.validator.isValidInteger( "test", "4.3214", -10, 10, true ) );
			assertFalse( local.validator.isValidInteger( "test", "-1.65", -10, 10, true ) );
			//other testing
			assertTrue( local.validator.isValidInteger( "test", "4", 1, 10, false ) );
			assertTrue( local.validator.isValidInteger( "test", "400", 1, 10000, false ) );
			assertTrue( local.validator.isValidInteger( "test", "400000000", 1, 400000000, false ) );
			assertFalse( local.validator.isValidInteger( "test", "4000000000000", 1, 10000, false ) );
			assertFalse( local.validator.isValidInteger( "test", "alsdkf", 10, 10000, false ) );
			assertFalse( local.validator.isValidInteger( "test", "--10", 10, 10000, false ) );
			assertFalse( local.validator.isValidInteger( "test", "14.1414234x", 10, 10000, false ) );
			assertFalse( local.validator.isValidInteger( "test", "Infinity", 10, 10000, false ) );
			assertFalse( local.validator.isValidInteger( "test", "-Infinity", 10, 10000, false ) );
			assertFalse( local.validator.isValidInteger( "test", "NaN", 10, 10000, false ) );
			assertFalse( local.validator.isValidInteger( "test", "-NaN", 10, 10000, false ) );
			assertFalse( local.validator.isValidInteger( "test", "+NaN", 10, 10000, false ) );
			assertFalse( local.validator.isValidInteger( "test", "1e-6", -999999999, 999999999, false ) );
			assertFalse( local.validator.isValidInteger( "test", "-1e-6", -999999999, 999999999, false ) );

		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetValidDate" output="false"
	            hint="Test of getValidDate method, of class org.owasp.esapi.Validator.">

		<cfscript>
			System.out.println( "getValidDate" );
			local.validator = instance.ESAPI.validator();
			assertTrue( local.validator.getValidDate( "test", "June 23, 1967", getJava( "java.text.DateFormat" ).getDateInstance( getJava( "java.text.DateFormat" ).MEDIUM, getJava( "java.util.Locale" ).US ), false ) != "" );
			try {
				local.validator.getValidDate( "test", "freakshow", getJava( "java.text.DateFormat" ).getDateInstance(), false );
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				// expected
			}

			// This test case fails due to an apparent bug in SimpleDateFormat
			try {
				local.validator.getValidDate( "test", "June 32, 2008", getJava( "java.text.DateFormat" ).getDateInstance(), false );
				// fail();
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidFileName" output="false"
	            hint="Test of isValidFileName method, of class org.owasp.esapi.Validator.">

		<cfscript>
			System.out.println( "isValidFileName" );
			local.validator = instance.ESAPI.validator();
			assertTrue( local.validator.isValidFileName( "test", "aspect.jar", false ) );
			assertFalse( local.validator.isValidFileName( "test", "", false ) );
			try {
				local.validator.isValidFileName( "test", "abc/def", false );
			}
			catch(cfesapi.org.owasp.esapi.errors.IntrusionException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidDirectoryPath" output="false"
	            hint="Test of isValidDirectoryPath method, of class org.owasp.esapi.Validator.">

		<cfscript>
			System.out.println( "isValidDirectoryPath" );

			local.isWindows = iif( System.getProperty( "os.name" ).indexOf( "Windows" ) != -1, de( true ), de( false ) );

			local.validator = instance.ESAPI.validator();
			if(local.isWindows) {
				// Windows paths that don't exist and thus should fail
				assertFalse( local.validator.isValidDirectoryPath( "test", "C:\pathNotExist", false ) );
				assertFalse( local.validator.isValidDirectoryPath( "test", "C:\jeff123", false ) );
				assertFalse( local.validator.isValidDirectoryPath( "test", "C:\temp\..\etc", false ) );

				// Windows paths that should pass
				assertTrue( local.validator.isValidDirectoryPath( "test", "C:\WINDOWS", false ) );
				assertTrue( local.validator.isValidDirectoryPath( "test", "C:\WINDOWS\system32", false ) );

				// Windows file should exist but is not a directory and should fail
				assertFalse( local.validator.isValidDirectoryPath( "test", "C:\WINDOWS\system32\cmd.exe", false ) );// Windows command shell
				// Unix specific paths should not pass
				assertFalse( local.validator.isValidDirectoryPath( "test", "/tmp", false ) );// Unix Temporary directory
				assertFalse( local.validator.isValidDirectoryPath( "test", "/bin/sh", false ) );// Unix Standard shell
				assertFalse( local.validator.isValidDirectoryPath( "test", "/etc/config", false ) );
				assertFalse( local.validator.isValidDirectoryPath( "test", "/", false ) );// Unix Root directory
				// Unix specific paths that should not exist or work
				assertFalse( local.validator.isValidDirectoryPath( "test", "/etc/pathDoesNotExist", false ) );
				assertFalse( local.validator.isValidDirectoryPath( "test", "/tmp/../etc", false ) );
			}
			else {
				// Windows paths should fail
				assertFalse( local.validator.isValidDirectoryPath( "test", "c:\pathNotExist", false ) );
				assertFalse( local.validator.isValidDirectoryPath( "test", "c:\temp\..\etc", false ) );

				// Standard Windows locations should fail
				assertFalse( local.validator.isValidDirectoryPath( "test", "c:\", false ) );// Windows root directory
				assertFalse( local.validator.isValidDirectoryPath( "test", "c:\Windows\temp", false ) );// Windows temporary directory
				assertFalse( local.validator.isValidDirectoryPath( "test", "c:\Windows\System32\cmd.exe", false ) );// Windows command shell
				// Unix specific paths should pass
				assertTrue( local.validator.isValidDirectoryPath( "test", "/", false ) );// Root directory
				assertTrue( local.validator.isValidDirectoryPath( "test", "/bin", false ) );// Always exist directory
				// Unix specific paths that should not exist or work
				assertFalse( local.validator.isValidDirectoryPath( "test", "/bin/sh", false ) );// Standard shell, not dir
				assertFalse( local.validator.isValidDirectoryPath( "test", "/etc/pathDoesNotExist", false ) );
				assertFalse( local.validator.isValidDirectoryPath( "test", "/tmp/../etc", false ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidPrintable" output="false"
	            hint="">

		<cfscript>
			System.out.println( "isValidPrintable" );
			local.validator = instance.ESAPI.validator();
			assertTrue( local.validator.isValidPrintable( "name", "abcDEF", 100, false ) );
			assertTrue( local.validator.isValidPrintable( "name", "!@##R()*$;><()", 100, false ) );
			local.bytes = [inputBaseN( "60", 16 ), inputBaseN( "FF", 16 ), inputBaseN( "10", 16 ), inputBaseN( "25", 16 )];
			assertFalse( local.validator.isValidPrintable( "name", local.bytes, 100, false ) );
			assertFalse( local.validator.isValidPrintable( "name", "%08", 100, false ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidFileContent" output="false"
	            hint="Test of isValidFileContent method, of class org.owasp.esapi.Validator.">

		<cfscript>
			System.out.println( "isValidFileContent" );
			local.content = getJava( "java.lang.String" ).init( "This is some file content" ).getBytes();
			local.validator = instance.ESAPI.validator();
			assertTrue( local.validator.isValidFileContent( "test", local.content, 100, false ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidFileUpload" output="false"
	            hint="Test of isValidFileUpload method, of class org.owasp.esapi.Validator.">

		<cfscript>
			System.out.println( "isValidFileUpload" );

			local.isWindows = iif( System.getProperty( "os.name" ).indexOf( "Windows" ) != -1, de( true ), de( false ) );

			local.validator = instance.ESAPI.validator();

			if(local.isWindows) {

				local.filepath = "C:\WINDOWS\system32";
				local.filename = "cmd.exe";
				local.content = getJava( "java.lang.String" ).init( "This is some file content" ).getBytes();
				assertTrue( local.validator.isValidFileUpload( "test", local.filepath, local.filename, local.content, 100, false ) );
			}
			else {

				local.filepath = "/bin";
				local.filename = "aspect.jar";
				local.content = getJava( "java.lang.String" ).init( "Thisi is some file content" ).getBytes();
				assertTrue( local.validator.isValidFileUpload( "test", local.filepath, local.filename, local.content, 100, false ) );

				// This will fail on MacOS X, as /etc is actually /private/etc
				// TODO: Fix canonicalization of symlinks on MacOS X
				local.filepath = "/etc";
				local.filename = "aspect.jar";
				local.content = getJava( "java.lang.String" ).init( "Thisi is some file content" ).getBytes();
				assertTrue( local.validator.isValidFileUpload( "test", local.filepath, local.filename, local.content, 100, false ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIsValidParameterSet" output="false"
	            hint="Test of isValidParameterSet method, of class org.owasp.esapi.Validator.">

		<cfscript>
			System.out.println( "isValidParameterSet" );

			local.requiredNames = [];
			local.requiredNames.add( "p1" );
			local.requiredNames.add( "p2" );
			local.requiredNames.add( "p3" );
			local.optionalNames = [];
			local.optionalNames.add( "p4" );
			local.optionalNames.add( "p5" );
			local.optionalNames.add( "p6" );
			local.request = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletRequest" ).init();
			local.response = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpServletResponse" ).init();
			local.request.addParameter( "p1", "value" );
			local.request.addParameter( "p2", "value" );
			local.request.addParameter( "p3", "value" );
			instance.ESAPI.httpUtilities().setCurrentHTTP( local.request, local.response );
			local.validator = instance.ESAPI.validator();
			assertTrue( local.validator.isValidHTTPRequestParameterSet( "HTTPParameters", local.requiredNames, local.optionalNames ) );
			local.request.addParameter( "p4", "value" );
			local.request.addParameter( "p5", "value" );
			local.request.addParameter( "p6", "value" );
			assertTrue( local.validator.isValidHTTPRequestParameterSet( "HTTPParameters", local.requiredNames, local.optionalNames ) );
			local.request.removeParameter( "p1" );
			assertFalse( local.validator.isValidHTTPRequestParameterSet( "HTTPParameters", local.requiredNames, local.optionalNames ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSafeReadLine" output="false"
	            hint="Test safe read line.">

		<cfscript>
			System.out.println( "safeReadLine" );

			local.s = getJava( "java.io.ByteArrayInputStream" ).init( getJava( "java.lang.String" ).init( "testString" ).getBytes() );
			local.validator = instance.ESAPI.validator();
			try {
				local.validator.safeReadLine( local.s, -1 );
				fail();
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException e) {
				// Expected
			}
			local.s.reset();
			try {
				local.validator.safeReadLine( local.s, 4 );
				fail();
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException e) {
				// Expected
			}
			local.s.reset();
			try {
				local.u = local.validator.safeReadLine( local.s, 20 );
				assertEquals( "testString", local.u );
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException e) {
				fail();
			}
		</cfscript>

	</cffunction>

</cfcomponent>