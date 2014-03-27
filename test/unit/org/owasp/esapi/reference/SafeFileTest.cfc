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
		// imports
		Utils = createObject("component", "org.owasp.esapi.util.Utils");

    	variables.CLASS = getMetaData(this);
    	variables.CLASS_NAME = listLast(variables.CLASS.name, ".");
    	/** Name of the file in the temporary directory */
    	variables.TEST_FILE_NAME = "test.file";
		variables.GOOD_FILE_CHARS = createObject("java", "org.owasp.esapi.util.CollectionsUtil").strToUnmodifiableSet("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" /* + "." */);
		variables.BAD_FILE_CHARS = createObject("java", "org.owasp.esapi.util.CollectionsUtil").strToUnmodifiableSet(Utils.toUnicode("\u0000") & /*(File.separatorChar == '/' ? '\\' : '/') +*/ "*|<>?:" /*+ "~!@#$%^&(){}[],`;"*/);

		variables.testDir = "";
		variables.testFile = "";

		variables.pathWithNullByte = "/temp/file.txt" & chr(0);

		variables.FileTestUtils = createObject("component", "esapi4cf.test.unit.org.owasp.esapi.util.FileTestUtils");
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			// create a file to test with
			variables.testDir = variables.FileTestUtils.createTmpDirectory(prefix=variables.CLASS_NAME).getCanonicalFile();
			variables.testFile = createObject("java", "java.io.File").init(variables.testDir, variables.TEST_FILE_NAME);
			variables.testFile.createNewFile();
			variables.testFile = variables.testFile.getCanonicalFile();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="tearDown" output="false">
		<cfscript>
			variables.FileTestUtils.deleteRecursively(variables.testDir);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEscapeCharactersInFilename" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var tf = "";
			var sf = "";

			System.out.println("testEscapeCharactersInFilenameInjection");
			tf = variables.testFile;
			if ( tf.exists() ) {
				System.out.println( "File is there: " & tf );
			}

			sf = createObject("java", "java.io.File").init(variables.testDir, "test^.file" );
			if ( sf.exists() ) {
				System.out.println( "  Injection allowed " & sf.getAbsolutePath() );
			} else {
				System.out.println( "  Injection didn't work " & sf.getAbsolutePath() );
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEscapeCharacterInDirectoryInjection" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var sf = "";

			System.out.println("testEscapeCharacterInDirectoryInjection");
			sf = createObject("java", "java.io.File").init(variables.testDir, "test\\^.^.\\file");
			if ( sf.exists() ) {
				System.out.println( "  Injection allowed " & sf.getAbsolutePath() );
			} else {
				System.out.println( "  Injection didn't work " & sf.getAbsolutePath() );
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testJavaFileInjectionGood" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var ch = "";
			var sf = "";

			for(i = variables.GOOD_FILE_CHARS.iterator();i.hasNext();) {
				ch = i.next().toString();	// avoids generic issues in 1.4&1.5
				sf = createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, variables.testDir, variables.TEST_FILE_NAME & ch);
				assertTrue(sf.exists(), 'File "' & variables.TEST_FILE_NAME & ch & '" should exist (ch=' & ch.charAt(0) & ').');
				sf = createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, variables.testDir, variables.TEST_FILE_NAME & ch & "test");
				assertTrue(sf.exists(), 'File "' & variables.TEST_FILE_NAME & ch & '" should exist (ch=' & ch.charAt(0) & ').');
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testJavaFileInjectionBad" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var ch = "";

			for(i = variables.BAD_FILE_CHARS.iterator();i.hasNext();) {
				ch = i.next().toString();	// avoids generic issues in 1.4&1.5
				try {
					createObject("component", "org.owasp.esapi.SafeFile").init(ESAPI=request.ESAPI, parent=variables.testDir, child=variables.TEST_FILE_NAME & ch);
					fail('Able to create SafeFile "' & variables.TEST_FILE_NAME & ch & '" (ch=' & ch.charAt(0) & ').');
				}
				catch(org.owasp.esapi.errors.ValidationException expected) { }
				try {
					createObject("component", "org.owasp.esapi.SafeFile").init(ESAPI=request.ESAPI, parent=variables.testDir, child=variables.TEST_FILE_NAME & ch  & "test");
					fail('Able to create SafeFile "' & variables.TEST_FILE_NAME & ch & '" (ch=' & ch.charAt(0) & ').');
				}
				catch(org.owasp.esapi.errors.ValidationException expected) { }
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testMultipleJavaFileInjectionGood" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var ch = "";
			var sf = "";

			for(i=variables.GOOD_FILE_CHARS.iterator();i.hasNext();) {
				ch = i.next().toString();	// avoids generic issues in 1.4&1.5
				ch = ch & ch & ch;
				sf = createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, variables.testDir, variables.TEST_FILE_NAME & ch);
				assertFalse(sf.exists(), 'File "' & variables.TEST_FILE_NAME & ch & '" should not exist (ch=' & ch.charAt(0) & ').');
				sf = createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, variables.testDir, variables.TEST_FILE_NAME & ch & "test");
				assertFalse(sf.exists(), 'File "' & variables.TEST_FILE_NAME & ch & '" should not exist (ch=' & ch.charAt(0) & ').');
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testMultipleJavaFileInjectionBad" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var ch = "";

			for(i = variables.BAD_FILE_CHARS.iterator();i.hasNext();) {
				ch = i.next().toString();	// avoids generic issues in 1.4&1.5
				ch = ch & ch & ch;
				try {
					createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, variables.testDir, variables.TEST_FILE_NAME & ch);
					fail('Able to create SafeFile "' & variables.TEST_FILE_NAME & ch & '" (ch=' & ch.charAt(0) & ').');
				}
				catch(org.owasp.esapi.errors.ValidationException expected) { }
				try {
					createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, variables.testDir, variables.TEST_FILE_NAME & ch  & "test");
					fail('Able to create SafeFile "' & variables.TEST_FILE_NAME & ch & '" (ch=' & ch.charAt(0) & ').');
				}
				catch(org.owasp.esapi.errors.ValidationException expected) { }
				i=variables.BAD_FILE_CHARS.iterator();
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testAlternateDataStream" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var sf = "";

			try {
				sf = createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, variables.testDir, variables.TEST_FILE_NAME & ":secret.txt");
				fail("Able to construct SafeFile for alternate data stream: " & sf.getPath());
			}
			catch(org.owasp.esapi.errors.ValidationException expected) { }
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="String" name="toHex" output="false">
		<cfargument required="true" type="binary" name="b">
		<cfscript>
			var hexDigit = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
			var array = [ hexDigit[(bitSHRN(arguments.b, 4)) & inputBaseN("0f", 16)], hexDigit[arguments.b & inputBaseN("0f", 16)] ];
			return toString(array);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreatePath" output="false">
		<cfscript>
			var sf = createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, variables.testFile.getPath());
			assertTrue(sf.exists());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreateParentPathName" output="false">
		<cfscript>
			var sf = createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, variables.testDir, variables.testFile.getName());
			assertTrue(sf.exists());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreateParentFileName" output="false">
		<cfscript>
			var sf = createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, variables.testFile.getParentFile(), variables.testFile.getName());
			assertTrue(sf.exists());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreateURI" output="false">
		<cfscript>
			var sf = createObject("component", "org.owasp.esapi.SafeFile").init(ESAPI=request.ESAPI, uri=variables.testFile.toURI());
			assertTrue(sf.exists());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreateFileNamePercentNull" output="false">
		<cfscript>
			try {
				createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, variables.testDir & createObject("java", "java.io.File").separator & "file%00.txt");
				fail("no exception thrown for file name with percent encoded null");
			}
			catch(org.owasp.esapi.errors.ValidationException expected) {
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreateFileNameQuestion" output="false">
		<cfscript>
			try {
				createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, variables.testFile.getParent() & createObject("java", "java.io.File").separator & "file?.txt");
				fail("no exception thrown for file name with question mark in it");
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				// expected
			}
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testCreateFileNameNull" output="false">
		<cfscript>
			var path = variables.testFile.getParent() & createObject("java", "java.io.File").separator;
			try {
				// CF seems to ignore the 'null' in strings so let's test to ensure this is always the case moving forward
				assertEquals(path & "file.txt", createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, path & "file" & chr(0) & ".txt").getPath());
				assertEquals(path & "file.txt", createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, path & "file" & javaCast("null", "") & ".txt").getPath());
				//fail("no exception thrown for file name with null in it");
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				fail("file name has null in it");
			}
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testCreateFileHighByte" output="false">
		<cfscript>
			try
			{
				createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, variables.testFile.getParent() & createObject("java", "java.io.File").separator & "file" & chr(160) & ".txt");
				fail("no exception thrown for file name with high byte in it");
			}
			catch(org.owasp.esapi.errors.ValidationException e)
			{
				// expected
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreateParentPercentNull" output="false">
		<cfscript>
			try
			{
				createObject("component", "org.owasp.esapi.SafeFile").init(request.ESAPI, variables.testFile.getParent() & createObject("java", "java.io.File").separator & "file%00.txt");
				fail("no exception thrown for file name with percent encoded null");
			}
			catch(org.owasp.esapi.errors.ValidationException e)
			{
				// expected
			}
		</cfscript>
	</cffunction>


</cfcomponent>
