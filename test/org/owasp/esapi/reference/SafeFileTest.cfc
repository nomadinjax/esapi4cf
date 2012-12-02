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
 * @author Damon Miller
 * @created 2011
--->
<cfcomponent extends="cfesapi.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		instance.ESAPI = createObject( "component", "cfesapi.org.owasp.esapi.ESAPI" ).init();

		instance.CLASS = getMetaData( this );
		instance.CLASS_NAME = listLast( instance.CLASS.name, "." );
		/** Name of the file in the temporary directory */
		instance.TEST_FILE_NAME = "test.file";
		instance.GOOD_FILE_CHARS = getJava("org.owasp.esapi.util.CollectionsUtil").strToUnmodifiableSet("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" /* + "." */);
		instance.BAD_FILE_CHARS = getJava("org.owasp.esapi.util.CollectionsUtil").strToUnmodifiableSet("\u0000" & /*(File.separatorChar == '/' ? '\\' : '/') +*/ "*|<>?:" /*+ "~!@#$%^&(){}[],`;"*/);

		instance.testDir = "";
		instance.testFile = "";

		instance.pathWithNullByte = "/temp/file.txt" & chr(0);

		instance.FileTestUtils = createObject("cfesapi.test.org.owasp.esapi.util.FileTestUtils");
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			// create a file to test with
			instance.testDir = instance.FileTestUtils.createTmpDirectory(prefix=instance.CLASS_NAME).getCanonicalFile();
			instance.testFile = getJava("java.io.File").init(instance.testDir, instance.TEST_FILE_NAME);
			instance.testFile.createNewFile();
			instance.testFile = instance.testFile.getCanonicalFile();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="tearDown" output="false">
		<cfscript>
			instance.FileTestUtils.deleteRecursively(instance.testDir);
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testEscapeCharactersInFilename" output="false">
		<cfscript>
			var local = {};

			System.out.println("testEscapeCharactersInFilenameInjection");
			local.tf = instance.testFile;
			if ( local.tf.exists() ) {
				System.out.println( "File is there: " & local.tf );
			}

			local.sf = getJava("java.io.File").init(instance.testDir, "test^.file" );
			if ( local.sf.exists() ) {
				System.out.println( "  Injection allowed " & local.sf.getAbsolutePath() );
			} else {
				System.out.println( "  Injection didn't work " & local.sf.getAbsolutePath() );
			}
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testEscapeCharacterInDirectoryInjection" output="false">
		<cfscript>
			var local = {};

			System.out.println("testEscapeCharacterInDirectoryInjection");
			local.sf = getJava("java.io.File").init(instance.testDir, "test\\^.^.\\file");
			if ( local.sf.exists() ) {
				System.out.println( "  Injection allowed " & local.sf.getAbsolutePath() );
			} else {
				System.out.println( "  Injection didn't work " & local.sf.getAbsolutePath() );
			}
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testJavaFileInjectionGood" output="false">
		<cfscript>
			var local = {};
			for(local.i = instance.GOOD_FILE_CHARS.iterator();local.i.hasNext();) {
				local.ch = local.i.next().toString();	// avoids generic issues in 1.4&1.5
				local.sf = createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testDir, instance.TEST_FILE_NAME & local.ch);
				assertFalse(local.sf.exists(), 'File "' & instance.TEST_FILE_NAME & local.ch & '" should not exist (local.ch=' & local.ch.charAt(0) & ').');
				local.sf = createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testDir, instance.TEST_FILE_NAME & local.ch & "test");
				assertFalse(local.sf.exists(), 'File "' & instance.TEST_FILE_NAME & local.ch & '" should not exist (local.ch=' & local.ch.charAt(0) & ').');
			}
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testJavaFileInjectionBad" output="false">
		<cfscript>
			var local = {};

			for(local.i = instance.BAD_FILE_CHARS.iterator();local.i.hasNext();) {
				local.ch = local.i.next().toString();	// avoids generic issues in 1.4&1.5
				try {
					createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testDir, instance.TEST_FILE_NAME & local.ch);
					fail('Able to create SafeFile "' & instance.TEST_FILE_NAME & local.ch & '" (local.ch=' & local.ch.charAt(0) & ').');
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException expected) { }
				try {
					createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testDir, instance.TEST_FILE_NAME & local.ch  & "test");
					fail('Able to create SafeFile "' & instance.TEST_FILE_NAME & local.ch & '" (local.ch=' & local.ch.charAt(0) & ').');
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException expected) { }
			}
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testMultipleJavaFileInjectionGood" output="false">
		<cfscript>
			var local = {};

			for(local.i=instance.GOOD_FILE_CHARS.iterator();local.i.hasNext();) {
				local.ch = local.i.next().toString();	// avoids generic issues in 1.4&1.5
				local.ch = local.ch & local.ch & local.ch;
				local.sf = createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testDir, instance.TEST_FILE_NAME & local.ch);
				assertFalse(local.sf.exists(), 'File "' & instance.TEST_FILE_NAME & local.ch & '" should not exist (local.ch=' & local.ch.charAt(0) & ').');
				local.sf = createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testDir, instance.TEST_FILE_NAME & local.ch & "test");
				assertFalse(local.sf.exists(), 'File "' & instance.TEST_FILE_NAME & local.ch & '" should not exist (local.ch=' & local.ch.charAt(0) & ').');
			}
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testMultipleJavaFileInjectionBad" output="false">
		<cfscript>
			var local = {};

			for(local.i = instance.BAD_FILE_CHARS.iterator();local.i.hasNext();) {
				local.ch = local.i.next().toString();	// avoids generic issues in 1.4&1.5
				local.ch = local.ch & local.ch & local.ch;
				try {
					createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testDir, instance.TEST_FILE_NAME & local.ch);
					fail('Able to create SafeFile "' & instance.TEST_FILE_NAME & local.ch & '" (local.ch=' & local.ch.charAt(0) & ').');
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException expected) { }
				try {
					createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testDir, instance.TEST_FILE_NAME & local.ch  & "test");
					fail('Able to create SafeFile "' & instance.TEST_FILE_NAME & local.ch & '" (local.ch=' & local.ch.charAt(0) & ').');
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException expected) { }
				local.i=instance.BAD_FILE_CHARS.iterator();
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testAlternateDataStream" output="false">
		<cfscript>
			var local = {};

			try {
				local.sf = createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testDir, instance.TEST_FILE_NAME & ":secret.txt");
				fail("Able to construct SafeFile for alternate data stream: " & local.sf.getPath());
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException expected) { }
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="String" name="toHex" output="false">
		<cfargument required="true" type="binary" name="b">
		<cfscript>
			var local = {};

			local.hexDigit = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
			local.array = [ local.hexDigit[(bitSHRN(arguments.b, 4)) & inputBaseN("0f", 16)], local.hexDigit[arguments.b & inputBaseN("0f", 16)] ];
			return new String(local.array);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreatePath" output="false">
		<cfscript>
			var local = {};

			local.sf = createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testFile.getPath());
			assertTrue(local.sf.exists());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreateParentPathName" output="false">
		<cfscript>
			var local = {};

			local.sf = createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testDir, instance.testFile.getName());
			assertTrue(local.sf.exists());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreateParentFileName" output="false">
		<cfscript>
			var local = {};

			local.sf = createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testFile.getParentFile(), instance.testFile.getName());
			assertTrue(local.sf.exists());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreateURI" output="false">
		<cfscript>
			var local = {};

			local.sf = createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(ESAPI=instance.ESAPI, uri=instance.testFile.toURI());
			assertTrue(local.sf.exists());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreateFileNamePercentNull" output="false">
		<cfscript>
			var local = {};

			try
			{
				createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testDir & getJava("java.io.File").separator & "file%00.txt");
				fail("no exception thrown for file name with percent encoded null");
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException expected)
			{
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreateFileNameQuestion" output="false">
		<cfscript>
			var local = {};

			try
			{
				createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testFile.getParent() & getJava("java.io.File").separator & "file?.txt");
				fail("no exception thrown for file name with question mark in it");
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e)
			{
				// expected
			}
		</cfscript>
	</cffunction>


	<!--- NULL test not valid for CFML
	<cffunction access="public" returntype="void" name="testCreateFileNameNull" output="false">
		<cfscript>
			var local = {};
			try
			{
				createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testFile.getParent() & getJava("java.io.File").separator & "file" & chr(0) & ".txt");
				fail("no exception thrown for file name with null in it");
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e)
			{
				// expected
			}
		</cfscript>
	</cffunction> --->


	<cffunction access="public" returntype="void" name="testCreateFileHighByte" output="false">
		<cfscript>
			var local = {};

			try
			{
				createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testFile.getParent() & getJava("java.io.File").separator & "file" & chr(160) & ".txt");
				fail("no exception thrown for file name with high byte in it");
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e)
			{
				// expected
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCreateParentPercentNull" output="false">
		<cfscript>
			var local = {};

			try
			{
				createObject("component", "cfesapi.org.owasp.esapi.SafeFile").init(instance.ESAPI, instance.testFile.getParent() & getJava("java.io.File").separator & "file%00.txt");
				fail("no exception thrown for file name with percent encoded null");
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e)
			{
				// expected
			}
		</cfscript>
	</cffunction>


</cfcomponent>