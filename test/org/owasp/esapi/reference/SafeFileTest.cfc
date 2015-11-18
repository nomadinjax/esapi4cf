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
import "org.owasp.esapi.SafeFile";

component extends="test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	/** Name of the file in the temporary directory */
	variables.TEST_FILE_NAME = "test.file";
	variables.GOOD_FILE_CHARS = createObject("java", "org.owasp.esapi.util.CollectionsUtil").strToUnmodifiableSet("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-");
	variables.BAD_FILE_CHARS = createObject("java", "org.owasp.esapi.util.CollectionsUtil").strToUnmodifiableSet(chr(0) & "*|<>?:");

	variables.testDir = "";
	variables.testFile = "";
	variables.fileSeparator = createObject("java", "java.io.File").separator;

	public void function setUp() {
		// create a file to test with
		variables.testDir = createObject("java", "java.io.File").init(getTempDirectory() & "\SafeFileTest").getCanonicalFile();
		variables.testDir.mkdirs();
		variables.testFile = createObject("java", "java.io.File").init(variables.testDir, variables.TEST_FILE_NAME);
		variables.testFile.createNewFile();
		variables.testFile = variables.testFile.getCanonicalFile();
	}

	public void function tearDown() {
		variables.testDir.delete();
	}

	public void function testEscapeCharactersInFilename() {
		System.out.println("testEscapeCharactersInFilenameInjection");
		var tf = variables.testFile;
		if ( tf.exists() ) {
			System.out.println( "File is there: " & tf );
		}

		var sf = createObject("java", "java.io.File").init(variables.testDir, "test^.file" );
		if ( sf.exists() ) {
			System.out.println( "  Injection allowed "& sf.getAbsolutePath() );
		} else {
			System.out.println( "  Injection didn't work "& sf.getAbsolutePath() );
		}
	}

	public void function testEscapeCharacterInDirectoryInjection() {
		System.out.println("testEscapeCharacterInDirectoryInjection");
		var sf = createObject("java", "java.io.File").init(variables.testDir, "test\\^.^.\\file");
		if ( sf.exists() ) {
			System.out.println( "  Injection allowed "& sf.getAbsolutePath() );
		} else {
			System.out.println( "  Injection didn't work "& sf.getAbsolutePath() );
		}
	}

	public void function testJavaFileInjectionGood() {
		for(var i=variables.GOOD_FILE_CHARS.iterator();i.hasNext();) {
			var ch = i.next().toString();	// avoids generic issues in 1.4&1.5
			var sf = new SafeFile(ESAPI=variables.ESAPI, parent=variables.testDir, child=variables.TEST_FILE_NAME & ch);
			assertFalse(sf.exists(), 'File "' & variables.TEST_FILE_NAME & ch & '" should not exist (ch=' & ch.charAt(0) & ').');
			sf = new SafeFile(ESAPI=variables.ESAPI, parent=variables.testDir, child=variables.TEST_FILE_NAME & ch & "test");
			assertFalse(sf.exists(), 'File "' & variables.TEST_FILE_NAME & ch & '" should not exist (ch=' & ch.charAt(0) & ').');
		}
	}

	public void function testJavaFileInjectionBad() {
		for(var i=variables.BAD_FILE_CHARS.iterator();i.hasNext();) {
			var ch = i.next().toString();	// avoids generic issues in 1.4&1.5
			try {
				var sf = new SafeFile(ESAPI=variables.ESAPI, parent=variables.testDir, child=variables.TEST_FILE_NAME & ch);
				fail('Able to create SafeFile "' & variables.TEST_FILE_NAME & ch & '" (ch=' & ch.charAt(0) & ').');
			}
			catch(org.owasp.esapi.errors.ValidationException expected) {
			}
			try {
				var sf = new SafeFile(ESAPI=variables.ESAPI, parent=variables.testDir, child=variables.TEST_FILE_NAME & ch  & "test");
				fail('Able to create SafeFile "' & variables.TEST_FILE_NAME & ch & '" (ch=' & ch.charAt(0) & ').');
			}
			catch(org.owasp.esapi.errors.ValidationException expected) {
			}
		}
	}

	public void function testMultipleJavaFileInjectionGood() {
		for(var i=variables.GOOD_FILE_CHARS.iterator();i.hasNext();) {
			var ch = i.next().toString();	// avoids generic issues in 1.4&1.5
			ch = ch & ch & ch;
			var sf = new SafeFile(ESAPI=variables.ESAPI, parent=variables.testDir, child=variables.TEST_FILE_NAME & ch);
			assertFalse(sf.exists(), 'File "' & variables.TEST_FILE_NAME & ch & '" should not exist (ch=' & ch.charAt(0) & ').');
			sf = new SafeFile(ESAPI=variables.ESAPI, parent=variables.testDir, child=variables.TEST_FILE_NAME & ch & "test");
			assertFalse(sf.exists(), 'File "' & variables.TEST_FILE_NAME & ch & '" should not exist (ch=' & ch.charAt(0) & ').');
		}
	}

	public void function testMultipleJavaFileInjectionBad() {
		for(var i=variables.BAD_FILE_CHARS.iterator();i.hasNext();) {
			var ch = i.next().toString();	// avoids generic issues in 1.4&1.5
			ch = ch & ch & ch;
			try {
				var sf = new SafeFile(ESAPI=variables.ESAPI, parent=variables.testDir, child=variables.TEST_FILE_NAME & ch);
				fail('Able to create SafeFile "' & variables.TEST_FILE_NAME & ch & '" (ch=' & ch.charAt(0) & ').');
			}
			catch(org.owasp.esapi.errors.ValidationException expected) {
			}
			try {
				var sf = new SafeFile(ESAPI=variables.ESAPI, parent=variables.testDir, child=variables.TEST_FILE_NAME & ch  & "test");
				fail('Able to create SafeFile "' & variables.TEST_FILE_NAME & ch & '" (ch=' & ch.charAt(0) & ').');
			}
			catch(org.owasp.esapi.errors.ValidationException expected) {
			}
		}
	}

	public void function testAlternateDataStream() {
		try {
			var sf = new SafeFile(ESAPI=variables.ESAPI, parent=variables.testDir, child=variables.TEST_FILE_NAME & ":secret.txt");
			fail("Able to construct SafeFile for alternate data stream: " & sf.getPath());
		}
		catch(org.owasp.esapi.errors.ValidationException expected) {
		}
	}

	/*public String function toHex(final byte b) {
		var hexDigit[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
		var arr = { hexDigit[(b >> 4) & 0x0f], hexDigit[b & 0x0f] };
		return new String(arr);
	}*/

	public void function testCreatePath() {
		var sf = new SafeFile(variables.ESAPI, variables.testFile.getPath());
		assertTrue(sf.exists());
	}

	public void function testCreateParentPathName() {
		var sf = new SafeFile(ESAPI=variables.ESAPI, parent=variables.testDir, child=variables.testFile.getName());
		assertTrue(sf.exists());
	}

	public void function testCreateParentFileName() {
		var sf = new SafeFile(ESAPI=variables.ESAPI, parent=variables.testFile.getParentFile(), child=variables.testFile.getName());
		assertTrue(sf.exists());
	}

	public void function testCreateURI() {
		var sf = new SafeFile(ESAPI=variables.ESAPI, uri=variables.testFile.toURI());
		assertTrue(sf.exists());
	}

	public void function testCreateFileNamePercentNull() {
		try {
			var sf = new SafeFile(variables.ESAPI, variables.testDir & variables.fileSeparator & "file%00.txt");
			fail("no exception thrown for file name with percent encoded null");
		}
		catch(org.owasp.esapi.errors.ValidationException expected) {
		}
	}

	public void function testCreateFileNameQuestion() {
		try {
			var sf = new SafeFile(variables.ESAPI, variables.testFile.getParent() & variables.fileSeparator & "file?.txt");
			fail("no exception thrown for file name with question mark in it");
		}
		catch(org.owasp.esapi.errors.ValidationException e) {
			// expected
		}
	}

	public void function testCreateFileNameNull() {
		var path = variables.testFile.getParent() & createObject("java", "java.io.File").separator;
		try {
			// CF seems to ignore the 'null' in strings so let's test to ensure this is always the case moving forward
			assertEquals(path & "file.txt", new SafeFile(variables.ESAPI, path & "file" & chr(0) & ".txt").getPath());
			assertEquals(path & "file.txt", new SafeFile(variables.ESAPI, path & "file" & javaCast("null", "") & ".txt").getPath());
			//fail("no exception thrown for file name with null in it");
		}
		catch(org.owasp.esapi.errors.ValidationException e) {
			fail("file name has null in it");
		}
	}

	public void function testCreateFileHighByte() {
		try {
			var sf = new SafeFile(variables.ESAPI, variables.testFile.getParent() & variables.fileSeparator & "file" & chr(160) & ".txt");
			fail("no exception thrown for file name with high byte in it");
		}
		catch(org.owasp.esapi.errors.ValidationException e) {
			// expected
		}
	}

	public void function testCreateParentPercentNull() {
		try {
			var sf = new SafeFile(variables.ESAPI, variables.testFile.getParent() & variables.fileSeparator & "file%00.txt");
			fail("no exception thrown for file name with percent encoded null");
		}
		catch(org.owasp.esapi.errors.ValidationException e) {
			// expected
		}
	}

}
