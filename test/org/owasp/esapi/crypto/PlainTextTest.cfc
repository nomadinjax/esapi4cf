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
import "org.owasp.esapi.crypto.PlainText";
import "org.owasp.esapi.util.Utils";

component extends="test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	variables.unicodeStr = new Utils().toUnicode("A\u00ea\u00f1\u00fcC");	// I.e., "AêñüC"
	variables.altString  = "AêñüC";											// Same as above.

	/* NOTE: This test will not work on Windows unless executed under
	 * Eclipse and the file is stored / treated as a UTF-8 encoded file
	 * rather than the Windows native OS encoding of Windows-1252 (aka,
	 * CP-1252). Therefore this test case has a check to not run the test
	 * unless
	 *     unicodeStr.equals(altString)
	 * is true. If not the test is skipped and a message is printed to stderr.
	 * Jim Manico made an attempt to address this (see private email to
	 * kevin.w.wall@gmail.com on 11/26/2009, subject "Re: [OWASP-ESAPI] Unit
	 * Tests Status") to correct this problem by setting some SVN attribute
	 * to standardize all source files to UTF-8, but not all Subversion clients
	 * are either honoring this or perhaps Windows just overrides this. Either
	 * way, this test (which used to be an assertTrue() expression) was
	 * introduced to account for this.
	 */
	public void function testUnicodeString() {
	    // These 2 strings are *meant* to be equal. If they are not, please
	    // do *NOT* change the test. It's a Windows thing. Sorry. Change your
	    // OS instead. ;-)
	    if ( ! variables.unicodeStr.equals(variables.altString) ) {
	        System.err.println("Skipping Unit test case " &
	                           "PlainTextTest.testUnicodeString() on OS " &
	                           System.getProperty("os.name") );
	        return;
	    }
	    var Arrays = createObject("java", "java.util.Arrays");
		try {
			var utf8Bytes = variables.unicodeStr.getBytes("UTF-8");
			var pt1 = new PlainText(variables.ESAPI, variables.unicodeStr);
			var pt2 = new PlainText(variables.ESAPI, variables.altString);

			assertTrue( pt1.isEquals(pt1) );   // Equals self
			assertFalse( pt1.isEquals(chr(0)) );
			assertTrue( pt1.isEquals(pt2) );
			assertFalse( pt1.isEquals( variables.unicodeStr ) );
			assertTrue( pt1.length() == arrayLen(utf8Bytes) );
			assertTrue( Arrays.equals(utf8Bytes, pt1.asBytes()) );
			assertTrue( pt1.hashCode() == variables.unicodeStr.hashCode() );

		} catch (UnsupportedEncodingException e) {
			fail("No UTF-8 byte encoding: " & e);
			e.printStackTrace(System.err);
		}
	}

	public void function testNullCase() {
	    var counter = 0;
	    try {
            var bytes = javaCast("null", "");
            var pt = new PlainText(variables.ESAPI, bytes);
            assertTrue(!isNull(pt));   // Should never get to here.
            fail("testNullCase(): Expected IllegalArgumentException");
        } catch (expression e) {
        	// lack of null support will end up here
        	// so just pass test
        	counter++;
        } catch (java.lang.IllegalArgumentException e) {
            // Will get this case if assertions are not enabled for PlainText.
            // System.err.println("Caught NullPointerException; exception was: " & e);
            // e.printStackTrace(System.err);
            counter++;
        } finally {
            assertTrue( counter > 0 );
        }
	}

	public void function testEmptyString() {
		var mt  = new PlainText(variables.ESAPI, "");
		assertTrue( mt.length() == 0 );
		var ba = mt.asBytes();
		assertTrue( !isNull(ba) && arrayLen(ba) == 0 );
	}

	public void function testOverwrite() {
		var Arrays = createObject("java", "java.util.Arrays");
		try {
			var origBytes = variables.unicodeStr.getBytes("UTF-8");
			var pt = new PlainText(variables.ESAPI, origBytes);
			assertTrue( pt.toString() == variables.unicodeStr );
			assertTrue( Arrays.equals(origBytes, pt.asBytes()) );
			assertTrue( pt.hashCode() == variables.unicodeStr.hashCode() );

			var origLen = arrayLen(origBytes);

			pt.overwrite();
	        var overwrittenBytes = pt.asBytes();
			assertTrue(!isNull(overwrittenBytes));
			assertFalse( Arrays.equals( origBytes, overwrittenBytes ) );

			// Ensure that ALL the bytes overwritten with '*'.
			var afterLen = arrayLen(overwrittenBytes);
			assertTrue( origLen == afterLen );
			var sum = 0;
			for( var i = 1; i <= afterLen; i++ ) {
			    if ( chr(overwrittenBytes[i]) == '*' ) {
			        sum++;
			    }
			}
			assertTrue( afterLen == sum );
		} catch (UnsupportedEncodingException e) {
			fail("No UTF-8 byte encoding: " & e);
			e.printStackTrace(System.err);
		}
	}

}
