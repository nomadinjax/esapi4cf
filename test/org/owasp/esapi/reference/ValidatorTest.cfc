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
import "org.owasp.esapi.beans.SafeRequest";
import "org.owasp.esapi.reference.Encoder";
import "org.owasp.esapi.reference.Validator";
import "org.owasp.esapi.reference.validation.HTMLValidationRule";
import "org.owasp.esapi.reference.validation.StringValidationRule";

/**
 * The Class ValidatorTest.
 */
component extends="test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	variables.PREFERRED_ENCODING = "UTF-8";

	variables.testForNull = false;
	if (server.coldfusion.productName == "Railo" || server.coldfusion.productName == "Lucee") {
		variables.testForNull = true;
	}

    public void function testAddRule() {
        var validator = variables.ESAPI.validator();
        var rule = new StringValidationRule(variables.ESAPI, "ridiculous");
        validator.addRule(rule);
        assertEquals(rule, validator.getRule("ridiculous"));
    }

    public void function testAssertValidFileUpload() {
        //		assertValidFileUpload(String, String, String, byte[], int, boolean, ValidationErrorList)
    }

    public void function testGetPrintable1() {
        //		getValidPrintable(String, char[], int, boolean, ValidationErrorList)
    }

    public void function testGetPrintable2() {
        //		getValidPrintable(String, String, int, boolean, ValidationErrorList)
    }

    public void function testGetRule() {
        var validator = variables.ESAPI.validator();
        var rule = new StringValidationRule(variables.ESAPI, "rule");
        validator.addRule(rule);
        assertSame(rule, validator.getRule("rule"));
        assertNotSame(rule, validator.getRule("ridiculous"));
    }

    public void function testGetValidCreditCard() {
        variables.System.out.println("getValidCreditCard");
        var instance = variables.ESAPI.validator();
        var errors = {};

        assertTrue(instance.isValidCreditCard("cctest1", "1234 9876 0000 0008", false));
        assertTrue(instance.isValidCreditCard("cctest2", "1234987600000008", false));
        assertFalse(instance.isValidCreditCard("cctest3", "12349876000000081", false));
        assertFalse(instance.isValidCreditCard("cctest4", "4417 1234 5678 9112", false));

        instance.getValidCreditCard("cctest5", "1234 9876 0000 0008", false, errors);
        assertEquals(0, errors.size());
        instance.getValidCreditCard("cctest6", "1234987600000008", false, errors);
        assertEquals(0, errors.size());
        instance.getValidCreditCard("cctest7", "12349876000000081", false, errors);
        assertEquals(1, errors.size());
        instance.getValidCreditCard("cctest8", "4417 1234 5678 9112", false, errors);
        assertEquals(2, errors.size());

        assertTrue(instance.isValidCreditCard("cctest1", "1234 9876 0000 0008", false, errors));
        assertTrue(errors.size()==2);
        assertTrue(instance.isValidCreditCard("cctest2", "1234987600000008", false, errors));
        assertTrue(errors.size()==2);
        assertFalse(instance.isValidCreditCard("cctest3", "12349876000000081", false, errors));
        assertTrue(errors.size()==3);
        assertFalse(instance.isValidCreditCard("cctest4", "4417 1234 5678 9112", false, errors));
        assertTrue(errors.size()==4);
    }

    public void function testGetValidDate() {
    	variables.System.out.println("getValidDate");
    	var instance = variables.ESAPI.validator();
    	var errors = {};
    	var jDateFormat = createObject("java", "java.text.DateFormat");
    	var minDate = createDate(1900, 1, 1);
        var maxDate = createDate(2100, 1, 1);
    	var Locale = createObject("java", "java.util.Locale");
    	assertTrue(instance.getValidDate("datetest1", "June 23, 1967", jDateFormat.getDateInstance(jDateFormat.MEDIUM, Locale.US), minDate, maxDate, false) != "");
    	instance.getValidDate("datetest2", "freakshow", jDateFormat.getDateInstance(), minDate, maxDate, false, errors);
    	assertEquals(1, errors.size());

    	// TODO: This test case fails due to an apparent bug in SimpleDateFormat
    	// Note: This seems to be fixed in JDK 6. Will leave it commented out since
    	//		 we only require JDK 5. -kww
    	instance.getValidDate("test", "June 32, 2008", jDateFormat.getDateInstance(), minDate, maxDate, false, errors);
    	// assertEquals( 2, errors.size() );
    }

    // FIXME: Should probably use SecurityConfigurationWrapper and force
    //		  Validator.AcceptLenientDates to be false.
    public void function testLenientDate() {
    	variables.System.out.println("testLenientDate");
    	var jDateFormat = createObject("java", "java.text.DateFormat");
    	var Locale = createObject("java", "java.util.Locale");

    	var acceptLenientDates = variables.ESAPI.securityConfiguration().getLenientDatesAccepted();
    	if ( acceptLenientDates ) {
    		assertTrue("Lenient date test skipped because Validator.AcceptLenientDates set to true", true);
    		return;
    	}

    	var lenientDateTest = "";
    	try {
    		// lenientDateTest will be null when Validator.AcceptLenientDates
    		// is set to false (the default).
    		var instance = variables.ESAPI.validator();
    		lenientDateTest = instance.getValidDate("datatest3-lenient", "15/2/2009 11:83:00",
    				                                jDateFormat.getDateInstance(jDateFormat.SHORT, Locale.US),
    				                                createDate(2000, 1, 1),
    				                                createDate(2100, 1, 1),
    				                                false);
    		fail("Failed to throw expected ValidationException when Validator.AcceptLenientDates set to false.");
    	} catch (org.owasp.esapi.errors.ValidationException ve) {
    		assertTrue( lenientDateTest == "");
    		var cause = deserializeJSON(ve.extendedInfo);
    		assertTrue( cause.type == "java.text.ParseException" );
    	} catch (Exception e) {
    		fail("Caught unexpected exception: " & e.getClass().getName() & "; msg: " & e);
    	}
    }

    public void function testGetValidDirectoryPath() {
        variables.System.out.println("getValidDirectoryPath");

        var instance = variables.ESAPI.validator();
        var errors = {};
        // find a directory that exists
        var parent = createObject("java", "java.io.File").init("/");
        var path = getTempDirectory();
        instance.getValidDirectoryPath("dirtest1", path, parent, true, errors);
        assertEquals(0, structCount(errors));
        instance.getValidDirectoryPath("dirtest3", "ridicul%00ous", parent, false, errors);
        assertEquals(1, structCount(errors));
        if (variables.testForNull) {
        	instance.getValidDirectoryPath("dirtest2", javaCast("null", ""), parent, false, errors);
	        assertEquals(2, structCount(errors));
        }
    }

    public void function testGetValidDouble() {
        variables.System.out.println("getValidDouble");
        var instance = variables.ESAPI.validator();
        var errors = {};
        var Double = createObject("java", "java.lang.Double");
        instance.getValidDouble("dtest1", "1.0", 0, 20, true, errors);
        assertEquals(0, errors.size());
        instance.getValidDouble("dtest4", "ridiculous", 0, 20, true, errors);
        assertEquals(1, errors.size());
        instance.getValidDouble("dtest5", "" & (Double.MAX_VALUE), 0, 20, true, errors);
        assertEquals(2, errors.size());
        instance.getValidDouble("dtest6", "" & (Double.MAX_VALUE & .00001), 0, 20, true, errors);
        assertEquals(3, errors.size());
       	if (variables.testForNull) {
	        instance.getValidDouble("dtest2", javaCast("null", ""), 0, 20, true, errors);
	        assertEquals(3, errors.size());
	        instance.getValidDouble("dtest3", javaCast("null", ""), 0, 20, false, errors);
	        assertEquals(4, errors.size());
        }
    }

    public void function testGetValidFileContent() {
        variables.System.out.println("getValidFileContent");
        var instance = variables.ESAPI.validator();
        var errors = {};
        var bytes = "";
        try {
            bytes = charsetDecode("12345", variables.PREFERRED_ENCODING);
        }
        catch (java.io.UnsupportedEncodingException e) {
            fail(variables.PREFERRED_ENCODING & " not a supported encoding?!?!!");
        }
        instance.getValidFileContent("test", bytes, 5, true, errors);
        assertEquals(0, errors.size());
        instance.getValidFileContent("test", bytes, 4, true, errors);
        assertEquals(1, errors.size());
    }

    public void function testGetValidFileName() {
        variables.System.out.println("getValidFileName");
        var instance = variables.ESAPI.validator();
        var errors = {};
        var testName = "aspe%20ct.jar";
        assertEquals(testName, instance.getValidFileName("test", testName, variables.ESAPI.securityConfiguration().getAllowedFileExtensions(), false, errors), "Percent encoding is not changed");
    }

    public void function testGetValidInput() {
        variables.System.out.println("getValidInput");
        var instance = variables.ESAPI.validator();
        var errors = {};
        // instance.getValidInput(String, String, String, int, boolean, ValidationErrorList)
    }

    public void function testGetValidInteger() {
        variables.System.out.println("getValidInteger");
        var instance = variables.ESAPI.validator();
        var errors = {};
        // instance.getValidInteger(String, String, int, int, boolean, ValidationErrorList)
    }

    public void function testGetValidListItem() {
        variables.System.out.println("getValidListItem");
        var instance = variables.ESAPI.validator();
        var errors = {};
        // instance.getValidListItem(String, String, List, ValidationErrorList)
    }

    public void function testGetValidNumber() {
        variables.System.out.println("getValidNumber");
        var instance = variables.ESAPI.validator();
        var errors = {};
        // instance.getValidNumber(String, String, long, long, boolean, ValidationErrorList)
    }

    public void function testGetValidRedirectLocation() {
        variables.System.out.println("getValidRedirectLocation");
        var instance = variables.ESAPI.validator();
        var errors = {};
        // instance.getValidRedirectLocation(String, String, boolean, ValidationErrorList)
    }

    public void function testGetValidSafeHTML() {
        variables.System.out.println("getValidSafeHTML");

        var instance = variables.ESAPI.validator();
        var errors = {};

        // new school test case setup
        var rule = new HTMLValidationRule(variables.ESAPI, "test");
        variables.ESAPI.validator().addRule(rule);

        assertEquals("Test.", variables.ESAPI.validator().getRule("test").getValid("test", "Test. <script>alert(document.cookie)</script>"));

        var test1 = "<b>Jeff</b>";
        var result1 = instance.getValidSafeHTML("test", test1, 100, false, errors);
        assertEquals(test1, result1);

        var test2 = '<a href="http://www.aspectsecurity.com">Aspect Security</a>';
        var result2 = instance.getValidSafeHTML("test", test2, 100, false, errors);
        assertEquals(test2, result2);

        var test3 = "Test. <script>alert(document.cookie)</script>";
        assertEquals("Test.", rule.getSafe("test", test3));

        assertEquals("Test. &lt;<div>load=alert()</div>", rule.getSafe("test", "Test. <<div on<script></script>load=alert()"));
        assertEquals("Test. <div>b</div>", rule.getSafe("test", "Test. <div style={xss:expression(xss)}>b</div>"));
        assertEquals("Test.", rule.getSafe("test", "Test. <s%00cript>alert(document.cookie)</script>"));
        assertEquals("Test. alert(document.cookie)", rule.getSafe("test", "Test. <s\tcript>alert(document.cookie)</script>"));
        assertEquals("Test. alert(document.cookie)", rule.getSafe("test", "Test. <s\tcript>alert(document.cookie)</script>"));
        // TODO: ENHANCE waiting for a way to validate text headed for an attribute for scripts
        // This would be nice to catch, but just looks like text to AntiSamy
        // assertFalse(instance.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
        // String result4 = instance.getValidSafeHTML("test", test4);
        // assertEquals("", result4);
    }

    public void function testIsInvalidFilename() {
        variables.System.out.println("testIsInvalidFilename");
        var instance = variables.ESAPI.validator();
        var allowedExts = variables.ESAPI.securityConfiguration().getAllowedFileExtensions();
        var invalidChars = listToArray("/\:*?""<>|", "");
        for (var i = 1; i <= arrayLen(invalidChars); i++) {
            assertFalse(instance.isValidFileName("test", "as" & invalidChars[i] & "pect.jar", allowedExts, false), invalidChars[i] & " is an invalid character for a filename");
        }
        assertFalse(instance.isValidFileName("test", "", allowedExts, false), "Files must have an extension");
        assertFalse(instance.isValidFileName("test.invalidExtension", "", allowedExts, false), "Files must have a valid extension");
        assertFalse(instance.isValidFileName("test", "", allowedExts, false), "Filennames cannot be the empty string");
    }

    public void function testIsValidDate() {
        variables.System.out.println("isValidDate");
        var instance = variables.ESAPI.validator();
        var format = createObject("java", "java.text.SimpleDateFormat").getDateInstance();
        var minDate = createDate(1900, 1, 1);
        var maxDate = createDate(2100, 1, 1);
        assertTrue(instance.isValidDate("datetest1", "September 11, 2001", format, minDate, maxDate, true));
        if (variables.testForNull) {
       		assertFalse(instance.isValidDate("datetest2", javaCast("null", ""), format, minDate, maxDate, false));
        }
        assertFalse(instance.isValidDate("datetest3", "", format, minDate, maxDate, false));

        var errors = {};
        assertTrue(instance.isValidDate("datetest1", "September 11, 2001", format, minDate, maxDate, true, errors));
        assertTrue(errors.size()==0);
        assertFalse(instance.isValidDate("datetest3", "", format, minDate, maxDate, false, errors));
        assertTrue(errors.size()==1);
       	if (variables.testForNull) {
        	assertFalse(instance.isValidDate("datetest2", javaCast("null", ""), format, minDate, maxDate, false, errors));
	        assertTrue(errors.size()==2);
        }
    }

    public void function testIsValidDirectoryPath() {
        variables.System.out.println("isValidDirectoryPath");
        var File = createObject("java", "java.io.File");

        // get an encoder with a special list of codecs and make a validator out of it
        var list = [];
        list.add("HTMLEntityCodec");
        var encoder = new Encoder(variables.ESAPI, list);
        var instance = new Validator(variables.ESAPI, encoder);

        var isWindows = (variables.System.getProperty("os.name").indexOf("Windows") != -1) ? true : false;
        var parent = File.init("/");

        var errors = {};

        if (isWindows) {
            var sysRoot = File.init(variables.System.getenv("SystemRoot")).getCanonicalPath();
            // Windows paths that don't exist and thus should fail
            assertFalse(instance.isValidDirectoryPath("test", "c:\ridiculous", parent, false));
            assertFalse(instance.isValidDirectoryPath("test", "c:\jeff", parent, false));
            assertFalse(instance.isValidDirectoryPath("test", "c:\temp\..\etc", parent, false));

            // Windows paths
            assertTrue(instance.isValidDirectoryPath("test", "C:\", parent, false));                        // Windows root directory
            assertTrue(instance.isValidDirectoryPath("test", sysRoot, parent, false));                  // Windows always exist directory
            assertFalse(instance.isValidDirectoryPath("test", sysRoot & "\System32\cmd.exe", parent, false));      // Windows command shell

            // Unix specific paths should not pass
            assertFalse(instance.isValidDirectoryPath("test", "/tmp", parent, false));      // Unix Temporary directory
            assertFalse(instance.isValidDirectoryPath("test", "/bin/sh", parent, false));   // Unix Standard shell
            assertFalse(instance.isValidDirectoryPath("test", "/etc/config", parent, false));

            // Unix specific paths that should not exist or work
            assertFalse(instance.isValidDirectoryPath("test", "/etc/ridiculous", parent, false));
            assertFalse(instance.isValidDirectoryPath("test", "/tmp/../etc", parent, false));

            assertFalse(instance.isValidDirectoryPath("test1", "c:\ridiculous", parent, false, errors));
            assertTrue(errors.size()==1);
            assertFalse(instance.isValidDirectoryPath("test2", "c:\jeff", parent, false, errors));
            assertTrue(errors.size()==2);
            assertFalse(instance.isValidDirectoryPath("test3", "c:\temp\..\etc", parent, false, errors));
            assertTrue(errors.size()==3);

            // Windows paths
            assertTrue(instance.isValidDirectoryPath("test4", "C:\", parent, false, errors));                        // Windows root directory
            assertTrue(errors.size()==3);
            assertTrue(instance.isValidDirectoryPath("test5", sysRoot, parent, false, errors));                  // Windows always exist directory
            assertTrue(errors.size()==3);
            assertFalse(instance.isValidDirectoryPath("test6", sysRoot & "\System32\cmd.exe", parent, false, errors));      // Windows command shell
            assertTrue(errors.size()==4);

            // Unix specific paths should not pass
            assertFalse(instance.isValidDirectoryPath("test7", "/tmp", parent, false, errors));      // Unix Temporary directory
            assertTrue(errors.size()==5);
            assertFalse(instance.isValidDirectoryPath("test8", "/bin/sh", parent, false, errors));   // Unix Standard shell
            assertTrue(errors.size()==6);
            assertFalse(instance.isValidDirectoryPath("test9", "/etc/config", parent, false, errors));
            assertTrue(errors.size()==7);

            // Unix specific paths that should not exist or work
            assertFalse(instance.isValidDirectoryPath("test10", "/etc/ridiculous", parent, false, errors));
            assertTrue(errors.size()==8);
            assertFalse(instance.isValidDirectoryPath("test11", "/tmp/../etc", parent, false, errors));
            assertTrue(errors.size()==9);

        } else {
            // Windows paths should fail
            assertFalse(instance.isValidDirectoryPath("test", "c:\ridiculous", parent, false));
            assertFalse(instance.isValidDirectoryPath("test", "c:\temp\..\etc", parent, false));

            // Standard Windows locations should fail
            assertFalse(instance.isValidDirectoryPath("test", "c:\", parent, false));                        // Windows root directory
            assertFalse(instance.isValidDirectoryPath("test", "c:\Windows\temp", parent, false));               // Windows temporary directory
            assertFalse(instance.isValidDirectoryPath("test", "c:\Windows\System32\cmd.exe", parent, false));   // Windows command shell

            // Unix specific paths should pass
            assertTrue(instance.isValidDirectoryPath("test", "/", parent, false));         // Root directory
            assertTrue(instance.isValidDirectoryPath("test", "/bin", parent, false));      // Always exist directory

            // Unix specific paths that should not exist or work
            assertFalse(instance.isValidDirectoryPath("test", "/bin/sh", parent, false));   // Standard shell, not dir
            assertFalse(instance.isValidDirectoryPath("test", "/etc/ridiculous", parent, false));
            assertFalse(instance.isValidDirectoryPath("test", "/tmp/../etc", parent, false));

            // Windows paths should fail
            assertFalse(instance.isValidDirectoryPath("test1", "c:\ridiculous", parent, false, errors));
            assertTrue(errors.size()==1);
            assertFalse(instance.isValidDirectoryPath("test2", "c:\temp\..\etc", parent, false, errors));
            assertTrue(errors.size()==2);

            // Standard Windows locations should fail
            assertFalse(instance.isValidDirectoryPath("test3", "c:\", parent, false, errors));                        // Windows root directory
            assertTrue(errors.size()==3);
            assertFalse(instance.isValidDirectoryPath("test4", "c:\Windows\temp", parent, false, errors));               // Windows temporary directory
            assertTrue(errors.size()==4);
            assertFalse(instance.isValidDirectoryPath("test5", "c:\Windows\System32\cmd.exe", parent, false, errors));   // Windows command shell
            assertTrue(errors.size()==5);

            // Unix specific paths should pass
            assertTrue(instance.isValidDirectoryPath("test6", "/", parent, false, errors));         // Root directory
            assertTrue(errors.size()==5);
            assertTrue(instance.isValidDirectoryPath("test7", "/bin", parent, false, errors));      // Always exist directory
            assertTrue(errors.size()==5);

            // Unix specific paths that should not exist or work
            assertFalse(instance.isValidDirectoryPath("test8", "/bin/sh", parent, false, errors));   // Standard shell, not dir
            assertTrue(errors.size()==6);
            assertFalse(instance.isValidDirectoryPath("test9", "/etc/ridiculous", parent, false, errors));
            assertTrue(errors.size()==7);
            assertFalse(instance.isValidDirectoryPath("test10", "/tmp/../etc", parent, false, errors));
            assertTrue(errors.size()==8);
        }
    }

    public void function testIsValidDouble() {
        // isValidDouble(String, String, double, double, boolean)
    	var instance = variables.ESAPI.validator();
    	var errors = {};
    	//testing negative range
        assertFalse(instance.isValidDouble("test1", "-4", 1, 10, false, errors));
        assertTrue(errors.size() == 1);
        assertTrue(instance.isValidDouble("test2", "-4", -10, 10, false, errors));
        assertTrue(errors.size() == 1);
        //testing empty string
        assertTrue(instance.isValidDouble("test5", "", -10, 10, true, errors));
        assertTrue(errors.size() == 1);
        assertFalse(instance.isValidDouble("test6", "", -10, 10, false, errors));
        assertTrue(errors.size() == 2);
        //testing improper range
        assertFalse(instance.isValidDouble("test7", "50.0", 10, -10, false, errors));
        assertTrue(errors.size() == 3);
        //testing non-integers
        assertTrue(instance.isValidDouble("test8", "4.3214", -10, 10, true, errors));
        assertTrue(errors.size() == 3);
        assertTrue(instance.isValidDouble("test9", "-1.65", -10, 10, true, errors));
        assertTrue(errors.size() == 3);
        //other testing
        assertTrue(instance.isValidDouble("test10", "4", 1, 10, false, errors));
        assertTrue(errors.size() == 3);
        assertTrue(instance.isValidDouble("test11", "400", 1, 10000, false, errors));
        assertTrue(errors.size() == 3);
        assertTrue(instance.isValidDouble("test12", "400000000", 1, 400000000, false, errors));
        assertTrue(errors.size() == 3);
        assertFalse(instance.isValidDouble("test13", "4000000000000", 1, 10000, false, errors));
        assertTrue(errors.size() == 4);
        assertFalse(instance.isValidDouble("test14", "alsdkf", 10, 10000, false, errors));
        assertTrue(errors.size() == 5);
        assertFalse(instance.isValidDouble("test15", "--10", 10, 10000, false, errors));
        assertTrue(errors.size() == 6);
        assertFalse(instance.isValidDouble("test16", "14.1414234x", 10, 10000, false, errors));
        assertTrue(errors.size() == 7);
        assertFalse(instance.isValidDouble("test17", "Infinity", 10, 10000, false, errors));
        assertTrue(errors.size() == 8);
        assertFalse(instance.isValidDouble("test18", "-Infinity", 10, 10000, false, errors));
        assertTrue(errors.size() == 9);
        assertFalse(instance.isValidDouble("test19", "NaN", 10, 10000, false, errors));
        assertTrue(errors.size() == 10);
        assertFalse(instance.isValidDouble("test20", "-NaN", 10, 10000, false, errors));
        assertTrue(errors.size() == 11);
        assertFalse(instance.isValidDouble("test21", "+NaN", 10, 10000, false, errors));
        assertTrue(errors.size() == 12);
        assertTrue(instance.isValidDouble("test22", "1e-6", -999999999, 999999999, false, errors));
        assertTrue(errors.size() == 12);
        assertTrue(instance.isValidDouble("test23", "-1e-6", -999999999, 999999999, false, errors));
        assertTrue(errors.size() == 12);

        if (variables.testForNull) {
	        //testing null value
	        assertTrue(instance.isValidDouble("test3", javaCast("null", ""), -10, 10, true, errors));
	        assertTrue(errors.size() == 12);
	        assertFalse(instance.isValidDouble("test4", javaCast("null", ""), -10, 10, false, errors));
	        assertTrue(errors.size() == 13);
        }
    }

    public void function testIsValidFileContent() {
        variables.System.out.println("isValidFileContent");
        var content = "";
        try {
            content = charsetDecode("This is some file content", variables.PREFERRED_ENCODING);
        }
        catch (java.io.UnsupportedEncodingException e) {
            fail(variables.PREFERRED_ENCODING & " not a supported encoding?!?!!!");
        }
        var instance = variables.ESAPI.validator();
        assertTrue(instance.isValidFileContent("test", content, 100, false));
    }

    public void function testIsValidFileName() {
        variables.System.out.println("isValidFileName");
        var allowedExts = variables.ESAPI.securityConfiguration().getAllowedFileExtensions();
        var instance = variables.ESAPI.validator();
        assertTrue(instance.isValidFileName("test", "aspect.jar", allowedExts, false), "Simple valid filename with a valid extension");
        assertTrue(instance.isValidFileName("test", "!@##$%^&{}[]()_+-=,.~'` abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.jar", allowedExts, false), "All valid filename characters are accepted");
        assertTrue(instance.isValidFileName("test", "aspe%20ct.jar", allowedExts, false), "Legal filenames that decode to legal filenames are accepted");

        var errors = {};
        assertTrue(instance.isValidFileName("test", "aspect.jar", allowedExts, false, errors), "Simple valid filename with a valid extension");
        assertTrue(instance.isValidFileName("test", "!@##$%^&{}[]()_+-=,.~'` abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.jar", allowedExts, false, errors), "All valid filename characters are accepted");
        assertTrue(instance.isValidFileName("test", "aspe%20ct.jar", allowedExts, false, errors), "Legal filenames that decode to legal filenames are accepted");
        assertTrue(errors.size() == 0);
    }

    public void function testIsValidFileUpload() {
        variables.System.out.println("isValidFileUpload");
        var File = createObject("java", "java.io.File");
        var filepath = File.init(variables.System.getProperty("user.dir")).getCanonicalPath();
        var filename = "aspect.jar";
        var parent = File.init("/").getCanonicalFile();
        var errors = {};
        var content = "";
        try {
            content = charsetDecode("This is some file content", variables.PREFERRED_ENCODING);
        }
        catch (java.io.UnsupportedEncodingException e) {
            fail(variables.PREFERRED_ENCODING & " not a supported encoding?!?!!!");
        }
        var instance = variables.ESAPI.validator();
        var allowedExts = variables.ESAPI.securityConfiguration().getAllowedFileExtensions();
        assertTrue(instance.isValidFileUpload("test", filepath, filename, parent, content, 100, allowedExts, false));
        assertTrue(instance.isValidFileUpload("test", filepath, filename, parent, content, 100, allowedExts, false, errors));
        assertTrue(errors.size() == 0);

        filepath = "/ridiculous";
        filename = "aspect.jar";
        try {
            content = charsetDecode("This is some file content", variables.PREFERRED_ENCODING);
        }
        catch (java.io.UnsupportedEncodingException e) {
            fail(variables.PREFERRED_ENCODING & " not a supported encoding?!?!!!");
        }
        assertFalse(instance.isValidFileUpload("test", filepath, filename, parent, content, 100, allowedExts, false));
        assertFalse(instance.isValidFileUpload("test", filepath, filename, parent, content, 100, allowedExts, false, errors));
        assertTrue(errors.size() == 1);
    }

    public void function testIsValidHTTPRequestParameterSet() {
        //		isValidHTTPRequestParameterSet(String, Set, Set)
    }

    public void function testisValidInput() {
        variables.System.out.println("isValidInput");
        var instance = variables.ESAPI.validator();
        assertTrue(instance.isValidInput("test", "jeff.williams@aspectsecurity.com", "Email", 100, false));
        assertFalse(instance.isValidInput("test", "jeff.williams@@aspectsecurity.com", "Email", 100, false));
        assertFalse(instance.isValidInput("test", "jeff.williams@aspectsecurity", "Email", 100, false));
        assertTrue(instance.isValidInput("test", "jeff.wil'liams@aspectsecurity.com", "Email", 100, false));
        assertTrue(instance.isValidInput("test", "jeff.wil''liams@aspectsecurity.com", "Email", 100, false));
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
        assertTrue(instance.isValidInput("test", "jeffWILLIAMS123", "HTTPParameterValue", 100, false));
        assertTrue(instance.isValidInput("test", "jeff .-/+=@_ WILLIAMS", "HTTPParameterValue", 100, false));
        // Removed per Issue 116 - The '*' character is valid as a parameter character
//        assertFalse(instance.isValidInput("test", "jeff*WILLIAMS", "HTTPParameterValue", 100, false));
        assertFalse(instance.isValidInput("test", "jeff^WILLIAMS", "HTTPParameterValue", 100, false));
        assertFalse(instance.isValidInput("test", "jeff\\WILLIAMS", "HTTPParameterValue", 100, false));

		if (variables.testForNull) {
        	assertTrue(instance.isValidInput("test", javaCast("null", ""), "Email", 100, true));
        	assertFalse(instance.isValidInput("test", javaCast("null", ""), "Email", 100, false));
        }

        var errors = {};

        assertTrue(instance.isValidInput("test1", "jeff.williams@aspectsecurity.com", "Email", 100, false, true, errors));
        assertTrue(errors.size()==0);
        assertFalse(instance.isValidInput("test2", "jeff.williams@@aspectsecurity.com", "Email", 100, false, true, errors));
        assertTrue(errors.size()==1);
        assertFalse(instance.isValidInput("test3", "jeff.williams@aspectsecurity", "Email", 100, false, true, errors));
        assertTrue(errors.size()==2);
        assertTrue(instance.isValidInput("test4", "jeff.wil'liams@aspectsecurity.com", "Email", 100, false, true, errors));
        assertTrue(errors.size()==2);
        assertTrue(instance.isValidInput("test5", "jeff.wil''liams@aspectsecurity.com", "Email", 100, false, true, errors));
        assertTrue(errors.size()==2);
        assertTrue(instance.isValidInput("test6", "123.168.100.234", "IPAddress", 100, false, true, errors));
        assertTrue(errors.size()==2);
        assertTrue(instance.isValidInput("test7", "192.168.1.234", "IPAddress", 100, false, true, errors));
        assertTrue(errors.size()==2);
        assertFalse(instance.isValidInput("test8", "..168.1.234", "IPAddress", 100, false, true, errors));
        assertTrue(errors.size()==3);
        assertFalse(instance.isValidInput("test9", "10.x.1.234", "IPAddress", 100, false, true, errors));
        assertTrue(errors.size()==4);
        assertTrue(instance.isValidInput("test10", "http://www.aspectsecurity.com", "URL", 100, false, true, errors));
        assertTrue(errors.size()==4);
        assertFalse(instance.isValidInput("test11", "http:///www.aspectsecurity.com", "URL", 100, false, true, errors));
        assertTrue(errors.size()==5);
        assertFalse(instance.isValidInput("test12", "http://www.aspect security.com", "URL", 100, false, true, errors));
        assertTrue(errors.size()==6);
        assertTrue(instance.isValidInput("test13", "078-05-1120", "SSN", 100, false, true, errors));
        assertTrue(errors.size()==6);
        assertTrue(instance.isValidInput("test14", "078 05 1120", "SSN", 100, false, true, errors));
        assertTrue(errors.size()==6);
        assertTrue(instance.isValidInput("test15", "078051120", "SSN", 100, false, true, errors));
        assertTrue(errors.size()==6);
        assertFalse(instance.isValidInput("test16", "987-65-4320", "SSN", 100, false, true, errors));
        assertTrue(errors.size()==7);
        assertFalse(instance.isValidInput("test17", "000-00-0000", "SSN", 100, false, true, errors));
        assertTrue(errors.size()==8);
        assertFalse(instance.isValidInput("test18", "(555) 555-5555", "SSN", 100, false, true, errors));
        assertTrue(errors.size()==9);
        assertFalse(instance.isValidInput("test19", "test", "SSN", 100, false, true, errors));
        assertTrue(errors.size()==10);
        assertTrue(instance.isValidInput("test20", "jeffWILLIAMS123", "HTTPParameterValue", 100, false, true, errors));
        assertTrue(errors.size()==10);
        assertTrue(instance.isValidInput("test21", "jeff .-/+=@_ WILLIAMS", "HTTPParameterValue", 100, false, true, errors));
        assertTrue(errors.size()==10);
        // Removed per Issue 116 - The '*' character is valid as a parameter character
//        assertFalse(instance.isValidInput("test", "jeff*WILLIAMS", "HTTPParameterValue", 100, false));
        assertFalse(instance.isValidInput("test22", "jeff^WILLIAMS", "HTTPParameterValue", 100, false, true, errors));
        assertTrue(errors.size()==11);
        assertFalse(instance.isValidInput("test23", "jeff\\WILLIAMS", "HTTPParameterValue", 100, false, true, errors));
        assertTrue(errors.size()==12);

		if (variables.testForNull) {
        	assertTrue(instance.isValidInput("test", javaCast("null", ""), "Email", 100, true, true, errors));
        	assertFalse(instance.isValidInput("test", javaCast("null", ""), "Email", 100, false, true, errors));
        }
    }

    public void function testIsValidInteger() {
        variables.System.out.println("isValidInteger");
        var instance = variables.ESAPI.validator();
        //testing negative range
        assertFalse(instance.isValidInteger("test", "-4", 1, 10, false));
        assertTrue(instance.isValidInteger("test", "-4", -10, 10, false));
        //testing null value
		if (variables.testForNull) {
        	assertTrue(instance.isValidInteger("test", javaCast("null", ""), -10, 10, true));
        	assertFalse(instance.isValidInteger("test", javaCast("null", ""), -10, 10, false));
        }
        //testing empty string
        assertTrue(instance.isValidInteger("test", "", -10, 10, true));
        assertFalse(instance.isValidInteger("test", "", -10, 10, false));
        //testing improper range
        assertFalse(instance.isValidInteger("test", "50", 10, -10, false));
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

        var errors = {};
        //testing negative range
        assertFalse(instance.isValidInteger("test1", "-4", 1, 10, false, errors));
        assertTrue(errors.size() == 1);
        assertTrue(instance.isValidInteger("test2", "-4", -10, 10, false, errors));
        assertTrue(errors.size() == 1);
        //testing empty string
        assertTrue(instance.isValidInteger("test5", "", -10, 10, true, errors));
        assertTrue(errors.size() == 1);
        assertFalse(instance.isValidInteger("test6", "", -10, 10, false, errors));
        assertTrue(errors.size() == 2);
        //testing improper range
        assertFalse(instance.isValidInteger("test7", "50", 10, -10, false, errors));
        assertTrue(errors.size() == 3);
        //testing non-integers
        assertFalse(instance.isValidInteger("test8", "4.3214", -10, 10, true, errors));
        assertTrue(errors.size() == 4);
        assertFalse(instance.isValidInteger("test9", "-1.65", -10, 10, true, errors));
        assertTrue(errors.size() == 5);
        //other testing
        assertTrue(instance.isValidInteger("test10", "4", 1, 10, false, errors));
        assertTrue(errors.size() == 5);
        assertTrue(instance.isValidInteger("test11", "400", 1, 10000, false, errors));
        assertTrue(errors.size() == 5);
        assertTrue(instance.isValidInteger("test12", "400000000", 1, 400000000, false, errors));
        assertTrue(errors.size() == 5);
        assertFalse(instance.isValidInteger("test13", "4000000000000", 1, 10000, false, errors));
        assertTrue(errors.size() == 6);
        assertFalse(instance.isValidInteger("test14", "alsdkf", 10, 10000, false, errors));
        assertTrue(errors.size() == 7);
        assertFalse(instance.isValidInteger("test15", "--10", 10, 10000, false, errors));
        assertTrue(errors.size() == 8);
        assertFalse(instance.isValidInteger("test16", "14.1414234x", 10, 10000, false, errors));
        assertTrue(errors.size() == 9);
        assertFalse(instance.isValidInteger("test17", "Infinity", 10, 10000, false, errors));
        assertTrue(errors.size() == 10);
        assertFalse(instance.isValidInteger("test18", "-Infinity", 10, 10000, false, errors));
        assertTrue(errors.size() == 11);
        assertFalse(instance.isValidInteger("test19", "NaN", 10, 10000, false, errors));
        assertTrue(errors.size() == 12);
        assertFalse(instance.isValidInteger("test20", "-NaN", 10, 10000, false, errors));
        assertTrue(errors.size() == 13);
        assertFalse(instance.isValidInteger("test21", "+NaN", 10, 10000, false, errors));
        assertTrue(errors.size() == 14);
        assertFalse(instance.isValidInteger("test22", "1e-6", -999999999, 999999999, false, errors));
        assertTrue(errors.size() == 15);
        assertFalse(instance.isValidInteger("test23", "-1e-6", -999999999, 999999999, false, errors));
        assertTrue(errors.size() == 16);

        if (variables.testForNull) {
	        //testing null value
	        assertTrue(instance.isValidInteger("test3", javaCast("null", ""), -10, 10, true, errors));
	        assertTrue(errors.size() == 16);
	        assertFalse(instance.isValidInteger("test4", javaCast("null", ""), -10, 10, false, errors));
	        assertTrue(errors.size() == 17);
	    }
    }

    public void function testIsValidListItem() {
        variables.System.out.println("isValidListItem");
        var instance = variables.ESAPI.validator();
        var list = [];
        list.add("one");
        list.add("two");
        assertTrue(instance.isValidListItem("test", "one", list));
        assertFalse(instance.isValidListItem("test", "three", list));

        var errors = {};
        assertTrue(instance.isValidListItem("test1", "one", list, errors));
        assertTrue(errors.size()==0);
        assertFalse(instance.isValidListItem("test2", "three", list, errors));
        assertTrue(errors.size()==1);
    }

    public void function testIsValidNumber() {
        variables.System.out.println("isValidNumber");
        var instance = variables.ESAPI.validator();
        //testing negative range
        assertFalse(instance.isValidNumber("test", "-4", 1, 10, false));
        assertTrue(instance.isValidNumber("test", "-4", -10, 10, false));
        if (variables.testForNull) {
	        //testing null value
        	assertTrue(instance.isValidNumber("test", javaCast("null", ""), -10, 10, true));
        	assertFalse(instance.isValidNumber("test", javaCast("null", ""), -10, 10, false));
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

        var errors = {};
      //testing negative range
        assertFalse(instance.isValidNumber("test1", "-4", 1, 10, false, errors));
        assertTrue(errors.size()==1);
        assertTrue(instance.isValidNumber("test2", "-4", -10, 10, false, errors));
        assertTrue(errors.size()==1);
        //testing empty string
        assertTrue(instance.isValidNumber("test5", "", -10, 10, true, errors));
        assertTrue(errors.size()==1);
        assertFalse(instance.isValidNumber("test6", "", -10, 10, false, errors));
        assertTrue(errors.size()==2);
        //testing improper range
        assertFalse(instance.isValidNumber("test7", "5", 10, -10, false, errors));
        assertTrue(errors.size()==3);
        //testing non-integers
        assertTrue(instance.isValidNumber("test8", "4.3214", -10, 10, true, errors));
        assertTrue(errors.size()==3);
        assertTrue(instance.isValidNumber("test9", "-1.65", -10, 10, true, errors));
        assertTrue(errors.size()==3);
        //other testing
        assertTrue(instance.isValidNumber("test10", "4", 1, 10, false, errors));
        assertTrue(errors.size()==3);
        assertTrue(instance.isValidNumber("test11", "400", 1, 10000, false, errors));
        assertTrue(errors.size()==3);
        assertTrue(instance.isValidNumber("test12", "400000000", 1, 400000000, false, errors));
        assertTrue(errors.size()==3);
        assertFalse(instance.isValidNumber("test13", "4000000000000", 1, 10000, false, errors));
        assertTrue(errors.size()==4);
        assertFalse(instance.isValidNumber("test14", "alsdkf", 10, 10000, false, errors));
        assertTrue(errors.size()==5);
        assertFalse(instance.isValidNumber("test15", "--10", 10, 10000, false, errors));
        assertTrue(errors.size()==6);
        assertFalse(instance.isValidNumber("test16", "14.1414234x", 10, 10000, false, errors));
        assertTrue(errors.size()==7);
        assertFalse(instance.isValidNumber("test17", "Infinity", 10, 10000, false, errors));
        assertTrue(errors.size()==8);
        assertFalse(instance.isValidNumber("test18", "-Infinity", 10, 10000, false, errors));
        assertTrue(errors.size()==9);
        assertFalse(instance.isValidNumber("test19", "NaN", 10, 10000, false, errors));
        assertTrue(errors.size()==10);
        assertFalse(instance.isValidNumber("test20", "-NaN", 10, 10000, false, errors));
        assertTrue(errors.size()==11);
        assertFalse(instance.isValidNumber("test21", "+NaN", 10, 10000, false, errors));
        assertTrue(errors.size()==12);
        assertTrue(instance.isValidNumber("test22", "1e-6", -999999999, 999999999, false, errors));
        assertTrue(errors.size()==12);
        assertTrue(instance.isValidNumber("test23", "-1e-6", -999999999, 999999999, false, errors));
        assertTrue(errors.size()==12);

        if (variables.testForNull) {
	        //testing null value
	        assertTrue(instance.isValidNumber("test3", javaCast("null", ""), -10, 10, true, errors));
	        assertTrue(errors.size()==12);
	        assertFalse(instance.isValidNumber("test4", javaCast("null", ""), -10, 10, false, errors));
	        assertTrue(errors.size()==13);
	    }
    }

    public void function testIsValidParameterSet() {
        variables.System.out.println("isValidParameterSet");

        var requiredNames = [];
        requiredNames.add("p1");
        requiredNames.add("p2");
        requiredNames.add("p3");
        var optionalNames = [];
        optionalNames.add("p4");
        optionalNames.add("p5");
        optionalNames.add("p6");
        var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
        var httpResponse = createObject("java", "org.owasp.esapi.http.MockHttpServletResponse").init();
        httpRequest.addParameter("p1", "value");
        httpRequest.addParameter("p2", "value");
        httpRequest.addParameter("p3", "value");
        variables.ESAPI.httpUtilities().setCurrentHTTP(httpRequest, httpResponse);
        var instance = variables.ESAPI.validator();
        var errors = {};
        assertTrue(instance.isValidHTTPRequestParameterSet("HTTPParameters", requiredNames, optionalNames));
        assertTrue(instance.isValidHTTPRequestParameterSet("HTTPParameters", requiredNames, optionalNames,errors, variables.ESAPI.currentRequest()));
        assertTrue(errors.size()==0);
        httpRequest.addParameter("p4", "value");
        httpRequest.addParameter("p5", "value");
        httpRequest.addParameter("p6", "value");
        assertTrue(instance.isValidHTTPRequestParameterSet("HTTPParameters", requiredNames, optionalNames));
        assertTrue(instance.isValidHTTPRequestParameterSet("HTTPParameters", requiredNames, optionalNames, errors, variables.ESAPI.currentRequest()));
        assertTrue(errors.size()==0);
        httpRequest.removeParameter("p1");
        assertFalse(instance.isValidHTTPRequestParameterSet("HTTPParameters", requiredNames, optionalNames));
        assertFalse(instance.isValidHTTPRequestParameterSet("HTTPParameters", requiredNames, optionalNames, errors, variables.ESAPI.currentRequest()));
        assertTrue(errors.size() ==1);
    }

    public void function testIsValidPrintable() {
        variables.System.out.println("isValidPrintable");
        var instance = variables.ESAPI.validator();
        assertTrue(instance.isValidPrintable("name", "abcDEF", 100, false));
        assertTrue(instance.isValidPrintable("name", "!@##R()*$;><()", 100, false));
        var chars = [chr(96), chr(255), chr(16), chr(37)];
        assertFalse(instance.isValidPrintable("name", arrayToList(chars, ""), 100, false));
        assertFalse(instance.isValidPrintable("name", "%08", 100, false));

        var errors = {};
        assertTrue(instance.isValidPrintable("name1", "abcDEF", 100, false, errors));
        assertTrue(errors.size()==0);
        assertTrue(instance.isValidPrintable("name2", "!@##R()*$;><()", 100, false, errors));
        assertTrue(errors.size()==0);
        assertFalse(instance.isValidPrintable("name3", arrayToList(chars, ""), 100, false, errors));
        assertTrue(errors.size()==1);
        assertFalse(instance.isValidPrintable("name4", "%08", 100, false, errors));
        assertTrue(errors.size()==2);

    }

    public void function testIsValidRedirectLocation() {
        //		isValidRedirectLocation(String, String, boolean)
    }

    public void function testIsValidSafeHTML() {
        variables.System.out.println("isValidSafeHTML");
        var instance = variables.ESAPI.validator();

        assertTrue(instance.isValidSafeHTML("test", "<b>Jeff</b>", 100, false));
        assertTrue(instance.isValidSafeHTML("test", '<a href="http://www.aspectsecurity.com">Aspect Security</a>', 100, false));
        assertTrue(instance.isValidSafeHTML("test", "Test. <script>alert(document.cookie)</script>", 100, false));
        assertTrue(instance.isValidSafeHTML("test", "Test. <div style={xss:expression(xss)}>", 100, false));
        assertTrue(instance.isValidSafeHTML("test", "Test. <s%00cript>alert(document.cookie)</script>", 100, false));
        assertTrue(instance.isValidSafeHTML("test", "Test. <s\tcript>alert(document.cookie)</script>", 100, false));
        assertTrue(instance.isValidSafeHTML("test", "Test. <s\r\n\0cript>alert(document.cookie)</script>", 100, false));

        // TODO: waiting for a way to validate text headed for an attribute for scripts
        // This would be nice to catch, but just looks like text to AntiSamy
        // assertFalse(instance.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
        var errors = {};
        assertTrue(instance.isValidSafeHTML("test1", "<b>Jeff</b>", 100, false, errors));
        assertTrue(instance.isValidSafeHTML("test2", '<a href="http://www.aspectsecurity.com">Aspect Security</a>', 100, false, errors));
        assertTrue(instance.isValidSafeHTML("test3", "Test. <script>alert(document.cookie)</script>", 100, false, errors));
        assertTrue(instance.isValidSafeHTML("test4", "Test. <div style={xss:expression(xss)}>", 100, false, errors));
        assertTrue(instance.isValidSafeHTML("test5", "Test. <s%00cript>alert(document.cookie)</script>", 100, false, errors));
        assertTrue(instance.isValidSafeHTML("test6", "Test. <s\tcript>alert(document.cookie)</script>", 100, false, errors));
        assertTrue(instance.isValidSafeHTML("test7", "Test. <s\r\n\0cript>alert(document.cookie)</script>", 100, false, errors));
        assertTrue(errors.size() == 0);

    }

    public void function testSafeReadLine() {
        variables.System.out.println("safeReadLine");

        var fileName = getTempDirectory() & variables.ESAPI.randomizer().getRandomFilename("txt");
        fileWrite(fileName, "testString", variables.PREFERRED_ENCODING);

        var s = fileOpen(fileName, "read", variables.PREFERRED_ENCODING, true);
        var instance = variables.ESAPI.validator();
        try {
            instance.safeReadLine(s, -1);
            fail("");
        }
        catch (org.owasp.esapi.errors.ValidationAvailabilityException e) {
            // Expected
        }
        fileSeek(s, 0);
        try {
            instance.safeReadLine(s, 4);
            fail("");
        }
        catch (org.owasp.esapi.errors.ValidationAvailabilityException e) {
            // Expected
        }
        fileSeek(s, 0);
        try {
            var u = instance.safeReadLine(s, 20);
            assertEquals("testString", u);
        }
        catch (org.owasp.esapi.errors.ValidationAvailabilityException e) {
            fail("");
        }

        // This sub-test attempts to validate that fileReadLine() and safeReadLine() are similar in operation
        // for the nominal case
        try {
            fileSeek(s, 0);
            var u = fileReadLine(s);
            fileSeek(s, 0);
            var v = instance.safeReadLine(s, 20);
            assertEquals(u, v);
        }
        catch (java.io.IOException e) {
            fail("");
        }
        catch (org.owasp.esapi.errors.ValidationAvailabilityException e) {
            fail("");
        }
    }

    public void function testIssue82_SafeString_Bad_Regex() {
        var instance = variables.ESAPI.validator();
        try {
            instance.getValidInput("address", "55 main st. pasadena ak", "SafeString", 512, false);
        }
        catch (ValidationException e) {
            fail(e.getLogMessage());
        }
    }

    public void function testGetParameterMap() {
//testing Validator.HTTPParameterName and Validator.HTTPParameterValue
        var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
        var safeRequest = new SafeRequest(variables.ESAPI, httpRequest);
//an example of a parameter from displaytag, should pass
        httpRequest.addParameter("d-49653-p", "pass");
        httpRequest.addParameter("<img ", "fail");
        httpRequest.addParameter(generateStringOfLength(32), "pass");
        httpRequest.addParameter(generateStringOfLength(33), "fail");
        assertEquals(safeRequest.getParameterMap().size(), 2);
        var map = safeRequest.getParameterMap();
        assertFalse(structKeyExists(map, "<img"));
        assertFalse(structKeyExists(map, generateStringOfLength(33)));
    }

    public void function testGetParameterNames() {
//testing Validator.HTTPParameterName
        var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
        var safeRequest = new SafeRequest(variables.ESAPI, httpRequest);
//an example of a parameter from displaytag, should pass
        httpRequest.addParameter("d-49653-p", "pass");
        httpRequest.addParameter("<img ", "fail");
        httpRequest.addParameter(generateStringOfLength(32), "pass");
        httpRequest.addParameter(generateStringOfLength(33), "fail");
        assertEquals(arrayLen(safeRequest.getParameterNames()), 2);
    }

    public void function testGetParameter() {
//testing Validator.HTTPParameterValue
        var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
        var safeRequest = new SafeRequest(variables.ESAPI, httpRequest);
        httpRequest.addParameter("p1", "Alice");
        httpRequest.addParameter("p2", "bob@alice.com");//mail-address from a submit-form
        httpRequest.addParameter("p3", variables.ESAPI.authenticator().generateStrongPassword());
        httpRequest.addParameter("p4", arrayToList(variables.ESAPI.encoder().CHAR_PASSWORD_SPECIALS, ""));
        //TODO - I think this should fair httpRequest.addParameter("p5", "�������?����"); //some special characters from european languages;
        httpRequest.addParameter("f1", "<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>");
        httpRequest.addParameter("f2", "<IMG SRC=&##106;&##97;&##118;&##97;&##115;&##99;&##114;&##105;&##112;&##116;&##58;&##97;&##108;&##101;&##114;&##116;&##40;&##39;&##88;&##83;&##83;&##39;&##41;>");
        httpRequest.addParameter("f3", "<IMG SRC=&##106;&##97;&##118;&##97;&##115;&##99;&##114;&##105;&##112;&##116;&##58;&##97;&##108;&##101;&##114;&##116;&##40;&##39;&##88;&##83;&##83;&##39;&##41;>");
        for (var i = 1; i <= 4; i++) {
            assertTrue(safeRequest.getParameter("p" & i) == httpRequest.getParameter("p" & i));
        }
        for (var i = 1; i <= 2; i++) {
        	var testResult = false;
        	try {
        		testResult = safeRequest.getParameter("f" & i) == httpRequest.getParameter("f" & i);
        	} catch (NullPointerException npe) {
        		//the test is this block SHOULD fail. a NPE is an acceptable failure state
        		testResult = false; //redundant, just being descriptive here
        	}
        	assertFalse(testResult);
        }
        assertEquals("", safeRequest.getParameter("e1"));

        //This is revealing problems with Jeff's original SafeRequest
        //mishandling of the AllowNull parameter. I'm adding a new Google code
        //bug to track this.
        //
        //assertNotNull(safeRequest.getParameter("e1", false));
    }

    public void function testGetCookies() {
//testing Validator.HTTPCookieName and Validator.HTTPCookieValue
        var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
        var safeRequest = new SafeRequest(variables.ESAPI, httpRequest);
//should support a base64-encode value
        httpRequest.setCookie("p1", "34=VJhjv7jiDu7tsdLrQQ2KcUwpfWUM2_mBae6UA8ttk4wBHdxxQ-1IBxyCOn3LWE08SDhpnBcJ7N5Vze48F2t8a1R_hXt7PX1BvgTM0pn-T4JkqGTm_tlmV4RmU3GT-dgn");
        httpRequest.setCookie("f1", '<A HREF="http://66.102.7.147/">XSS</A>');
        httpRequest.setCookie("load-balancing", "pass");
        httpRequest.setCookie("'bypass", "fail");
        var cookies = safeRequest.getCookies();
        assertEquals(cookies[1].getValue(), httpRequest.getCookies()[1].getValue());
        assertEquals(cookies[2].getName(), httpRequest.getCookies()[3].getName());
        assertTrue(arrayLen(cookies) == 2);
    }

    public void function testGetHeader() {
//testing Validator.HTTPHeaderValue
        var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
        var safeRequest = new SafeRequest(variables.ESAPI, httpRequest);
        httpRequest.addHeader("p1", "login");
        httpRequest.addHeader("f1", '<A HREF="http://0x42.0x0000066.0x7.0x93/">XSS</A>');
        httpRequest.addHeader("p2", generateStringOfLength(150));
        httpRequest.addHeader("f2", generateStringOfLength(151));
        assertEquals(safeRequest.getHeader("p1"), httpRequest.getHeader("p1"));
        assertEquals(safeRequest.getHeader("p2"), httpRequest.getHeader("p2"));
        assertFalse(safeRequest.getHeader("f1") == httpRequest.getHeader("f1"));
        assertFalse(safeRequest.getHeader("f2") == httpRequest.getHeader("f2"));
        assertEquals("", safeRequest.getHeader("p3"));
    }

    public void function testGetHeaderNames() {
//testing Validator.HTTPHeaderName
        var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
        var safeRequest = new SafeRequest(variables.ESAPI, httpRequest);
        httpRequest.addHeader("d-49653-p", "pass");
        httpRequest.addHeader("<img ", "fail");
        httpRequest.addHeader(generateStringOfLength(32), "pass");
        httpRequest.addHeader(generateStringOfLength(33), "fail");
        assertEquals(arrayLen(safeRequest.getHeaderNames()), 2);
    }

    public void function testGetQueryString() {
//testing Validator.HTTPQueryString
        var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
        var safeRequest = new SafeRequest(variables.ESAPI, httpRequest);
        httpRequest.setQueryString("mail=bob@alice.com&passwd=" & arrayToList(variables.ESAPI.encoder().CHAR_PASSWORD_SPECIALS, ""));// TODO, fix this & "&special=�����");
        assertEquals(safeRequest.getQueryString(), httpRequest.getQueryString());
        httpRequest.setQueryString("mail=<IMG SRC=""jav\tascript:alert('XSS');"">");
        assertFalse(safeRequest.getQueryString() == httpRequest.getQueryString());
        httpRequest.setQueryString("mail=bob@alice.com-passwd=johny");
        assertTrue(safeRequest.getQueryString() == httpRequest.getQueryString());
        httpRequest.setQueryString("mail=bob@alice.com-passwd=johny&special"); //= is missing!
        assertFalse(safeRequest.getQueryString() == httpRequest.getQueryString());
    }

    public void function testGetRequestURI() {
//testing Validator.HTTPURI
        var httpRequest = createObject("java", "org.owasp.esapi.http.MockHttpServletRequest").init();
        var safeRequest = new SafeRequest(variables.ESAPI, httpRequest);
        try {
            httpRequest.setRequestURI("/app/page.jsp");
        } catch (UnsupportedEncodingException ignored) {
        }
        assertEquals(safeRequest.getRequestURI(), httpRequest.getRequestURI());
    }

    private string function generateStringOfLength(required numeric length) {
        var longString = createObject("java", "java.lang.StringBuilder").init();
        for (var i = 0; i < arguments.length; i++) {
            longString.append("a");
        }
        return longString.toString();
    }

    public void function testGetContextPath() {
        // Root Context Path ("")
        assertTrue(variables.ESAPI.validator().isValidInput("HTTPContextPath", "", "HTTPContextPath", 512, true));
        // Deployed Context Path ("/context")
        assertTrue(variables.ESAPI.validator().isValidInput("HTTPContextPath", "/context", "HTTPContextPath", 512, true));
        // Fail-case - URL Splitting
        assertFalse(variables.ESAPI.validator().isValidInput("HTTPContextPath", "/\\nGET http://evil.com", "HTTPContextPath", 512, true));
    }
}
