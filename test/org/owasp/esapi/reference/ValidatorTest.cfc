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
		
		instance.PREFERRED_ENCODING = "UTF-8";
	</cfscript>
 
	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			structClear(request);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="tearDown" output="false">
		<cfscript>
			structClear(request);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testAddRule" output="false">
		<cfscript>
			local.validator = instance.ESAPI.validator();
			local.rule = new cfesapi.org.owasp.esapi.reference.validation.StringValidationRule(instance.ESAPI, "ridiculous");
			local.validator.addRule(local.rule);
			assertEquals(local.rule, local.validator.getRule("ridiculous"));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetRule" output="false">
		<cfscript>
			local.validator = instance.ESAPI.validator();
			local.rule = new cfesapi.org.owasp.esapi.reference.validation.StringValidationRule(instance.ESAPI, "rule");
			local.validator.addRule(local.rule);
			assertEquals(local.rule, local.validator.getRule("rule"));
			assertFalse(local.rule.toString() == local.validator.getRule("ridiculous").toString());
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidCreditCard" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("getValidCreditCard");
			local.validator = instance.ESAPI.validator();
			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();

			assertTrue(local.validator.isValidCreditCard("cctest1", "1234 9876 0000 0008", false));
			assertTrue(local.validator.isValidCreditCard("cctest2", "1234987600000008", false));
			assertFalse(local.validator.isValidCreditCard("cctest3", "12349876000000081", false));
			assertFalse(local.validator.isValidCreditCard("cctest4", "4417 1234 5678 9112", false));

			local.validator.getValidCreditCard("cctest5", "1234 9876 0000 0008", false, local.errors);
			assertEquals(0, local.errors.size());
			local.validator.getValidCreditCard("cctest6", "1234987600000008", false, local.errors);
			assertEquals(0, local.errors.size());
			local.validator.getValidCreditCard("cctest7", "12349876000000081", false, local.errors);
			assertEquals(1, local.errors.size());
			local.validator.getValidCreditCard("cctest8", "4417 1234 5678 9112", false, local.errors);
			assertEquals(2, local.errors.size());
			
	        assertTrue(local.validator.isValidCreditCard("cctest1", "1234 9876 0000 0008", false, local.errors));
	        assertTrue(local.errors.size()==2);
	        assertTrue(local.validator.isValidCreditCard("cctest2", "1234987600000008", false, local.errors));
	        assertTrue(local.errors.size()==2);
	        assertFalse(local.validator.isValidCreditCard("cctest3", "12349876000000081", false, local.errors));
	        assertTrue(local.errors.size()==3);
	        assertFalse(local.validator.isValidCreditCard("cctest4", "4417 1234 5678 9112", false, local.errors));
	        assertTrue(local.errors.size()==4);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidDate" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("getValidDate");
			local.validator = instance.ESAPI.validator();
			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
			assertTrue(local.validator.getValidDate("datetest1", "June 23, 1967", newJava("java.text.DateFormat").getDateInstance(newJava("java.text.DateFormat").MEDIUM, newJava("java.util.Locale").US), false) != "");
			local.validator.getValidDate("datetest2", "freakshow", newJava("java.text.DateFormat").getDateInstance(), false, local.errors);
			assertEquals(1, local.errors.size());

			// TODO: This test case fails due to an apparent bug in SimpleDateFormat
	    	// Note: This seems to be fixed in JDK 6. Will leave it commented out since
	    	//		 we only require JDK 5. -kww
			local.validator.getValidDate("test", "June 32, 2008", newJava("java.text.DateFormat").getDateInstance(), false, local.errors);
			// assertEquals( 2, local.errors.size() );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testLenientDate" output="false">
		<cfscript>
		    // FIXME: Should probably use SecurityConfigurationWrapper and force
		    //		  Validator.AcceptLenientDates to be false.
	    	newJava("java.lang.System").out.println("testLenientDate");
	    	local.acceptLenientDates = instance.ESAPI.securityConfiguration().getLenientDatesAccepted();
	    	if ( local.acceptLenientDates ) {
	    		assertTrue("Lenient date test skipped because Validator.AcceptLenientDates set to true", true);
	    		return;
	    	}
	
	    	local.lenientDateTest = "";
	    	try {
	    		// lenientDateTest will be null when Validator.AcceptLenientDates
	    		// is set to false (the default).
	    		local.validator = instance.ESAPI.validator();
	    		local.lenientDateTest = local.validator.getValidDate("datatest3-lenient", "15/2/2009 11:83:00",
	    				                                newJava("java.text.DateFormat").getDateInstance(newJava("java.text.DateFormat").SHORT, newJava("java.util.Locale").US),
	    				                                false);
	    		fail("Failed to throw expected ValidationException when Validator.AcceptLenientDates set to false.");
	    	} catch (cfesapi.org.owasp.esapi.errors.ValidationException ve) {
	    		assertIsEmpty( local.lenientDateTest );
	    		// we cannot verify this because getCause() is null
	    		//local.cause = ve.getCause();
	    		//assertTrue( local.cause.getClass().getName() == "java.text.ParseException" );
	    	} catch (java.lang.Exception e) {
	    		fail("Caught unexpected exception: " & e.getClass().getName() & "; msg: " & e.toString());
	    	}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidDirectoryPath" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("getValidDirectoryPath");
			local.validator = instance.ESAPI.validator();
			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
			// find a directory that exists
			local.parent = newJava("java.io.File").init("/");
			local.path = instance.ESAPI.securityConfiguration().getResourceFile("ESAPI.properties").getParentFile().getCanonicalPath();
			local.validator.getValidDirectoryPath("dirtest1", local.path, local.parent, true, local.errors);
			assertEquals(0, local.errors.size());
			local.validator.getValidDirectoryPath("dirtest2", "", local.parent, false, local.errors);
			assertEquals(1, local.errors.size());
			local.validator.getValidDirectoryPath("dirtest3", "ridicul%00ous", local.parent, false, local.errors);
			assertEquals(2, local.errors.size());
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidDouble" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("getValidDouble");
			local.validator = instance.ESAPI.validator();
			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
			local.validator.getValidDouble("dtest1", "1.0", 0, 20, true, local.errors);
			assertEquals(0, local.errors.size());
			local.validator.getValidDouble("dtest2", "", 0, 20, true, local.errors);
			assertEquals(0, local.errors.size());
			local.validator.getValidDouble("dtest3", "", 0, 20, false, local.errors);
			assertEquals(1, local.errors.size());
			local.validator.getValidDouble("dtest4", "ridiculous", 0, 20, true, local.errors);
			assertEquals(2, local.errors.size());
			local.validator.getValidDouble("dtest5", "" & (newJava("java.lang.Double").MAX_VALUE), 0, 20, true, local.errors);
			assertEquals(3, local.errors.size());
			local.validator.getValidDouble("dtest6", "" & (newJava("java.lang.Double").MAX_VALUE & .00001), 0, 20, true, local.errors);
			assertEquals(4, local.errors.size());
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidFileContent" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("getValidFileContent");
			local.validator = instance.ESAPI.validator();
			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
			local.bytes = "";
			try {
			   local.bytes = newJava("java.lang.String").init("12345").getBytes(instance.PREFERRED_ENCODING);
			}
			catch (java.io.UnsupportedEncodingException e) {
			   fail(instance.PREFERRED_ENCODING & " not a supported encoding?!?!!");
			}
			local.validator.getValidFileContent("test", local.bytes, 5, true, local.errors);
			assertEquals(0, local.errors.size());
			local.validator.getValidFileContent("test", local.bytes, 4, true, local.errors);
			assertEquals(1, local.errors.size());
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidFileName" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("getValidFileName");
			local.validator = instance.ESAPI.validator();
			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
			local.testName = "aspe%20ct.jar";
			assertEquals(local.testName, local.validator.getValidFileName("test", local.testName, instance.ESAPI.securityConfiguration().getAllowedFileExtensions(), false, local.errors), "Percent encoding is not changed");
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidInput" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("getValidInput");
			local.validator = instance.ESAPI.validator();
			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
			// local.validator.getValidInput(String, String, String, int, boolean, ValidationErrorList)
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidInteger" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("getValidInteger");
			local.validator = instance.ESAPI.validator();
			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
			// local.validator.getValidInteger(String, String, int, int, boolean, ValidationErrorList)
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidListItem" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("getValidListItem");
			local.validator = instance.ESAPI.validator();
			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
			// local.validator.getValidListItem(String, String, List, ValidationErrorList)
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidNumber" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("getValidNumber");
			local.validator = instance.ESAPI.validator();
			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
			// local.validator.getValidNumber(String, String, long, long, boolean, ValidationErrorList)
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidRedirectLocation" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("getValidRedirectLocation");
			local.validator = instance.ESAPI.validator();
			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
			// local.validator.getValidRedirectLocation(String, String, boolean, ValidationErrorList)
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetValidSafeHTML" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("getValidSafeHTML");
			local.validator = instance.ESAPI.validator();
			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();

			// new school test case setup
			local.rule = new cfesapi.org.owasp.esapi.reference.validation.HTMLValidationRule(instance.ESAPI, "test");
			instance.ESAPI.validator().addRule(local.rule);

			assertEquals("Test.", instance.ESAPI.validator().getRule("test").getValid("test", "Test. <script>alert(document.cookie)</script>"));

			local.test1 = "<b>Jeff</b>";
			local.result1 = local.validator.getValidSafeHTML("test", local.test1, 100, false, local.errors);
			assertEquals(local.test1, local.result1);

			local.test2 = '<a href="http://www.aspectsecurity.com">Aspect Security</a>';
			local.result2 = local.validator.getValidSafeHTML("test", local.test2, 100, false, local.errors);
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
			// assertFalse(local.validator.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));
			// String result4 = local.validator.getValidSafeHTML("test", test4);
			// assertEquals("", result4);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsInvalidFilename" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("testIsInvalidFilename");
			local.validator = instance.ESAPI.validator();
			local.invalidChars = newJava("java.lang.String").init('/\:*?"<>|').toCharArray();
			for (local.i = 1; local.i <= arrayLen(local.invalidChars); local.i++) {
			   assertFalse(local.validator.isValidFileName(context="test", input="as" & local.invalidChars[local.i] & "pect.jar", allowNull=false), local.invalidChars[local.i] & " is an invalid character for a filename");
			}
			assertFalse(local.validator.isValidFileName(context="test", input="", allowNull=false), "Files must have an extension");
			assertFalse(local.validator.isValidFileName(context="test.invalidExtension", input="", allowNull=false), "Files must have a valid extension");
			assertFalse(local.validator.isValidFileName(context="test", input="", allowNull=false), "Filennames cannot be the empty string");
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidDate" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("isValidDate");
			local.validator = instance.ESAPI.validator();
			local.format = newJava("java.text.SimpleDateFormat").getDateInstance();
			assertTrue(local.validator.isValidDate("datetest1", "September 11, 2001", local.format, true));
			assertFalse(local.validator.isValidDate("datetest2", "", local.format, false));
			assertFalse(local.validator.isValidDate("datetest3", "", local.format, false));

	        local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
	        assertTrue(local.validator.isValidDate("datetest1", "September 11, 2001", local.format, true, local.errors));
	        assertTrue(local.errors.size()==0);
	        assertFalse(local.validator.isValidDate("datetest2", "", local.format, false, local.errors));
	        assertTrue(local.errors.size()==1);
	        assertFalse(local.validator.isValidDate("datetest3", "", local.format, false, local.errors));
	        assertTrue(local.errors.size()==2);
   		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidDirectoryPath" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("isValidDirectoryPath");

			// get an encoder with a special list of codecs and make a validator out of it
			local.list = [];
			local.list.add("HTMLEntityCodec");
			local.encoder = new cfesapi.org.owasp.esapi.reference.DefaultEncoder(instance.ESAPI, local.list);
			local.validator = new cfesapi.org.owasp.esapi.reference.DefaultValidator(instance.ESAPI, local.encoder);

			local.isWindows = (newJava("java.lang.System").getProperty("os.name").indexOf("Windows") != -1) ? true : false;
			local.parent = newJava("java.io.File").init("/");

			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();

			if (local.isWindows) {
				local.sysRoot = newJava("java.io.File").init(newJava("java.lang.System").getenv("SystemRoot")).getCanonicalPath();
				// Windows paths that don't exist and thus should fail
				assertFalse(local.validator.isValidDirectoryPath("test", "c:\ridiculous", local.parent, false));
				assertFalse(local.validator.isValidDirectoryPath("test", "c:\jeff", local.parent, false));
				assertFalse(local.validator.isValidDirectoryPath("test", "c:\temp\..\etc", local.parent, false));

				// Windows paths
				assertTrue(local.validator.isValidDirectoryPath("test", "C:\", local.parent, false));                        // Windows root directory
				assertTrue(local.validator.isValidDirectoryPath("test", local.sysRoot, local.parent, false));                  // Windows always exist directory
				assertFalse(local.validator.isValidDirectoryPath("test", local.sysRoot & "\System32\cmd.exe", local.parent, false));      // Windows command shell

				// Unix specific paths should not pass
				assertFalse(local.validator.isValidDirectoryPath("test", "/tmp", local.parent, false));      // Unix Temporary directory
				assertFalse(local.validator.isValidDirectoryPath("test", "/bin/sh", local.parent, false));   // Unix Standard shell
				assertFalse(local.validator.isValidDirectoryPath("test", "/etc/config", parent, false));

				// Unix specific paths that should not exist or work
				assertFalse(local.validator.isValidDirectoryPath("test", "/etc/ridiculous", local.parent, false));
				assertFalse(local.validator.isValidDirectoryPath("test", "/tmp/../etc", local.parent, false));

	            assertFalse(local.validator.isValidDirectoryPath("test1", "c:\ridiculous", local.parent, false, local.errors));
	            assertTrue(local.errors.size()==1);
	            assertFalse(local.validator.isValidDirectoryPath("test2", "c:\jeff", local.parent, false, local.errors));
	            assertTrue(local.errors.size()==2);
	            assertFalse(local.validator.isValidDirectoryPath("test3", "c:\temp\..\etc", local.parent, false, local.errors));
	            assertTrue(local.errors.size()==3);
	
	            // Windows paths
	            assertTrue(local.validator.isValidDirectoryPath("test4", "C:\", local.parent, false, local.errors));                        // Windows root directory
	            assertTrue(local.errors.size()==3);
	            assertTrue(local.validator.isValidDirectoryPath("test5", sysRoot, local.parent, false, local.errors));                  // Windows always exist directory
	            assertTrue(local.errors.size()==3);
	            assertFalse(local.validator.isValidDirectoryPath("test6", sysRoot & "\System32\cmd.exe", local.parent, false, local.errors));      // Windows command shell
	            assertTrue(local.errors.size()==4);
	
	            // Unix specific paths should not pass
	            assertFalse(local.validator.isValidDirectoryPath("test7", "/tmp", local.parent, false, local.errors));      // Unix Temporary directory
	            assertTrue(local.errors.size()==5);
	            assertFalse(local.validator.isValidDirectoryPath("test8", "/bin/sh", local.parent, false, local.errors));   // Unix Standard shell
	            assertTrue(local.errors.size()==6);
	            assertFalse(local.validator.isValidDirectoryPath("test9", "/etc/config", local.parent, false, local.errors));
	            assertTrue(local.errors.size()==7);
	
	            // Unix specific paths that should not exist or work
	            assertFalse(local.validator.isValidDirectoryPath("test10", "/etc/ridiculous", local.parent, false, local.errors));
	            assertTrue(local.errors.size()==8);
	            assertFalse(local.validator.isValidDirectoryPath("test11", "/tmp/../etc", local.parent, false, local.errors));
	            assertTrue(local.errors.size()==9);
            }
			else {
				// Windows paths should fail
				assertFalse(local.validator.isValidDirectoryPath("test", "c:\ridiculous", local.parent, false));
				assertFalse(local.validator.isValidDirectoryPath("test", "c:\temp\..\etc", local.parent, false));

				// Standard Windows locations should fail
				assertFalse(local.validator.isValidDirectoryPath("test", "c:\", local.parent, false));                        // Windows root directory
				assertFalse(local.validator.isValidDirectoryPath("test", "c:\Windows\temp", local.parent, false));               // Windows temporary directory
				assertFalse(local.validator.isValidDirectoryPath("test", "c:\Windows\System32\cmd.exe", local.parent, false));   // Windows command shell

				// Unix specific paths should pass
				assertTrue(local.validator.isValidDirectoryPath("test", "/", local.parent, false));         // Root directory
				assertTrue(local.validator.isValidDirectoryPath("test", "/bin", local.parent, false));      // Always exist directory

				// Unix specific paths that should not exist or work
				assertFalse(local.validator.isValidDirectoryPath("test", "/bin/sh", local.parent, false));   // Standard shell, not dir
				assertFalse(local.validator.isValidDirectoryPath("test", "/etc/ridiculous", local.parent, false));
				assertFalse(local.validator.isValidDirectoryPath("test", "/tmp/../etc", local.parent, false));
				
	            // Windows paths should fail
	            assertFalse(local.validator.isValidDirectoryPath("test1", "c:\ridiculous", local.parent, false, local.errors));
	            assertTrue(local.errors.size()==1);
	            assertFalse(local.validator.isValidDirectoryPath("test2", "c:\temp\..\etc", local.parent, false, local.errors));
	            assertTrue(local.errors.size()==2);
	
	            // Standard Windows locations should fail
	            assertFalse(local.validator.isValidDirectoryPath("test3", "c:\", local.parent, false, local.errors));                        // Windows root directory
	            assertTrue(local.errors.size()==3);
	            assertFalse(local.validator.isValidDirectoryPath("test4", "c:\Windows\temp", local.parent, false, local.errors));               // Windows temporary directory
	            assertTrue(local.errors.size()==4);
	            assertFalse(local.validator.isValidDirectoryPath("test5", "c:\Windows\System32\cmd.exe", local.parent, false, local.errors));   // Windows command shell
	            assertTrue(local.errors.size()==5);
	
	            // Unix specific paths should pass
	            assertTrue(local.validator.isValidDirectoryPath("test6", "/", local.parent, false, local.errors));         // Root directory
	            assertTrue(local.errors.size()==5);
	            assertTrue(local.validator.isValidDirectoryPath("test7", "/bin", local.parent, false, local.errors));      // Always exist directory
	            assertTrue(local.errors.size()==5);
	
	            // Unix specific paths that should not exist or work
	            assertFalse(local.validator.isValidDirectoryPath("test8", "/bin/sh", local.parent, false, local.errors));   // Standard shell, not dir
	            assertTrue(local.errors.size()==6);
	            assertFalse(local.validator.isValidDirectoryPath("test9", "/etc/ridiculous", local.parent, false, local.errors));
	            assertTrue(local.errors.size()==7);
	            assertFalse(local.validator.isValidDirectoryPath("test10", "/tmp/../etc", local.parent, false, local.errors));
	            assertTrue(local.errors.size()==8);
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidDouble" output="false">
		<cfscript>
			// isValidDouble(String, String, double, double, boolean)
			local.validator = instance.ESAPI.validator();
			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
			//testing negative range
			assertFalse(local.validator.isValidDouble("test1", "-4", 1, 10, false, local.errors));
			assertTrue(local.errors.size() == 1);
			assertTrue(local.validator.isValidDouble("test2", "-4", -10, 10, false, local.errors));
			assertTrue(local.errors.size() == 1);
			//testing null value
			assertTrue(local.validator.isValidDouble("test3", "", -10, 10, true, local.errors));
			assertTrue(local.errors.size() == 1);
			assertFalse(local.validator.isValidDouble("test4", "", -10, 10, false, local.errors));
			assertTrue(local.errors.size() == 2);
			//testing empty string
			assertTrue(local.validator.isValidDouble("test5", "", -10, 10, true, local.errors));
			assertTrue(local.errors.size() == 2);
			assertFalse(local.validator.isValidDouble("test6", "", -10, 10, false, local.errors));
			assertTrue(local.errors.size() == 3);
			//testing improper range
			assertFalse(local.validator.isValidDouble("test7", "50.0", 10, -10, false, local.errors));
			assertTrue(local.errors.size() == 4);
			//testing non-integers
			assertTrue(local.validator.isValidDouble("test8", "4.3214", -10, 10, true, local.errors));
			assertTrue(local.errors.size() == 4);
			assertTrue(local.validator.isValidDouble("test9", "-1.65", -10, 10, true, local.errors));
			assertTrue(local.errors.size() == 4);
			//other testing
			assertTrue(local.validator.isValidDouble("test10", "4", 1, 10, false, local.errors));
			assertTrue(local.errors.size() == 4);
			assertTrue(local.validator.isValidDouble("test11", "400", 1, 10000, false, local.errors));
			assertTrue(local.errors.size() == 4);
			assertTrue(local.validator.isValidDouble("test12", "400000000", 1, 400000000, false, local.errors));
			assertTrue(local.errors.size() == 4);
			assertFalse(local.validator.isValidDouble("test13", "4000000000000", 1, 10000, false, local.errors));
			assertTrue(local.errors.size() == 5);
			assertFalse(local.validator.isValidDouble("test14", "alsdkf", 10, 10000, false, local.errors));
			assertTrue(local.errors.size() == 6);
			assertFalse(local.validator.isValidDouble("test15", "--10", 10, 10000, false, local.errors));
			assertTrue(local.errors.size() == 7);
			assertFalse(local.validator.isValidDouble("test16", "14.1414234x", 10, 10000, false, local.errors));
			assertTrue(local.errors.size() == 8);
			assertFalse(local.validator.isValidDouble("test17", "Infinity", 10, 10000, false, local.errors));
			assertTrue(local.errors.size() == 9);
			assertFalse(local.validator.isValidDouble("test18", "-Infinity", 10, 10000, false, local.errors));
			assertTrue(local.errors.size() == 10);
			assertFalse(local.validator.isValidDouble("test19", "NaN", 10, 10000, false, local.errors));
			assertTrue(local.errors.size() == 11);
			assertFalse(local.validator.isValidDouble("test20", "-NaN", 10, 10000, false, local.errors));
			assertTrue(local.errors.size() == 12);
			assertFalse(local.validator.isValidDouble("test21", "+NaN", 10, 10000, false, local.errors));
			assertTrue(local.errors.size() == 13);
			assertTrue(local.validator.isValidDouble("test22", "1e-6", -999999999, 999999999, false, local.errors));
			assertTrue(local.errors.size() == 13);
			assertTrue(local.validator.isValidDouble("test23", "-1e-6", -999999999, 999999999, false, local.errors));
			assertTrue(local.errors.size() == 13);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidFileContent" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("isValidFileContent");
			local.content = "";
			try {
			   local.content = newJava("java.lang.String").init("This is some file content").getBytes(instance.PREFERRED_ENCODING);
			}
			catch (java.io.UnsupportedEncodingException e) {
			   fail(instance.PREFERRED_ENCODING & " not a supported encoding?!?!!!");
			}
			local.validator = instance.ESAPI.validator();
			assertTrue(local.validator.isValidFileContent("test", local.content, 100, false));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidFileName" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("isValidFileName");
			local.validator = instance.ESAPI.validator();
			assertTrue(local.validator.isValidFileName(context="test", input="aspect.jar", allowNull=false), "Simple valid filename with a valid extension");
			assertTrue(local.validator.isValidFileName(context="test", input="!@##$%^&{}[]()_+-=,.~'` abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.jar", allowNull=false), "All valid filename characters are accepted");
			assertTrue(local.validator.isValidFileName(context="test", input="aspe%20ct.jar", allowNull=false), "Legal filenames that decode to legal filenames are accepted");

			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
	        assertTrue(local.validator.isValidFileName(context="test", input="aspect.jar", allowNull=false, errorList=local.errors), "Simple valid filename with a valid extension");
	        assertTrue(local.validator.isValidFileName(context="test", input="!@##$%^&{}[]()_+-=,.~'` abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.jar", allowNull=false, errorList=local.errors), "All valid filename characters are accepted");
	        assertTrue(local.validator.isValidFileName(context="test", input="aspe%20ct.jar", allowNull=false, errorList=local.errors), "Legal filenames that decode to legal filenames are accepted");
	        assertTrue(local.errors.size() == 0);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidFileUpload" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("isValidFileUpload");
			local.filepath = newJava("java.io.File").init(newJava("java.lang.System").getProperty("user.dir")).getCanonicalPath();
			local.filename = "aspect.jar";
			local.parent = newJava("java.io.File").init("/").getCanonicalFile();
			local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
			local.content = "";
			try {
			   local.content = newJava("java.lang.String").init("This is some file content").getBytes(instance.PREFERRED_ENCODING);
			}
			catch (java.io.UnsupportedEncodingException e) {
			   fail(instance.PREFERRED_ENCODING & " not a supported encoding?!?!!!");
			}
			local.validator = instance.ESAPI.validator();
			assertTrue(local.validator.isValidFileUpload("test", local.filepath, local.filename, local.parent, local.content, 100, false));
			assertTrue(local.validator.isValidFileUpload("test", local.filepath, local.filename, local.parent, local.content, 100, false, local.errors));
        	assertTrue(local.errors.size() == 0);

			local.filepath = "/ridiculous";
			local.filename = "aspect.jar";
			try {
			   local.content = newJava("java.lang.String").init("This is some file content").getBytes(instance.PREFERRED_ENCODING);
			}
			catch (java.io.UnsupportedEncodingException e) {
			   fail(instance.PREFERRED_ENCODING & " not a supported encoding?!?!!!");
			}
			assertFalse(local.validator.isValidFileUpload("test", local.filepath, local.filename, local.parent, local.content, 100, false));
	        assertFalse(local.validator.isValidFileUpload("test", local.filepath, local.filename, local.parent, local.content, 100, false, local.errors));
	        assertTrue(local.errors.size() == 1);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidHTTPRequestParameterSet" output="false">
		<cfscript>
			//		isValidHTTPRequestParameterSet(String, Set, Set)
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidInput" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("isValidInput");
			local.validator = instance.ESAPI.validator();
			assertTrue(local.validator.isValidInput("test", "jeff.williams@aspectsecurity.com", "Email", 100, false));
			assertFalse(local.validator.isValidInput("test", "jeff.williams@@aspectsecurity.com", "Email", 100, false));
			assertFalse(local.validator.isValidInput("test", "jeff.williams@aspectsecurity", "Email", 100, false));
	        assertTrue(local.validator.isValidInput("test", "jeff.wil'liams@aspectsecurity.com", "Email", 100, false));
	        assertTrue(local.validator.isValidInput("test", "jeff.wil''liams@aspectsecurity.com", "Email", 100, false));
			assertTrue(local.validator.isValidInput("test", "123.168.100.234", "IPAddress", 100, false));
			assertTrue(local.validator.isValidInput("test", "192.168.1.234", "IPAddress", 100, false));
			assertFalse(local.validator.isValidInput("test", "..168.1.234", "IPAddress", 100, false));
			assertFalse(local.validator.isValidInput("test", "10.x.1.234", "IPAddress", 100, false));
			assertTrue(local.validator.isValidInput("test", "http://www.aspectsecurity.com", "URL", 100, false));
			assertFalse(local.validator.isValidInput("test", "http:///www.aspectsecurity.com", "URL", 100, false));
			assertFalse(local.validator.isValidInput("test", "http://www.aspect security.com", "URL", 100, false));
			assertTrue(local.validator.isValidInput("test", "078-05-1120", "SSN", 100, false));
			assertTrue(local.validator.isValidInput("test", "078 05 1120", "SSN", 100, false));
			assertTrue(local.validator.isValidInput("test", "078051120", "SSN", 100, false));
			assertFalse(local.validator.isValidInput("test", "987-65-4320", "SSN", 100, false));
			assertFalse(local.validator.isValidInput("test", "000-00-0000", "SSN", 100, false));
			assertFalse(local.validator.isValidInput("test", "(555) 555-5555", "SSN", 100, false));
			assertFalse(local.validator.isValidInput("test", "test", "SSN", 100, false));
	        assertTrue(local.validator.isValidInput("test", "jeffWILLIAMS123", "HTTPParameterValue", 100, false));
	        assertTrue(local.validator.isValidInput("test", "jeff .-/+=@_ WILLIAMS", "HTTPParameterValue", 100, false));
	        // Removed per Issue 116 - The '*' character is valid as a parameter character
			// assertFalse(local.validator.isValidInput("test", "jeff*WILLIAMS", "HTTPParameterValue", 100, false));
	        assertFalse(local.validator.isValidInput("test", "jeff^WILLIAMS", "HTTPParameterValue", 100, false));
	        assertFalse(local.validator.isValidInput("test", "jeff\\WILLIAMS", "HTTPParameterValue", 100, false));

			// null tests not valid for CF
			//assertTrue(local.validator.isValidInput("test", null, "Email", 100, true));
			//assertFalse(local.validator.isValidInput("test", null, "Email", 100, false));

	        local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
	
	        assertTrue(local.validator.isValidInput(context="test1", input="jeff.williams@aspectsecurity.com", type="Email", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==0);
	        assertFalse(local.validator.isValidInput(context="test2", input="jeff.williams@@aspectsecurity.com", type="Email", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==1);
	        assertFalse(local.validator.isValidInput(context="test3", input="jeff.williams@aspectsecurity", type="Email", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==2);
	        assertTrue(local.validator.isValidInput(context="test4", input="jeff.wil'liams@aspectsecurity.com", type="Email", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==2);
	        assertTrue(local.validator.isValidInput(context="test5", input="jeff.wil''liams@aspectsecurity.com", type="Email", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==2);
	        assertTrue(local.validator.isValidInput(context="test6", input="123.168.100.234", type="IPAddress", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==2);
	        assertTrue(local.validator.isValidInput(context="test7", input="192.168.1.234", type="IPAddress", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==2);
	        assertFalse(local.validator.isValidInput(context="test8", input="..168.1.234", type="IPAddress", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==3);
	        assertFalse(local.validator.isValidInput(context="test9", input="10.x.1.234", type="IPAddress", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==4);
	        assertTrue(local.validator.isValidInput(context="test10", input="http://www.aspectsecurity.com", type="URL", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==4);
	        assertFalse(local.validator.isValidInput(context="test11", input="http:///www.aspectsecurity.com", type="URL", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==5);
	        assertFalse(local.validator.isValidInput(context="test12", input="http://www.aspect security.com", type="URL", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==6);
	        assertTrue(local.validator.isValidInput(context="test13", input="078-05-1120", type="SSN", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==6);
	        assertTrue(local.validator.isValidInput(context="test14", input="078 05 1120", type="SSN", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==6);
	        assertTrue(local.validator.isValidInput(context="test15", input="078051120", type="SSN", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==6);
	        assertFalse(local.validator.isValidInput(context="test16", input="987-65-4320", type="SSN", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==7);
	        assertFalse(local.validator.isValidInput(context="test17", input="000-00-0000", type="SSN", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==8);
	        assertFalse(local.validator.isValidInput(context="test18", input="(555) 555-5555", type="SSN", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==9);
	        assertFalse(local.validator.isValidInput(context="test19", input="test", type="SSN", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==10);
	        assertTrue(local.validator.isValidInput(context="test20", input="jeffWILLIAMS123", type="HTTPParameterValue", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==10);
	        assertTrue(local.validator.isValidInput(context="test21", input="jeff .-/+=@_ WILLIAMS", type="HTTPParameterValue", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==10);
	        // Removed per Issue 116 - The '*' character is valid as a parameter character
	//        assertFalse(instance.isValidInput(context="test", input="jeff*WILLIAMS", type="HTTPParameterValue", maxLength=100, allowNull=false, errorList=local.errors));
	        assertFalse(local.validator.isValidInput(context="test22", input="jeff^WILLIAMS", type="HTTPParameterValue", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==11);
	        assertFalse(local.validator.isValidInput(context="test23", input="jeff\\WILLIAMS", type="HTTPParameterValue", maxLength=100, allowNull=false, errorList=local.errors));
	        assertTrue(local.errors.size()==12);
	
	        // null tests not valid for CF
	        //assertTrue(local.validator.isValidInput(context="test", input=null, type="Email", maxLength=100, allowNull=true, errorList=local.errors));
	        //assertFalse(local.validator.isValidInput(context="test", input=null, type="Email", maxLength=100, allowNull=false, errorList=local.errors));
	        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidInteger" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("isValidInteger");
			local.validator = instance.ESAPI.validator();
			//testing negative range
			assertFalse(local.validator.isValidInteger("test", "-4", 1, 10, false));
			assertTrue(local.validator.isValidInteger("test", "-4", -10, 10, false));
			//testing empty value
			assertTrue(local.validator.isValidInteger("test", "", -10, 10, true));
			assertFalse(local.validator.isValidInteger("test", "", -10, 10, false));
			//testing empty string
			assertTrue(local.validator.isValidInteger("test", "", -10, 10, true));
			assertFalse(local.validator.isValidInteger("test", "", -10, 10, false));
			//testing improper range
			assertFalse(local.validator.isValidInteger("test", "50", 10, -10, false));
			//testing non-integers
			assertFalse(local.validator.isValidInteger("test", "4.3214", -10, 10, true));
			assertFalse(local.validator.isValidInteger("test", "-1.65", -10, 10, true));
			//other testing
			assertTrue(local.validator.isValidInteger("test", "4", 1, 10, false));
			assertTrue(local.validator.isValidInteger("test", "400", 1, 10000, false));
			assertTrue(local.validator.isValidInteger("test", "400000000", 1, 400000000, false));
			assertFalse(local.validator.isValidInteger("test", "4000000000000", 1, 10000, false));
			assertFalse(local.validator.isValidInteger("test", "alsdkf", 10, 10000, false));
			assertFalse(local.validator.isValidInteger("test", "--10", 10, 10000, false));
			assertFalse(local.validator.isValidInteger("test", "14.1414234x", 10, 10000, false));
			assertFalse(local.validator.isValidInteger("test", "Infinity", 10, 10000, false));
			assertFalse(local.validator.isValidInteger("test", "-Infinity", 10, 10000, false));
			assertFalse(local.validator.isValidInteger("test", "NaN", 10, 10000, false));
			assertFalse(local.validator.isValidInteger("test", "-NaN", 10, 10000, false));
			assertFalse(local.validator.isValidInteger("test", "+NaN", 10, 10000, false));
			assertFalse(local.validator.isValidInteger("test", "1e-6", -999999999, 999999999, false));
			assertFalse(local.validator.isValidInteger("test", "-1e-6", -999999999, 999999999, false));

	        local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
	        //testing negative range
	        assertFalse(local.validator.isValidInteger("test1", "-4", 1, 10, false, local.errors));
	        assertTrue(local.errors.size() == 1);
	        assertTrue(local.validator.isValidInteger("test2", "-4", -10, 10, false, local.errors));
	        assertTrue(local.errors.size() == 1);
	        //testing null value
	        assertTrue(local.validator.isValidInteger("test3", "", -10, 10, true, local.errors));
	        assertTrue(local.errors.size() == 1);
	        assertFalse(local.validator.isValidInteger("test4", "", -10, 10, false, local.errors));
	        assertTrue(local.errors.size() == 2);
	        //testing empty string
	        assertTrue(local.validator.isValidInteger("test5", "", -10, 10, true, local.errors));
	        assertTrue(local.errors.size() == 2);
	        assertFalse(local.validator.isValidInteger("test6", "", -10, 10, false, local.errors));
	        assertTrue(local.errors.size() == 3);
	        //testing improper range
	        assertFalse(local.validator.isValidInteger("test7", "50", 10, -10, false, local.errors));
	        assertTrue(local.errors.size() == 4);
	        //testing non-integers
	        assertFalse(local.validator.isValidInteger("test8", "4.3214", -10, 10, true, local.errors));
	        assertTrue(local.errors.size() == 5);
	        assertFalse(local.validator.isValidInteger("test9", "-1.65", -10, 10, true, local.errors));
	        assertTrue(local.errors.size() == 6);
	        //other testing
	        assertTrue(local.validator.isValidInteger("test10", "4", 1, 10, false, local.errors));
	        assertTrue(local.errors.size() == 6);
	        assertTrue(local.validator.isValidInteger("test11", "400", 1, 10000, false, local.errors));
	        assertTrue(local.errors.size() == 6);
	        assertTrue(local.validator.isValidInteger("test12", "400000000", 1, 400000000, false, local.errors));
	        assertTrue(local.errors.size() == 6);
	        assertFalse(local.validator.isValidInteger("test13", "4000000000000", 1, 10000, false, local.errors));
	        assertTrue(local.errors.size() == 7);
	        assertFalse(local.validator.isValidInteger("test14", "alsdkf", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size() == 8);
	        assertFalse(local.validator.isValidInteger("test15", "--10", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size() == 9);
	        assertFalse(local.validator.isValidInteger("test16", "14.1414234x", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size() == 10);
	        assertFalse(local.validator.isValidInteger("test17", "Infinity", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size() == 11);
	        assertFalse(local.validator.isValidInteger("test18", "-Infinity", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size() == 12);
	        assertFalse(local.validator.isValidInteger("test19", "NaN", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size() == 13);
	        assertFalse(local.validator.isValidInteger("test20", "-NaN", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size() == 14);
	        assertFalse(local.validator.isValidInteger("test21", "+NaN", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size() == 15);
	        assertFalse(local.validator.isValidInteger("test22", "1e-6", -999999999, 999999999, false, local.errors));
	        assertTrue(local.errors.size() == 16);
	        assertFalse(local.validator.isValidInteger("test23", "-1e-6", -999999999, 999999999, false, local.errors));
	        assertTrue(local.errors.size() == 17);
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidListItem" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("isValidListItem");
			local.validator = instance.ESAPI.validator();
			local.list = [];
			local.list.add("one");
			local.list.add("two");
			assertTrue(local.validator.isValidListItem("test", "one", local.list));
			assertFalse(local.validator.isValidListItem("test", "three", local.list));
	
	        local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
	        assertTrue(local.validator.isValidListItem("test1", "one", local.list, local.errors));
	        assertTrue(local.errors.size()==0);
	        assertFalse(local.validator.isValidListItem("test2", "three", local.list, local.errors));
	        assertTrue(local.errors.size()==1);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidNumber" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("isValidNumber");
			local.validator = instance.ESAPI.validator();
			//testing negative range
			assertFalse(local.validator.isValidNumber("test", "-4", 1, 10, false));
			assertTrue(local.validator.isValidNumber("test", "-4", -10, 10, false));
			//testing empty value
			assertTrue(local.validator.isValidNumber("test", "", -10, 10, true));
			assertFalse(local.validator.isValidNumber("test", "", -10, 10, false));
			//testing empty string
			assertTrue(local.validator.isValidNumber("test", "", -10, 10, true));
			assertFalse(local.validator.isValidNumber("test", "", -10, 10, false));
			//testing improper range
			assertFalse(local.validator.isValidNumber("test", "5", 10, -10, false));
			//testing non-integers
			assertTrue(local.validator.isValidNumber("test", "4.3214", -10, 10, true));
			assertTrue(local.validator.isValidNumber("test", "-1.65", -10, 10, true));
			//other testing
			assertTrue(local.validator.isValidNumber("test", "4", 1, 10, false));
			assertTrue(local.validator.isValidNumber("test", "400", 1, 10000, false));
			assertTrue(local.validator.isValidNumber("test", "400000000", 1, 400000000, false));
			assertFalse(local.validator.isValidNumber("test", "4000000000000", 1, 10000, false));
			assertFalse(local.validator.isValidNumber("test", "alsdkf", 10, 10000, false));
			assertFalse(local.validator.isValidNumber("test", "--10", 10, 10000, false));
			assertFalse(local.validator.isValidNumber("test", "14.1414234x", 10, 10000, false));
			assertFalse(local.validator.isValidNumber("test", "Infinity", 10, 10000, false));
			assertFalse(local.validator.isValidNumber("test", "-Infinity", 10, 10000, false));
			assertFalse(local.validator.isValidNumber("test", "NaN", 10, 10000, false));
			assertFalse(local.validator.isValidNumber("test", "-NaN", 10, 10000, false));
			assertFalse(local.validator.isValidNumber("test", "+NaN", 10, 10000, false));
			assertTrue(local.validator.isValidNumber("test", "1e-6", -999999999, 999999999, false));
			assertTrue(local.validator.isValidNumber("test", "-1e-6", -999999999, 999999999, false));
			
	        local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
			// testing negative range
	        assertFalse(local.validator.isValidNumber("test1", "-4", 1, 10, false, local.errors));
	        assertTrue(local.errors.size()==1);
	        assertTrue(local.validator.isValidNumber("test2", "-4", -10, 10, false, local.errors));
	        assertTrue(local.errors.size()==1);
	        //testing null value
	        assertTrue(local.validator.isValidNumber("test3", "", -10, 10, true, local.errors));
	        assertTrue(local.errors.size()==1);
	        assertFalse(local.validator.isValidNumber("test4", "", -10, 10, false, local.errors));
	        assertTrue(local.errors.size()==2);
	        //testing empty string
	        assertTrue(local.validator.isValidNumber("test5", "", -10, 10, true, local.errors));
	        assertTrue(local.errors.size()==2);
	        assertFalse(local.validator.isValidNumber("test6", "", -10, 10, false, local.errors));
	        assertTrue(local.errors.size()==3);
	        //testing improper range
	        assertFalse(local.validator.isValidNumber("test7", "5", 10, -10, false, local.errors));
	        assertTrue(local.errors.size()==4);
	        //testing non-integers
	        assertTrue(local.validator.isValidNumber("test8", "4.3214", -10, 10, true, local.errors));
	        assertTrue(local.errors.size()==4);
	        assertTrue(local.validator.isValidNumber("test9", "-1.65", -10, 10, true, local.errors));
	        assertTrue(local.errors.size()==4);
	        //other testing
	        assertTrue(local.validator.isValidNumber("test10", "4", 1, 10, false, local.errors));
	        assertTrue(local.errors.size()==4);
	        assertTrue(local.validator.isValidNumber("test11", "400", 1, 10000, false, local.errors));
	        assertTrue(local.errors.size()==4);
	        assertTrue(local.validator.isValidNumber("test12", "400000000", 1, 400000000, false, local.errors));
	        assertTrue(local.errors.size()==4);
	        assertFalse(local.validator.isValidNumber("test13", "4000000000000", 1, 10000, false, local.errors));
	        assertTrue(local.errors.size()==5);
	        assertFalse(local.validator.isValidNumber("test14", "alsdkf", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size()==6);
	        assertFalse(local.validator.isValidNumber("test15", "--10", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size()==7);
	        assertFalse(local.validator.isValidNumber("test16", "14.1414234x", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size()==8);
	        assertFalse(local.validator.isValidNumber("test17", "Infinity", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size()==9);
	        assertFalse(local.validator.isValidNumber("test18", "-Infinity", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size()==10);
	        assertFalse(local.validator.isValidNumber("test19", "NaN", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size()==11);
	        assertFalse(local.validator.isValidNumber("test20", "-NaN", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size()==12);
	        assertFalse(local.validator.isValidNumber("test21", "+NaN", 10, 10000, false, local.errors));
	        assertTrue(local.errors.size()==13);
	        assertTrue(local.validator.isValidNumber("test22", "1e-6", -999999999, 999999999, false, local.errors));
	        assertTrue(local.errors.size()==13);
	        assertTrue(local.validator.isValidNumber("test23", "-1e-6", -999999999, 999999999, false, local.errors));
	        assertTrue(local.errors.size()==13);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidParameterSet" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("isValidParameterSet");
			local.requiredNames = [];
			local.requiredNames.add("p1");
			local.requiredNames.add("p2");
			local.requiredNames.add("p3");
			local.optionalNames = [];
			local.optionalNames.add("p4");
			local.optionalNames.add("p5");
			local.optionalNames.add("p6");
			local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
			local.response = new cfesapi.test.org.owasp.esapi.http.MockHttpServletResponse();
			local.request.addParameter("p1", "value");
			local.request.addParameter("p2", "value");
			local.request.addParameter("p3", "value");
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, local.response);
			local.validator = instance.ESAPI.validator();
	        local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
			assertTrue(local.validator.isValidHTTPRequestParameterSet("HTTPParameters", local.request, local.requiredNames, local.optionalNames));
	        assertTrue(local.validator.isValidHTTPRequestParameterSet("HTTPParameters", local.request, local.requiredNames, local.optionalNames, local.errors));
	        assertTrue(local.errors.size()==0);
			local.request.addParameter("p4", "value");
			local.request.addParameter("p5", "value");
			local.request.addParameter("p6", "value");
			assertTrue(local.validator.isValidHTTPRequestParameterSet("HTTPParameters", local.request, local.requiredNames, local.optionalNames));
	        assertTrue(local.validator.isValidHTTPRequestParameterSet("HTTPParameters", local.request, local.requiredNames, local.optionalNames, local.errors));
	        assertTrue(local.errors.size()==0);
			local.request.removeParameter("p1");
			assertFalse(local.validator.isValidHTTPRequestParameterSet("HTTPParameters", local.request, local.requiredNames, local.optionalNames));
	        assertFalse(local.validator.isValidHTTPRequestParameterSet("HTTPParameters", local.request, local.requiredNames, local.optionalNames, local.errors));
	        assertTrue(local.errors.size() ==1);
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidPrintable" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("isValidPrintable");
			local.validator = instance.ESAPI.validator();
			assertTrue(local.validator.isValidPrintable("name", "abcDEF", 100, false));
			assertTrue(local.validator.isValidPrintable("name", "!@##R()*$;><()", 100, false));
			local.chars = [inputBaseN("60", 16), inputBaseN("FF", 16), inputBaseN("10", 16), inputBaseN("25", 16)];
			assertFalse(local.validator.isValidPrintable("name", local.chars, 100, false));
			assertFalse(local.validator.isValidPrintable("name", [inputBaseN("08", 16)], 100, false));

	        local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
	        assertTrue(local.validator.isValidPrintable("name1", "abcDEF", 100, false, local.errors));
	        assertTrue(local.errors.size()==0);
	        assertTrue(local.validator.isValidPrintable("name2", "!@##R()*$;><()", 100, false, local.errors));
	        assertTrue(local.errors.size()==0);
	        assertFalse(local.validator.isValidPrintable("name3", chars, 100, false, local.errors));
	        assertTrue(local.errors.size()==1);
	        assertFalse(local.validator.isValidPrintable("name4", "%08", 100, false, local.errors));
	        assertTrue(local.errors.size()==2);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidRedirectLocation" output="false">
		<cfscript>
			//		isValidRedirectLocation(String, String, boolean)
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIsValidSafeHTML" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("isValidSafeHTML");
			local.validator = instance.ESAPI.validator();

			assertTrue(local.validator.isValidSafeHTML("test", "<b>Jeff</b>", 100, false));
			assertTrue(local.validator.isValidSafeHTML("test", '<a href="http://www.aspectsecurity.com">Aspect Security</a>', 100, false));
			assertTrue(local.validator.isValidSafeHTML("test", "Test. <script>alert(document.cookie)</script>", 100, false));
			assertTrue(local.validator.isValidSafeHTML("test", "Test. <div style={xss:expression(xss)}>", 100, false));
			assertTrue(local.validator.isValidSafeHTML("test", "Test. <s%00cript>alert(document.cookie)</script>", 100, false));
			assertTrue(local.validator.isValidSafeHTML("test", "Test. <s\tcript>alert(document.cookie)</script>", 100, false));
			assertTrue(local.validator.isValidSafeHTML("test", "Test. <s\r\n\0cript>alert(document.cookie)</script>", 100, false));

			// TODO: waiting for a way to validate text headed for an attribute for scripts
			// This would be nice to catch, but just looks like text to AntiSamy
			// assertFalse(local.validator.isValidSafeHTML("test", "\" onload=\"alert(document.cookie)\" "));

	        local.errors = new cfesapi.org.owasp.esapi.ValidationErrorList();
	        assertTrue(local.validator.isValidSafeHTML("test1", "<b>Jeff</b>", 100, false, local.errors));
	        assertTrue(local.validator.isValidSafeHTML("test2", '<a href="http://www.aspectsecurity.com">Aspect Security</a>', 100, false, local.errors));
	        assertTrue(local.validator.isValidSafeHTML("test3", "Test. <script>alert(document.cookie)</script>", 100, false, local.errors));
	        assertTrue(local.validator.isValidSafeHTML("test4", "Test. <div style={xss:expression(xss)}>", 100, false, local.errors));
	        assertTrue(local.validator.isValidSafeHTML("test5", "Test. <s%00cript>alert(document.cookie)</script>", 100, false, local.errors));
	        assertTrue(local.validator.isValidSafeHTML("test6", "Test. <s\tcript>alert(document.cookie)</script>", 100, false, local.errors));
	        assertTrue(local.validator.isValidSafeHTML("test7", "Test. <s\r\n\0cript>alert(document.cookie)</script>", 100, false, local.errors));
	        assertTrue(local.errors.size() == 0);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testSafeReadLine" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("safeReadLine");

			local.bytes = "";
			try {
			   local.bytes = newJava("java.lang.String").init("testString").getBytes(instance.PREFERRED_ENCODING);
			}
			catch (java.io.UnsupportedEncodingException e1) {
			   fail(instance.PREFERRED_ENCODING & " not a supported encoding?!?!!!");
			}
			local.s = newJava("java.io.ByteArrayInputStream").init(local.bytes);
			local.validator = instance.ESAPI.validator();
			try {
			   local.validator.safeReadLine(local.s, -1);
			   fail();
			}
			catch (cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException e) {
			   // Expected
			}
			local.s.reset();
			try {
			   local.validator.safeReadLine(local.s, 4);
			   fail();
			}
			catch (cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException e) {
			   // Expected
			}
			local.s.reset();
			try {
			   local.u = local.validator.safeReadLine(local.s, 20);
			   assertEquals("testString", local.u);
			}
			catch (cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException e) {
			   fail();
			}

			// This sub-test attempts to validate that BufferedReader.readLine() and safeReadLine() are similar in operation
			// for the nominal case
			try {
			   local.s.reset();
			   local.isr = newJava("java.io.InputStreamReader").init(local.s);
			   local.br = newJava("java.io.BufferedReader").init(local.isr);
			   local.u = local.br.readLine();
			   local.s.reset();
			   local.v = local.validator.safeReadLine(local.s, 20);
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
			local.validator = instance.ESAPI.validator();
			try {
			   local.validator.getValidInput("address", "55 main st. pasadena ak", "SafeString", 512, false);
			}
			catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
			   fail(e.getLogMessage());
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetParameterMap" output="false">
		<cfscript>
			//testing Validator.HTTPParameterName and Validator.HTTPParameterValue
	        local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
	        local.safeRequest = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.request);
			//an example of a parameter from displaytag, should pass
	        local.request.addParameter("d-49653-p", "pass");
	        local.request.addParameter("<img ", "fail");
	        local.request.addParameter(generateStringOfLength(32), "pass");
	        local.request.addParameter(generateStringOfLength(33), "fail");
	        assertEquals(local.safeRequest.getParameterMap().size(), 2);
	        assertNull(local.safeRequest.getParameterMap().get("<img"));
	        assertNull(local.safeRequest.getParameterMap().get(generateStringOfLength(33)));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetParameterNames" output="false">
		<cfscript>
			//testing Validator.HTTPParameterName
	        local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
	        local.safeRequest = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.request);
			//an example of a parameter from displaytag, should pass
	        local.request.addParameter("d-49653-p", "pass");
	        local.request.addParameter("<img ", "fail");
	        local.request.addParameter(generateStringOfLength(32), "pass");
	        local.request.addParameter(generateStringOfLength(33), "fail");
	        assertEquals(arrayLen(local.safeRequest.getParameterNames()), 2);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetParameter" output="false">
		<cfscript>
			//testing Validator.HTTPParameterValue
	        local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
	        local.safeRequest = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.request);
	        local.request.addParameter("p1", "Alice");
	        local.request.addParameter("p2", "bob@alice.com");//mail-address from a submit-form
	        local.request.addParameter("p3", instance.ESAPI.authenticator().generateStrongPassword());
	        local.request.addParameter("p4", arrayToList(newJava("org.owasp.esapi.EncoderConstants").CHAR_PASSWORD_SPECIALS, ""));
	        //TODO - I think this should fair request.addParameter("p5", "ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½ï¿½?ï¿½ï¿½ï¿½ï¿½"); //some special characters from european languages;
	        local.request.addParameter("f1", "<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>");
	        local.request.addParameter("f2", "<IMG SRC=&##106;&##97;&##118;&##97;&##115;&##99;&##114;&##105;&##112;&##116;&##58;&##97;&##108;&##101;&##114;&##116;&##40;&##39;&##88;&##83;&##83;&##39;&##41;>");
	        local.request.addParameter("f3", "<IMG SRC=&##106;&##97;&##118;&##97;&##115;&##99;&##114;&##105;&##112;&##116;&##58;&##97;&##108;&##101;&##114;&##116;&##40;&##39;&##88;&##83;&##83;&##39;&##41;>");
	        for (local.i = 1; local.i <= 4; local.i++) {
	            assertEquals(local.safeRequest.getParameter("p" & local.i), local.request.getParameter("p" & local.i));
	        }
	        for (local.i = 1; local.i <= 2; local.i++) {
	        	local.testResult = false;
	        	try {
	        		local.testResult = local.safeRequest.getParameter("f" & local.i) == local.request.getParameter("f" & local.i);
	        	} catch (NullPointerException npe) {
	        		//the test is this block SHOULD fail. a NPE is an acceptable failure state
	        		local.testResult = false; //redundant, just being descriptive here
	        	}
	        	assertFalse(local.testResult);
	        }
	        assertNull(local.safeRequest.getParameter("e1"));
	
	        //This is revealing problems with Jeff's original SafeRequest
	        //mishandling of the AllowNull parameter. I'm adding a new Google code
	        //bug to track this.
	        //
	        //assertNotNull(local.safeRequest.getParameter("e1", false));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetCookies" output="false">
		<cfscript>
			//testing Validator.HTTPCookieName and Validator.HTTPCookieValue
	        local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
	        local.safeRequest = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.request);
			//should support a base64-encode value
	        local.request.setCookie("p1", "34=VJhjv7jiDu7tsdLrQQ2KcUwpfWUM2_mBae6UA8ttk4wBHdxxQ-1IBxyCOn3LWE08SDhpnBcJ7N5Vze48F2t8a1R_hXt7PX1BvgTM0pn-T4JkqGTm_tlmV4RmU3GT-dgn");
	        local.request.setCookie("f1", '<A HREF="http://66.102.7.147/">XSS</A>');
	        local.request.setCookie("load-balancing", "pass");
	        local.request.setCookie("'bypass", "fail");
	        local.cookies = local.safeRequest.getCookies();
	        assertEquals(local.cookies[1].getValue(), local.request.getCookies()[1].getValue());
	        assertEquals(local.cookies[2].getName(), local.request.getCookies()[3].getName());
	        assertTrue(arrayLen(local.cookies) == 2);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetHeader" output="false">
		<cfscript>
			//testing Validator.HTTPHeaderValue
	        local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
	        local.safeRequest = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.request);
	        local.request.addHeader("p1", "login");
	        local.request.addHeader("f1", '<A HREF="http://0x42.0x0000066.0x7.0x93/">XSS</A>');
	        local.request.addHeader("p2", generateStringOfLength(150));
	        local.request.addHeader("f2", generateStringOfLength(151));
	        assertEquals(local.safeRequest.getHeader("p1"), local.request.getHeader("p1"));
	        assertEquals(local.safeRequest.getHeader("p2"), local.request.getHeader("p2"));
	        assertFalse(local.safeRequest.getHeader("f1") == local.request.getHeader("f1"));
	        assertFalse(local.safeRequest.getHeader("f2") == local.request.getHeader("f2"));
	        assertIsEmpty(local.safeRequest.getHeader("p3"));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetHeaderNames" output="false">
		<cfscript>
			//testing Validator.HTTPHeaderName
	        local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
	        local.safeRequest = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.request);
	        local.request.addHeader("d-49653-p", "pass");
	        local.request.addHeader("<img ", "fail");
	        local.request.addHeader(generateStringOfLength(32), "pass");
	        local.request.addHeader(generateStringOfLength(33), "fail");
	        assertEquals(arrayLen(local.safeRequest.getHeaderNames()), 2);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetQueryString" output="false">
		<cfscript>
			//testing Validator.HTTPQueryString
	        local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
	        local.safeRequest = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.request);
	        local.request.setQueryString("mail=bob@alice.com&passwd=" & arrayToList(newJava("org.owasp.esapi.EncoderConstants").CHAR_PASSWORD_SPECIALS, ""));
	        assertEquals(local.safeRequest.getQueryString(), local.request.getQueryString());
	        local.request.setQueryString('mail=<IMG SRC="jav\tascript:alert(''XSS'');">');
	        assertFalse(local.safeRequest.getQueryString() == local.request.getQueryString());
	        local.request.setQueryString("mail=bob@alice.com-passwd=johny");
	        assertTrue(local.safeRequest.getQueryString() == local.request.getQueryString());
	        local.request.setQueryString("mail=bob@alice.com-passwd=johny&special"); //= is missing!
	        assertFalse(local.safeRequest.getQueryString() == local.request.getQueryString());
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetRequestURI" output="false">
		<cfscript>
			//testing Validator.HTTPURI
	        local.request = new cfesapi.test.org.owasp.esapi.http.MockHttpServletRequest();
	        local.safeRequest = new cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest(instance.ESAPI, local.request);
	        try {
	            local.request.setRequestURI("/app/page.jsp");
	        } catch (UnsupportedEncodingException ignored) {
	        }
	        assertEquals(local.safeRequest.getRequestURI(), local.request.getRequestURI());
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="generateStringOfLength" output="false">
		<cfargument type="numeric" name="length" required="true">
		<cfscript>
	        local.longString = newJava("java.lang.StringBuilder").init();
	        for (local.i = 0; local.i < arguments.length; local.i++) {
	            local.longString.append("a");
	        }
	        return local.longString.toString();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetContextPath" output="false">
		<cfscript>
	        // Root Context Path ("")
	        assertTrue(instance.ESAPI.validator().isValidInput("HTTPContextPath", "", "HTTPContextPath", 512, true));
	        // Deployed Context Path ("/context")
	        assertTrue(instance.ESAPI.validator().isValidInput("HTTPContextPath", "/context", "HTTPContextPath", 512, true));
	        // Fail-case - URL Splitting
	        assertFalse(instance.ESAPI.validator().isValidInput("HTTPContextPath", "/\\nGET http://evil.com", "HTTPContextPath", 512, true));
		</cfscript> 
	</cffunction>


</cfcomponent>
