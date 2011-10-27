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
		instance.unicodeStr = "A\u00ea\u00f1\u00fcC";	// I.e., "AêñüC"
		instance.altString  = "AêñüC";					// Same as above.
	</cfscript>
 
	<cffunction access="public" returntype="void" name="testUnicodeString" output="false">
		<cfscript>
		    // These 2 strings are *meant* to be equal. If they are not, please
		    // do *NOT* change the test. It's a Windows thing. Sorry. Change your
		    // OS instead. ;-)
		    if ( ! instance.unicodeStr.equals(instance.altString) ) {
		        newJava("java.lang.System").err.println("Skipping MXUnit test case PlainTextTest.testUnicodeString() on OS " & newJava("java.lang.System").getProperty("os.name") );
		        return;
		    }

			// CFB/ACF throws syntax errors when newJava() is used in assertX() 
			Arrays = newJava("java.util.Arrays");

			try {
				local.utf8Bytes = instance.unicodeStr.getBytes("UTF-8");
				local.pt1 = new cfesapi.org.owasp.esapi.crypto.PlainText(instance.ESAPI, instance.unicodeStr);
				local.pt2 = new cfesapi.org.owasp.esapi.crypto.PlainText(instance.ESAPI, instance.altString);

				assertTrue( local.pt1.equals(local.pt1) );   // Equals self
				assertFalse( local.pt1.equals("") );
				assertTrue( local.pt1.equals(local.pt2) );
				assertFalse( local.pt1.equals( instance.unicodeStr ) );
				assertTrue( local.pt1.length() == local.utf8Bytes.length );
				assertTrue( Arrays.equals(local.utf8Bytes, local.pt1.asBytes()) );
				assertTrue( local.pt1.hashCode() == instance.unicodeStr.hashCode() );

			} catch (java.io.UnsupportedEncodingException e) {
				fail("No UTF-8 byte encoding: " & e);
				e.printStackTrace(newJava("java.lang.System").err);
			}
		</cfscript> 
	</cffunction>

	<!--- test invalid as CF does not support nulls

		<cffunction access="public" returntype="void" name="testNullCase" output="false">
		<cfscript>
		local.counter = 0;
		try {
		local.bytes = toBinary("");
		local.pt = new cfesapi.org.owasp.esapi.crypto.PlainText(instance.ESAPI, local.bytes);
		assertTrue( !isNull(local.pt) );   // Should never get to here.
		fail("testNullCase(): Expected NullPointerException or AssertionError");
		} catch (NullPointerException e) {
		// Will get this case if assertions are not enabled for PlainText.
		// newJava("java.lang.System").err.println("Caught NullPointerException; exception was: " + e);
		// e.printStackTrace(newJava("java.lang.System").err);
		local.counter++;
		} catch (AssertionError e) {
		// Will get this case if assertions *are* enabled for PlainText.
		// newJava("java.lang.System").err.println("Caught AssertionError; exception was: " + e);
		// e.printStackTrace(newJava("java.lang.System").err);
		local.counter++;
		} finally {
		assertTrue( local.counter > 0 );
		}
		</cfscript>
		</cffunction>

		--->

	<cffunction access="public" returntype="void" name="testEmptyString" output="false">
		<cfscript>
			local.mt = new cfesapi.org.owasp.esapi.crypto.PlainText(instance.ESAPI, "");
			assertTrue( len(local.mt.toString()) == 0 );
			local.ba = local.mt.asBytes();
			assertTrue( !isNull(local.ba) && len(local.ba) == 0 );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testOverwrite" output="false">
		<cfscript>
			// CFB/ACF throws syntax errors when newJava() is used in assertX() 
			Arrays = newJava("java.util.Arrays");
			
			try {
				local.origBytes = instance.unicodeStr.getBytes("UTF-8");
				local.pt = new cfesapi.org.owasp.esapi.crypto.PlainText(instance.ESAPI, local.origBytes);
				assertTrue( local.pt.toString() == instance.unicodeStr );
				assertTrue( Arrays.equals(local.origBytes, local.pt.asBytes()) );
				assertTrue( local.pt.hashCode() == instance.unicodeStr.hashCode() );

				local.origLen = arrayLen(local.origBytes);

				local.pt.overwrite();
		        local.overwrittenBytes = local.pt.asBytes();
				assertTrue( !isNull(local.overwrittenBytes) );
				assertFalse( Arrays.equals( local.origBytes, local.overwrittenBytes ) );

				// Ensure that ALL the bytes overwritten with '*'.
				local.afterLen = arrayLen(local.overwrittenBytes);
				assertTrue( local.origLen == local.afterLen );
				local.sum = 0;
				for( local.i = 1; local.i <= local.afterLen; local.i++ ) {
				    if ( local.overwrittenBytes[local.i] == asc('*') ) {
				        local.sum++;
				    }
				}
				assertTrue( local.afterLen == local.sum );
			} catch (UnsupportedEncodingException e) {
				fail("No UTF-8 byte encoding: " & e);
				e.printStackTrace(newJava("java.lang.System").err);
			}
		</cfscript> 
	</cffunction>


</cfcomponent>
