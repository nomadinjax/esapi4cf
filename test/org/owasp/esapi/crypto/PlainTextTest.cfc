<cfcomponent extends="cfesapi.test.TestCase" output="false">

	<cfscript>
		instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
		instance.unicodeStr = "A\u00ea\u00f1\u00fcC";	// I.e., "AêñüC"
		instance.altString  = "AêñüC";					// Same as above.
	</cfscript>

	<cffunction access="public" returntype="void" name="testUnicodeString" output="false">
		<cfscript>
			System = createObject("java", "java.lang.System");
			
		    // These 2 strings are *meant* to be equal. If they are not, please
		    // do *NOT* change the test. It's a Windows thing. Sorry. Change your
		    // OS instead. ;-)
		    if ( ! instance.unicodeStr.equals(instance.altString) ) {
		        System.err.println("Skipping MXUnit test case PlainTextTest.testUnicodeString() on OS " & System.getProperty("os.name") );
		        return;
		    }
			try {
				local.utf8Bytes = instance.unicodeStr.getBytes("UTF-8");
				local.pt1 = createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, instance.unicodeStr);
				local.pt2 = createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, instance.altString);

				assertTrue( local.pt1.equals(local.pt1) );   // Equals self
				assertFalse( local.pt1.equals("") );
				assertTrue( local.pt1.equals(local.pt2) );
				assertFalse( local.pt1.equals( instance.unicodeStr ) );
				assertTrue( local.pt1.length() == local.utf8Bytes.length );
				assertTrue( Arrays.equals(local.utf8Bytes, local.pt1.asBytes()) );
				assertTrue( local.pt1.hashCode() == instance.unicodeStr.hashCode() );

			} catch (UnsupportedEncodingException e) {
				fail("No UTF-8 byte encoding: " & e);
				e.printStackTrace(System.err);
			}
		</cfscript>
	</cffunction>

	<!--- test invalid as CF does not support nulls

		<cffunction access="public" returntype="void" name="testNullCase" output="false">
		<cfscript>
		local.counter = 0;
		try {
		local.bytes = toBinary("");
		local.pt = createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, local.bytes);
		assertTrue( !isNull(local.pt) );   // Should never get to here.
		fail("testNullCase(): Expected NullPointerException or AssertionError");
		} catch (NullPointerException e) {
		// Will get this case if assertions are not enabled for PlainText.
		// System.err.println("Caught NullPointerException; exception was: " + e);
		// e.printStackTrace(System.err);
		local.counter++;
		} catch (AssertionError e) {
		// Will get this case if assertions *are* enabled for PlainText.
		// System.err.println("Caught AssertionError; exception was: " + e);
		// e.printStackTrace(System.err);
		local.counter++;
		} finally {
		assertTrue( local.counter > 0 );
		}
		</cfscript>
		</cffunction>
 --->

	<cffunction access="public" returntype="void" name="testEmptyString" output="false">
		<cfscript>
			local.mt = createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, "");
			assertTrue( len(local.mt.toString()) == 0 );
			local.ba = local.mt.asBytes();
			assertTrue( !isNull(local.ba) && len(local.ba) == 0 );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testOverwrite" output="false">
		<cfscript>
			Arrays = createObject("java", "java.util.Arrays");

			try {
				local.origBytes = instance.unicodeStr.getBytes("UTF-8");
				local.pt = createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, local.origBytes);
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
				e.printStackTrace(System.err);
			}
		</cfscript>
	</cffunction>


</cfcomponent>
