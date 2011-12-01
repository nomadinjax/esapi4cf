<!--- /**
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
 */ --->
<cfcomponent displayname="CryptoHelperTest" extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false">

	<cfscript>
		instance.ESAPI = newComponent("cfesapi.org.owasp.esapi.ESAPI").init();
		CryptoHelper = newComponent("cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI);
	</cfscript>

	<cffunction access="public" returntype="void" name="testGenerateSecretKeySunnyDay" output="false">
		<cfset var local = {}/>

		<cfscript>
			try {
				local.key = CryptoHelper.generateSecretKeyESAPI("AES", 128);
				assertTrue(local.key.getAlgorithm() == "AES");
				assertTrue(128 / 8 == arrayLen(local.key.getEncoded()));
			}
			catch(cfesapi.org.owasp.esapi.errors.EncryptionException e) {
				// OK if not covered in code coverage -- not expected.
				fail("Caught unexpected EncryptionException; msg was " & e.message);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGenerateSecretKeyEncryptionException" output="false">
		<cfset var local = {}/>

		<cfscript>
			try {
				local.key = CryptoHelper.generateSecretKeyESAPI("NoSuchAlg", 128);
				assertTrue(!structKeyExists(local, "key"));// Not reached!
			}
			catch(cfesapi.org.owasp.esapi.errors.EncryptionException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testOverwriteByteArrayByte" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.secret = newJava("java.lang.String").init("secret password").getBytes();
			local.len = arrayLen(local.secret);
			CryptoHelper.overwrite(local.secret, "x");
			assertTrue(arrayLen(local.secret) == local.len);// Length unchanged
			assertTrue(checkByteArray(local.secret, "x"));// Filled with 'x'
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testCopyByteArraySunnyDay" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.src = newByte(20);
			local.src = fillByteArray(local.src, "A");
			local.dest = newByte(20);
			local.dest = fillByteArray(local.dest, "B");
			CryptoHelper.copyByteArray(local.src, local.dest);
			assertTrue(checkByteArray(local.src, "A"));// Still filled with 'A'
			assertTrue(checkByteArray(local.dest, "A"));// Now filled with 'B'
		</cfscript>

	</cffunction>

	<!--- NULL tests not valid in CF

	<cffunction access="public" returntype="void" name="testCopyByteArraySrcNullPointerException" output="false">

	    <cfscript>
	        local.ba = newByte(16);
	        CryptoHelper.copyByteArray(null, local.ba, arrayLen(local.ba));
	    </cfscript>

	</cffunction>

	--->
	<!--- NULL tests not valid in CF

	<cffunction access="public" returntype="void" name="testCopyByteArrayDestNullPointerException" output="false">

	    <cfscript>
	        local.ba = newByte(16);
	        CryptoHelper.copyByteArray(local.ba, null, arrayLen(local.ba));
	    </cfscript>

	</cffunction>

	--->

	<cffunction access="public" returntype="void" name="testCopyByteArrayIndexOutOfBoundsException" output="false">
		<cfset var local = {}/>

		<cfscript>
			try {
				local.ba8 = newByte(8);
				local.ba16 = newByte(16);
				CryptoHelper.copyByteArray(local.ba8, local.ba16, arrayLen(local.ba16));
			}
			catch(java.lang.ArrayIndexOutOfBoundsException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testArrayCompare" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.ba1 = newByte(32);
			local.ba2 = newByte(32);
			local.ba3 = newByte(48);

			// Note: Don't need cryptographically secure random numbers for this!
			local.prng = newJava("java.util.Random").init();

			local.prng.nextBytes(local.ba1);
			local.prng.nextBytes(local.ba2);
			local.prng.nextBytes(local.ba3);

			/*
			 * Unfortunately, can't rely no the nanosecond timer because as the
			 * Javadoc for System.nanoTime() states, " No guarantees are made
			 * about how frequently values change", so this is not very reliable.
			 *
			 * However, on can uncomment the code and observe that elapsed times
			 * are generally less than 10 millionth of a second. I suppose if we
			 * declared a large enough epsilon, we could make it work, but it is
			 * easier to convince yourself from the CryptoHelper.arrayCompare() code
			 * itself that it always goes through all the bits of the byte array
			 * if it compares any bits at all.
			 */
			//long start, stop, diff;
			//start = System.nanoTime();
			/* NULL test not valid for CF
			assertTrue(CryptoHelper.arrayCompare(null, null));
			*/
			//stop = System.nanoTime();
			//diff = stop - start;
			//System.out.println("diff: " + diff + " nanosec");
			//start = System.nanoTime();
			assertTrue(CryptoHelper.arrayCompare(local.ba1, local.ba1));
			//stop = System.nanoTime();
			//diff = stop - start;
			//System.out.println("diff: " + diff + " nanosec");
			//start = System.nanoTime();
			assertFalse(CryptoHelper.arrayCompare(local.ba1, local.ba2));
			//stop = System.nanoTime();
			//diff = stop - start;
			//System.out.println("diff: " + diff + " nanosec");
			//start = System.nanoTime();
			assertFalse(CryptoHelper.arrayCompare(local.ba1, local.ba3));
			//stop = System.nanoTime();
			//diff = stop - start;
			//System.out.println("diff: " + diff + " nanosec");
			//start = System.nanoTime();
			/* NULL test not valid for CF
			assertFalse(CryptoHelper.arrayCompare(local.ba1, null));
			*/
			//stop = System.nanoTime();
			//diff = stop - start;
			//System.out.println("diff: " + diff + " nanosec");
			local.ba2 = local.ba1;
			//start = System.nanoTime();
			assertTrue(CryptoHelper.arrayCompare(local.ba1, local.ba2));
			//stop = System.nanoTime();
			//diff = stop - start;
			//System.out.println("diff: " + diff + " nanosec");
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="binary" name="fillByteArray" output="false">
		<cfargument required="true" type="binary" name="ba"/>
		<cfargument required="true" type="String" name="b"/>

		<cfset var local = {}/>

		<cfscript>
			/*
			 * Adobe CF does not allow you to change the value of an index within a ByteArray.
			 * Railo CF does allow this:
			 *
			 * local.b = asc(arguments.b);
			 * for (local.i = 1; local.i <= arrayLen(arguments.ba); local.i++) {
			 *         arguments.ba[local.i] = local.b;
			 * }
			 *
			 * The below is to work around Adobe CF's shortcoming... not sure if this is on Adobe's radar.
			 */
			local.ba = [];
			for(local.i = 1; local.i <= arrayLen(arguments.ba); local.i++) {
				local.ba[local.i] = arguments.b;
			}
			return arrayToList(local.ba, "").getBytes();
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="checkByteArray" output="false">
		<cfargument required="true" type="binary" name="ba"/>
		<cfargument required="true" type="String" name="b"/>

		<cfset var local = {}/>

		<cfscript>
			for(local.i = 1; local.i <= arrayLen(arguments.ba); local.i++) {
				if(arguments.ba[local.i] != asc(arguments.b)) {
					return false;
				}
			}
			return true;
		</cfscript>

	</cffunction>

</cfcomponent>