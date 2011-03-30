<cfcomponent extends="cfesapi.test.org.owasp.esapi.TestCase" output="false">

	<cfscript>
		CryptoHelper = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI);
	</cfscript>

	<cffunction access="public" returntype="void" name="testGenerateSecretKeySunnyDay" output="false">
		<cfscript>
	        try {
	            local.key = CryptoHelper.generateSecretKey("AES", 128);
	            assertTrue(local.key.getAlgorithm() == "AES");
	            assertTrue(128 / 8 == len(local.key.getEncoded()));
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
	            // OK if not covered in code coverage -- not expected.
	            fail("Caught unexpected EncryptionException; msg was " & e.getMessage());
	        }
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGenerateSecretKeyEncryptionException" output="false">
		<cfscript>
			try {
		        local.key = CryptoHelper.generateSecretKey("NoSuchAlg", 128);
		        assertTrue(isNull(local.key)); // Not reached!
		    } catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
	        }
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testOverwriteByteArrayByte" output="false">
		<cfscript>
	        local.secret = createObject("java", "java.lang.String").init("secret password").getBytes();
	        local.len = len(local.secret);
	        CryptoHelper.overwrite(local.secret, 'x');
	        assertTrue(len(local.secret) == local.len); // Length unchanged
	        assertTrue(checkByteArray(local.secret, 'x')); // Filled with 'x'
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCopyByteArraySunnyDay" output="false">
		<cfscript>
	        local.src = newByte(20);
	        fillByteArray(local.src, 'A');
	        local.dest = newByte(20);
	        fillByteArray(local.dest, 'B');
	        CryptoHelper.copyByteArray(local.src, local.dest);
	        assertTrue(checkByteArray(local.src, 'A')); // Still filled with 'A'
	        assertTrue(checkByteArray(local.dest, 'A')); // Now filled with 'B'
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCopyByteArraySrcNullPointerException" output="false">
		<cfscript>
	        local.ba = newByte(16);
	        CryptoHelper.copyByteArray(toBinary(toBase64("")), local.ba, len(local.ba));
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCopyByteArrayDestNullPointerException" output="false">
		<cfscript>
	        local.ba = newByte(16);
	        CryptoHelper.copyByteArray(local.ba, toBinary(toBase64("")), len(local.ba));
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCopyByteArrayIndexOutOfBoundsException" output="false">
		<cfscript>
	        local.ba8 = newByte(8);
	        local.ba16 = newByte(16);
	        CryptoHelper.copyByteArray(local.ba8, local.ba16, len(local.ba16));
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testArrayCompare" output="false">
		<cfscript>
        local.ba1 = newByte(32);
        local.ba2 = newByte(32);
        local.ba3 = newByte(48);

        // Note: Don't need cryptographically secure random numbers for this!
        local.prng = createObject("java", "java.util.Random").init();

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

//        long start, stop, diff;

//        start = System.nanoTime();
        //assertTrue(CryptoHelper.arrayCompare(null, null));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " + diff + " nanosec");

//        start = System.nanoTime();
        assertTrue(CryptoHelper.arrayCompare(local.ba1, local.ba1));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " + diff + " nanosec");

//        start = System.nanoTime();
        assertFalse(CryptoHelper.arrayCompare(local.ba1, local.ba2));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " + diff + " nanosec");

//        start = System.nanoTime();
        assertFalse(CryptoHelper.arrayCompare(local.ba1, local.ba3));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " + diff + " nanosec");

//        start = System.nanoTime();
        //assertFalse(CryptoHelper.arrayCompare(local.ba1, null));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " + diff + " nanosec");

        local.ba2 = local.ba1;
//        start = System.nanoTime();
        assertTrue(CryptoHelper.arrayCompare(local.ba1, local.ba2));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " + diff + " nanosec");
    	</cfscript>
	</cffunction>


	<cffunction access="private" returntype="binary" name="newByte" outuput="false">
		<cfargument type="numeric" name="len" required="true">
		<cfscript>
			StringBuilder = createObject("java", "java.lang.StringBuilder").init();
			StringBuilder.setLength(arguments.len);
			return StringBuilder.toString().getBytes();
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="void" name="fillByteArray" output="false">
		<cfargument type="binary" name="ba" required="true">
		<cfargument type="String" name="b" required="true">
		<cfscript>
	        for (local.i = 1; local.i <= len(arguments.ba); local.i++) {
	        	// TODO: CF does not allow us to modify the binary object - need workaround
	            arguments.ba[local.i] = asc(arguments.b);
	        }
    	</cfscript>
	</cffunction>


	<cffunction access="private" returntype="boolean" name="checkByteArray" output="false">
		<cfargument type="binary" name="ba" required="true">
		<cfargument type="String" name="b" required="true">
		<cfscript>
	        for (local.i = 1; local.i <= len(arguments.ba); local.i++) {
	            if (arguments.ba[local.i] != asc(arguments.b)) {
	                return false;
	            }
	        }
	        return true;
    	</cfscript>
	</cffunction>


</cfcomponent>
