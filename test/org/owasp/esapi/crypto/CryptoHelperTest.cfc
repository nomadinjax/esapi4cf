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
import "org.owasp.esapi.crypto.CryptoHelper";
import "org.owasp.esapi.crypto.KeyDerivationFunction";
import "org.owasp.esapi.util.Utils";

component extends="esapi4cf.test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

    public void function testGenerateSecretKeySunnyDay() {
        try {
            var key = new CryptoHelper(variables.ESAPI).generateSecretKey("AES", 128);
            assertTrue(key.getAlgorithm() == "AES");
            assertTrue(128 / 8 == arrayLen(key.getEncoded()));
        } catch (EncryptionException e) {
            // OK if not covered in code coverage -- not expected.
            fail("Caught unexpected EncryptionException; msg was " & e.getMessage());
        }
    }

    public void function testGenerateSecretKeyEncryptionException() {
        try {
        	var key = new CryptoHelper(variables.ESAPI).generateSecretKey("NoSuchAlg", 128);
        	fail("Failed to throw exception on invalid algorithm");
        }
        catch (org.owasp.esapi.errors.EncryptionException ex) {
        	// expected
        }
        assertTrue(isNull(key)); // Not reached!
    }

    public void function testOverwriteByteArrayByte() {
        var secret = charsetDecode("secret password", "utf-8");
        var len = arrayLen(secret);
        new CryptoHelper(variables.ESAPI).overwrite(secret, 'x');
        assertTrue(arrayLen(secret) == len); // Length unchanged
        assertTrue(checkByteArray(secret, 'x')); // Filled with 'x'
    }

    public void function testCopyByteArraySunnyDay() {
    	var Utils = new Utils();
        var src = Utils.newByte(20);
        fillByteArray(src, 'A');
        var dest = Utils.newByte(20);
        fillByteArray(dest, 'B');
        new CryptoHelper(variables.ESAPI).copyByteArray(src, dest);
        assertTrue(checkByteArray(src, 'A')); // Still filled with 'A'
        assertTrue(checkByteArray(dest, 'A')); // Now filled with 'B'
    }

    public void function testCopyByteArraySrcNullPointerException() {
        var ba = new Utils().newByte(16);
        try {
        	new CryptoHelper(variables.ESAPI).copyByteArray(javaCast("null", ""), ba, arrayLen(ba));
        	fail("Failed to throw NullPointerException");
        }
        catch (expression ex) {
        	// expected
        }
    }

    public void function testCopyByteArrayDestNullPointerException() {
        var ba = new Utils().newByte(16);
        try {
        	new CryptoHelper(variables.ESAPI).copyByteArray(ba, javaCast("null", ""), arrayLen(ba));
        	fail("Failed to throw NullPointerException");
        }
        catch (expression ex) {
        	// expected
        }
    }

    public void function testCopyByteArrayIndexOutOfBoundsException() {
    	var Utils = new Utils();
        var ba8 = Utils.newByte(8);
        var ba16 = Utils.newByte(16);
        try {
        	new CryptoHelper(variables.ESAPI).copyByteArray(ba8, ba16, arrayLen(ba16));
        	fail("Failed to throw ArrayIndexOutOfBoundsException");
        }
        catch (java.lang.ArrayIndexOutOfBoundsException ex) {
        	// expected
        }
    }

    public void function testArrayCompare() {
    	var Utils = new Utils();
        var ba1 = Utils.newByte(32);
        var ba2 = Utils.newByte(32);
        var ba3 = Utils.newByte(48);

        // Note: Don't need cryptographically secure random numbers for this!
        var prng = createObject("java", "java.util.Random").init();

        prng.nextBytes(ba1);
        prng.nextBytes(ba2);
        prng.nextBytes(ba3);

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

		var CryptoHelper = new CryptoHelper(variables.ESAPI);

//        long start, stop, diff;

//        start = System.nanoTime();
		try {
        	assertTrue(CryptoHelper.arrayCompare(javaCast("null", ""), javaCast("null", "")));
        	fail("Failed to error on null arguments.");
        }
        catch (expression ex) {
        	// expected
        }
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " & diff & " nanosec");

//        start = System.nanoTime();
        assertTrue(CryptoHelper.arrayCompare(ba1, ba1));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " & diff & " nanosec");

//        start = System.nanoTime();
        assertFalse(CryptoHelper.arrayCompare(ba1, ba2));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " & diff & " nanosec");

//        start = System.nanoTime();
        assertFalse(CryptoHelper.arrayCompare(ba1, ba3));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " & diff & " nanosec");

//        start = System.nanoTime();
		try {
        	assertFalse(CryptoHelper.arrayCompare(ba1, javaCast("null", "")));
        	fail("Failed to error on null arguments.");
        }
        catch (expression ex) {
        	// expected
        }
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " & diff & " nanosec");

        ba2 = ba1;
//        start = System.nanoTime();
        assertTrue(CryptoHelper.arrayCompare(ba1, ba2));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " & diff & " nanosec");
    }

    public void function testIsValidKDFVersion() {
    	var CryptoHelper = new CryptoHelper(variables.ESAPI);
    	var KeyDerivationFunction = new KeyDerivationFunction(variables.ESAPI);
    	assertTrue( CryptoHelper.isValidKDFVersion(20110203, false, false));
    	assertTrue( CryptoHelper.isValidKDFVersion(20130830, false, false));
    	assertTrue( CryptoHelper.isValidKDFVersion(33330303, false, false));
    	assertTrue( CryptoHelper.isValidKDFVersion(99991231, false, false));

    	assertFalse( CryptoHelper.isValidKDFVersion(0, false, false));
    	assertFalse( CryptoHelper.isValidKDFVersion(99991232, false, false));
    	assertFalse( CryptoHelper.isValidKDFVersion(20110202, false, false));

    	assertTrue( CryptoHelper.isValidKDFVersion(20110203, true, false));
    	assertTrue( CryptoHelper.isValidKDFVersion(KeyDerivationFunction.kdfVersion, true, false));
    	assertFalse( CryptoHelper.isValidKDFVersion(KeyDerivationFunction.kdfVersion + 1, true, false));

    	try {
        	CryptoHelper.isValidKDFVersion(77777777, true, true);
        	fail("Failed to CryptoHelper.isValidKDFVersion() failed to throw IllegalArgumentException.");
    	}
    	catch (any e) {
    		assertTrue(e.type == "java.lang.IllegalArgumentException");
    	}
    }

    private void function fillByteArray(required binary ba, required b) {
        for (var i = 1; i <= arrayLen(arguments.ba); i++) {
            arguments.ba[i] = asc(arguments.b);
        }
    }

    private boolean function checkByteArray(required binary ba, required b) {
        for (var i = 1; i <= arrayLen(arguments.ba); i++) {
            if (arguments.ba[i] != asc(arguments.b)) {
                return false;
            }
        }
        return true;
    }

}