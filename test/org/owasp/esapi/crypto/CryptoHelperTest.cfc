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
component CryptoHelperTest extends="cfesapi.test.org.owasp.esapi.lang.TestCase" {

	instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();
	CryptoHelper = new cfesapi.org.owasp.esapi.crypto.CryptoHelper(instance.ESAPI);

	// @Test
	
	public void function testGenerateSecretKeySunnyDay() {
		try {
			local.key = CryptoHelper.generateSecretKey("AES", 128);
			assertTrue(local.key.getAlgorithm() == "AES");
			assertTrue(128 / 8 == arrayLen(local.key.getEncoded()));
		}
		catch(cfesapi.org.owasp.esapi.errors.EncryptionException e) {
			// OK if not covered in code coverage -- not expected.
			fail("Caught unexpected EncryptionException; msg was " & e.message);
		}
	}
	
	// @Test(expected = EncryptionException.class)
	
	public void function testGenerateSecretKeyEncryptionException() {
		try {
			local.key = CryptoHelper.generateSecretKey("NoSuchAlg", 128);
			assertTrue(isNull(local.key));// Not reached!
		}
		catch(cfesapi.org.owasp.esapi.errors.EncryptionException e) {
			// expected
		}
	}
	
	// @Test
	
	public void function testOverwriteByteArrayByte() {
		local.secret = newJava("java.lang.String").init("secret password").getBytes();
		local.len = arrayLen(local.secret);
		CryptoHelper.overwrite(local.secret, "x");
		assertTrue(arrayLen(local.secret) == local.len);// Length unchanged
		assertTrue(checkByteArray(local.secret, "x"));// Filled with 'x'
	}
	
	// @Test
	
	public void function testCopyByteArraySunnyDay() {
		local.src = newByte(20);
		local.src = fillByteArray(local.src, "A");
		local.dest = newByte(20);
		local.dest = fillByteArray(local.dest, "B");
		CryptoHelper.copyByteArray(local.src, local.dest);
		assertTrue(checkByteArray(local.src, "A"));// Still filled with 'A'
		assertTrue(checkByteArray(local.dest, "A"));// Now filled with 'B'
	}
	
	/* NULL tests not valid in CF
	// @Test(expected = NullPointerException.class)
	
	public void function testCopyByteArraySrcNullPointerException() {
	    local.ba = newByte(16);
	    CryptoHelper.copyByteArray(null, local.ba, arrayLen(local.ba));
	} */
	/* NULL tests not valid in CF
	// @Test(expected = NullPointerException.class)
	
	public void function testCopyByteArrayDestNullPointerException() {
	    local.ba = newByte(16);
	    CryptoHelper.copyByteArray(local.ba, null, arrayLen(local.ba));
	} */
	// @Test(expected = IndexOutOfBoundsException.class)
	
	public void function testCopyByteArrayIndexOutOfBoundsException() {
		try {
			local.ba8 = newByte(8);
			local.ba16 = newByte(16);
			CryptoHelper.copyByteArray(local.ba8, local.ba16, arrayLen(local.ba16));
		}
		catch(java.lang.ArrayIndexOutOfBoundsException e) {
			// expected
		}
	}
	
	// @Test
	
	public void function testArrayCompare() {
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
	}
	
	private binary function fillByteArray(required binary ba, required String b) {
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
	}
	
	private boolean function checkByteArray(required binary ba, required String b) {
		for(local.i = 1; local.i <= arrayLen(arguments.ba); local.i++) {
			if(arguments.ba[local.i] != asc(arguments.b)) {
				return false;
			}
		}
		return true;
	}
	
}