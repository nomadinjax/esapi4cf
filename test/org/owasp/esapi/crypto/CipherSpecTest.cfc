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
/** JUnit test to test CipherSpec class. */
component CipherSpecTest extends="cfesapi.test.org.owasp.esapi.lang.TestCase" {

	instance.dfltAESCipher = "";
	instance.dfltECBCipher = "";// will be "AES/ECB/NoPadding";
	instance.dfltOtherCipher = "";
	instance.cipherSpec = "";
	instance.myIV = "";

	// @Before 
	public void function setUp() {
		instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
	
		// This will throw ConfigurationException if IV type is not set to
		// 'fixed', which it's not. (We have it set to 'random'.)
		// myIV = Hex.decode( ESAPI.securityConfiguration().getFixedIV() );
		instance.myIV = createObject("java", "org.owasp.esapi.codecs.Hex").decode("0x000102030405060708090a0b0c0d0e0f");
	
		instance.dfltAESCipher = createObject("java", "javax.crypto.Cipher").getInstance("AES");
		instance.dfltECBCipher = createObject("java", "javax.crypto.Cipher").getInstance("AES/ECB/NoPadding");
		instance.dfltOtherCipher = createObject("java", "javax.crypto.Cipher").getInstance("Blowfish/OFB8/PKCS5Padding");
	
		assertTrue(!isNull(instance.dfltAESCipher));
		assertTrue(!isNull(instance.dfltECBCipher));
		assertTrue(!isNull(instance.dfltOtherCipher));
	
		instance.cipherSpec = new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, cipher=instance.dfltOtherCipher);
		assertTrue(!isNull(instance.cipherSpec));
	}
	
	// @After 
	public void function tearDown() {
		instance.ESAPI = "";
	}
	
	/** Test CipherSpec(String cipherXform, int keySize, int blockSize, final byte[] iv) */
	// @Test 
	
	public void function testCipherSpecStringIntIntByteArray() {
		instance.cipherSpec = new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, cipherXform="AES/CBC/NoPadding", keySize=128, blockSize=8, iv=instance.myIV);
		assertTrue(!isNull(instance.cipherSpec));
		instance.cipherSpec = "";
		local.caughtException = false;
		try {
			// Invalid cipher xform -- empty
			instance.cipherSpec = new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, cipherXform="", keySize=128, blockSize=8, iv=instance.myIV);
		}
		catch(java.lang.IllegalArgumentException t) {
			local.caughtException = true;
		}
		assertTrue(local.caughtException && instance.cipherSpec == "");
		local.caughtException = false;
		try {
			// Invalid cipher xform -- missing padding scheme
			instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipherXform="AES/CBC", keySize=128, blockSize=8, iv=instance.myIV);
		}
		catch(java.lang.AssertionError t) {
			local.caughtException = true;
		}
		assertTrue(local.caughtException && instance.cipherSpec == "");
	}
	
	/** CipherSpec(final Cipher cipher, int keySize) */
	// @Test 
	public void function testCipherSpecCipherInt() {
		instance.cipherSpec = new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, cipher=instance.dfltOtherCipher, keySize=112);
		assertTrue(!isNull(instance.cipherSpec));
		assertTrue(instance.cipherSpec.getCipherAlgorithm() == "Blowfish");
		assertTrue(instance.cipherSpec.getCipherMode() == "OFB8");
	
		instance.cipherSpec = new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, cipher=instance.dfltAESCipher, keySize=256);
		assertTrue(!isNull(instance.cipherSpec));
		assertTrue(instance.cipherSpec.getCipherAlgorithm() == "AES");
		assertTrue(instance.cipherSpec.getCipherMode() == "ECB");
		assertTrue(instance.cipherSpec.getPaddingScheme() == "NoPadding");
		// System.out.println("testCipherSpecInt(): " & instance.cipherSpec);
	}
	
	/** Test CipherSpec(final byte[] iv) */
	// @Test 
	public void function testCipherSpecByteArray() {
		assertTrue(!isNull(instance.myIV));
		assertTrue(len(instance.myIV) > 0);
		instance.cipherSpec = new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, iv=instance.myIV);
		assertTrue(instance.cipherSpec.getKeySize() == instance.ESAPI.securityConfiguration().getEncryptionKeyLength());
		assertTrue(instance.cipherSpec.getCipherTransformation() == instance.ESAPI.securityConfiguration().getCipherTransformation());
	}
	
	/** Test CipherSpec() */
	// @Test 
	public void function testCipherSpec() {
		instance.cipherSpec = new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, cipher=instance.dfltECBCipher);
		assertTrue(instance.cipherSpec.getCipherTransformation() == "AES/ECB/NoPadding");
		assertTrue(!len(instance.cipherSpec.getIV()));
	
		instance.cipherSpec = new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, cipher=instance.dfltOtherCipher);
		assertTrue(instance.cipherSpec.getCipherMode() == "OFB8");
	}
	
	/** Test setCipherTransformation(String cipherXform) */
	// @Test 
	public void function testSetCipherTransformation() {
		instance.cipherSpec = new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI);
		instance.cipherSpec.setCipherTransformation("AlgName/Mode/Padding");
		instance.cipherSpec.getCipherAlgorithm() == "AlgName/Mode/Padding";
	
		try {
			// Don't use null here as compiling JUnit tests disables assertion
			// checking so we get a NullPointerException here instead.
			instance.cipherSpec.setCipherTransformation("");// Throws IllegalArgumentException
		}
		catch(java.lang.IllegalArgumentException e) {
			assertTrue(true);// Doesn't work w/ @Test(expected=IllegalArgumentException.class)
		}
	}
	
	/** Test getCipherTransformation() */
	// @Test 
	public void function testGetCipherTransformation() {
		assertTrue(new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI).getCipherTransformation() == "AES/CBC/PKCS5Padding");
	}
	
	/** Test setKeySize() */
	// @Test 
	public void function testSetKeySize() {
		assertTrue(new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI).setKeySize(56).getKeySize() == 56);
	}
	
	/** Test getKeySize() */
	// @Test 
	public void function testGetKeySize() {
		assertTrue(new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI).getKeySize() == instance.ESAPI.securityConfiguration().getEncryptionKeyLength());
	}
	
	/** Test setBlockSize() */
	// @Test 
	public void function testSetBlockSize() {
		try {
			instance.cipherSpec.setBlockSize(0);// Throws AssertionError
		}
		catch(java.lang.AssertionError e) {
			assertTrue(true);// Doesn't work w/ @Test(expected=AssertionError.class)
		}
		try {
			instance.cipherSpec.setBlockSize(-1);// Throws AssertionError
		}
		catch(java.lang.AssertionError e) {
			assertTrue(true);// Doesn't work w/ @Test(expected=AssertionError.class)
		}
		assertTrue(instance.cipherSpec.setBlockSize(4).getBlockSize() == 4);
	}
	
	/** Test getBlockSize() */
	// @Test 
	public void function testGetBlockSize() {
		assertTrue(instance.cipherSpec.getBlockSize() == 8);
	}
	
	/** Test getCipherAlgorithm() */
	// @Test 
	public void function testGetCipherAlgorithm() {
		assertTrue(instance.cipherSpec.getCipherAlgorithm() == "Blowfish");
	}
	
	/** Test getCipherMode */
	// @Test 
	public void function testGetCipherMode() {
		assertTrue(instance.cipherSpec.getCipherMode() == "OFB8");
	}
	
	/** Test getPaddingScheme() */
	// @Test 
	public void function testGetPaddingScheme() {
		assertTrue(instance.cipherSpec.getPaddingScheme() == "PKCS5Padding");
	}
	
	/** Test setIV() */
	// @Test 
	public void function testSetIV() {
		try {
			// Test that ECB mode allows a null IV
			instance.cipherSpec = new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, cipher=instance.dfltECBCipher);
			instance.cipherSpec.setIV(toBinary(""));
			assertTrue(true);
		}
		catch(java.lang.AssertionError e) {
			assertFalse(false, "Test failed; unexpected exception");
		}
		try {
			// Test that CBC mode does allows a null IV
			instance.cipherSpec = new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, cipher=instance.dfltAESCipher);
			instance.cipherSpec.setIV(toBinary(""));
			assertFalse(false, "Test failed; Expected exception not thrown");
		}
		catch(java.lang.AssertionError e) {
			assertTrue(true);
		}
	}
	
	/** Test requiresIV() */
	// @Test 
	public void function testRequiresIV() {
		assertTrue(new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, cipher=instance.dfltECBCipher).requiresIV() == false);
		instance.cipherSpec = new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, cipher=instance.dfltAESCipher);
		assertTrue(instance.cipherSpec.getCipherMode() == "ECB");
		assertTrue(instance.cipherSpec.requiresIV() == false);
		assertTrue(new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, cipher=instance.dfltOtherCipher).requiresIV());
	}
	
	/** Test serialization */
	// @Test 
	public void function testSerialization() {
		System = createObject("java", "java.lang.System");
		JavaFile = createObject("java", "java.io.File");
		FileOutputStream = createObject("java", "java.io.FileOutputStream");
		ObjectOutputStream = createObject("java", "java.io.ObjectOutputStream");
		FileInputStream = createObject("java", "java.io.FileInputStream");
		ObjectInputStream = createObject("java", "java.io.ObjectInputStream");
	
		local.filename = "cipherspec.ser";
		local.serializedFile = JavaFile.init(local.filename);
		local.success = false;
		try {
			// Delete any old serialized file. If it fails, it's not
			// a big deal. If we can't overwrite it later, we'll get
			// an IOException.
			//
			// NOTE: FindBugs complains we are not checking return value here.
			//       Guess what? We don't care!!!
			local.serializedFile.delete();
		
			instance.cipherSpec = new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, cipherXform="AES/CBC/NoPadding", keySize=128, blockSize=8, iv=instance.myIV);
			local.fos = FileOutputStream.init(local.filename);
			local.out = ObjectOutputStream.init(local.fos);
			local.out.writeObject(instance.cipherSpec);
			local.out.close();
			local.fos.close();
		
			local.fis = FileInputStream.init(local.filename);
			local.in = ObjectInputStream.init(local.fis);
			local.restoredCipherSpec = local.in.readObject();
			local.in.close();
			local.fis.close();
		
			// check that cipherSpec and restoredCipherSpec are equal. Just
			// compare them via their string representations.
			assertEquals(instance.cipherSpec.toString(), local.restoredCipherSpec.toString(), "Serialized restored CipherSpec differs from saved CipherSpec");
		
			local.success = true;
		}
		catch(java.io.IOException ex) {
			// RAILO error: ex.printStackTrace(System.err);
			fail("testSerialization(): Unexpected IOException: " & ex);
		}
		catch(java.lang.ClassNotFoundException ex) {
			// RAILO error: ex.printStackTrace(System.err);
			fail("testSerialization(): Unexpected ClassNotFoundException: " & ex);
		}
		finally
		{
			// If test succeeds, remove the file. If it fails, leave it behind
			// for further analysis.
			if(local.success && local.serializedFile.exists()) {
				local.deleted = local.serializedFile.delete();
				if(!local.deleted) {
					try {
						System.err.println("Unable to delete file: " & local.serializedFile.getCanonicalPath());
					}
					catch(java.io.IOException e) {// Ignore
					}
				}
			}
		}
	}
	
}