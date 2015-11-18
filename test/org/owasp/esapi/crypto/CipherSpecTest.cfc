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
import "org.owasp.esapi.crypto.CipherSpec";

/** JUnit test to test CipherSpec class. */
component extends="test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	variables.dfltAESCipher = "";
	variables.dfltECBCipher = "";	// will be "AES/ECB/NoPadding";
	variables.dfltOtherCipher = "";
	variables.cipherSpec = "";
	variables.myIV = "";

	public void function setUp() {
		// This will throw ConfigurationException if IV type is not set to
		// 'fixed', which it's not. (We have it set to 'random'.)
		// myIV = Hex.decode( ESAPI.securityConfiguration().getFixedIV() );
		variables.myIV = createObject("java", "org.owasp.esapi.codecs.Hex").decode( "0x000102030405060708090a0b0c0d0e0f" );

		variables.dfltAESCipher   = createObject("java", "javax.crypto.Cipher").getInstance("AES");
		variables.dfltECBCipher   = createObject("java", "javax.crypto.Cipher").getInstance("AES/ECB/NoPadding");
		variables.dfltOtherCipher = createObject("java", "javax.crypto.Cipher").getInstance("Blowfish/OFB8/PKCS5Padding");

		assertTrue(!isNull(variables.dfltAESCipher));
		assertTrue(!isNull(variables.dfltECBCipher));
		assertTrue(!isNull(variables.dfltOtherCipher));

		variables.cipherSpec = new CipherSpec(variables.ESAPI, variables.dfltOtherCipher);
		assertTrue(!isNull(variables.cipherSpec));
	}

	/** Test CipherSpec(String cipherXform, int keySize, int blockSize, final byte[] iv) */
	public void function testCipherSpecStringIntIntByteArray() {

		variables.cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipherXform="AES/CBC/NoPadding", keySize=128, blockSize=8, iv=variables.myIV);
		assertTrue(!isNull(variables.cipherSpec));
		variables.cipherSpec = "";
		var caughtException = false;
		try {
			// Invalid cipher xform -- empty
			variables.cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipherXform="", keySize=128, blockSize=8, iv=variables.myIV);
		}
		catch(java.lang.IllegalArgumentException t) {
			caughtException = true;
		}
		assertTrue(caughtException && (variables.cipherSpec == ""));
		caughtException = false;
		try {
			// Invalid cipher xform -- missing padding scheme
			variables.cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipherXform="AES/CBC", keySize=128, blockSize=8, iv=variables.myIV);
		}
		catch(java.lang.IllegalArgumentException t) {
		    caughtException = true;
		}
        assertTrue(caughtException && (variables.cipherSpec == ""));
	}

	/** CipherSpec(final Cipher cipher, int keySize) */
	public void function testCipherSpecCipherInt() {
    	variables.cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipher=variables.dfltOtherCipher, keySize=112);
    	assertTrue(!isNull(variables.cipherSpec));
    	assertTrue( variables.cipherSpec.getCipherAlgorithm() == "Blowfish");
    	assertTrue( variables.cipherSpec.getCipherMode() == "OFB8");

    	variables.cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipher=variables.dfltAESCipher, keySize=256);
    	assertTrue(!isNull(variables.cipherSpec));
    	assertTrue( variables.cipherSpec.getCipherAlgorithm() == "AES");
    	assertTrue( variables.cipherSpec.getCipherMode() == "ECB");
    	assertTrue( variables.cipherSpec.getPaddingScheme() == "NoPadding");
    	// System.out.println("testCipherSpecInt(): " & variables.cipherSpec);
	}

	/** Test CipherSpec(final byte[] iv) */
	public void function testCipherSpecByteArray() {
		assertTrue(!isNull(variables.myIV));
		assertTrue(arrayLen(variables.myIV) > 0);
		variables.cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, iv=variables.myIV);
		assertTrue(variables.cipherSpec.getKeySize() == variables.ESAPI.securityConfiguration().getEncryptionKeyLength());
		assertTrue(variables.cipherSpec.getCipherTransformation() == variables.ESAPI.securityConfiguration().getCipherTransformation());
	}

	/** Test CipherSpec() */
	public void function testCipherSpec() {
		variables.cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipher=variables.dfltECBCipher);
		assertTrue(variables.cipherSpec.getCipherTransformation() == "AES/ECB/NoPadding");
		assertTrue(variables.cipherSpec.getIV() == "");

		variables.cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipher=variables.dfltOtherCipher);
		assertTrue(variables.cipherSpec.getCipherMode() == "OFB8");
	}

	/** Test setCipherTransformation(String cipherXform) */
	public void function testSetCipherTransformation() {
		variables.cipherSpec = new CipherSpec(variables.ESAPI);
		variables.cipherSpec.setCipherTransformation("AlgName/Mode/Padding");
		variables.cipherSpec.getCipherAlgorithm() == "AlgName/Mode/Padding";

		try {
			// Don't use null here as compiling JUnit tests disables assertion
			// checking so we get a NullPointerException here instead.
			variables.cipherSpec.setCipherTransformation(""); // Throws IllegalArgumentException
		} catch (java.lang.IllegalArgumentException e) {
			assertTrue(true);	// Doesn't work w/ @Test(expected=IllegalArgumentException.class)
		}
	}

	/** Test getCipherTransformation() */
	public void function testGetCipherTransformation() {
		assertTrue(new CipherSpec(variables.ESAPI).getCipherTransformation() == "AES/CBC/PKCS5Padding");
	}

	/** Test setKeySize() */
	public void function testSetKeySize() {
		assertTrue(new CipherSpec(variables.ESAPI).setKeySize(56).getKeySize() == 56);
	}

	/** Test getKeySize() */
	public void function testGetKeySize() {
		assertTrue(new CipherSpec(variables.ESAPI).getKeySize() == variables.ESAPI.securityConfiguration().getEncryptionKeyLength());
	}

	/** Test setBlockSize() */
	public void function testSetBlockSize() {
		try {
			variables.cipherSpec.setBlockSize(0); // Throws AssertionError
		} catch (AssertionError e) {
			assertTrue(true);	// Doesn't work w/ @Test(expected=AssertionError.class)
		}
		try {
			variables.cipherSpec.setBlockSize(-1); // Throws AssertionError
		} catch (AssertionError e) {
			assertTrue(true);	// Doesn't work w/ @Test(expected=AssertionError.class)
		}
		assertTrue( variables.cipherSpec.setBlockSize(4).getBlockSize() == 4 );
	}

	/** Test getBlockSize() */
	public void function testGetBlockSize() {
		assertTrue( variables.cipherSpec.getBlockSize() == 8 );
	}

	/** Test getCipherAlgorithm() */
	public void function testGetCipherAlgorithm() {
		assertTrue( variables.cipherSpec.getCipherAlgorithm() == "Blowfish");
	}

	/** Test getCipherMode */
	public void function testGetCipherMode() {
		assertTrue( variables.cipherSpec.getCipherMode() == "OFB8");
	}

	/** Test getPaddingScheme() */
	public void function testGetPaddingScheme() {
		assertTrue( variables.cipherSpec.getPaddingScheme() == "PKCS5Padding");
	}

	/** Test setIV() */
	public void function testSetIV() {
		try {
			// Test that ECB mode allows a null IV
			variables.cipherSpec = new CipherSpec(variables.ESAPI, variables.dfltECBCipher);
			variables.cipherSpec.setIV("");
			assertTrue(true);
		} catch ( AssertionError e) {
			assertFalse("Test failed; unexpected exception", false);
		}
		try {
			// Test that CBC mode does allows a null IV
			variables.cipherSpec = new CipherSpec(variables.ESAPI, variables.dfltAESCipher);
			variables.cipherSpec.setIV("");
			assertFalse(false, "Test failed; Expected exception not thrown");
		} catch ( AssertionError e) {
			assertTrue(true);
		}
	}

	/** Test requiresIV() */
	public void function testRequiresIV() {
		assertTrue(new CipherSpec(variables.ESAPI, variables.dfltECBCipher).requiresIV() == false);
		variables.cipherSpec = new CipherSpec(variables.ESAPI, variables.dfltAESCipher);
		assertTrue(variables.cipherSpec.getCipherMode() == "ECB");
		assertTrue(variables.cipherSpec.requiresIV() == false );
		assertTrue(new CipherSpec(variables.ESAPI, variables.dfltOtherCipher).requiresIV() );
	}

	/** Test serialization */
	public void function testSerialization() {
        var filename = "cipherspec.ser";
        var serializedFile = createObject("java", "java.io.File").init(filename);
        var success = false;
        try {
            // Delete any old serialized file. If it fails, it's not
            // a big deal. If we can't overwrite it later, we'll get
            // an IOException.
            //
            // NOTE: FindBugs complains we are not checking return value here.
            //       Guess what? We don't care!!!
            serializedFile.delete();


            variables.cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipherXform="AES/CBC/NoPadding", keySize=128, blockSize=8, iv=variables.myIV);
            var fos = createObject("java", "java.io.FileOutputStream").init(filename);
            var out = createObject("java", "java.io.ObjectOutputStream").init(fos);
            out.writeObject(variables.cipherSpec);
            out.close();
            fos.close();

            var fis = createObject("java", "java.io.FileInputStream").init(filename);
            var ins = createObject("java", "java.io.ObjectInputStream").init(fis);
            var restoredCipherSpec = ins.readObject();
            ins.close();
            fis.close();

            // check that cipherSpec and restoredCipherSpec are equal. Just
            // compare them via their string representations.
            assertEquals("Serialized restored CipherSpec differs from saved CipherSpec", variables.cipherSpec.toString(), restoredCipherSpec.toString() );

            success = true;
        } catch(java.io.IOException ex) {
            //ex.printStackTrace(System.err);
            fail("testSerialization(): Unexpected IOException: " & ex);
        } catch(java.lang.ClassNotFoundException ex) {
            //ex.printStackTrace(System.err);
            fail("testSerialization(): Unexpected ClassNotFoundException: " & ex);
        } finally {
            // If test succeeds, remove the file. If it fails, leave it behind
            // for further analysis.
            if ( success && serializedFile.exists() ) {
                var deleted = serializedFile.delete();
                if ( !deleted ) {
                    try {
                        variables.System.err.println("Unable to delete file: " & serializedFile.getCanonicalPath() );
                    } catch (IOException e) {
                        ; // Ignore
                    }
                }
            }
        }
	}

}