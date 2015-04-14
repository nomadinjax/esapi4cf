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
import "org.owasp.esapi.crypto.CipherText";
import "org.owasp.esapi.crypto.CryptoHelper";
import "org.owasp.esapi.crypto.PlainText";

/**
 * The Class EncryptorTest.
 */
component extends="esapi4cf.test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	public void function setup() {
        // This is only mechanism to change this for now. Will do this with
        // a soon to be CryptoControls class or equivalent mechanism in a
    	// future release.
        variables.ESAPI.securityConfiguration().setCipherTransformation("AES/CBC/PKCS5Padding");
    }

    /**
	 * Test of hash method, of class org.owasp.esapi.Encryptor.
     *
     * @throws EncryptionException
     */
    public void function testHash() {
        variables.System.out.println("testHash()");
        var instance = variables.ESAPI.encryptor();
        var hash1 = instance.hash("test1", "salt");
        var hash2 = instance.hash("test2", "salt");
        assertFalse(hash1.equals(hash2));
        var hash3 = instance.hash("test", "salt1");
        var hash4 = instance.hash("test", "salt2");
        assertFalse(hash3.equals(hash4));
    }

    /**
	 * Test of new encrypt / decrypt method for Strings whose length is
	 * not a multiple of the cipher block size (16 bytes for AES).
	 *
	 * @throws EncryptionException
	 *             the encryption exception
	 */
    public void function testEncryptDecrypt1() {
        variables.System.out.println("testEncryptDecrypt2()");
        var instance = variables.ESAPI.encryptor();
        var plaintext = "test1234test1234tes"; // Not a multiple of block size (16 bytes)
        //try {
            var ct = instance.encrypt(new PlainText(variables.ESAPI, plaintext));
            var pt = instance.decrypt(ct);
            assertEquals(plaintext, pt.toString());
        /*}
        catch(org.owasp.esapi.errors.EncryptionException e) {
        	fail("testEncryptDecrypt2(): Caught exception: " & e);
        }*/
    }

    /**
	 * Test of new encrypt / decrypt method for Strings whose length is
	 * same as cipher block size (16 bytes for AES).
	 */
    public void function testEncryptDecrypt2() {
        variables.System.out.println("testEncryptDecrypt2()");
        var instance = variables.ESAPI.encryptor();
        var plaintext = "test1234test1234";
        try {
            var ct = instance.encrypt(new PlainText(variables.ESAPI, plaintext));
            var pt = instance.decrypt(ct);
            assertEquals(plaintext, pt.toString());
        }
        catch(org.owasp.esapi.errors.EncryptionException e) {
        	fail("testEncryptDecrypt2(): Caught exception: " & e);
        }
    }

    /**
     * Test of encrypt methods for empty String.
     */
    public void function testEncryptEmptyStrings() {
        variables.System.out.println("testEncryptEmptyStrings()");
        var instance = variables.ESAPI.encryptor();
        var plaintext = "";
        try {
            // System.out.println("New encryption methods");
            var ct = instance.encrypt(new PlainText(variables.ESAPI, plaintext));
            var pt = instance.decrypt(ct);
            assertEquals("", pt.toString());
        } catch(org.owasp.esapi.errors.EncryptionException e) {
            fail("testEncryptEmptyStrings() -- Caught exception: " & e);
        }
    }

    /**
     * Test encryption method for null.
     */
    public void function testEncryptNull() {
        variables.System.out.println("testEncryptNull()");
        var instance = variables.ESAPI.encryptor();
        try {
			var ct = instance.encrypt(new PlainText(variables.ESAPI, chr(0)));  // Should throw NPE or AssertionError
            fail("New encrypt(PlainText) method did not throw. Result was: " & ct.toString());
        } catch(any t) {
            // It should be one of these, depending on whether or not assertions are enabled.
            assertTrue(t.type == "java.lang.IllegalArgumentException" || t.type == "mxunit.exception.AssertionFailedError");
        }
    }

    /**
     * Test decryption method for null.
     */
    /* ERROR:
    invalid call of the function decrypt first Argument (ciphertext) is of invalid type, can't cast String [] to a value of type [ciphertext]
    public void function testDecryptNull() {
        variables.System.out.println("testDecryptNull()");
        var instance = variables.ESAPI.encryptor();
        try {
			var pt = instance.decrypt(chr(0));  // Should throw IllegalArgumentException or AssertionError
            fail("New decrypt(PlainText) method did not throw. Result was: " & pt.toString());
        } catch(any t) {
        	writedump(t);abort;
            // It should be one of these, depending on whether or not assertions are enabled.
            assertTrue(t.type == "java.lang.IllegalArgumentException" || t.type == "mxunit.exception.AssertionFailedError");
        }
    }*/

    /**
     * Test of new encrypt / decrypt methods added in ESAPI 2.0.
     */
    public void function testNewEncryptDecrypt() {
    	variables.System.out.println("testNewEncryptDecrypt()");
    	try {

    	    // Let's try it with a 2-key version of 3DES. This should work for all
    	    // installations, whereas the 3-key Triple DES will only work for those
    	    // who have the Unlimited Strength Jurisdiction Policy files installed.
			runNewEncryptDecryptTestCase("DESede/CBC/PKCS5Padding", 112, charsetDecode("1234567890", "UTF-8"));
			runNewEncryptDecryptTestCase("DESede/CBC/NoPadding", 112, charsetDecode("12345678", "UTF-8"));

			runNewEncryptDecryptTestCase("DES/ECB/NoPadding", 56, charsetDecode("test1234", "UTF-8"));

	        runNewEncryptDecryptTestCase("AES/CBC/PKCS5Padding", 128, charsetDecode("Encrypt the world!", "UTF-8"));

	        // These tests are only valid (and run) if one has the JCE Unlimited
	        // Strength Jurisdiction Policy files installed for this Java VM.
	            // 256-bit AES
            runNewEncryptDecryptTestCase("AES/ECB/NoPadding", 256, charsetDecode("test1234test1234", "UTF-8"));
                // 168-bit (aka, 3-key) Triple DES
            runNewEncryptDecryptTestCase("DESede/CBC/PKCS5Padding", 168, charsetDecode("Groucho's secret word", "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			fail("OK, who stole UTF-8 encoding from the Java rt.jar ???");
		}

    }

    /**
     * Helper method to test new encryption / decryption.
     * @param cipherXform	Cipher transformation
     * @param keySize	Size of key, in bits.
     * @param plaintextBytes Byte array of plaintext.
     * @return The base64-encoded IV+ciphertext (or just ciphertext if no IV) or
     *         null if {@code keysize} is greater than 128 bits and unlimited
     *         strength crypto is not available for this Java VM.
     */
    private string function runNewEncryptDecryptTestCase(required string cipherXform, required numeric keySize, required binary plaintextBytes) {
    	variables.System.out.println("New encrypt / decrypt: " & arguments.cipherXform);

    	if ( arguments.keySize > 128 && !CryptoPolicy.isUnlimitedStrengthCryptoAvailable() ) {
    	    variables.System.out.println("Skipping test for cipher transformation " & arguments.cipherXform & " with key size of " & arguments.keySize & " bits because this requires JCE Unlimited Strength Jurisdiction Policy files to be installed and they are not.");
    	    return null;
    	}

    	//try {
			var cipherAlg = arguments.cipherXform.split("/")[1];
    		// Generate an appropriate random secret key
			var skey = new CryptoHelper(variables.ESAPI).generateSecretKey(arguments.cipherXform, arguments.keySize);
			// Adjust key size for DES and DESede specific oddities.
			// NOTE: Key size that encrypt() method is using is 192 bits!!!
    		//        which is 3 times 64 bits, but DES key size is only 56 bits.
    		// See 'IMPORTANT NOTE', in JavaEncryptor, near line 376. It's a "feature"!!!
			if ( cipherAlg.equals( "DESede" ) ) {
				arguments.keySize = 192;
			} else if ( cipherAlg.equals( "DES" ) ) {
				arguments.keySize = 64;
			} // Else... use specified keySize.

			assertTrue(skey.getAlgorithm() == cipherAlg);

			assertEquals(arguments.keySize / 8, arrayLen(skey.getEncoded()));
//			variables.System.out.println("testNewEncryptDecrypt(): Skey length (bits) = " & 8 * skey.getEncoded().length);

			// Change to a possibly different cipher. This is kludgey at best. Am thinking about an
			// alternate way to do this using a new 'CryptoControls' class. Maybe not until release 2.1.
			// Change the cipher transform from whatever it currently is to the specified cipherXform.
			var oldCipherXform = variables.ESAPI.securityConfiguration().setCipherTransformation(arguments.cipherXform);
	    	if ( ! arguments.cipherXform.equals(oldCipherXform) ) {
	    		variables.System.out.println('Cipher xform changed from "' & oldCipherXform & '" to "' & arguments.cipherXform & '"');
	    	}

	    	// Get an Encryptor instance with the specified, possibly new, cipher transformation.
	    	var instance = variables.ESAPI.encryptor();
	    	var plaintext = new PlainText(variables.ESAPI, arguments.plaintextBytes);
	    	var origPlainText = new PlainText(variables.ESAPI, plaintext.toString()); // Make _copy_ of original for comparison.

	    	// Do the encryption with the new encrypt() method and get back the CipherText.
	    	var ciphertext = instance.encrypt(plaintext, skey);	// The new encrypt() method.
	    	variables.System.out.println("DEBUG: Encrypt(): CipherText object is -- " & ciphertext.toString());
	    	assertTrue(!isNull(ciphertext));
//	    	variables.System.out.println("DEBUG: After encryption: base64-encoded IV&ciphertext: " & ciphertext.getEncodedIVCipherText());
//	    	variables.System.out.println("\t\tOr... " & variables.ESAPI.encoder().decodeFromBase64(ciphertext.getEncodedIVCipherText()) );
//	    	variables.System.out.println("DEBUG: After encryption: base64-encoded raw ciphertext: " & ciphertext.getBase64EncodedRawCipherText());
//	    	variables.System.out.println("\t\tOr... " & variables.ESAPI.encoder().decodeFromBase64(ciphertext.getBase64EncodedRawCipherText()) );

	    	// If we are supposed to have overwritten the plaintext, check this to see
	    	// if origPlainText was indeed overwritten.
			var overwritePlaintext = variables.ESAPI.securityConfiguration().overwritePlainText();
			if ( overwritePlaintext ) {
				assertTrue( isPlaintextOverwritten(plaintext) );
			}

	    	// Take the resulting ciphertext and decrypt w/ new decryption method.
	    	var decryptedPlaintext  = instance.decrypt(ciphertext, skey);		// The new decrypt() method.

	    	// Make sure we got back the same thing we started with.
	    	variables.System.out.println("\tOriginal plaintext: " & origPlainText);
	    	variables.System.out.println("\tResult after decryption: " & decryptedPlaintext);
			assertTrue( origPlainText.toString() == decryptedPlaintext.toString(), "Failed to decrypt properly." );

	    	// Restore the previous cipher transformation. For now, this is only way to do this.
			var previousCipherXform = variables.ESAPI.securityConfiguration().setCipherTransformation(null);
	    	assertTrue( previousCipherXform.equals( arguments.cipherXform ) );
	    	var defaultCipherXform = variables.ESAPI.securityConfiguration().getCipherTransformation();
	    	assertTrue( defaultCipherXform.equals( oldCipherXform ) );

	    	return ciphertext.getEncodedIVCipherText();
		/*} catch (any e) {
			// OK if not counted toward code coverage.
			variables.System.out.println("testNewEncryptDecrypt(): Caught unexpected exception: " & e.getClass().getName());
			e.printStackTrace(variables.System.out);
			fail("Caught unexpected exception; msg was: " & e);
		}*/
		return null;
    }

    private boolean function isPlaintextOverwritten(required PlainText plaintext) {
    	// Note: An assumption here that the original plaintext did not consist
    	// entirely of all '*' characters.
    	var ptBytes = plaintext.toString();

		if (find("*", ptBytes)) {
			return false;
		}
    	return true;
    }

    // TODO - Because none of the encryption / decryption tests persists
    //		  encrypted data across runs, that means everything is run
    //		  under same JVM at same time thus always with the same
    //		  _native_ byte encoding.
    //
    //		  Need test(s) such that data is persisted across JVM runs
    //		  so we can test a run on (say) a Windows Intel box can decrypt
    //		  encrypted data produced by the reference Encryptor on
    //		  (say) a Solaris SPARC box. I.e., test that the change to
    //		  JavaEncryptor to use UTF-8 encoding throughout works as
    //		  desired.
    //
    //		  Files saved across tests need to be added to SVN (under
    //		  resources or where) and they should be named so we know
    //		  where and how they were created. E.g., WinOS-AES-ECB.dat,
    //		  Sparc-Solaris-AEC-CBC-PKCS5Padding.dat, etc., but they should be
    //		  able to be decrypted from any platform. May wish to place that
    //		  under a separate JUnit test.
    //
    // TODO - Need to test rainy day paths of new encrypt / decrypt so can
    //		  verify that exception handling working OK, etc. Maybe also in
    //		  a separate JUnit test, since everything here seems to be sunny
    //		  day path. (Note: Some of this no in new test case,
    //		  org.owasp.esapi.crypto.ESAPICryptoMACByPassTest.)
    //
    //				-kevin wall


    /**
	 * Test of sign method, of class org.owasp.esapi.Encryptor.
	 *
	 * @throws EncryptionException
	 *             the encryption exception
	 */
    public void function testSign() {
        variables.System.out.println("testSign()");
        var instance = variables.ESAPI.encryptor();
        var plaintext = variables.ESAPI.randomizer().getRandomString( 32, variables.ESAPI.encoder().CHAR_ALPHANUMERICS );
        var signature = instance.sign(plaintext);
        assertTrue( instance.verifySignature( signature, plaintext ) );
        assertFalse( instance.verifySignature( signature, "ridiculous" ) );
        assertFalse( instance.verifySignature( "ridiculous", plaintext ) );
    }

    /**
	 * Test of verifySignature method, of class org.owasp.esapi.Encryptor.
	 *
	 * @throws EncryptionException
	 *             the encryption exception
	 */
    public void function testVerifySignature() {
        variables.System.out.println("testVerifySignature()");
        var instance = variables.ESAPI.encryptor();
        var plaintext = variables.ESAPI.randomizer().getRandomString( 32, variables.ESAPI.encoder().CHAR_ALPHANUMERICS );
        var signature = instance.sign(plaintext);
        assertTrue( instance.verifySignature( signature, plaintext ) );
    }


    /**
	 * Test of seal method, of class org.owasp.esapi.Encryptor.
	 *
     * @throws IntegrityException
	 */
    public void function testSeal() {
        variables.System.out.println("testSeal()");
        var instance = variables.ESAPI.encryptor();
        var plaintext = variables.ESAPI.randomizer().getRandomString( 32, variables.ESAPI.encoder().CHAR_ALPHANUMERICS );
        var seal = instance.seal( plaintext, instance.getTimeStamp() + 1000*60 );
        instance.verifySeal( seal );

        var progressMark = 1;
        var caughtExpectedEx = false;
        try {
            seal = instance.seal("", instance.getTimeStamp() + 1000*60);
            progressMark++;
            instance.verifySeal(seal);
            progressMark++;
        } catch(Exception e) {
            fail("Failed empty string test: " & e & "; progress mark = " & progressMark);
        }
        try {
            seal = instance.seal(javaCast("null", ""), instance.getTimeStamp() + 1000*60);
            fail("Did not throw expected IllegalArgumentException");
        } catch(java.lang.IllegalArgumentException e) {
            caughtExpectedEx = true;
        } catch(expression e) {
            caughtExpectedEx = true;
        } catch(any e) {
            fail("Failed null string test; did not get expected IllegalArgumentException: " & e);
        }
        assertTrue(caughtExpectedEx);

        try {
            seal = instance.seal("test", 0);
            progressMark++;
            // instance.verifySeal(seal);
            progressMark++;
        } catch(Exception e) {
            fail("Fail test with 0 timestamp: " & e & "; progress mark = " & progressMark);
        }
        try {
            seal = instance.seal("test", -1);
            progressMark++;
            // instance.verifySeal(seal);
            progressMark++;
        } catch(Exception e) {
            fail("Fail test with -1 timestamp: " & e & "; progress mark = " & progressMark);
        }
    }

    /**
	 * Test of verifySeal method, of class org.owasp.esapi.Encryptor.
	 *
     * @throws EnterpriseSecurityException
	 */
    public void function testVerifySeal() {
        var NSEC = 5;
        variables.System.out.println("testVerifySeal()");
        var instance = variables.ESAPI.encryptor();
        var plaintext = "ridiculous:with:delimiters";    // Should now work w/ : (issue #28)
        var seal = instance.seal( plaintext, instance.getRelativeTimeStamp( 1000 * NSEC ) );
        var Long = createObject("java", "java.lang.Long");
        try {
        	assertFalse(isNull(seal), "Encryptor.seal() returned null");
        	assertTrue(instance.verifySeal( seal ), "Failed to verify seal");
        } catch ( Exception e ) {
        	fail();
        }
        var progressMark = 1;
        try {
            // NOTE: I regrouped these all into a single try / catch since they
            //       all test the same thing. Hence if one fails, they all should.
            //       Also changed these tests so they no longer depend on the
            //       deprecated encrypt() methods. IMO, *all these multiple
            //       similar tests are not really required*, as they all are more
            //       or less testing the same thing.
            //                                              -kevin wall
            // ================================================================
            // Try to validate some invalid seals.
            //
            // All these should return false and log a warning with an Exception stack
            // trace caused by an EncryptionException indicating "Invalid seal".
        	assertFalse( instance.verifySeal( plaintext ) );
        	progressMark++;
            assertFalse( instance.verifySeal( instance.encrypt( new PlainText(variables.ESAPI, plaintext) ).getBase64EncodedRawCipherText() ) );
            progressMark++;
            assertFalse( instance.verifySeal( instance.encrypt( new PlainText(variables.ESAPI, 100 & ":" & plaintext) ).getBase64EncodedRawCipherText() ) );
            progressMark++;
            assertFalse( instance.verifySeal( instance.encrypt( new PlainText(variables.ESAPI, Long.MAX_VALUE & ":" & plaintext) ).getBase64EncodedRawCipherText() ) );
            progressMark++;
            assertFalse( instance.verifySeal( instance.encrypt( new PlainText(variables.ESAPI, Long.MAX_VALUE & ":random:" & plaintext) ).getBase64EncodedRawCipherText() ) );
            progressMark++;
            assertFalse( instance.verifySeal( instance.encrypt( new PlainText(variables.ESAPI, Long.MAX_VALUE & ":random:" & plaintext & ":badsig")  ).getBase64EncodedRawCipherText() ) );
            progressMark++;
            assertFalse( instance.verifySeal( instance.encrypt( new PlainText(variables.ESAPI, Long.MAX_VALUE & ":random:" & plaintext & ":" & instance.sign( Long.MAX_VALUE & ":random:" & plaintext) ) ).getBase64EncodedRawCipherText() ) );
            progressMark++;
        } catch ( Exception e ) {
        	// fail("Failed invalid seal test # " & progressMark & " to verify seal.");
            variables.System.err.println("Failed seal verification at step ## " & progressMark);
            variables.System.err.println("Exception was: " & e);
            e.printStackTrace(variables.System.err);
        }

        try {
            sleep(1000 * (NSEC + 1) );
                // Seal now past expiration date.
            assertFalse( instance.verifySeal( seal ) );
        } catch ( Exception e ) {
            fail("Failed expired seal test. Seal should be expired.");
        }
    }


    public void function testEncryptionSerialization() {
        var secretMsg = "Secret Message";
        variables.ESAPI.securityConfiguration().setCipherTransformation("AES/CBC/PKCS5Padding");
        var ct = variables.ESAPI.encryptor().encrypt(new PlainText(variables.ESAPI, secretMsg));

        var serializedCipherText = ct.asPortableSerializedByteArray();

        var plainText = variables.ESAPI.encryptor().decrypt(new CipherText(variables.ESAPI).fromPortableSerializedBytes(serializedCipherText));

        assertTrue( secretMsg.equals( plainText.toString() ) );
    }

}
