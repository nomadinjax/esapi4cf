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
import "org.owasp.esapi.crypto.CipherSpec";
import "org.owasp.esapi.crypto.CipherText";
import "test.org.owasp.esapi.reference.crypto.CryptoPolicy";

component extends="test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

    variables.POST_CLEANUP = true;

	variables.cipherSpec_ = "";
    variables.encryptor = "";
    variables.decryptor = "";
    variables.ivSpec = "";

    public void function preCleanup() {
    	try {
            // These two calls have side-effects that cause FindBugs to complain.
    		removeFile("ciphertext.ser");
    		removeFile("ciphertext-portable.ser");
    		// Do NOT remove this file...
    		//		src/test/resource/ESAPI2.0-ciphertext-portable.ser
    	} catch(Exception ex) {
    		;	// Do nothing
    	}
    }

	public void function setUp() {
        variables.encryptor = createObject("java", "javax.crypto.Cipher").getInstance("AES/CBC/PKCS5Padding");
        variables.decryptor = createObject("java", "javax.crypto.Cipher").getInstance("AES/CBC/PKCS5Padding");
        var ivBytes = variables.ESAPI.randomizer().getRandomBytes(variables.encryptor.getBlockSize());
        variables.ivSpec = createObject("java", "javax.crypto.spec.IvParameterSpec").init(ivBytes);
	}

	public void function postCleanup() {
	    if ( variables.POST_CLEANUP ) {
	            // These two calls have side-effects that cause FindBugs to complain.
	        removeFile("ciphertext.ser");
	        removeFile("ciphertext-portable.ser");
	    }
	}

	/** Test the default CTOR */
	public void function testCipherText() {
		var ct =  new CipherText(variables.ESAPI);

		cipherSpec_ = new CipherSpec(variables.ESAPI);
		assertTrue( ct.getCipherTransformation() == cipherSpec_.getCipherTransformation());
		assertTrue( ct.getBlockSize() == cipherSpec_.getBlockSize() );
	}

	public void function testCipherTextCipherSpec() {
		cipherSpec_ = new CipherSpec(ESAPI=variables.ESAPI, cipherXform="DESede/OFB8/NoPadding", keySize=112);
		var ct = new CipherText(variables.ESAPI, cipherSpec_);
		assertTrue(isNull(ct.getRawCipherText()));
		assertTrue( ct.getCipherAlgorithm() == "DESede" );
		assertTrue( ct.getKeySize() == cipherSpec_.getKeySize() );
	}

	public void function testCipherTextCipherSpecByteArray()
	{
		try {
			var cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipher=variables.encryptor, keySize=128);
			cipherSpec.setIV(variables.ivSpec.getIV());
			var key = new CryptoHelper(variables.ESAPI).generateSecretKey(cipherSpec.getCipherAlgorithm(), 128);
			variables.encryptor.init(createObject("java", "javax.crypto.Cipher").ENCRYPT_MODE, key, variables.ivSpec);
			var raw = variables.encryptor.doFinal(charsetDecode("Hello", "utf-8"));
			var ct = new CipherText(variables.ESAPI, cipherSpec, raw);
			assertTrue(!isNull(ct));
			var ctRaw = ct.getRawCipherText();
			assertTrue(!isNull(ctRaw));
			assertArrayEquals(raw, ctRaw);
			assertTrue( ct.getCipherTransformation() == cipherSpec.getCipherTransformation() );;
			assertTrue( ct.getCipherAlgorithm() == cipherSpec.getCipherAlgorithm() );
			assertTrue( ct.getPaddingScheme() == cipherSpec.getPaddingScheme() );
			assertTrue( ct.getBlockSize() == cipherSpec.getBlockSize() );
			assertTrue( ct.getKeySize() == cipherSpec.getKeySize() );
			var ctIV = ct.getIV();
			var csIV = cipherSpec.getIV();
			assertArrayEquals(ctIV, csIV);
		} catch( Exception ex) {
			// As far as test coverage goes, we really don't want this to be covered.
			fail("Caught unexpected exception: " & ex.getClass().getName() & "; exception message was: " & ex.getMessage());
		}
	}

	public void function testDecryptionUsingCipherText() {
		try {
			var cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipher=variables.encryptor, keySize=128);
			cipherSpec.setIV(variables.ivSpec.getIV());
			assertTrue(!isNull(cipherSpec.getIV()));
			assertTrue( arrayLen(cipherSpec.getIV()) > 0 );
			var key = new CryptoHelper(variables.ESAPI).generateSecretKey(cipherSpec.getCipherAlgorithm(), 128);
			variables.encryptor.init(createObject("java", "javax.crypto.Cipher").ENCRYPT_MODE, key, variables.ivSpec);
			var ctraw = variables.encryptor.doFinal(charsetDecode("Hello", "utf-8"));
			var ct = new CipherText(variables.ESAPI, cipherSpec, ctraw);
			assertTrue( ct.getCipherMode() == "CBC" );
			assertTrue( ct.requiresIV() ); // CBC mode requires an IV.
			var b64ctraw = ct.getBase64EncodedRawCipherText();
			assertTrue(!isNull(b64ctraw));
			assertArrayEquals( variables.ESAPI.encoder().decodeFromBase64(b64ctraw), ctraw );
			variables.decryptor.init(createObject("java", "javax.crypto.Cipher").DECRYPT_MODE, key, createObject("java", "javax.crypto.spec.IvParameterSpec").init(ct.getIV()));
			var ptraw = variables.decryptor.doFinal(variables.ESAPI.encoder().decodeFromBase64(b64ctraw));
			assertTrue(!isNull(ptraw));
			assertTrue( arrayLen(ptraw) > 0 );
			var plaintext = charsetEncode(ptraw, "utf-8");
			assertTrue( plaintext == "Hello" );
			assertArrayEquals( ct.getRawCipherText(), ctraw );

			var ivAndRaw = variables.ESAPI.encoder().decodeFromBase64( ct.getEncodedIVCipherText() );
			assertTrue(arrayLen(ivAndRaw) > arrayLen(ctraw));
			assertTrue( ct.getBlockSize() == ( arrayLen(ivAndRaw) - arrayLen(ctraw) ) );
		} catch( Exception ex) {
		    // Note: FindBugs reports a false positive here...
		    //    REC_CATCH_EXCEPTION: Exception is caught when Exception is not thrown
		    // but exceptions really can be thrown. This probably is because FindBugs
		    // examines the byte-code rather than the source code. However "fixing" this
		    // so that it doesn't complain will make the test much more complicated as there
		    // are about 3 or 4 different exception types.
		    //
		    // On a completely different note, as far as test coverage metrics goes,
			// we really don't care if this is covered or nit as it is not our intent
		    // to be causing exceptions here.
			ex.printStackTrace(System.err);
			fail("Caught unexpected exception: " & ex.getClass().getName() & "; exception message was: " & ex.getMessage());
		}
	}

	public void function testMIC() {
		try {
			var cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipher=variables.encryptor, keySize=128);
			cipherSpec.setIV(variables.ivSpec.getIV());
			var key = new CryptoHelper(variables.ESAPI).generateSecretKey(cipherSpec.getCipherAlgorithm(), 128);
			variables.encryptor.init(createObject("java", "javax.crypto.Cipher").ENCRYPT_MODE, key, variables.ivSpec);
			var ctraw = variables.encryptor.doFinal(charsetDecode("Hello", "utf-8"));
			var ct = new CipherText(variables.ESAPI, cipherSpec, ctraw);
			assertTrue( !isNull(ct.getIV()) && arrayLen(ct.getIV()) > 0 );
			var authKey = new CryptoHelper(variables.ESAPI).computeDerivedKey(key, arrayLen(key.getEncoded()) * 8, "authenticity");
			ct.computeAndStoreMAC( authKey );
			try {
				ct.setIVandCiphertext(variables.ivSpec.getIV(), ctraw);	// Expected to log & throw.
			} catch( Exception ex ) {
				assertTrue( isInstanceOf(ex, "EncryptionException") );
			}
			try {
				ct.setCiphertext(ctraw);	// Expected to log and throw message about
											// not being able to store raw ciphertext.
			} catch( Exception ex ) {
				assertTrue( isInstanceOf(ex, "EncryptionException") );
			}
			variables.decryptor.init(createObject("java", "javax.crypto.Cipher").DECRYPT_MODE, key, createObject("java", "javax.crypto.spec.IvParameterSpec").init( ct.getIV() ) );
			var ptraw = variables.decryptor.doFinal( ct.getRawCipherText() );
			assertTrue( !isNull(ptraw) && arrayLen(ptraw) > 0 );
			ct.validateMAC( authKey );
		} catch( Exception ex) {
			// As far as test coverage goes, we really don't want this to be covered.
			ex.printStackTrace(System.err);
			fail("Caught unexpected exception: " & ex.getClass().getName() & "; exception message was: " & ex.getMessage());
		}
	}

	/** Test <i>portable</i> serialization. */
	public void function testPortableSerialization() {
	    variables.System.out.println("CipherTextTest.testPortableSerialization() starting...");
	    var filename = "ciphertext-portable.ser";
	    var serializedFile = createObject("java", "java.io.File").init(filename);
	    serializedFile.delete();    // Delete any old serialized file.

	    var keySize = 128;
	    if ( new CryptoPolicy().isUnlimitedStrengthCryptoAvailable() ) {
	        keySize = 256;
	    }
	    var cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipher=variables.encryptor, keySize=keySize);
	    cipherSpec.setIV(variables.ivSpec.getIV());
	    var key = "";
	    try {
	        key = new CryptoHelper(variables.ESAPI).generateSecretKey(cipherSpec.getCipherAlgorithm(), keySize);

	        variables.encryptor.init(createObject("java", "javax.crypto.Cipher").ENCRYPT_MODE, key, variables.ivSpec);
	        var raw = variables.encryptor.doFinal(charsetDecode("This is my secret message!!!", "utf-8"));
	        var ciphertext = new CipherText(variables.ESAPI, cipherSpec, raw);
	        	// TODO: Replace this w/ call to KeyDerivationFunction as this is
	        	//		 deprecated! Shame on me!
	        var authKey = new CryptoHelper(variables.ESAPI).computeDerivedKey(key, arrayLen(key.getEncoded()) * 8, "authenticity");
	        ciphertext.computeAndStoreMAC( authKey );
//          System.err.println("Original ciphertext being serialized: " & ciphertext);
	        var serializedBytes = ciphertext.asPortableSerializedByteArray();

	        var fos = createObject("java", "java.io.FileOutputStream").init(serializedFile);
            fos.write(serializedBytes);
                // Note: FindBugs complains that this test may fail to close
                // the fos output stream. We don't really care.
            fos.close();

            // NOTE: FindBugs complains about this (OS_OPEN_STREAM). It apparently
            //       is too lame to know that 'fis.read()' is a serious side-effect.
            var fis = createObject("java", "java.io.FileInputStream").init(serializedFile);
            var avail = fis.available();
            var bytes = new Utils().newByte(avail);
            fis.read(bytes, 0, avail);

            // Sleep one second to prove that the timestamp on the original
            // CipherText object is the one that we use and not just the
            // current time. Only after that, do we restore the serialized bytes.
            try {
                sleep(1000);
            } catch (InterruptedException e) {
                ;    // Ignore
            }
            var restoredCipherText = CipherText.fromPortableSerializedBytes(bytes);
//          System.err.println("Restored ciphertext: " & restoredCipherText);
            assertTrue( ciphertext == restoredCipherText);
	    } catch (EncryptionException e) {
	        Assert.fail("Caught EncryptionException: " & e);
        } catch (FileNotFoundException e) {
            Assert.fail("Caught FileNotFoundException: " & e);
        } catch (IOException e) {
            Assert.fail("Caught IOException: " & e);
        } catch (Exception e) {
            Assert.fail("Caught Exception: " & e);
        } finally {
            // FindBugs complains that we are ignoring this return value. We really don't care.
            serializedFile.delete();
        }
	}

	/** Test <i>portable</i> serialization for backward compatibility with ESAPI 2.0. */
	public void function testPortableSerializationBackwardCompatibility() {
	    variables.System.out.println("testPortableSerializationBackwardCompatibility() starting...");
	    var filename = "src/test/resources/ESAPI2.0-ciphertext-portable.ser";  // Do NOT remove
	    var serializedFile = createObject("java", "java.io.File").init(filename);

	    try {
	    	// String expectedMsg = "This is my secret message!!!";

            // NOTE: FindBugs complains about this (OS_OPEN_STREAM). It apparently
            //       is too lame to know that 'fis.read()' is a serious side-effect.
            var fis = createObject("java", "java.io.FileInputStream").init(serializedFile);
            var avail = fis.available();
            var bytes = new Utils().newByte(avail);
            fis.read(bytes, 0, avail);
            // We can't go as far and decrypt it because the file was encrypted using a
            // temporary session key.
            var restoredCipherText = new CipherText(variables.ESAPI).fromPortableSerializedBytes(bytes);
            assertTrue(!isNull(restoredCipherText));
            var retrievedKdfVersion = restoredCipherText.getKDFVersion();
	    } catch (org.owasp.esapi.errors.EncryptionException e) {
	        fail("Caught EncryptionException: " & e);
        } catch (java.io.FileNotFoundException e) {
            fail("Caught FileNotFoundException: " & e);
        } catch (java.io.IOException e) {
            fail("Caught IOException: " & e);
        } catch (any e) {
            fail("Caught Exception: " & e);
        } finally {
        	; // Do NOT delete the file.
        }
	}

	/** Test Java serialization. */
	public void function testJavaSerialization() {
        var filename = "ciphertext.ser";
        var serializedFile = createObject("java", "java.io.File").init(filename);
        try {
            serializedFile.delete();	// Delete any old serialized file.

            var cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipher=variables.encryptor, keySize=128);
			cipherSpec.setIV(variables.ivSpec.getIV());
			var key = new CryptoHelper(variables.ESAPI).generateSecretKey(cipherSpec.getCipherAlgorithm(), 128);
			variables.encryptor.init(createObject("java", "javax.crypto.Cipher").ENCRYPT_MODE, key, variables.ivSpec);
			var raw = variables.encryptor.doFinal(charsetDecode("This is my secret message!!!", "utf-8"));
			var ciphertext = new CipherText(variables.ESAPI, cipherSpec, raw);

            var fos = createObject("java", "java.io.FileOutputStream").init(filename);
            var out = createObject("java", "java.io.ObjectOutputStream").init(fos);
            out.writeObject(ciphertext);
            out.close();
            fos.close();

            var fis = createObject("java", "java.io.FileInputStream").init(filename);
            var ins = createObject("java", "java.io.ObjectInputStream").init(fis);
            var restoredCipherText = ins.readObject();
            ins.close();
            fis.close();

            // check that ciphertext and restoredCipherText are equal. Requires
            // multiple checks. (Hmmm... maybe overriding equals() and hashCode()
            // is in order???)
            assertEquals(ciphertext.toString(), restoredCipherText.toString(), "1: Serialized restored CipherText differs from saved CipherText");
            assertArrayEquals(ciphertext.getIV(), restoredCipherText.getIV(), "2: Serialized restored CipherText differs from saved CipherText");
            assertEquals(ciphertext.getBase64EncodedRawCipherText(), restoredCipherText.getBase64EncodedRawCipherText(), "3: Serialized restored CipherText differs from saved CipherText");

        } catch(IOException ex) {
            ex.printStackTrace(System.err);
            fail("testJavaSerialization(): Unexpected IOException: " & ex);
        } catch(ClassNotFoundException ex) {
            ex.printStackTrace(System.err);
            fail("testJavaSerialization(): Unexpected ClassNotFoundException: " & ex);
        } catch (EncryptionException ex) {
			ex.printStackTrace(System.err);
			fail("testJavaSerialization(): Unexpected EncryptionException: " & ex);
		} catch (IllegalBlockSizeException ex) {
			ex.printStackTrace(System.err);
			fail("testJavaSerialization(): Unexpected IllegalBlockSizeException: " & ex);
		} catch (BadPaddingException ex) {
			ex.printStackTrace(System.err);
			fail("testJavaSerialization(): Unexpected BadPaddingException: " & ex);
		} catch (InvalidKeyException ex) {
			ex.printStackTrace(System.err);
			fail("testJavaSerialization(): Unexpected InvalidKeyException: " & ex);
		} catch (InvalidAlgorithmParameterException ex) {
			ex.printStackTrace(System.err);
			fail("testJavaSerialization(): Unexpected InvalidAlgorithmParameterException: " & ex);
		}  finally {
		    // FindBugs complains that we are ignoring this return value. We really don't care.
            serializedFile.delete();
        }
	}

	private void function removeFile(required string fname) {
    	try {
    		if (!isNull(arguments.fname)) {
    			var f = createObject("java", "java.io.File").init(arguments.fname);
    			// Findbugs complains about ignoring this return value. Too bad.
    			f.delete();
    		}
    	} catch(Exception ex) {
    			// Do nothing
    	}
	}
}
