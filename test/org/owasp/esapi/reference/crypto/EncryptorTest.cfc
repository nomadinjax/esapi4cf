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
<cfcomponent extends="cfesapi.test.TestCase" output="false">

	<cfscript>
		System = createObject("java", "java.lang.System");
		
		instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
	</cfscript>
 
	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			// This is only mechanism to change this for now. Will do this with a soon to be CryptoControls class in next release.
	        instance.ESAPI.securityConfiguration().setCipherTransformation("AES/CBC/PKCS5Padding");
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testHash" output="false" hint="Test of hash method, of class org.owasp.esapi.Encryptor.">
		<cfscript>
	        System.out.println("testHash()");
	        local.encryptor = instance.ESAPI.encryptor();
	        local.hash1 = local.encryptor.hash("test1", "salt");
	        local.hash2 = local.encryptor.hash("test2", "salt");
	        assertFalse(local.hash1.equals(local.hash2));
	        local.hash3 = local.encryptor.hash("test", "salt1");
	        local.hash4 = local.encryptor.hash("test", "salt2");
	        assertFalse(local.hash3.equals(local.hash4));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncrypt" output="false" hint="Test of deprecated encrypt method for Strings.">
		<cfscript>
	        System.out.println("testEncrypt()");
	        local.encryptor = instance.ESAPI.encryptor();
	        local.plaintext = "test123456";	// Not multiple of block cipher size
	        local.ciphertext = local.encryptor.encrypt(plain=local.plaintext);
	    	local.result = local.encryptor.decrypt(ciphertext=local.ciphertext);
	        assertEquals(local.plaintext, local.result);
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testDecrypt" output="false" hint="Test of deprecated decrypt method for Strings.">
		<cfscript>
	        System.out.println("testDecrypt()");
	        local.encryptor = instance.ESAPI.encryptor();
	        try {
	            local.plaintext = "test123";
	            local.ciphertext = local.encryptor.encrypt(plain=local.plaintext);
	            assertFalse(local.plaintext.equals(local.ciphertext));
	        	local.result = local.encryptor.decrypt(ciphertext=local.ciphertext);
	        	assertEquals(local.plaintext, local.result);
	        }
	        catch( cfesapi.org.owasp.esapi.errors.EncryptionException e ) {
	        	fail();
	        }
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncryptEmptyStrings" output="false" hint="Test of deprecated encrypt methods for empty String.">
		<cfscript>
	        System.out.println("testEncryptEmptyStrings()");
	        local.encryptor = instance.ESAPI.encryptor();
	        local.plaintext = "";
	        //try {
	            // System.out.println("Deprecated encryption methods");
	            local.ciphertext = local.encryptor.encrypt(plain=local.plaintext);
	            local.result = local.encryptor.decrypt(ciphertext=local.ciphertext);
	            assertTrue( local.result == "" );

	            // System.out.println("New encryption methods");
	            local.ct = local.encryptor.encrypt(plain=createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, local.plaintext));
	            local.pt = local.encryptor.decrypt(ciphertext=local.ct);
	            assertTrue( local.pt.toString() == "" );
	        /*} catch(java.lang.Exception e) {
	            fail("testEncryptEmptyStrings() -- Caught exception: " & e);
	        }*/
    	</cfscript> 
	</cffunction>

	<!--- NULL test

		<cffunction access="public" returntype="void" name="testEncryptNull" output="false" hint="Test deprecated encryption / decryption methods for null.">
		<cfscript>
		System.out.println("testEncryptNull()");
		local.encryptor = instance.ESAPI.encryptor();
		local.plaintext = "";
		try {
		local.nullStr = null;
		local.encryptor.encrypt(local.nullStr);
		fail("testEncryptNull(): Did not result in expected exception!");
		} catch(java.lang.Throwable t) {
		// It should be one of these, depending on whether or not assertions are enabled.
		assertTrue( isInstanceOf(t, "java.lang.NullPointerException") || isInstanceOf(t, "java.lang.AssertionError"));
		}
		</cfscript>
		</cffunction>

		--->

	<cffunction access="public" returntype="void" name="testNewEncryptDecrypt" output="false" hint="Test of new encrypt / decrypt methods added in ESAPI 2.0.">
		<cfscript>
	    	System.out.println("testNewEncryptDecrypt()");
	    	String = createObject("java", "java.lang.String");

	    	try {
	    	    // Let's try it with a 2-key version of 3DES. This should work for all
	    	    // installations, whereas the 3-key Triple DES will only work for those
	    	    // who have the Unlimited Strength Jurisdiction Policy files installed.
				runNewEncryptDecryptTestCase("DESede/CBC/PKCS5Padding", 112, String.init("1234567890").getBytes("UTF-8"));
				runNewEncryptDecryptTestCase("DESede/CBC/NoPadding", 112, String.init("12345678").getBytes("UTF-8"));

				runNewEncryptDecryptTestCase("DES/ECB/NoPadding", 56, String.init("test1234").getBytes("UTF-8"));

		        runNewEncryptDecryptTestCase("AES/CBC/PKCS5Padding", 128, String.init("Encrypt the world!").getBytes("UTF-8"));

		        // These tests are only valid (and run) if one has the JCE Unlimited
		        // Strength Jurisdiction Policy files installed for this Java VM.
		        // 256-bit AES
	            runNewEncryptDecryptTestCase("AES/ECB/NoPadding", 256, String.init("test1234test1234").getBytes("UTF-8"));
	            // 168-bit (aka, 3-key) Triple DES
	            runNewEncryptDecryptTestCase("DESede/CBC/PKCS5Padding", 168, String.init("Groucho's secret word").getBytes("UTF-8"));
			} catch (UnsupportedEncodingException e) {
				fail("OK, who stole UTF-8 encoding from the Java rt.jar ???");
			}
    	</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="runNewEncryptDecryptTestCase" output="false" hint="Helper method to test new encryption / decryption.">
		<cfargument type="String" name="cipherXform" required="true" hint="Cipher transformation">
		<cfargument type="numeric" name="keySize" required="true" hint="Size of key, in bits.">
		<cfargument type="binary" name="plaintextBytes" required="true" hint="Byte array of plaintext.">
		<cfscript>
	    	System.out.println("New encrypt / decrypt: " & arguments.cipherXform);

	    	if ( arguments.keySize > 128 && !createObject("java", "org.owasp.esapi.crypto.CryptoPolicy").isUnlimitedStrengthCryptoAvailable() ) {
	    	    System.out.println("Skipping test for cipher transformation " & arguments.cipherXform & " with key size of " & arguments.keySize & " bits because this requires JCE Unlimited Strength Jurisdiction Policy files to be installed and they are not.");
	    	    return "";
	    	}

	    	//try {
	    		// Generate an appropriate random secret key
				local.skey = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoHelper").generateSecretKey(arguments.cipherXform, arguments.keySize);
				assertTrue( local.skey.getAlgorithm() == arguments.cipherXform.split("/")[1] );
				local.cipherAlg = arguments.cipherXform.split("/")[1];

				// Adjust key size for DES and DESede specific oddities.
				// NOTE: Key size that encrypt() method is using is 192 bits!!!
	    		//        which is 3 times 64 bits, but DES key size is only 56 bits.
	    		// See 'IMPORTANT NOTE', in JavaEncryptor, near line 376. It's a "feature"!!!
				if ( local.cipherAlg.equals( "DESede" ) ) {
					arguments.keySize = 192;
				} else if ( local.cipherAlg.equals( "DES" ) ) {
					arguments.keySize = 64;
				} // Else... use specified keySize.
				assertTrue( (arguments.keySize / 8) == arrayLen(local.skey.getEncoded()) );
	//			System.out.println("testNewEncryptDecrypt(): Skey length (bits) = " + 8 * skey.getEncoded().length);

				// Change to a possibly different cipher. This is kludgey at best. Am thinking about an
				// alternate way to do this using a new 'CryptoControls' class. Maybe not until release 2.1.
				// Change the cipher transform from whatever it currently is to the specified cipherXform.
		    	local.oldCipherXform = instance.ESAPI.securityConfiguration().setCipherTransformation(arguments.cipherXform);
		    	if ( ! arguments.cipherXform.equals(local.oldCipherXform) ) {
		    		System.out.println('Cipher xform changed from "' & local.oldCipherXform & '" to "' & arguments.cipherXform & '"');
		    	}

		    	// Get an Encryptor instance with the specified, possibly new, cipher transformation.
		    	local.encryptor = instance.ESAPI.encryptor();
		    	local.plaintext = createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, arguments.plaintextBytes);
		    	local.origPlainText = createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init( instance.ESAPI, local.plaintext.toString() ); // Make _copy_ of original for comparison.

		    	// Do the encryption with the new encrypt() method and get back the CipherText.
		    	local.ciphertext = local.encryptor.encrypt(local.skey, local.plaintext);	// The new encrypt() method.
		    	System.out.println("DEBUG: Encrypt(): CipherText object is -- " & local.ciphertext.toString());
		    	assertTrue( !isNull(local.ciphertext) );
	//	    	System.out.println("DEBUG: After encryption: base64-encoded IV+ciphertext: " + local.ciphertext.getEncodedIVCipherText());
	//	    	System.out.println("\t\tOr... " + instance.ESAPI.encoder().decodeFromBase64(local.ciphertext.getEncodedIVCipherText()) );
	//	    	System.out.println("DEBUG: After encryption: base64-encoded raw ciphertext: " + local.ciphertext.getBase64EncodedRawCipherText());
	//	    	System.out.println("\t\tOr... " + instance.ESAPI.encoder().decodeFromBase64(local.ciphertext.getBase64EncodedRawCipherText()) );

		    	// If we are supposed to have overwritten the plaintext, check this to see
		    	// if origPlainText was indeed overwritten.
				local.overwritePlaintext = instance.ESAPI.securityConfiguration().overwritePlainText();
				if ( local.overwritePlaintext ) {
					assertTrue( isPlaintextOverwritten(local.plaintext) );
				}

		    	// Take the resulting ciphertext and decrypt w/ new decryption method.
		    	local.decryptedPlaintext  = local.encryptor.decrypt(local.skey, local.ciphertext);		// The new decrypt() method.

		    	// Make sure we got back the same thing we started with.
		    	System.out.println("\tOriginal plaintext: " & local.origPlainText.toString());
		    	System.out.println("\tResult after decryption: " & local.decryptedPlaintext.toString());
				assertTrue( local.origPlainText.toString() == local.decryptedPlaintext.toString(), "Failed to decrypt properly." );

		    	// Restore the previous cipher transformation. For now, this is only way to do this.
		    	local.previousCipherXform = instance.ESAPI.securityConfiguration().setCipherTransformation("");
		    	assertTrue( local.previousCipherXform.equals( arguments.cipherXform ) );
		    	local.defaultCipherXform = instance.ESAPI.securityConfiguration().getCipherTransformation();
		    	assertTrue( local.defaultCipherXform.equals( local.oldCipherXform ) );

		    	return local.ciphertext.getEncodedIVCipherText();
			/*} catch (java.lang.Exception e) {
				// OK if not counted toward code coverage.
				System.out.println("testNewEncryptDecrypt(): Caught unexpected exception: " & e.getClass().getName());
				e.printStackTrace(System.out);
				fail("Caught unexpected exception; msg was: " & e);
			}*/
			return "";
    	</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="boolean" name="isPlaintextOverwritten" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.crypto.PlainText" name="plaintext" required="true">
		<cfscript>
	    	// Note: An assumption here that the original plaintext did not consist entirely of all '*' characters.
	    	local.ptBytes = arguments.plaintext.asBytes();

	    	for ( local.i = 1; local.i <= len(local.ptBytes); local.i++ ) {
	    		if ( local.ptBytes[local.i] != asc('*') ) {
	    			return false;
	    		}
	    	}
	    	return true;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testSign" output="false" hint="Test of sign method, of class org.owasp.esapi.Encryptor.">
		<cfscript>
	        System.out.println("testSign()");
	        local.encryptor = instance.ESAPI.encryptor();
	        local.plaintext = instance.ESAPI.randomizer().getRandomString( 32, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS );
	        local.signature = local.encryptor.sign(local.plaintext);
	        assertTrue( local.encryptor.verifySignature( local.signature, local.plaintext ) );
	        assertFalse( local.encryptor.verifySignature( local.signature, "ridiculous" ) );
	        assertFalse( local.encryptor.verifySignature( "ridiculous", local.plaintext ) );
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testVerifySignature" output="false" hint="Test of verifySignature method, of class org.owasp.esapi.Encryptor.">
		<cfscript>
		    System.out.println("testVerifySignature()");
	        local.encryptor = instance.ESAPI.encryptor();
	        local.plaintext = instance.ESAPI.randomizer().getRandomString( 32, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS );
	        local.signature = local.encryptor.sign(local.plaintext);
	        assertTrue( local.encryptor.verifySignature( local.signature, local.plaintext ) );
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testSeal" output="false" hint="Test of seal method, of class org.owasp.esapi.Encryptor.">
		<cfscript>
	        System.out.println("testSeal()");
	        local.encryptor = instance.ESAPI.encryptor();
	        local.plaintext = instance.ESAPI.randomizer().getRandomString( 32, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS );
	        local.seal = local.encryptor.seal( local.plaintext, createObject("java", "java.lang.Long").init(local.encryptor.getTimeStamp() + 1000*60).longValue() );
	        local.encryptor.verifySeal( local.seal );

	        local.progressMark = 1;
	        local.caughtExpectedEx = false;
	        try {
	            local.seal = local.encryptor.seal("", createObject("java", "java.lang.Long").init(local.encryptor.getTimeStamp() + 1000*60).longValue());
	            local.progressMark++;
	            local.encryptor.verifySeal(local.seal);
	            local.progressMark++;
	        } catch(java.lang.Exception e) {
	            fail("Failed empty string test: " & e & "; progress mark = " & local.progressMark);
	        }
	        /* NULL test
	        try {
	            local.seal = local.encryptor.seal(null, createObject("java", "java.lang.Long").init(local.encryptor.getTimeStamp() + 1000*60).longValue());
	            fail("Did not throw expected IllegalArgumentException");
	        } catch(java.lang.IllegalArgumentException e) {
	            local.caughtExpectedEx = true;
	        } catch(java.lang.Exception e) {
	            fail("Failed null string test; did not get expected IllegalArgumentException: " & e);
	        }
	        assertTrue(local.caughtExpectedEx);*/

	        try {
	            local.seal = local.encryptor.seal("test", 0);
	            local.progressMark++;
	            // local.encryptor.verifySeal(local.seal);
	            local.progressMark++;
	        } catch(java.lang.Exception e) {
	            fail("Fail test with 0 timestamp: " & e & "; progress mark = " & local.progressMark);
	        }
	        try {
	            local.seal = local.encryptor.seal("test", -1);
	            local.progressMark++;
	            // local.encryptor.verifySeal(local.seal);
	            local.progressMark++;
	        } catch(java.lang.Exception e) {
	            fail("Fail test with -1 timestamp: " & e & "; progress mark = " & local.progressMark);
	        }
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testVerifySeal" output="false" hint="Test of verifySeal method, of class org.owasp.esapi.Encryptor.">
		<cfscript>
	        local.NSEC = 5;
	        System.out.println("testVerifySeal()");
	        local.encryptor = instance.ESAPI.encryptor();
	        local.plaintext = "ridiculous:with:delimiters";    // Should now work w/ : (issue #28)
	        local.seal = local.encryptor.seal( local.plaintext, local.encryptor.getRelativeTimeStamp( 1000 * local.NSEC ) );
	        try {
	        	assertTrue( local.encryptor.verifySeal( local.seal ) );
	        } catch ( Exception e ) {
	        	fail();
	        }
	        local.progressMark = 1;
	        try {
	        	Long = createObject("java", "java.lang.Long");
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
	        	assertFalse( local.encryptor.verifySeal( local.plaintext ) );
	        	local.progressMark++;
	            assertFalse( local.encryptor.verifySeal( local.encryptor.encrypt( plain=createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, local.plaintext) ).getBase64EncodedRawCipherText() ) );
	            local.progressMark++;
	            assertFalse( local.encryptor.verifySeal( local.encryptor.encrypt( plain=createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, 100 & ":" & local.plaintext) ).getBase64EncodedRawCipherText() ) );
	            local.progressMark++;
	            assertFalse( local.encryptor.verifySeal( local.encryptor.encrypt( plain=createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, Long.MAX_VALUE & ":" & local.plaintext) ).getBase64EncodedRawCipherText() ) );
	            local.progressMark++;
	            assertFalse( local.encryptor.verifySeal( local.encryptor.encrypt( plain=createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, Long.MAX_VALUE & ":random:" & local.plaintext) ).getBase64EncodedRawCipherText() ) );
	            local.progressMark++;
	            assertFalse( local.encryptor.verifySeal( local.encryptor.encrypt( plain=createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, Long.MAX_VALUE & ":random:" & local.plaintext & ":badsig")  ).getBase64EncodedRawCipherText() ) );
	            local.progressMark++;
	            assertFalse( local.encryptor.verifySeal( local.encryptor.encrypt( plain=createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, Long.MAX_VALUE & ":random:" & local.plaintext & ":" & local.encryptor.sign( Long.MAX_VALUE & ":random:" & local.plaintext) ) ).getBase64EncodedRawCipherText() ) );
	            local.progressMark++;
	        } catch ( Exception e ) {
	        	// fail("Failed invalid seal test # " + progressMark + " to verify seal.");
	            System.err.println("Failed seal verification at step ## " & local.progressMark);
	            System.err.println("Exception was: " & e);
	            e.printStackTrace(System.err);
	        }

	        try {
	            sleep(1000 * (local.NSEC + 1) );
	            // Seal now past expiration date.
	            assertFalse( local.encryptor.verifySeal( local.seal ) );
	        } catch ( Exception e ) {
	            fail("Failed expired seal test. Seal should be expired.");
	        }
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncryptionSerialization" output="false">
		<cfscript>
	        local.secretMsg = "Secret Message";
	        instance.ESAPI.securityConfiguration().setCipherTransformation("AES/CBC/PKCS5Padding");
	        local.ct = instance.ESAPI.encryptor().encrypt(plain=createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, local.secretMsg));

	        local.serializedCipherText = local.ct.asPortableSerializedByteArray();

	        local.plainText = instance.ESAPI.encryptor().decrypt(ciphertext=createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherText").init(instance.ESAPI).fromPortableSerializedBytes(local.serializedCipherText) );

	        assertTrue( local.secretMsg.equals( local.plainText.toString() ) );
    	</cfscript> 
	</cffunction>


</cfcomponent>
