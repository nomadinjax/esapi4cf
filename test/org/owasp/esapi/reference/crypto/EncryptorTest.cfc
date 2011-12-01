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
<cfcomponent displayname="EncryptorTest" extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false" hint="The Class EncryptorTest.">

	<cfscript>
		instance.ESAPI = newComponent("cfesapi.org.owasp.esapi.ESAPI").init();
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			// This is only mechanism to change this for now. Will do this with
			// a soon to be CryptoControls class in next release.
			instance.ESAPI.securityConfiguration().setCipherTransformation("AES/CBC/PKCS5Padding");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="tearDown" output="false">

		<cfscript>
			// none
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testHash" output="false"
	            hint="Test of hash method, of class org.owasp.esapi.Encryptor.">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("testHash()");
			local.encryptor = instance.ESAPI.encryptor();
			local.hash1 = local.encryptor.hashESAPI("test1", "salt");
			local.hash2 = local.encryptor.hashESAPI("test2", "salt");
			assertFalse(local.hash1.equals(local.hash2));
			local.hash3 = local.encryptor.hashESAPI("test", "salt1");
			local.hash4 = local.encryptor.hashESAPI("test", "salt2");
			assertFalse(local.hash3.equals(local.hash4));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncrypt" output="false"
	            hint="Test of deprecated encrypt method for Strings.">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("testEncrypt()");
			local.encryptor = instance.ESAPI.encryptor();
			local.plaintext = "test123456";// Not multiple of block cipher size
			local.ciphertext = local.encryptor.encryptESAPI(plain=local.plaintext);
			local.result = local.encryptor.decryptESAPI(ciphertext=local.ciphertext);
			assertEquals(local.plaintext, local.result);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testDecrypt" output="false"
	            hint="Test of deprecated decrypt method for Strings.">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("testDecrypt()");
			local.encryptor = instance.ESAPI.encryptor();
			try {
				local.plaintext = "test123";
				local.ciphertext = local.encryptor.encryptESAPI(plain=local.plaintext);
				assertFalse(local.plaintext.equals(local.ciphertext));
				local.result = local.encryptor.decryptESAPI(ciphertext=local.ciphertext);
				assertEquals(local.plaintext, local.result);
			}
			catch(cfesapi.org.owasp.esapi.errors.EncryptionException e) {
				fail();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncryptEmptyStrings" output="false"
	            hint="Test of encrypt methods for empty String.">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("testEncryptEmptyStrings()");
			local.encryptor = instance.ESAPI.encryptor();
			local.plaintext = "";
			try {
				// newJava("java.lang.System").out.println("Deprecated encryption methods");
				local.ciphertext = local.encryptor.encryptESAPI(plain=local.plaintext);
				local.result = local.encryptor.decryptESAPI(ciphertext=local.ciphertext);
				assertTrue(local.result == "");

				// newJava("java.lang.System").out.println("New encryption methods");
				local.plain = newComponent("cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, local.plaintext);
				local.ct = local.encryptor.encryptESAPI(plain=local.plain);
				local.pt = local.encryptor.decryptESAPI(ciphertext=local.ct);
				assertTrue(local.pt.toStringESAPI() == "");
			}
			catch(java.lang.Exception e) {
				fail("testEncryptEmptyStrings() -- Caught exception: " & e);
			}
		</cfscript>

	</cffunction>

	<!--- NULL test not valid in CF
	<cffunction access="public" returntype="void" name="testEncryptNull" output="false"
	            hint="Test encryption / decryption methods for null.">

	    <cfscript>
	        newJava("java.lang.System").out.println("testEncryptNull()");
	        local.encryptor = instance.ESAPI.encryptor();
	        local.plaintext = "";
	        try {
	            local.nullStr = null;
	            local.encryptor.encryptESAPI(local.nullStr);
	            fail("testEncryptNull(): Did not result in expected exception!");
	        }
	        catch(java.lang.Throwable t) {
	            // It should be one of these, depending on whether or not assertions are enabled.
	            assertTrue(isInstanceOf(t, "java.lang.NullPointerException") || isInstanceOf(t, "java.lang.AssertionError"));
	        }
	    </cfscript>

	</cffunction> --->

	<cffunction access="public" returntype="void" name="testNewEncryptDecrypt" output="false"
	            hint="Test of new encrypt / decrypt methods added in ESAPI 2.0.">

		<cfscript>
			newJava("java.lang.System").out.println("testNewEncryptDecrypt()");

			try {
				// Let's try it with a 2-key version of 3DES. This should work for all
				// installations, whereas the 3-key Triple DES will only work for those
				// who have the Unlimited Strength Jurisdiction Policy files installed.
				runNewEncryptDecryptTestCase("DESede/CBC/PKCS5Padding", 112, newJava("java.lang.String").init("1234567890").getBytes("UTF-8"));
				runNewEncryptDecryptTestCase("DESede/CBC/NoPadding", 112, newJava("java.lang.String").init("12345678").getBytes("UTF-8"));

				runNewEncryptDecryptTestCase("DES/ECB/NoPadding", 56, newJava("java.lang.String").init("test1234").getBytes("UTF-8"));

				runNewEncryptDecryptTestCase("AES/CBC/PKCS5Padding", 128, newJava("java.lang.String").init("Encrypt the world!").getBytes("UTF-8"));

				// These tests are only valid (and run) if one has the JCE Unlimited
				// Strength Jurisdiction Policy files installed for this Java VM.
				// 256-bit AES
				runNewEncryptDecryptTestCase("AES/ECB/NoPadding", 256, newJava("java.lang.String").init("test1234test1234").getBytes("UTF-8"));
				// 168-bit (aka, 3-key) Triple DES
				runNewEncryptDecryptTestCase("DESede/CBC/PKCS5Padding", 168, newJava("java.lang.String").init("Groucho's secret word").getBytes("UTF-8"));
			}
			catch(java.io.UnsupportedEncodingException e) {
				fail("OK, who stole UTF-8 encoding from the Java rt.jar ???");
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="runNewEncryptDecryptTestCase" output="false"
	            hint="Helper method to test new encryption / decryption.">
		<cfargument required="true" type="String" name="cipherXform" hint="Cipher transformation"/>
		<cfargument required="true" type="numeric" name="keySize" hint="Size of key, in bits."/>
		<cfargument required="true" type="binary" name="plaintextBytes" hint="Byte array of plaintext."/>

		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("New encrypt / decrypt: " & arguments.cipherXform);

			if(arguments.keySize > 128 && !newJava("org.owasp.esapi.crypto.CryptoPolicy").isUnlimitedStrengthCryptoAvailable()) {
				newJava("java.lang.System").out.println("Skipping test for cipher transformation " & arguments.cipherXform & " with key size of " & arguments.keySize & " bits because this requires JCE Unlimited Strength Jurisdiction Policy files to be installed and they are not.");
				return "";
			}

			try {
				// Generate an appropriate random secret key
				local.skey = newComponent("cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI).generateSecretKeyESAPI(arguments.cipherXform, arguments.keySize);
				local.cipherXformArray = arguments.cipherXform.split("/");
				assertTrue(local.skey.getAlgorithm() == local.cipherXformArray[1]);
				local.cipherAlg = local.cipherXformArray[1];

				// Adjust key size for DES and DESede specific oddities.
				// NOTE: Key size that encrypt() method is using is 192 bits!!!
				//which is 3 times 64 bits, but DES key size is only 56 bits.
				// See 'IMPORTANT NOTE', in JavaEncryptor, near line 376. It's a "feature"!!!
				if(local.cipherAlg.equals("DESede")) {
					arguments.keySize = 192;
				}
				if(local.cipherAlg.equals("DES")) {
					arguments.keySize = 64;
				}// Else... use specified keySize.
				else
					assertTrue((arguments.keySize / 8) == arrayLen(local.skey.getEncoded()));
				//newJava("java.lang.System").out.println("testNewEncryptDecrypt(): Skey length (bits) = " + 8 * skey.getEncoded().length);
				// Change to a possibly different cipher. This is kludgey at best. Am thinking about an
				// alternate way to do this using a new 'CryptoControls' class. Maybe not until release 2.1.
				// Change the cipher transform from whatever it currently is to the specified cipherXform.
				local.oldCipherXform = instance.ESAPI.securityConfiguration().setCipherTransformation(arguments.cipherXform);
				if(!arguments.cipherXform.equals(local.oldCipherXform)) {
					newJava("java.lang.System").out.println('Cipher xform changed from "' & local.oldCipherXform & '" to "' & arguments.cipherXform & '"');
				}

				// Get an Encryptor instance with the specified, possibly new, cipher transformation.
				local.encryptor = instance.ESAPI.encryptor();
				local.plaintext = newComponent("cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, arguments.plaintextBytes);
				local.origPlainText = newComponent("cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, local.plaintext.toStringESAPI());// Make _copy_ of original for comparison.
				// Do the encryption with the new encrypt() method and get back the CipherText.
				local.ciphertext = local.encryptor.encryptESAPI(local.skey, local.plaintext);// The new encrypt() method.
				newJava("java.lang.System").out.println("DEBUG: Encrypt(): CipherText object is -- " & local.ciphertext.toStringESAPI());
				assertTrue(structKeyExists(local, "ciphertext"));
				//newJava("java.lang.System").out.println("DEBUG: After encryption: base64-encoded IV+ciphertext: " + local.ciphertext.getEncodedIVCipherText());
				//newJava("java.lang.System").out.println("\t\tOr... " + instance.ESAPI.encoder().decodeFromBase64(local.ciphertext.getEncodedIVCipherText()) );
				//newJava("java.lang.System").out.println("DEBUG: After encryption: base64-encoded raw ciphertext: " + local.ciphertext.getBase64EncodedRawCipherText());
				//newJava("java.lang.System").out.println("\t\tOr... " + instance.ESAPI.encoder().decodeFromBase64(local.ciphertext.getBase64EncodedRawCipherText()) );
				// If we are supposed to have overwritten the plaintext, check this to see
				// if origPlainText was indeed overwritten.
				local.overwritePlaintext = instance.ESAPI.securityConfiguration().overwritePlainText();
				if(local.overwritePlaintext) {
					assertTrue(isPlaintextOverwritten(local.plaintext));
				}

				// Take the resulting ciphertext and decrypt w/ new decryption method.
				local.decryptedPlaintext = local.encryptor.decryptESAPI(local.skey, local.ciphertext);// The new decrypt() method.
				// Make sure we got back the same thing we started with.
				newJava("java.lang.System").out.println("\tOriginal plaintext: " & local.origPlainText.toString());
				newJava("java.lang.System").out.println("\tResult after decryption: " & local.decryptedPlaintext.toString());
				assertTrue(local.origPlainText.toString() == local.decryptedPlaintext.toString(), "Failed to decrypt properly.");

				// Restore the previous cipher transformation. For now, this is only way to do this.
				local.previousCipherXform = instance.ESAPI.securityConfiguration().setCipherTransformation("");
				assertTrue(local.previousCipherXform.equals(arguments.cipherXform));
				local.defaultCipherXform = instance.ESAPI.securityConfiguration().getCipherTransformation();
				assertTrue(local.defaultCipherXform.equals(local.oldCipherXform));

				return local.ciphertext.getEncodedIVCipherText();
			}
			catch(Exception e) {
				// OK if not counted toward code coverage.
				newJava("java.lang.System").out.println("testNewEncryptDecrypt(): Caught unexpected exception: " & e.getClass().getName());
				e.printStackTrace(newJava("java.lang.System").out);
				fail("Caught unexpected exception; msg was: " & e);
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="isPlaintextOverwritten" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.crypto.PlainText" name="plaintext"/>

		<cfset var local = {}/>

		<cfscript>
			// Note: An assumption here that the original plaintext did not consist
			// entirely of all '*' characters.
			local.ptBytes = arguments.plaintext.asBytes();

			for(local.i = 1; local.i <= arrayLen(local.ptBytes); local.i++) {
				if(local.ptBytes[local.i] != asc("*")) {
					return false;
				}
			}
			return true;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSign" output="false"
	            hint="Test of sign method, of class org.owasp.esapi.Encryptor.">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("testSign()");
			local.encryptor = instance.ESAPI.encryptor();
			local.plaintext = instance.ESAPI.randomizer().getRandomString(32, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			local.signature = local.encryptor.sign(local.plaintext);
			assertTrue(local.encryptor.verifySignature(local.signature, local.plaintext));
			assertFalse(local.encryptor.verifySignature(local.signature, "ridiculous"));
			assertFalse(local.encryptor.verifySignature("ridiculous", local.plaintext));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testVerifySignature" output="false"
	            hint="Test of verifySignature method, of class org.owasp.esapi.Encryptor.">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("testVerifySignature()");
			local.encryptor = instance.ESAPI.encryptor();
			local.plaintext = instance.ESAPI.randomizer().getRandomString(32, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			local.signature = local.encryptor.sign(local.plaintext);
			assertTrue(local.encryptor.verifySignature(local.signature, local.plaintext));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSeal" output="false"
	            hint="Test of seal method, of class org.owasp.esapi.Encryptor.">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("testSeal()");
			local.encryptor = instance.ESAPI.encryptor();
			local.plaintext = instance.ESAPI.randomizer().getRandomString(32, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			local.seal = local.encryptor.seal(local.plaintext, javaCast("long", local.encryptor.getTimeStamp() + 1000 * 60));
			local.encryptor.verifySeal(local.seal);

			local.progressMark = 1;
			local.caughtExpectedEx = false;
			try {
				local.seal = local.encryptor.seal("", javaCast("long", local.encryptor.getTimeStamp() + 1000 * 60));
				local.progressMark++;
				local.encryptor.verifySeal(local.seal);
				local.progressMark++;
			}
			catch(java.lang.Exception e) {
				fail("Failed empty string test: " & e & "; progress mark = " & local.progressMark);
			}

			/* NULL test not valid in CF
			try {
			    local.seal = local.encryptor.seal(null, javaCast("long", local.encryptor.getTimeStamp() + 1000 * 60));
			    fail("Did not throw expected IllegalArgumentException");
			}
			catch(java.lang.IllegalArgumentException e) {
			    local.caughtExpectedEx = true;
			}
			catch(java.lang.Exception e) {
			    fail("Failed null string test; did not get expected IllegalArgumentException: " & e);
			}
			assertTrue(local.caughtExpectedEx);*/
			try {
				local.seal = local.encryptor.seal("test", 0);
				local.progressMark++;
				// local.encryptor.verifySeal(local.seal);
				local.progressMark++;
			}
			catch(java.lang.Exception e) {
				fail("Fail test with 0 timestamp: " & e & "; progress mark = " & local.progressMark);
			}
			try {
				local.seal = local.encryptor.seal("test", -1);
				local.progressMark++;
				// local.encryptor.verifySeal(local.seal);
				local.progressMark++;
			}
			catch(java.lang.Exception e) {
				fail("Fail test with -1 timestamp: " & e & "; progress mark = " & local.progressMark);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testVerifySeal" output="false"
	            hint="Test of verifySeal method, of class org.owasp.esapi.Encryptor.">
		<cfset var local = {}/>

		<cfscript>
			local.NSEC = 5;
			newJava("java.lang.System").out.println("testVerifySeal()");
			local.encryptor = instance.ESAPI.encryptor();
			local.plaintext = "ridiculous:with:delimiters";// Should now work w/ : (issue #28)
			local.seal = local.encryptor.seal(local.plaintext, local.encryptor.getRelativeTimeStamp(1000 * local.NSEC));
			try {
				assertTrue(local.encryptor.verifySeal(local.seal));
			}
			catch(java.lang.Exception e) {
				fail();
			}
			local.progressMark = 1;
			try {
				// NOTE: I regrouped these all into a single try / catch since they
				//       all test the same thing. Hence if one fails, they all should.
				//       Also changed these tests so they no longer depend on the
				//       deprecated encrypt() methods. IMO, *all these multiple
				//       similar tests are not really required*, as they all are more
				//       or less testing the same thing.
				//      -kevin wall
				// ================================================================
				// Try to validate some invalid seals.
				//
				// All these should return false and log a warning with an Exception stack
				// trace caused by an EncryptionException indicating "Invalid seal".
				assertFalse(local.encryptor.verifySeal(local.plaintext));
				local.progressMark++;
				local.plain = newComponent("cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, local.plaintext);
				assertFalse(local.encryptor.verifySeal(local.encryptor.encryptESAPI(plain=local.plain).getBase64EncodedRawCipherText()));
				local.progressMark++;
				local.plain = newComponent("cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, 100 & ":" & local.plaintext);
				assertFalse(local.encryptor.verifySeal(local.encryptor.encryptESAPI(plain=local.plain).getBase64EncodedRawCipherText()));
				local.progressMark++;
				local.plain = newComponent("cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, newJava("java.lang.Long").MAX_VALUE & ":" & local.plaintext);
				assertFalse(local.encryptor.verifySeal(local.encryptor.encryptESAPI(plain=local.plain).getBase64EncodedRawCipherText()));
				local.progressMark++;
				local.plain = newComponent("cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, newJava("java.lang.Long").MAX_VALUE & ":random:" & local.plaintext);
				assertFalse(local.encryptor.verifySeal(local.encryptor.encryptESAPI(plain=local.plain).getBase64EncodedRawCipherText()));
				local.progressMark++;
				local.plain = newComponent("cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, newJava("java.lang.Long").MAX_VALUE & ":random:" & local.plaintext & ":badsig");
				assertFalse(local.encryptor.verifySeal(local.encryptor.encryptESAPI(plain=local.plain).getBase64EncodedRawCipherText()));
				local.progressMark++;
				local.plain = newComponent("cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, newJava("java.lang.Long").MAX_VALUE & ":random:" & local.plaintext & ":" & local.encryptor.sign(newJava("java.lang.Long").MAX_VALUE & ":random:" & local.plaintext));
				assertFalse(local.encryptor.verifySeal(local.encryptor.encryptESAPI(plain=local.plain).getBase64EncodedRawCipherText()));
				local.progressMark++;
			}
			catch(java.lang.Exception e) {
				// fail("Failed invalid seal test # " + progressMark + " to verify seal.");
				newJava("java.lang.System").err.println("Failed seal verification at step ## " & local.progressMark);
				newJava("java.lang.System").err.println("Exception was: " & e);
				e.printStackTrace(newJava("java.lang.System").err);
			}

			try {
				sleep(1000 * (local.NSEC + 1));
				// Seal now past expiration date.
				assertFalse(local.encryptor.verifySeal(local.seal));
			}
			catch(java.lang.Exception e) {
				fail("Failed expired seal test. Seal should be expired.");
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncryptionSerialization" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.secretMsg = "Secret Message";
			instance.ESAPI.securityConfiguration().setCipherTransformation("AES/CBC/PKCS5Padding");
			local.plain = newComponent("cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, local.secretMsg);
			local.ct = instance.ESAPI.encryptor().encryptESAPI(plain=local.plain);

			local.serializedCipherText = local.ct.asPortableSerializedByteArray();

			local.plainText = instance.ESAPI.encryptor().decryptESAPI(ciphertext=newComponent("cfesapi.org.owasp.esapi.crypto.CipherText").init(instance.ESAPI).fromPortableSerializedBytes(local.serializedCipherText));

			assertTrue(local.secretMsg.equals(local.plainText.toStringESAPI()));
		</cfscript>

	</cffunction>

</cfcomponent>