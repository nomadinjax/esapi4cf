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
<cfcomponent extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false">

	<cfscript>
	    static.POST_CLEANUP = true;

		instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
		instance.cipherSpec = "";
	    instance.encryptor = "";
	    instance.decryptor = "";
	    instance.ivSpec = "";
	</cfscript>
 
	<cffunction access="private" returntype="binary" name="newByte" outuput="false">
		<cfargument type="numeric" name="len" required="true">
		<cfscript>
			StringBuilder = createObject("java", "java.lang.StringBuilder").init();
			StringBuilder.setLength(arguments.len);
			return StringBuilder.toString().getBytes();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			// These two calls have side-effects that cause FindBugs to complain.
	        createObject("java", "java.io.File").init("ciphertext.ser").delete();
	        createObject("java", "java.io.File").init("ciphertext-portable.ser").delete();

	        instance.encryptor = createObject("java", "javax.crypto.Cipher").getInstance("AES/CBC/PKCS5Padding");
	        instance.decryptor = createObject("java", "javax.crypto.Cipher").getInstance("AES/CBC/PKCS5Padding");
	        local.ivBytes = instance.ESAPI.randomizer().getRandomBytes(instance.encryptor.getBlockSize());
	        instance.ivSpec = createObject("java", "javax.crypto.spec.IvParameterSpec").init(local.ivBytes);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="tearDown" output="false">
		<cfscript>
			if ( static.POST_CLEANUP ) {
	            // These two calls have side-effects that cause FindBugs to complain.
		        createObject("java", "java.io.File").init("ciphertext.ser").delete();
		        createObject("java", "java.io.File").init("ciphertext-portable.ser").delete();
		    }
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testCipherText" output="false">
		<cfscript>
			local.ct = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherText").init(instance.ESAPI);

			instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(instance.ESAPI);
			assertTrue( local.ct.getCipherTransformation() == instance.cipherSpec.getCipherTransformation() );
			assertTrue( local.ct.getBlockSize() == instance.cipherSpec.getBlockSize() );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testCipherTextCipherSpec" output="false">
		<cfscript>
			instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipherXform="DESede/OFB8/NoPadding", keySize=112);
			local.ct = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherText").init(instance.ESAPI, instance.cipherSpec );
			assertTrue( !arrayLen(local.ct.getRawCipherText()) );
			assertTrue( local.ct.getCipherAlgorithm() == "DESede" );
			assertTrue( local.ct.getKeySize() == instance.cipherSpec.getKeySize() );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testCipherTextCipherSpecByteArray" output="false">
		<cfscript>
			Cipher = createObject("java", "javax.crypto.Cipher");
			CryptoHelper = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI);

			try {
				local.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.encryptor, keySize=128);
				local.cipherSpec.setIV(instance.ivSpec.getIV());
				local.key = CryptoHelper.generateSecretKey(local.cipherSpec.getCipherAlgorithm(), 128);
				instance.encryptor.init(Cipher.ENCRYPT_MODE, local.key, instance.ivSpec);
				local.raw = instance.encryptor.doFinal(createObject("java", "java.lang.String").init("Hello").getBytes("UTF8"));
				local.ct = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherText").init(ESAPI=instance.ESAPI, cipherSpec=local.cipherSpec, cipherText=local.raw);
				assertTrue( !isNull(local.ct) );
				local.ctRaw = local.ct.getRawCipherText();
				assertTrue( !isNull(local.ctRaw) );
				//assertArrayEquals(local.raw, local.ctRaw);
				assertEquals(charsetEncode(local.raw, 'utf-8'), charsetEncode(local.ctRaw, 'utf-8'));
				assertTrue( local.ct.getCipherTransformation() == local.cipherSpec.getCipherTransformation() );
				assertTrue( local.ct.getCipherAlgorithm() == local.cipherSpec.getCipherAlgorithm() );
				assertTrue( local.ct.getPaddingScheme() == local.cipherSpec.getPaddingScheme() );
				assertTrue( local.ct.getBlockSize() == local.cipherSpec.getBlockSize() );
				assertTrue( local.ct.getKeySize() == local.cipherSpec.getKeySize() );
				local.ctIV = local.ct.getIV();
				local.csIV = local.cipherSpec.getIV();
				//assertArrayEquals(local.ctIV, local.csIV);
				assertEquals(charsetEncode(local.ctIV, 'utf-8'), charsetEncode(local.csIV, 'utf-8'));
			} catch( java.lang.Exception ex) {
				// As far as test coverage goes, we really don't want this to be covered.
				fail("Caught unexpected exception: " & ex.getClass().getName() & "; exception message was: " & ex.getMessage());
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testDecryptionUsingCipherText" output="false">
		<cfscript>
			System = createObject("java", "java.lang.System");
			Cipher = createObject("java", "javax.crypto.Cipher");
			CryptoHelper = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI);

			try {
				local.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.encryptor, keySize=128);
				local.cipherSpec.setIV(instance.ivSpec.getIV());
				assertTrue( !isNull(local.cipherSpec.getIV()) );
				assertTrue( arrayLen(local.cipherSpec.getIV()) > 0 );
				local.key = CryptoHelper.generateSecretKey(local.cipherSpec.getCipherAlgorithm(), 128);
				instance.encryptor.init(Cipher.ENCRYPT_MODE, local.key, instance.ivSpec);
				local.ctraw = instance.encryptor.doFinal(createObject("java", "java.lang.String").init("Hello").getBytes("UTF8"));
				local.ct = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherText").init(ESAPI=instance.ESAPI, cipherSpec=local.cipherSpec, cipherText=local.ctraw);
				assertTrue( local.ct.getCipherMode() == "CBC" );
				assertTrue( local.ct.requiresIV() ); // CBC mode requires an IV.
				local.b64ctraw = local.ct.getBase64EncodedRawCipherText();
				assertTrue( !isNull(local.b64ctraw));
				//assertArrayEquals( instance.ESAPI.encoder().decodeFromBase64(local.b64ctraw), local.ctraw );
				assertEquals( charsetEncode(instance.ESAPI.encoder().decodeFromBase64(local.b64ctraw), 'utf-8'), charsetEncode(local.ctraw, 'utf-8') );
				instance.decryptor.init(Cipher.DECRYPT_MODE, local.key, createObject("java", "javax.crypto.spec.IvParameterSpec").init(local.ct.getIV()));
				local.ptraw = instance.decryptor.doFinal(instance.ESAPI.encoder().decodeFromBase64(local.b64ctraw));
				assertTrue( !isNull(local.ptraw) );
				assertTrue( arrayLen(local.ptraw) > 0 );
				local.plaintext = createObject("java", "java.lang.String").init( local.ptraw, "UTF-8");
				assertTrue( local.plaintext.equals("Hello") );
				//assertArrayEquals( local.ct.getRawCipherText(), local.ctraw );
				assertEquals( charsetEncode(local.ct.getRawCipherText(), 'utf-8'), charsetEncode(local.ctraw, 'utf-8') );

				local.ivAndRaw = instance.ESAPI.encoder().decodeFromBase64( local.ct.getEncodedIVCipherText() );
				assertTrue( arrayLen(local.ivAndRaw) > arrayLen(local.ctraw) );
				assertTrue( local.ct.getBlockSize() == ( arrayLen(local.ivAndRaw) - arrayLen(local.ctraw) ) );
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
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testMIC" output="false">
		<cfscript>
			Cipher = createObject("java", "javax.crypto.Cipher");
			CryptoHelper = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI);

			try {
				local.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.encryptor, keySize=128);
				local.cipherSpec.setIV(instance.ivSpec.getIV());
				local.key = CryptoHelper.generateSecretKey(local.cipherSpec.getCipherAlgorithm(), 128);
				instance.encryptor.init(Cipher.ENCRYPT_MODE, local.key, instance.ivSpec);
				local.ctraw = instance.encryptor.doFinal(createObject("java", "java.lang.String").init("Hello").getBytes("UTF8"));
				local.ct = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherText").init(ESAPI=instance.ESAPI, cipherSpec=local.cipherSpec, cipherText=local.ctraw);
				assertTrue( !isNull(local.ct.getIV()) && arrayLen(local.ct.getIV()) > 0 );
				local.authKey = CryptoHelper.computeDerivedKey(local.key, arrayLen(local.key.getEncoded()) * 8, "authenticity");
				local.ct.computeAndStoreMAC( local.authKey );
				try {
					local.ct.setIVandCiphertext(instance.ivSpec.getIV(), local.ctraw);	// Expected to log & throw.
				} catch( cfesapi.org.owasp.esapi.errors.EncryptionException ex ) {
					assertTrue( len(ex.message) );
				}
				try {
					local.ct.setCiphertext(local.ctraw);	// Expected to log and throw message about
												// not being able to store raw ciphertext.
				} catch( cfesapi.org.owasp.esapi.errors.EncryptionException ex ) {
					assertTrue( len(ex.message) );
				}
				instance.decryptor.init(Cipher.DECRYPT_MODE, local.key, createObject("java", "javax.crypto.spec.IvParameterSpec").init( local.ct.getIV() ) );
				local.ptraw = instance.decryptor.doFinal( local.ct.getRawCipherText() );
				assertTrue( !isNull(local.ptraw) && arrayLen(local.ptraw) > 0 );
				local.ct.validateMAC( local.authKey );
			} catch( Exception ex) {
				// As far as test coverage goes, we really don't want this to be covered.
				ex.printStackTrace(System.err);
				fail("Caught unexpected exception: " & ex.getClass().getName() & "; exception message was: " & ex.getMessage());
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testPortableSerialization" output="false">
		<cfscript>
			Cipher = createObject("java", "javax.crypto.Cipher");
			CryptoHelper = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI);

		    System.err.println("CipherTextTest.testPortableSerialization()...");
		    local.filename = "ciphertext-portable.ser";
		    local.serializedFile = createObject("java", "java.io.File").init(local.filename);
		    local.serializedFile.delete();    // Delete any old serialized file.

		    local.keySize = 128;
		    if ( createObject("component", "cfesapi.test.org.owasp.esapi.reference.crypto.CryptoPolicy").isUnlimitedStrengthCryptoAvailable() ) {
		        local.keySize = 256;
		    }
		    local.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.encryptor, keySize=local.keySize);
		    local.cipherSpec.setIV(instance.ivSpec.getIV());
		    try {
		        local.key = CryptoHelper.generateSecretKey(local.cipherSpec.getCipherAlgorithm(), local.keySize);

		        instance.encryptor.init(Cipher.ENCRYPT_MODE, local.key, instance.ivSpec);
		        local.raw = instance.encryptor.doFinal(createObject("java", "java.lang.String").init("This is my secret message!!!").getBytes("UTF8"));
		        local.ciphertext = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherText").init(ESAPI=instance.ESAPI, cipherSpec=local.cipherSpec, cipherText=local.raw);
		        local.authKey = CryptoHelper.computeDerivedKey(local.key, arrayLen(local.key.getEncoded()) * 8, "authenticity");
		        local.ciphertext.computeAndStoreMAC( local.authKey );
	//          System.err.println("Original ciphertext being serialized: " & ciphertext);
		        local.serializedBytes = local.ciphertext.asPortableSerializedByteArray();

		        local.fos = createObject("java", "java.io.FileOutputStream").init(local.serializedFile);
	            local.fos.write(local.serializedBytes);
                // Note: FindBugs complains that this test may fail to close the fos output stream. We don't really care.
	            local.fos.close();

	            // NOTE: FindBugs complains about this (OS_OPEN_STREAM). It apparently
	            //       is too lame to know that 'fis.read()' is a serious side-effect.
	            local.fis = createObject("java", "java.io.FileInputStream").init(local.serializedFile);
	            local.avail = local.fis.available();
	            local.bytes = newByte(local.avail);
	            local.fis.read(local.bytes, 0, local.avail);

	            // Sleep one second to prove that the timestamp on the original
	            // CipherText object is the one that we use and not just the
	            // current time. Only after that, do we restore the serialized bytes.
	            try {
	                sleep(1000);
	            } catch (InterruptedException e) {
	                ;    // Ignore
	            }
	            local.restoredCipherText = CipherText.fromPortableSerializedBytes(local.bytes);
	//          System.err.println("Restored ciphertext: " & restoredCipherText);
	            assertTrue( local.ciphertext.equals(local.restoredCipherText));
		    } catch (EncryptionException e) {
		        fail("Caught EncryptionException: " & e);
	        } catch (FileNotFoundException e) {
	            fail("Caught FileNotFoundException: " & e);
	        } catch (IOException e) {
	            fail("Caught IOException: " & e);
	        } catch (Exception e) {
	            fail("Caught Exception: " & e);
	        } finally {
	            // FindBugs complains that we are ignoring this return value. We really don't care.
	            local.serializedFile.delete();
	        }
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testJavaSerialization" output="false">
		<cfscript>
			Cipher = createObject("java", "javax.crypto.Cipher");
			CryptoHelper = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI);

	        local.filename = "ciphertext.ser";
	        local.serializedFile = createObject("java", "java.io.File").init(local.filename);
	        try {
	            local.serializedFile.delete();	// Delete any old serialized file.

	            local.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.encryptor, keySize=128);
				local.cipherSpec.setIV(instance.ivSpec.getIV());
				local.key = CryptoHelper.generateSecretKey(local.cipherSpec.getCipherAlgorithm(), 128);
				instance.encryptor.init(Cipher.ENCRYPT_MODE, local.key, instance.ivSpec);
				local.raw = instance.encryptor.doFinal(createObject("java", "java.lang.String").init("This is my secret message!!!").getBytes("UTF8"));
				local.ciphertext = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherText").init(ESAPI=instance.ESAPI, cipherSpec=local.cipherSpec, cipherText=local.raw);

	            local.fos = createObject("java", "java.io.FileOutputStream").init(local.filename);
	            local.out = createObject("java", "java.io.ObjectOutputStream").init(local.fos);
	            local.out.writeObject(local.ciphertext);
	            local.out.close();
	            local.fos.close();

	            local.fis = createObject("java", "java.io.FileInputStream").init(local.filename);
	            local.in = createObject("java", "java.io.ObjectInputStream").init(local.fis);
	            local.restoredCipherText = local.in.readObject();
	            local.in.close();
	            local.fis.close();

	            // check that ciphertext and restoredCipherText are equal. Requires
	            // multiple checks. (Hmmm... maybe overriding equals() and hashCode()
	            // is in order???)
	            assertEquals(local.ciphertext.toString(), local.restoredCipherText.toString(), "1: Serialized restored CipherText differs from saved CipherText");
	            assertEquals(charsetEncode(local.ciphertext.getIV(), 'utf-8'), charsetEncode(local.restoredCipherText.getIV(), 'utf-8'), "2: Serialized restored CipherText differs from saved CipherText");
	            assertEquals(local.ciphertext.getBase64EncodedRawCipherText(), local.restoredCipherText.getBase64EncodedRawCipherText(), "3: Serialized restored CipherText differs from saved CipherText");

	        } catch(java.io.IOException ex) {
	            // RAILO error: ex.printStackTrace(System.err);
	            fail("testJavaSerialization(): Unexpected IOException: " & ex);
	        } catch(java.lang.ClassNotFoundException ex) {
	            // RAILO error: ex.printStackTrace(System.err);
	            fail("testJavaSerialization(): Unexpected ClassNotFoundException: " & ex);
	        } catch (org.owasp.esapi.errors.EncryptionException ex) {
				// RAILO error: ex.printStackTrace(System.err);
				fail("testJavaSerialization(): Unexpected EncryptionException: " & ex);
			} catch (javax.crypto.IllegalBlockSizeException ex) {
				// RAILO error: ex.printStackTrace(System.err);
				fail("testJavaSerialization(): Unexpected IllegalBlockSizeException: " & ex);
			} catch (javax.crypto.BadPaddingException ex) {
				// RAILO error: ex.printStackTrace(System.err);
				fail("testJavaSerialization(): Unexpected BadPaddingException: " & ex);
			} catch (java.security.InvalidKeyException ex) {
				// RAILO error: ex.printStackTrace(System.err);
				fail("testJavaSerialization(): Unexpected InvalidKeyException: " & ex);
			} catch (java.security.InvalidAlgorithmParameterException ex) {
				// RAILO error: ex.printStackTrace(System.err);
				fail("testJavaSerialization(): Unexpected InvalidAlgorithmParameterException: " & ex);
			}  finally {
			    // FindBugs complains that we are ignoring this return value. We really don't care.
	            local.serializedFile.delete();
	        }
		</cfscript> 
	</cffunction>


</cfcomponent>
