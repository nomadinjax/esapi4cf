<cfcomponent extends="cfesapi.test.TestCase" output="false">

	<cfscript>
		instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
		instance.dfltAESCipher = "";
		instance.dfltECBCipher = "";	// will be "AES/ECB/NoPadding";
		instance.dfltOtherCipher = "";
		instance.cipherSpec = "";
		instance.myIV = "";
	</cfscript>
 
	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			// This will throw ConfigurationException if IV type is not set to
			// 'fixed', which it's not. (We have it set to 'random'.)
			// myIV = Hex.decode( ESAPI.securityConfiguration().getFixedIV() );
			instance.myIV = createObject("java", "org.owasp.esapi.codecs.Hex").decode( "0x000102030405060708090a0b0c0d0e0f" );

			instance.dfltAESCipher   = createObject("java", "javax.crypto.Cipher").getInstance("AES");
			instance.dfltECBCipher   = createObject("java", "javax.crypto.Cipher").getInstance("AES/ECB/NoPadding");
			instance.dfltOtherCipher = createObject("java", "javax.crypto.Cipher").getInstance("Blowfish/OFB8/PKCS5Padding");

			assertTrue( !isNull(instance.dfltAESCipher) );
			assertTrue( !isNull(instance.dfltECBCipher) );
			assertTrue( !isNull(instance.dfltOtherCipher) );

			instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltOtherCipher);
			assertTrue( !isNull(instance.cipherSpec) );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testCipherSpecStringIntIntByteArray" output="false">
		<cfscript>
			instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipherXform="AES/CBC/NoPadding", keySize=128, blockSize=8, iv=instance.myIV);
			assertTrue( !isNull(instance.cipherSpec) );
			instance.cipherSpec = "";
			local.caughtException = false;
			try {
				// Invalid cipher xform -- empty
				instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipherXform="", keySize=128, blockSize=8, iv=instance.myIV);
			} catch( java.lang.Throwable t ) {
				local.caughtException = true;
			}
			assertTrue( local.caughtException && instance.cipherSpec == "" );
			local.caughtException = false;
			try {
				// Invalid cipher xform -- missing padding scheme
				instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipherXform="AES/CBC", keySize=128, blockSize=8, iv=instance.myIV);
			} catch( java.lang.Throwable t ) {
			    local.caughtException = true;
			}
	        assertTrue( local.caughtException && instance.cipherSpec == "" );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testCipherSpecCipherInt" output="false">
		<cfscript>
	    	instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltOtherCipher, keySize=112);
	    	assertTrue( !isNull(instance.cipherSpec) );
	    	assertTrue( instance.cipherSpec.getCipherAlgorithm() == "Blowfish");
	    	assertTrue( instance.cipherSpec.getCipherMode() == "OFB8");

	    	instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltAESCipher, keySize=256);
	    	assertTrue( !isNull(instance.cipherSpec) );
	    	assertTrue( instance.cipherSpec.getCipherAlgorithm() == "AES");
	    	assertTrue( instance.cipherSpec.getCipherMode() == "ECB" );
	    	assertTrue( instance.cipherSpec.getPaddingScheme() == "NoPadding" );
	    	// System.out.println("testCipherSpecInt(): " & instance.cipherSpec);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testCipherSpecByteArray" output="false">
		<cfscript>
			assertTrue( !isNull(instance.myIV) );
			assertTrue( len(instance.myIV) > 0 );
			instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, iv=instance.myIV);
			assertTrue( instance.cipherSpec.getKeySize() == instance.ESAPI.securityConfiguration().getEncryptionKeyLength() );
			assertTrue( instance.cipherSpec.getCipherTransformation() == instance.ESAPI.securityConfiguration().getCipherTransformation() );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testCipherSpec" output="false">
		<cfscript>
			instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltECBCipher );
			assertTrue( instance.cipherSpec.getCipherTransformation() == "AES/ECB/NoPadding" );
			assertTrue( !len(instance.cipherSpec.getIV()) );

			instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltOtherCipher);
			assertTrue( instance.cipherSpec.getCipherMode() == "OFB8" );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testSetCipherTransformation" output="false">
		<cfscript>
			instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI);
			instance.cipherSpec.setCipherTransformation("AlgName/Mode/Padding");
			instance.cipherSpec.getCipherAlgorithm() == "AlgName/Mode/Padding";

			try {
					// Don't use null here as compiling JUnit tests disables assertion
					// checking so we get a NullPointerException here instead.
				instance.cipherSpec.setCipherTransformation(""); // Throws AssertionError
			} catch (java.lang.AssertionError e) {
				assertTrue(true);	// Doesn't work w/ @Test(expected=AssertionError.class)
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetCipherTransformation" output="false">
		<cfscript>
			assertTrue( createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI).getCipherTransformation() == "AES/CBC/PKCS5Padding" );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testSetKeySize" output="false">
		<cfscript>
			assertTrue( createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI).setKeySize(56).getKeySize() == 56 );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetKeySize" output="false">
		<cfscript>
			assertTrue( createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI).getKeySize() == instance.ESAPI.securityConfiguration().getEncryptionKeyLength() );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testSetBlockSize" output="false">
		<cfscript>
			try {
				instance.cipherSpec.setBlockSize(0); // Throws AssertionError
			} catch (java.lang.AssertionError e) {
				assertTrue(true);	// Doesn't work w/ @Test(expected=AssertionError.class)
			}
			try {
				instance.cipherSpec.setBlockSize(-1); // Throws AssertionError
			} catch (java.lang.AssertionError e) {
				assertTrue(true);	// Doesn't work w/ @Test(expected=AssertionError.class)
			}
			assertTrue( instance.cipherSpec.setBlockSize(4).getBlockSize() == 4 );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetBlockSize" output="false">
		<cfscript>
			assertTrue( instance.cipherSpec.getBlockSize() == 8 );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetCipherAlgorithm" output="false">
		<cfscript>
			assertTrue( instance.cipherSpec.getCipherAlgorithm() == "Blowfish" );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetCipherMode" output="false">
		<cfscript>
			assertTrue( instance.cipherSpec.getCipherMode() == "OFB8" );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetPaddingScheme" output="false">
		<cfscript>
			assertTrue( instance.cipherSpec.getPaddingScheme() == "PKCS5Padding" );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetIV" output="false">
		<cfscript>
			// TODO: testGetIV
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testSetIV" output="false">
		<cfscript>
			try {
				// Test that ECB mode allows a null IV
				instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltECBCipher);
				instance.cipherSpec.setIV(toBinary(""));
				assertTrue(true);
			} catch ( java.lang.AssertionError e) {
				assertFalse(false, "Test failed; unexpected exception");
			}
			try {
				// Test that CBC mode does allows a null IV
				instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltAESCipher);
				instance.cipherSpec.setIV(toBinary(""));
				assertFalse(false, "Test failed; Expected exception not thrown");
			} catch ( java.lang.AssertionError e) {
				assertTrue(true);
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testRequiresIV" output="false">
		<cfscript>
			assertTrue( createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltECBCipher).requiresIV() == false );
			instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltAESCipher);
			assertTrue( instance.cipherSpec.getCipherMode() == "ECB" );
			assertTrue( instance.cipherSpec.requiresIV() == false );
			assertTrue( createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltOtherCipher).requiresIV() );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testToString" output="false">
		<cfscript>
			// TODO: toString
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEquals" output="false">
		<cfscript>
			// TODO: equals
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testHashCode" output="false">
		<cfscript>
			// TODO: hashCode
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testCanEqual" output="false">
		<cfscript>
			// TODO: canEqual
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetFromCipherXform" output="false">
		<cfscript>
			// TODO: testGetFromCipherXform
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testSerialization" output="false">
		<cfscript>
			System = createObject("java", "java.lang.System");
			
	        local.filename = "cipherspec.ser";
	        local.serializedFile = createObject("java", "java.io.File").init(local.filename);
	        local.success = false;
	        try {
	            // Delete any old serialized file. If it fails, it's not
	            // a big deal. If we can't overwrite it later, we'll get
	            // an IOException.
	            //
	            // NOTE: FindBugs complains we are not checking return value here.
	            //       Guess what? We don't care!!!
	            local.serializedFile.delete();


	            instance.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipherXform="AES/CBC/NoPadding", keySize=128, blockSize=8, iv=instance.myIV);
	            local.fos = createObject("java", "java.io.FileOutputStream").init(local.filename);
	            local.out = createObject("java", "java.io.ObjectOutputStream").init(local.fos);
	            local.out.writeObject(instance.cipherSpec);
	            local.out.close();
	            local.fos.close();

	            local.fis = createObject("java", "java.io.FileInputStream").init(local.filename);
	            local.in = createObject("java", "java.io.ObjectInputStream").init(local.fis);
	            local.restoredCipherSpec = local.in.readObject();
	            local.in.close();
	            local.fis.close();

	            // check that cipherSpec and restoredCipherSpec are equal. Just
	            // compare them via their string representations.
	            assertEquals(instance.cipherSpec.toString(), local.restoredCipherSpec.toString(), "Serialized restored CipherSpec differs from saved CipherSpec" );

	            local.success = true;
	        } catch(java.io.IOException ex) {
	            ex.printStackTrace(System.err);
	            fail("testSerialization(): Unexpected IOException: " & ex);
	        } catch(java.lang.ClassNotFoundException ex) {
	            ex.printStackTrace(System.err);
	            fail("testSerialization(): Unexpected ClassNotFoundException: " & ex);
	        } finally {
	            // If test succeeds, remove the file. If it fails, leave it behind
	            // for further analysis.
	            if ( local.success && local.serializedFile.exists() ) {
	                local.deleted = local.serializedFile.delete();
	                if ( !local.deleted ) {
	                    try {
	                        System.err.println("Unable to delete file: " & local.serializedFile.getCanonicalPath() );
	                    } catch (IOException e) {
	                        ; // Ignore
	                    }
	                }
	            }
	        }
		</cfscript> 
	</cffunction>


</cfcomponent>
