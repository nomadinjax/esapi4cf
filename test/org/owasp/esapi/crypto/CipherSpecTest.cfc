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
<cfcomponent displayname="CipherSpecTest" extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false" hint="JUnit test to test CipherSpec class.">

	<cfscript>
		instance.ESAPI = newComponent("cfesapi.org.owasp.esapi.ESAPI").init();

		instance.dfltAESCipher = "";
		instance.dfltECBCipher = "";// will be "AES/ECB/NoPadding";
		instance.dfltOtherCipher = "";
		instance.cipherSpec = "";
		instance.myIV = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			// This will throw ConfigurationException if IV type is not set to
			// 'fixed', which it's not. (We have it set to 'random'.)
			// myIV = Hex.decode( ESAPI.securityConfiguration().getFixedIV() );
			instance.myIV = newJava("org.owasp.esapi.codecs.Hex").decode("0x000102030405060708090a0b0c0d0e0f");

			instance.dfltAESCipher = newJava("javax.crypto.Cipher").getInstance("AES");
			instance.dfltECBCipher = newJava("javax.crypto.Cipher").getInstance("AES/ECB/NoPadding");
			instance.dfltOtherCipher = newJava("javax.crypto.Cipher").getInstance("Blowfish/OFB8/PKCS5Padding");

			assertTrue(structKeyExists(instance, "dfltAESCipher"));
			assertTrue(structKeyExists(instance, "dfltECBCipher"));
			assertTrue(structKeyExists(instance, "dfltOtherCipher"));

			instance.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltOtherCipher);
			assertTrue(structKeyExists(instance, "cipherSpec"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="tearDown" output="false">

		<cfscript>
			// none
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testCipherSpecStringIntIntByteArray" output="false"
	            hint="Test CipherSpec(String cipherXform, int keySize, int blockSize, final byte[] iv)">
		<cfset var local = {}/>

		<cfscript>
			instance.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipherXform="AES/CBC/NoPadding", keySize=128, blockSize=8, iv=instance.myIV);
			assertTrue(structKeyExists(instance, "cipherSpec"));
			instance.cipherSpec = "";
			local.caughtException = false;
			try {
				// Invalid cipher xform -- empty
				instance.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipherXform="", keySize=128, blockSize=8, iv=instance.myIV);
			}
			catch(java.lang.IllegalArgumentException t) {
				local.caughtException = true;
			}
			assertTrue(local.caughtException && instance.cipherSpec == "");
			local.caughtException = false;
			try {
				// Invalid cipher xform -- missing padding scheme
				instance.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipherXform="AES/CBC", keySize=128, blockSize=8, iv=instance.myIV);
			}
			catch(java.lang.AssertionError t) {
				local.caughtException = true;
			}
			assertTrue(local.caughtException && instance.cipherSpec == "");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testCipherSpecCipherInt" output="false"
	            hint="CipherSpec(final Cipher cipher, int keySize)">

		<cfscript>
			instance.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltOtherCipher, keySize=112);
			assertTrue(structKeyExists(instance, "cipherSpec"));
			assertTrue(instance.cipherSpec.getCipherAlgorithm() == "Blowfish");
			assertTrue(instance.cipherSpec.getCipherMode() == "OFB8");

			instance.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltAESCipher, keySize=256);
			assertTrue(structKeyExists(instance, "cipherSpec"));
			assertTrue(instance.cipherSpec.getCipherAlgorithm() == "AES");
			assertTrue(instance.cipherSpec.getCipherMode() == "ECB");
			assertTrue(instance.cipherSpec.getPaddingScheme() == "NoPadding");
			// newJava("java.lang.System").out.println("testCipherSpecInt(): " & instance.cipherSpec);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testCipherSpecByteArray" output="false"
	            hint="Test CipherSpec(final byte[] iv)">

		<cfscript>
			assertTrue(structKeyExists(instance, "myIV"));
			assertTrue(len(instance.myIV) > 0);
			instance.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, iv=instance.myIV);
			assertTrue(instance.cipherSpec.getKeySize() == instance.ESAPI.securityConfiguration().getEncryptionKeyLength());
			assertTrue(instance.cipherSpec.getCipherTransformation() == instance.ESAPI.securityConfiguration().getCipherTransformation());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testCipherSpec" output="false"
	            hint="Test CipherSpec()">

		<cfscript>
			instance.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltECBCipher);
			assertTrue(instance.cipherSpec.getCipherTransformation() == "AES/ECB/NoPadding");
			assertTrue(!arrayLen(instance.cipherSpec.getIV()));

			instance.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltOtherCipher);
			assertTrue(instance.cipherSpec.getCipherMode() == "OFB8");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSetCipherTransformation" output="false"
	            hint="Test setCipherTransformation(String cipherXform)">

		<cfscript>
			instance.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI);
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
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetCipherTransformation" output="false"
	            hint="Test getCipherTransformation()">

		<cfscript>
			assertTrue(newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI).getCipherTransformation() == "AES/CBC/PKCS5Padding");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSetKeySize" output="false"
	            hint="Test setKeySize()">

		<cfscript>
			assertTrue(newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI).setKeySize(56).getKeySize() == 56);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetKeySize" output="false"
	            hint="Test getKeySize()">

		<cfscript>
			assertTrue(newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI).getKeySize() == instance.ESAPI.securityConfiguration().getEncryptionKeyLength());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSetBlockSize" output="false"
	            hint="Test setBlockSize()">

		<cfscript>
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
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetBlockSize" output="false"
	            hint="Test getBlockSize()">

		<cfscript>
			assertTrue(instance.cipherSpec.getBlockSize() == 8);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetCipherAlgorithm" output="false"
	            hint="Test getCipherAlgorithm()">

		<cfscript>
			assertTrue(instance.cipherSpec.getCipherAlgorithm() == "Blowfish");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetCipherMode" output="false"
	            hint="Test getCipherMode">

		<cfscript>
			assertTrue(instance.cipherSpec.getCipherMode() == "OFB8");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetPaddingScheme" output="false"
	            hint="Test getPaddingScheme()">

		<cfscript>
			assertTrue(instance.cipherSpec.getPaddingScheme() == "PKCS5Padding");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSetIV" output="false"
	            hint="Test setIV()">

		<cfscript>
			try {
				// Test that ECB mode allows a null IV
				instance.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltECBCipher);
				instance.cipherSpec.setIV(toBinary(""));
				assertTrue(true);
			}
			catch(java.lang.AssertionError e) {
				assertFalse(false, "Test failed; unexpected exception");
			}
			try {
				// Test that CBC mode does allows a null IV
				instance.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltAESCipher);
				instance.cipherSpec.setIV(toBinary(""));
				assertFalse(false, "Test failed; Expected exception not thrown");
			}
			catch(java.lang.AssertionError e) {
				assertTrue(true);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testRequiresIV" output="false"
	            hint="Test requiresIV()">

		<cfscript>
			assertTrue(newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltECBCipher).requiresIV() == false);
			instance.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltAESCipher);
			assertTrue(instance.cipherSpec.getCipherMode() == "ECB");
			assertTrue(instance.cipherSpec.requiresIV() == false);
			assertTrue(newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.dfltOtherCipher).requiresIV());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSerialization" output="false"
	            hint="Test serialization">
		<cfset var local = {}/>

		<cfscript>
			local.filename = "cipherspec.ser";
			local.serializedFile = newJava("java.io.File").init(local.filename);
			local.success = false;
			try {
				// Delete any old serialized file. If it fails, it's not
				// a big deal. If we can't overwrite it later, we'll get
				// an IOException.
				//
				// NOTE: FindBugs complains we are not checking return value here.
				//       Guess what? We don't care!!!
				local.serializedFile.delete();

				instance.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipherXform="AES/CBC/NoPadding", keySize=128, blockSize=8, iv=instance.myIV);
				local.fos = newJava("java.io.FileOutputStream").init(local.filename);
				local.out = newJava("java.io.ObjectOutputStream").init(local.fos);
				local.out.writeObject(instance.cipherSpec);
				local.out.close();
				local.fos.close();

				local.fis = newJava("java.io.FileInputStream").init(local.filename);
				local.in = newJava("java.io.ObjectInputStream").init(local.fis);
				local.restoredCipherSpec = local.in.readObject();
				local.in.close();
				local.fis.close();

				// check that cipherSpec and restoredCipherSpec are equal. Just
				// compare them via their string representations.
				assertEquals(instance.cipherSpec.toStringESAPI(), local.restoredCipherSpec.toStringESAPI(), "Serialized restored CipherSpec differs from saved CipherSpec");

				local.success = true;
			}
			catch(java.io.IOException ex) {
				// RAILO error: ex.printStackTrace(newJava("java.lang.System").err);
				fail("testSerialization(): Unexpected IOException: " & ex);
			}
			catch(java.lang.ClassNotFoundException ex) {
				// RAILO error: ex.printStackTrace(newJava("java.lang.System").err);
				fail("testSerialization(): Unexpected ClassNotFoundException: " & ex);
			}
			// If test succeeds, remove the file. If it fails, leave it behind
			// for further analysis.
			if(local.success && local.serializedFile.exists()) {
				local.deleted = local.serializedFile.delete();
				if(!local.deleted) {
					try {
						newJava("java.lang.System").err.println("Unable to delete file: " & local.serializedFile.getCanonicalPath());
					}
					catch(java.io.IOException e) {// Ignore
					}
				}
			}
		</cfscript>

	</cffunction>

</cfcomponent>