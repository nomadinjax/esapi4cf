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
<cfcomponent displayname="CipherTextSerializerTest" extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false">

	<cfscript>
		instance.ESAPI = newComponent("cfesapi.org.owasp.esapi.ESAPI").init();
		instance.encryptor = "";
		instance.ivSpec = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfset var local = {}/>

		<cfscript>
			instance.encryptor = newJava("javax.crypto.Cipher").getInstance("AES/CBC/PKCS5Padding");
			local.ivBytes = instance.ESAPI.randomizer().getRandomBytes(instance.encryptor.getBlockSize());
			instance.ivSpec = newJava("javax.crypto.spec.IvParameterSpec").init(local.ivBytes);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="tearDown" output="false">

		<cfscript>
			newJava("java.lang.System").out.flush();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testAsSerializedByteArray" output="false">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("CipherTextSerializerTest.testAsSerializedByteArray() ...");
			local.cipherSpec = newComponent("cfesapi.org.owasp.esapi.crypto.CipherSpec").init(ESAPI=instance.ESAPI, cipher=instance.encryptor, keySize=128);
			local.cipherSpec.setIV(instance.ivSpec.getIV());
			local.key = "";
			try {
				local.key = newComponent("cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI).generateSecretKeyESAPI(local.cipherSpec.getCipherAlgorithm(), 128);
				instance.encryptor.init(newJava("javax.crypto.Cipher").ENCRYPT_MODE, local.key, instance.ivSpec);

				local.raw = instance.encryptor.doFinal(newJava("java.lang.String").init("Hello").getBytes("UTF8"));
				local.plain = newComponent("cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, "Hello");
				local.ct = instance.ESAPI.encryptor().encryptESAPI(local.key, local.plain);
				assertTrue(structKeyExists(local, "ct"));// Here to eliminate false positive from FindBugs.
				local.cts = newComponent("cfesapi.org.owasp.esapi.crypto.CipherTextSerializer").init(ESAPI=instance.ESAPI, cipherTextObj=local.ct);
				local.serializedBytes = local.cts.asSerializedByteArray();
				local.result = newComponent("cfesapi.org.owasp.esapi.crypto.CipherText").init(ESAPI=instance.ESAPI).fromPortableSerializedBytes(local.serializedBytes);
				local.pt = instance.ESAPI.encryptor().decryptESAPI(local.key, local.result);
				assertTrue("Hello" == local.pt.toStringESAPI());
			}
			catch(java.lang.Exception e) {
				fail("Test failed: Caught exception: " & e.getClass().getName() & "; msg was: " & e);
				e.printStackTrace(newJava("java.lang.System").err);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testAsCipherText" output="false">
		<cfset var local = {}/>

		<cfscript>
			newJava("java.lang.System").out.println("CipherTextSerializerTest.testAsCipherText() ...");
			try {
				local.plain = newComponent("cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, "Hello");
				local.ct = instance.ESAPI.encryptor().encryptESAPI(plain=local.plain);
				local.cts = newComponent("cfesapi.org.owasp.esapi.crypto.CipherTextSerializer").init(ESAPI=instance.ESAPI, cipherTextObj=local.ct);
				local.result = local.cts.asCipherText();
				assertTrue(local.ct.equalsESAPI(local.result));
				local.pt = instance.ESAPI.encryptor().decryptESAPI(ciphertext=local.result);
				assertTrue("Hello" == local.pt.toStringESAPI());
			}
			catch(cfesapi.org.owasp.esapi.errors.EncryptionException e) {
				fail("Caught EncryptionException; exception msg: " & e);
			}
		</cfscript>

	</cffunction>

</cfcomponent>