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
		instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();
		instance.encryptor = "";
    	instance.ivSpec = "";
	</cfscript>
 
	<cffunction access="public" returntype="void" name="setUp" output="false">
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
		<cfscript>
			newJava("java.lang.System").out.println("CipherTextSerializerTest.testAsSerializedByteArray() ...");
			Cipher = newJava("javax.crypto.Cipher");
			CryptoHelper = new cfesapi.org.owasp.esapi.crypto.CryptoHelper(instance.ESAPI);

	        local.cipherSpec = new cfesapi.org.owasp.esapi.crypto.CipherSpec(ESAPI=instance.ESAPI, cipher=instance.encryptor, keySize=128);
	        local.cipherSpec.setIV(instance.ivSpec.getIV());
	        try {
	            local.key = CryptoHelper.generateSecretKey(local.cipherSpec.getCipherAlgorithm(), 128);
	            instance.encryptor.init(Cipher.ENCRYPT_MODE, local.key, instance.ivSpec);

	            local.raw = instance.encryptor.doFinal(newJava("java.lang.String").init("Hello").getBytes("UTF8"));
	            local.ct = instance.ESAPI.encryptor().encrypt(local.key, new cfesapi.org.owasp.esapi.crypto.PlainText(instance.ESAPI, "Hello") );
	            assertTrue( !isNull(local.ct) );   // Here to eliminate false positive from FindBugs.
	            local.cts = new cfesapi.org.owasp.esapi.crypto.CipherTextSerializer(ESAPI=instance.ESAPI, cipherTextObj=local.ct );
	            local.serializedBytes = local.cts.asSerializedByteArray();
	            local.result = new cfesapi.org.owasp.esapi.crypto.CipherText(ESAPI=instance.ESAPI).fromPortableSerializedBytes(local.serializedBytes);
	            local.pt = instance.ESAPI.encryptor().decrypt(local.key, local.result);
	            assertTrue( "Hello" == local.pt.toString() );
	        } catch (Exception e) {
	            fail("Test failed: Caught exception: " & e.getClass().getName() & "; msg was: " & e);
	            e.printStackTrace(newJava("java.lang.System").err);
	        }
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testAsCipherText" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("CipherTextSerializerTest.testAsCipherText() ...");
	        try {
	            local.ct = instance.ESAPI.encryptor().encrypt( plain=new cfesapi.org.owasp.esapi.crypto.PlainText(instance.ESAPI, "Hello") );
	            local.cts = new cfesapi.org.owasp.esapi.crypto.CipherTextSerializer(ESAPI=instance.ESAPI, cipherTextObj=local.ct );
	            local.result = local.cts.asCipherText();
	            assertTrue( local.ct.equals(local.result) );
	            local.pt = instance.ESAPI.encryptor().decrypt(ciphertext=local.result);
	            assertTrue( "Hello" == local.pt.toString() );
	        } catch (EncryptionException e) {
	            fail("Caught EncryptionException; exception msg: " & e);
	        }
    	</cfscript> 
	</cffunction>


</cfcomponent>
