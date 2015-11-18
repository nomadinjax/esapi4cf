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
import "org.owasp.esapi.crypto.CipherText";
import "org.owasp.esapi.crypto.CipherTextSerializer";
import "org.owasp.esapi.crypto.CryptoHelper";
import "org.owasp.esapi.crypto.PlainText";

component extends="test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

    variables.encryptor = "";
    variables.ivSpec = "";  // Note: FindBugs reports false positive
                                            // about this being unread field. See
    										// testAsSerializedByteArray().

    public void function setUp() {
        variables.encryptor = createObject("java", "javax.crypto.Cipher").getInstance("AES/CBC/PKCS5Padding");
        var ivBytes = "";
        ivBytes = variables.ESAPI.randomizer().getRandomBytes(variables.encryptor.getBlockSize());
        variables.ivSpec = createObject("java", "javax.crypto.spec.IvParameterSpec").init(ivBytes);
    }

    public void function testAsSerializedByteArray() {
    	System.out.println("CipherTextSerializerTest.testAsSerializedByteArray() ...");
        var cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipher=variables.encryptor, keySize=128);
        cipherSpec.setIV(variables.ivSpec.getIV());
        var key = "";
        try {
            key = new CryptoHelper(variables.ESAPI).generateSecretKey(cipherSpec.getCipherAlgorithm(), 128);
            variables.encryptor.init(createObject("java", "javax.crypto.Cipher").ENCRYPT_MODE, key, variables.ivSpec);

            var raw = variables.encryptor.doFinal(charsetDecode("Hello", "utf-8"));
            var ct = variables.ESAPI.encryptor().encrypt(new PlainText(variables.ESAPI, "Hello"), key);
            assertTrue(!isNull(ct));   // Here to eliminate false positive from FindBugs.
            var cts = new CipherTextSerializer(variables.ESAPI, ct);
            var serializedBytes = cts.asSerializedByteArray();
            var result = new CipherText(variables.ESAPI).fromPortableSerializedBytes(serializedBytes);
            var pt = variables.ESAPI.encryptor().decrypt(result, key);
            assertTrue("Hello" == pt.toString());
        } catch (Exception e) {
            fail("Test failed: Caught exception: " & e.getClass().getName() & "; msg was: " & e);
            e.printStackTrace(System.err);
        }
    }

    public void function testAsCipherText() {
        try {
        	System.out.println("CipherTextSerializerTest.testAsCipherText() ...");
            var ct = variables.ESAPI.encryptor().encrypt(new PlainText(variables.ESAPI, "Hello"));
            var cts = new CipherTextSerializer(variables.ESAPI, ct);
            var result = cts.asCipherText();
            assertTrue( ct.isEquals(result) );
            var pt = variables.ESAPI.encryptor().decrypt(result);
            assertTrue("Hello" == pt.toString());
        } catch (EncryptionException e) {
            fail("Caught EncryptionException; exception msg: " & e);
        }
    }

}
