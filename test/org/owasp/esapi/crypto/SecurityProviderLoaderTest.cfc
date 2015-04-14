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
import "org.owasp.esapi.crypto.SecurityProviderLoader";

/**
 * Test for class {@code SecurityProviderLoader}. Note that these tests
 * use Bouncy Castle's JCE provider so a version their jar must be added
 * to your class path. If you wish to add it via Maven, you can do so by
 * adding this to your <b><i>pom.xml</i></b>:
 * <pre>
 * <dependency>
 *      <groupId>org.bouncycastle</groupId>
 *      <artifactId>bcprov-jdk15</artifactId>
 *      <version>1.44</version>
 * </dependency>
 * </pre>
 * It has been tested with Bouncy Castle 1.44, but any later version should
 * do as well.
 */
component extends="esapi4cf.test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

    variables.HAS_BOUNCY_CASTLE = false;

    public void function setUpBeforeClass() {
        try {
            var providerClass = "org.bouncycastle.jce.provider.BouncyCastleProvider";
            var cryptoProvider = createObject("java", providerClass);
            assertTrue(!isNull(cryptoProvider));
            variables.HAS_BOUNCY_CASTLE = true;
        } catch(any ex) {
            // Note: FindBugs reports a false positive here...
            //    REC_CATCH_EXCEPTION: Exception is caught when Exception is not thrown
            // but exceptions really can be thrown.
            variables.HAS_BOUNCY_CASTLE = false;
        }
    }

    public void function testInsertProviderAt() {
        if ( ! variables.HAS_BOUNCY_CASTLE ) {
            System.out.println("SecurityProviderLoaderTest.testInsertProviderAt(): Skipping test -- must have Bouncy Castle JCE provider in classpath.");
            return;
        }

        try {
            new SecurityProviderLoader(variables.ESAPI).insertProviderAt("BC", 1);
            assertTrue(true);
        } catch (java.security.NoSuchProviderException e) {
            fail("Caught NoSuchProviderException trying to load Bouncy Castle; exception was: " & e);
        }
    }

    public void function testLoadESAPIPreferredJCEProvider() {
        // Note: OK if empty string or unset, in fact default is empty string.
        var preferredProvider = variables.ESAPI.securityConfiguration().getPreferredJCEProvider();
        try {
            new SecurityProviderLoader(variables.ESAPI).loadESAPIPreferredJCEProvider();
            assertTrue(true);
        } catch (java.security.NoSuchProviderException e) {
            fail("Caught NoSuchProviderException trying to preferred JCE provider " & preferredProvider & "; exception was: " & e);
        }
    }

    public void function testNoSuchProviderException() {
    	try {
        	new SecurityProviderLoader(variables.ESAPI).insertProviderAt("DrBobsSecretSnakeOilElixirCryptoJCE", 5);
        	fail("Failed to throw NoSuchProviderException");
        }
        catch (java.security.NoSuchProviderException ex) {
        	// expected
        }
    }

    public void function testBogusProviderWithFQCN() {
    	try {
        	new SecurityProviderLoader(variables.ESAPI).insertProviderAt("com.snakeoil.DrBobsSecretSnakeOilElixirCryptoJCE", 5);
        	fail("Failed to throw exception on bogus provider");
        }
        catch (java.security.NoSuchProviderException ex) {
        	// expected
        }
    }

    public void function testWithBouncyCastle() {
        if ( ! variables.HAS_BOUNCY_CASTLE ) {
            System.out.println("SecurityProviderLoaderTest.testInsertProviderAt(): Skipping test -- must have Bouncy Castle JCE provider in classpath.");
            return;
        }

        try {
            new SecurityProviderLoader(variables.ESAPI).insertProviderAt("BC", 1);
            assertTrue(true);
        } catch (java.security.NoSuchProviderException e) {
            fail("Caught NoSuchProviderException trying to load Bouncy Castle; exception was: " & e);
        }

        // First encrypt w/ preferred cipher transformation (AES/CBC/PKCS5Padding).
        try {
            var clearMsg = "This is top secret! We are all out of towels!";
            var origMsg = clearMsg.toString(); // Must keep 'cuz by default, clearMsg is overwritten.
            var ct = variables.ESAPI.encryptor().encrypt(clearMsg);
            assertEquals( "*********************************************", clearMsg.toString() );
            var plain = variables.ESAPI.encryptor().decrypt(ct);
            assertEquals( origMsg, plain.toString() );
        } catch (EncryptionException e) {
            fail("Encryption w/ Bouncy Castle failed with EncryptionException for preferred cipher transformation; exception was: " & e);
        }

        // Next, try a "combined mode" cipher mode available in Bouncy Castle.
        var origCipherXform = null;
        try {
            origCipherXform = variables.ESAPI.securityConfiguration().setCipherTransformation("AES/GCM/NoPadding");
            var clearMsg = new PlainText("This is top secret! We are all out of towels!");
            var origMsg = clearMsg.toString(); // Must keep 'cuz by default, clearMsg is overwritten.
            var ct = variables.ESAPI.encryptor().encrypt(clearMsg);
            var plain = variables.ESAPI.encryptor().decrypt(ct);
            assertEquals( origMsg, plain.toString() );
            // Verify that no MAC is calculated for GCM cipher mode. There is no method to
            // validate this, so we look at the String representation of this CipherText
            // object and pick it out of there.
            var str = ct.toString();
            assertTrue( str.matches(".*, MAC is absent;.*") );
        } catch (EncryptionException e) {
            fail("Encryption w/ Bouncy Castle failed with EncryptionException for preferred cipher transformation; exception was: " & e);
        } finally {
            variables.ESAPI.securityConfiguration().setCipherTransformation(origCipherXform);
        }
    }
}
