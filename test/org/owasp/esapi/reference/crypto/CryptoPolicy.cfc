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

/**
 * Helper class to see if unlimited strength crypto is available. If it is
 * not, then symmetric encryption algorithms are restricted to 128-bit
 * key size or the encryption must provide key weakening or key escrow.
 * <p>
 * This program attempts to generate a 256-bit AES key and use it to do
 * to a simple encryption. If the encryption succeeds, the assumption is
 * that the JVM being used has the "unlimited" strength JCE jurisdiction
 * policy files installed.
 * </p><p>
 * We use this for JUnit tests. If unlimited strength crypto is not available,
 * we simply skip certain JUnit tests that would require it.
 * </p><p>
 * The reason for not adding this class to ESAPI proper is because its mostly
 * pointless to find out at runtime that you don't have the unlimited strength
 * JCE jurisdiction policy files installed. If you don't, you're SOL until you
 * install them and even if you could do that from a running JVM, chances are
 * slim to none that one could easily get your JCE provider to work with them.
 * (Well, one <i>might</i> be able to unload the JCE classes, but you hopefully
 * are not running your JVM process as 'root' or other privileged account
 * anyway, so you probably can't install these policy files from your JVM in
 * the first place.)
 * </p>
 */

/*
 * @skip
 */
component extends="org.owasp.esapi.util.Object" {
	pageEncoding "utf-8";

	variables.System = createObject("java", "java.lang.System");

    variables.checked = false;
    variables.unlimited = false;

    /**
     * Check to see if unlimited strength crypto is available.
     * There is an implicit assumption that the JCE jurisdiction policy
     * files are not going to be changing while this given JVM is running.
     *
     * @return True if we can provide keys longer than 128 bits.
     */
    public boolean function isUnlimitedStrengthCryptoAvailable()
    {
        if ( variables.checked == false ) {
            variables.unlimited = checkCrypto();
            variables.checked = true;
        }
        return variables.unlimited;
    }

    private boolean function checkCrypto()
    {
        try {
            var keyGen = createObject("java", "javax.crypto.KeyGenerator").getInstance("AES");
            keyGen.init(256);   // Max sym key size is 128 unless unlimited
                                // strength jurisdiction policy files installed.
            var skey = keyGen.generateKey();
            var raw = skey.getEncoded();
            var skeySpec = createObject("java", "javax.crypto.spec.SecretKeySpec").init(raw, "AES");
            var cipher = createObject("java", "javax.crypto.Cipher").getInstance("AES/ECB/NoPadding");

                // This usually will throw InvalidKeyException unless the
                // unlimited jurisdiction policy files are installed. However,
                // it can succeed even if it's not a provider chooses to use
                // an exemption mechanism such as key escrow, key recovery, or
                // key weakening for this cipher instead.
            cipher.init(createObject("java", "javax.crypto.Cipher").ENCRYPT_MODE, skeySpec);

                // Try the encryption on dummy string to make sure it works.
                // Not using padding so # bytes must be multiple of AES cipher
                // block size which is 16 bytes. Also, OK not to use UTF-8 here.
            var encrypted = cipher.doFinal(toBinary("1234567890123456"));
            if (isNull(encrypted)) throws("Encryption of test string failed!");
            var em = cipher.getExemptionMechanism();
            if (!isNull(em)) {
                createObject("java", "java.lang.System").out.println("Cipher uses exemption mechanism " & em.getName());
                return false;   // This is actually an indeterminate case, but
                                // we can't bank on it at least for this
                                // (default) provider.
            }
        } catch(java.security.InvalidKeyException ikex) {
            createObject("java", "java.lang.System").out.println("CryptoPolicy: 256 bits is invalid key size ==> unlimited strength crypto NOT installed!");
            return false;
        } catch(any ex) {
            System.out.println("Caught unexpected exception: " & ex);
            //ex.printStackTrace(System.out);
            return false;
        }
        return true;
    }

}