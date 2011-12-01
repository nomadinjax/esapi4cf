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
<cfcomponent displayname="CryptoPolicy" extends="cfesapi.org.owasp.esapi.lang.Object" output="false" hint="Helper class to see if unlimited strength crypto is available. If it is not, then symmetric encryption algorithms are restricted to 128-bit key size or the encryption must provide key weakening or key escrow. This program attempts to generate a 256-bit AES key and use it to do to a simple encryption. If the encryption succeeds, the assumption is that the JVM being used has the 'unlimited' strength JCE jurisdiction policy files installed. We use this for JUnit tests. If unlimited strength crypto is not available, we simply skip certain JUnit tests that would require it. The reason for not adding this class to ESAPI proper is because its mostly pointless to find out at runtime that you don't have the unlimited strength JCE jurisdiction policy files installed. If you don't, you're SOL until you install them and even if you could do that from a running JVM, chances are slim to none that one could easily get your JCE provider to work with them. (Well, one might be able to unload the JCE classes, but you hopefully are not running your JVM process as 'root' or other privileged account anyway, so you probably can't install these policy files from your JVM in the first place.)">

	<cfscript>
		instance.checked = false;
		instance.unlimited = false;
	</cfscript>

	<cffunction access="public" returntype="boolean" name="isUnlimitedStrengthCryptoAvailable" output="false"
	            hint="Check to see if unlimited strength crypto is available. There is an implicit assumption that the JCE jurisdiction policy files are not going to be changing while this given JVM is running.">

		<cfscript>
			if(instance.checked == false) {
				instance.unlimited = checkCrypto();
				instance.checked = true;
			}
			return instance.unlimited;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="checkCrypto" output="false">
		<cfset var local = {}/>

		<cfscript>
			try {
				local.keyGen = newJava("javax.crypto.KeyGenerator").getInstance("AES");
				local.keyGen.init(256);// Max sym key size is 128 unless unlimited
				// strength jurisdiction policy files installed.
				local.skey = local.keyGen.generateKey();
				local.raw = local.skey.getEncoded();
				local.skeySpec = newJava("javax.crypto.spec.SecretKeySpec").init(local.raw, "AES");
				local.cipher = newJava("javax.crypto.Cipher").getInstance("AES/ECB/NoPadding");

				// This usually will throw InvalidKeyException unless the
				// unlimited jurisdiction policy files are installed. However,
				// it can succeed even if it's not a provider chooses to use
				// an exemption mechanism such as key escrow, key recovery, or
				// key weakening for this cipher instead.
				local.cipher.init(newJava("javax.crypto.Cipher").ENCRYPT_MODE, local.skeySpec);

				// Try the encryption on dummy string to make sure it works.
				// Not using padding so # bytes must be multiple of AES cipher
				// block size which is 16 bytes. Also, OK not to use UTF-8 here.
				local.encrypted = local.cipher.doFinal(String.init("1234567890123456").getBytes());
				assert(structKeyExists(local, "encrypted"), "Encryption of test string failed!");
				local.em = local.cipher.getExemptionMechanism();
				if(structKeyExists(local, "em")) {
					newJava("java.lang.System").out.println("Cipher uses exemption mechanism " & local.em.getName());
					return false;// This is actually an indeterminate case, but
					// we can't bank on it at least for this
					// (default) provider.
				}
			}
			catch(java.security.InvalidKeyException ikex) {
				newJava("java.lang.System").out.println("Invalid key size - unlimited strength crypto NOT installed!");
				return false;
			}
			catch(java.lang.Exception ex) {
				newJava("java.lang.System").out.println("Caught unexpected exception: " & ex);
				ex.printStackTrace(newJava("java.lang.System").out);
				return false;
			}
			return true;
		</cfscript>

	</cffunction>

</cfcomponent>