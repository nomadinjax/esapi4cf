<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 --->
<!---
 * The Encryptor interface provides a set of methods for performing common
 * encryption, random number, and hashing operations. Implementations should
 * rely on a strong cryptographic implementation, such as JCE or BouncyCastle.
 * Implementors should take care to ensure that they initialize their
 * implementation with a strong "master key", and that they protect this secret
 * as much as possible.
 * <P>
 * <img src="doc-files/Encryptor.jpg">
 * <P>
 * Possible future enhancements (depending on feedback) might include:
 * <UL>
 * <LI>encryptFile</LI>
 * </UL>
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 --->
<cfinterface>

	<cffunction access="public" returntype="String" name="hashString" output="false"
	            hint="Returns a string representation of the hash of the provided plaintext and salt. The salt helps to protect against a rainbow table attack by mixing in some extra data with the plaintext. Some good choices for a salt might be an account name or some other string that is known to the application but not to an attacker. See http://www.matasano.com/log/958/enough-with-the-rainbow-tables-what-you-need-to-know-about-secure-password-schemes/ for more information about hashing as it pertains to password schemes.">
		<cfargument required="true" type="String" name="plaintext" hint="the plaintext String to encrypt"/>
		<cfargument required="true" type="String" name="salt" hint="the salt to add to the plaintext String before hashing"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="encryptString" output="false"
	            hint="Encrypts the provided plaintext and returns a ciphertext string. @deprecated Why this method is deprecated? Most cryptographers strongly suggest that if you are creating crypto functionality for general-purpose use, at a minimum you should ensure that it provides authenticity, integrity, and confidentiality. This method only provides confidentiality, but not authenticity or integrity. Therefore, you are encouraged to use one of the other encryption methods referenced below. Because this method provides neither authenticity nor integrity, it may be removed in some future ESAPI Java release. Note: there are some cases where authenticity / integrity are not that important. For instance, consider a case where the encrypted data is never out of your application's control. For example, if you receive data that your application is encrypting itself and then storing the encrypted data in its own database for later use (and no other applications can query or update that column of the database), providing confidentiality alone might be sufficient. However, if there are cases where your application will be sending or receiving already encrypted data over an insecure, unauthenticated channel, in such cases authenticity and integrity of the encrypted data likely is important.">
		<cfargument required="true" type="String" name="plaintext" hint="the plaintext String to encrypt"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="decryptString" output="false"
	            hint="Decrypts the provided ciphertext string (encrypted with the encrypt method) and returns a plaintext string. @deprecated Why this method is deprecated? Most cryptographers strongly suggest that if you are creating crypto functionality for general-purpose use, at a minimum you should ensure that it provides authenticity, integrity, and confidentiality. This method only provides confidentiality, but not authenticity or integrity. Therefore, you are encouraged to use one of the other encryption methods referenced below. Because this method provides neither authenticity nor integrity, it may be removed in some future ESAPI Java release. Note: there are some cases where authenticity / integrity are not that important. For instance, consider a case where the encrypted data is never out of your application's control. For example, if you receive data that your application is encrypting itself and then storing the encrypted data in its own database for later use (and no other applications can query or update that column of the database), providing confidentiality alone might be sufficient. However, if there are cases where your application will be sending or receiving already encrypted data over an insecure, unauthenticated channel, in such cases authenticity and integrity of the encrypted data likely is important.">
		<cfargument required="true" type="String" name="ciphertext" hint="the ciphertext (encrypted plaintext)"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="sign" output="false"
	            hint="Create a digital signature for the provided data and return it in a string.">
		<cfargument required="true" type="String" name="data" hint="the data to sign"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="verifySignature" output="false"
	            hint="Verifies a digital signature (created with the sign method) and returns the boolean result.">
		<cfargument required="true" type="String" name="signature" hint="the signature to verify against 'data'"/>
		<cfargument required="true" type="String" name="data" hint="the data to verify against 'signature'"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="seal" output="false"
	            hint="Creates a seal that binds a set of data and includes an expiration timestamp.">
		<cfargument required="true" type="String" name="data" hint="the data to seal"/>
		<cfargument required="true" type="numeric" name="timestamp" hint="the absolute expiration date of the data, expressed as seconds since the epoch"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="unseal" output="false"
	            hint="Unseals data (created with the seal method) and throws an exception describing any of the various problems that could exist with a seal, such as an invalid seal format, expired timestamp, or decryption error.">
		<cfargument required="true" type="String" name="seal" hint="the sealed data"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="verifySeal" output="false"
	            hint="Verifies a seal (created with the seal method) and throws an exception describing any of the various problems that could exist with a seal, such as an invalid seal format, expired timestamp, or data mismatch.">
		<cfargument required="true" type="String" name="seal" hint="the seal to verify"/>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getRelativeTimeStamp" output="false"
	            hint="Gets an absolute timestamp representing an offset from the current time to be used by other functions in the library.">
		<cfargument required="true" type="numeric" name="offset" hint="the offset to add to the current time"/>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getTimeStamp" output="false"
	            hint="Gets a timestamp representing the current date and time to be used by other functions in the library.">
	</cffunction>

</cfinterface>