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
<cfinterface hint="The Encryptor interface provides a set of methods for performing common encryption, random number, and hashing operations. Implementations should rely on a strong cryptographic implementation, such as JCE or BouncyCastle. Implementors should take care to ensure that they initialize their implementation with a strong 'master key', and that they protect this secret as much as possible.">
	<!--- RAILO ERROR: The name [hash] is already used by a Build in Function

		<cffunction access="public" returntype="String" name="hash" output="false" hint="Returns a string representation of the hash of the provided plaintext and salt. The salt helps to protect against a rainbow table attack by mixing in some extra data with the plaintext. Some good choices for a salt might be an account name or some other string that is known to the application but not to an attacker. ">
		<cfargument type="String" name="plaintext" required="true" hint="the plaintext String to encrypt">
		<cfargument type="String" name="salt" required="true" hint="the salt to add to the plaintext String before hashing">
		<cfargument type="numeric" name="iterations" required="false" hint="the number of times to iterate the hash">
		</cffunction>
 --->
	<!--- RAILO ERROR: The name [encrypt] is already used by a Build in Function

		<cffunction access="public" returntype="any" name="encrypt" output="false" hint="Encrypts the provided plaintext bytes using the cipher transformation specified by the property Encryptor.CipherTransformation as defined in the ESAPI.properties file and the specified secret key. This method is similar to ##encrypt(PlainText) except that it permits a specific SecretKey to be used for encryption.">
		<cfargument type="any" name="key" required="false" hint="The SecretKey to use for encrypting the plaintext.">
		<cfargument type="any" name="plain" required="true" hint="The byte stream to be encrypted. Note if a Java String is to be encrypted, it should be converted using 'some string'.getBytes('UTF-8').">
		</cffunction>
 --->
	<!--- RAILO ERROR: The name [decrypt] is already used by a Build in Function

		<cffunction access="public" returntype="any" name="decrypt" output="false" hint="Decrypts the provided CipherText using the information from it and the specified secret key. This decrypt method is similar to ##decrypt(CipherText) except that it allows decrypting with a secret key other than the master secret key.">
		<cfargument type="any" name="key" required="false" hint="The SecretKey to use for encrypting the plaintext.">
		<cfargument type="any" name="ciphertext" required="true" hint="The CipherText object to be decrypted.">
		</cffunction>
 --->

	<cffunction access="public" returntype="String" name="sign" output="false" hint="Create a digital signature for the provided data and return it in a string. 'Limitations:' A new public/private key pair used for ESAPI 2.0 digital signatures with this method and ##verifySignature(String, String) are dynamically created when the default reference implementation class, JavaEncryptor is first created. Because this key pair is not persisted nor is the public key shared, this method and the corresponding ##verifySignature(String, String) can not be used with expected results across JVM instances. This limitation will be addressed in ESAPI 2.1.">
		<cfargument type="String" name="data" required="true" hint="the data to sign">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="verifySignature" output="false" hint="Verifies a digital signature (created with the sign method) and returns the boolean result. 'Limitations:' A new public/private key pair used for ESAPI 2.0 digital signatures with this method and ##sign(String) are dynamically created when the default reference implementation class, JavaEncryptor is first created. Because this key pair is not persisted nor is the public key shared, this method and the corresponding ##sign(String) can not be used with expected results across JVM instances. This limitation will be addressed in ESAPI 2.1.">
		<cfargument type="String" name="signature" required="true" hint="the signature to verify against 'data'">
		<cfargument type="String" name="data" required="true" hint="the data to verify against 'signature'">
	</cffunction>


	<cffunction access="public" returntype="String" name="seal" output="false" hint="Creates a seal that binds a set of data and includes an expiration timestamp.">
		<cfargument type="String" name="data" required="true" hint="the data to seal">
		<cfargument type="numeric" name="timestamp" required="true" hint="the absolute expiration date of the data, expressed as seconds since the epoch">
	</cffunction>


	<cffunction access="public" returntype="String" name="unseal" output="false" hint="Unseals data (created with the seal method) and throws an exception describing any of the various problems that could exist with a seal, such as an invalid seal format, expired timestamp, or decryption error.">
		<cfargument type="String" name="seal" required="true" hint="the sealed data">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="verifySeal" output="false" hint="Verifies a seal (created with the seal method) and throws an exception describing any of the various problems that could exist with a seal, such as an invalid seal format, expired timestamp, or data mismatch.">
		<cfargument type="String" name="seal" required="true" hint="the seal to verify">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getRelativeTimeStamp" output="false" hint="Gets an absolute timestamp representing an offset from the current time to be used by other functions in the library.">
		<cfargument type="numeric" name="offset" required="true" hint="the offset to add to the current time">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getTimeStamp" output="false" hint="Gets a timestamp representing the current date and time to be used by other functions in the library.">
	</cffunction>

</cfinterface>
