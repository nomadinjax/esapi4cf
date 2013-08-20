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
<cfcomponent implements="org.owasp.esapi.Encryptor" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Encryptor interface. This implementation layers on the JCE provided cryptographic package. Algorithms used are configurable in the ESAPI.properties file.">

	<cfscript>
		variables.ESAPI = "";

		/** The private key. */
		variables.privateKey = "";

		/** The public key. */
		variables.publicKey = "";

		variables.parameterSpec = "";
		variables.secretKey = "";
		variables.encryptAlgorithm = "PBEWithMD5AndDES";
		variables.signatureAlgorithm = "SHAwithDSA";
		variables.hashAlgorithm = "SHA-512";
		variables.randomAlgorithm = "SHA1PRNG";
		variables.encoding = "UTF-8";
	</cfscript>
 
	<cffunction access="public" returntype="org.owasp.esapi.Encryptor" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI">
		<cfscript>
			// CF8 requires 'var' at the top
			var salt = "";
			var pass = "";
			var kf = "";
			var keyGen = "";
			var random = "";
			var seed = "";
			var pair = "";
			
			variables.ESAPI = arguments.ESAPI;

			salt = variables.ESAPI.securityConfiguration().getMasterSalt();
			pass = variables.ESAPI.securityConfiguration().getMasterPassword();

			// setup algorithms
			variables.encryptAlgorithm = variables.ESAPI.securityConfiguration().getEncryptionAlgorithm();
			variables.signatureAlgorithm = variables.ESAPI.securityConfiguration().getDigitalSignatureAlgorithm();
			variables.randomAlgorithm = variables.ESAPI.securityConfiguration().getRandomAlgorithm();
			variables.hashAlgorithm = variables.ESAPI.securityConfiguration().getHashAlgorithm();

			try {
				// Set up encryption and decryption
				variables.parameterSpec = newJava( "javax.crypto.spec.PBEParameterSpec" ).init( salt, 20 );
				kf = newJava( "javax.crypto.SecretKeyFactory" ).getInstance( variables.encryptAlgorithm );
				variables.secretKey = kf.generateSecret( newJava( "javax.crypto.spec.PBEKeySpec" ).init( pass ) );
				variables.encoding = variables.ESAPI.securityConfiguration().getCharacterEncoding();

				// Set up signing keypair using the master password and salt
				keyGen = newJava( "java.security.KeyPairGenerator" ).getInstance( "DSA" );
				random = newJava( "java.security.SecureRandom" ).getInstance( variables.randomAlgorithm );
				seed = hashString( toString( pass ), toString( salt ) ).getBytes();
				random.setSeed( seed );
				keyGen.initialize( 1024, random );
				pair = keyGen.generateKeyPair();
				variables.privateKey = pair.getPrivate();
				variables.publicKey = pair.getPublic();
			}
			catch(java.lang.Exception e) {
				// can't throw this exception in initializer, but this will log it
				createObject( "component", "org.owasp.esapi.errors.EncryptionException" ).init( variables.ESAPI, "Encryption failure", "Error creating Encryptor", e );
			}

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="hashString" output="false" hint="Hashes the data using the specified algorithm and the Java MessageDigest class. This method first adds the salt, a separator (':'), and the data, and then rehashes 1024 times to help strengthen weak passwords.">
		<cfargument required="true" type="String" name="plaintext">
		<cfargument required="true" type="String" name="salt">
		<cfscript>
			// CF8 requires 'var' at the top
			var digest = "";
			var i = "";
			var encoded = "";
			
			var bytes = "";
			try {
				digest = newJava( "java.security.MessageDigest" ).getInstance( variables.hashAlgorithm );
				digest.reset();
				digest.update( variables.ESAPI.securityConfiguration().getMasterSalt() );
				digest.update( newJava( "java.lang.String" ).init( arguments.salt ).getBytes() );
				digest.update( newJava( "java.lang.String" ).init( arguments.plaintext ).getBytes() );

				// rehash a number of times to help strengthen weak passwords
				bytes = digest.digest();
				for(i = 0; i < 1024; i++) {
					digest.reset();
					bytes = digest.digest( bytes );
				}
				encoded = variables.ESAPI.encoder().encodeForBase64( bytes, false );
				return encoded;
			}
			catch(java.security.NoSuchAlgorithmException e) {
				throwException( createObject( "component", "org.owasp.esapi.errors.EncryptionException" ).init( variables.ESAPI, "Internal error", "Can't find hash algorithm " & variables.hashAlgorithm, e ) );
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encryptString" output="false">
		<cfargument required="true" type="String" name="plaintext">
		<cfscript>
			// CF8 requires 'var' at the top
			var encrypter = "";
			var output = "";
			var enc = "";
			
			// Note - Cipher is not threadsafe so we create one locally
			try {
				encrypter = newJava( "javax.crypto.Cipher" ).getInstance( variables.encryptAlgorithm );
				encrypter.init( newJava( "javax.crypto.Cipher" ).ENCRYPT_MODE, variables.secretKey, variables.parameterSpec );
				output = arguments.plaintext.getBytes( variables.encoding );
				enc = encrypter.doFinal( output );
				return variables.ESAPI.encoder().encodeForBase64( enc, false );
			}
			catch(java.lang.Exception e) {
				throwException( createObject( "component", "org.owasp.esapi.errors.EncryptionException" ).init( variables.ESAPI, "Encryption failure", "Encryption problem: " & e.getMessage(), e ) );
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="decryptString" output="false">
		<cfargument required="true" type="String" name="ciphertext">
		<cfscript>
			// CF8 requires 'var' at the top
			var decrypter = "";
			var dec = "";
			var output = "";
			
			// Note - Cipher is not threadsafe so we create one locally
			try {
				decrypter = newJava( "javax.crypto.Cipher" ).getInstance( variables.encryptAlgorithm );
				decrypter.init( newJava( "javax.crypto.Cipher" ).DECRYPT_MODE, variables.secretKey, variables.parameterSpec );
				dec = variables.ESAPI.encoder().decodeFromBase64( arguments.ciphertext );
				output = decrypter.doFinal( dec );
				return newJava( "java.lang.String" ).init( output, variables.encoding );
			}
			catch(java.lang.Exception e) {
				throwException( createObject( "component", "org.owasp.esapi.errors.EncryptionException" ).init( variables.ESAPI, "Decryption failed", "Decryption problem: " & e.getMessage(), e ) );
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="sign" output="false">
		<cfargument required="true" type="String" name="data">
		<cfscript>
			// CF8 requires 'var' at the top
			var signer = "";
			var bytes = "";
			
			try {
				signer = newJava( "java.security.Signature" ).getInstance( variables.signatureAlgorithm );
				signer.initSign( variables.privateKey );
				signer.update( newJava( "java.lang.String" ).init( arguments.data ).getBytes() );
				bytes = signer.sign();
				return variables.ESAPI.encoder().encodeForBase64( bytes, true );
			}
			catch(java.lang.Exception e) {
				throwException( createObject( "component", "org.owasp.esapi.errors.EncryptionException" ).init( variables.ESAPI, "Signature failure", "Can't find signature algorithm " & variables.signatureAlgorithm, e ) );
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="verifySignature" output="false">
		<cfargument required="true" type="String" name="signature">
		<cfargument required="true" type="String" name="data">
		<cfscript>
			// CF8 requires 'var' at the top
			var bytes = "";
			var signer = "";
			
			try {
				bytes = variables.ESAPI.encoder().decodeFromBase64( arguments.signature );
				signer = newJava( "java.security.Signature" ).getInstance( variables.signatureAlgorithm );
				signer.initVerify( variables.publicKey );
				signer.update( newJava( "java.lang.String" ).init( arguments.data ).getBytes() );
				return signer.verify( bytes );
			}
			catch(java.lang.Exception e) {
				createObject( "component", "org.owasp.esapi.errors.EncryptionException" ).init( variables.ESAPI, "Invalid signature", "Problem verifying signature: " & e.getMessage(), e );
				return false;
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="seal" output="false">
		<cfargument required="true" type="String" name="data">
		<cfargument required="true" type="numeric" name="timestamp">
		<cfscript>
			// CF8 requires 'var' at the top
			var random = "";
			
			try {
				// mix in some random data so even identical data and timestamp produces different seals
				random = variables.ESAPI.randomizer().getRandomString( 10, newJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
				return this.encryptString( arguments.timestamp & ":" & random & ":" & arguments.data );
			}
			catch(org.owasp.esapi.errors.EncryptionException e) {
				throwException( createObject( "component", "org.owasp.esapi.errors.IntegrityException" ).init( variables.ESAPI, e.message, e.detail, e ) );
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="unseal" output="false">
		<cfargument required="true" type="String" name="seal">
		<cfscript>
			// CF8 requires 'var' at the top
			var index = "";
			var timestring = "";
			var timestamp = "";
			var expiration = "";
			var sealedValue = "";
			
			var plaintext = "";
			try {
				plaintext = decryptString( arguments.seal );
			}
			catch(org.owasp.esapi.errors.EncryptionException e) {
				throwException( createObject( "component", "org.owasp.esapi.errors.EncryptionException" ).init( variables.ESAPI, "Invalid seal", "Seal did not decrypt properly", e ) );
			}

			index = plaintext.indexOf( ":" );
			if(index == -1) {
				throwException( createObject( "component", "org.owasp.esapi.errors.EncryptionException" ).init( variables.ESAPI, "Invalid seal", "Seal did not contain properly formatted separator" ) );
			}

			timestring = plaintext.substring( 0, index );
			timestamp = newJava( "java.util.Date" ).init().getTime();
			expiration = newJava( "java.lang.Long" ).init( timestring );
			if(timestamp > expiration) {
				throwException( createObject( "component", "org.owasp.esapi.errors.EncryptionException" ).init( variables.ESAPI, "Invalid seal", "Seal expiration date has expired" ) );
			}

			index = plaintext.indexOf( ":", index + 1 );
			sealedValue = plaintext.substring( index + 1 );
			return sealedValue;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="verifySeal" output="false">
		<cfargument required="true" type="String" name="seal">
		<cfscript>
			try {
				unseal( arguments.seal );
				return true;
			}
			catch(org.owasp.esapi.errors.EncryptionException e) {
				return false;
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getTimeStamp" output="false">
		<cfscript>
			return javaCast( "long", newJava( "java.util.Date" ).init().getTime() );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getRelativeTimeStamp" output="false">
		<cfargument required="true" type="numeric" name="offset">
		<cfscript>
			return javaCast( "long", newJava( "java.util.Date" ).init().getTime() + arguments.offset );
		</cfscript> 
	</cffunction>


</cfcomponent>
