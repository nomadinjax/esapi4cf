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
 * @author Damon Miller
 * @created 2011
 --->
<cfcomponent implements="esapi4cf.org.owasp.esapi.Encryptor" extends="esapi4cf.org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Encryptor interface. This implementation layers on the JCE provided cryptographic package. Algorithms used are configurable in the ESAPI.properties file.">

	<cfscript>
		instance.ESAPI = "";

		/** The private key. */
		instance.privateKey = "";

		/** The public key. */
		instance.publicKey = "";

		instance.parameterSpec = "";
		instance.secretKey = "";
		instance.encryptAlgorithm = "PBEWithMD5AndDES";
		instance.signatureAlgorithm = "SHAwithDSA";
		instance.hashAlgorithm = "SHA-512";
		instance.randomAlgorithm = "SHA1PRNG";
		instance.encoding = "UTF-8";
	</cfscript>

	<cffunction access="public" returntype="esapi4cf.org.owasp.esapi.Encryptor" name="init" output="false">
		<cfargument required="true" type="esapi4cf.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			var local = {};

			instance.ESAPI = arguments.ESAPI;

			local.salt = instance.ESAPI.securityConfiguration().getMasterSalt();
			local.pass = instance.ESAPI.securityConfiguration().getMasterPassword();

			// setup algorithms
			instance.encryptAlgorithm = instance.ESAPI.securityConfiguration().getEncryptionAlgorithm();
			instance.signatureAlgorithm = instance.ESAPI.securityConfiguration().getDigitalSignatureAlgorithm();
			instance.randomAlgorithm = instance.ESAPI.securityConfiguration().getRandomAlgorithm();
			instance.hashAlgorithm = instance.ESAPI.securityConfiguration().getHashAlgorithm();

			try {
				// Set up encryption and decryption
				instance.parameterSpec = getJava( "javax.crypto.spec.PBEParameterSpec" ).init( local.salt, 20 );
				local.kf = getJava( "javax.crypto.SecretKeyFactory" ).getInstance( instance.encryptAlgorithm );
				instance.secretKey = local.kf.generateSecret( getJava( "javax.crypto.spec.PBEKeySpec" ).init( local.pass ) );
				instance.encoding = instance.ESAPI.securityConfiguration().getCharacterEncoding();

				// Set up signing keypair using the master password and salt
				local.keyGen = getJava( "java.security.KeyPairGenerator" ).getInstance( "DSA" );
				local.random = getJava( "java.security.SecureRandom" ).getInstance( instance.randomAlgorithm );
				local.seed = hashString( toString( local.pass ), toString( local.salt ) ).getBytes();
				local.random.setSeed( local.seed );
				local.keyGen.initialize( 1024, local.random );
				local.pair = local.keyGen.generateKeyPair();
				instance.privateKey = local.pair.getPrivate();
				instance.publicKey = local.pair.getPublic();
			}
			catch(java.lang.Exception e) {
				// can't throw this exception in initializer, but this will log it
				createObject( "component", "esapi4cf.org.owasp.esapi.errors.EncryptionException" ).init( instance.ESAPI, "Encryption failure", "Error creating Encryptor", e );
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="hashString" output="false"
	            hint="Hashes the data using the specified algorithm and the Java MessageDigest class. This method first adds the salt, a separator (':'), and the data, and then rehashes 1024 times to help strengthen weak passwords.">
		<cfargument required="true" type="String" name="plaintext"/>
		<cfargument required="true" type="String" name="salt"/>

		<cfscript>
			var local = {};

			local.bytes = "";
			try {
				local.digest = getJava( "java.security.MessageDigest" ).getInstance( instance.hashAlgorithm );
				local.digest.reset();
				local.digest.update( instance.ESAPI.securityConfiguration().getMasterSalt() );
				local.digest.update( getJava( "java.lang.String" ).init( arguments.salt ).getBytes() );
				local.digest.update( getJava( "java.lang.String" ).init( arguments.plaintext ).getBytes() );

				// rehash a number of times to help strengthen weak passwords
				local.bytes = local.digest.digest();
				for(local.i = 0; local.i < 1024; local.i++) {
					local.digest.reset();
					local.bytes = local.digest.digest( local.bytes );
				}
				local.encoded = instance.ESAPI.encoder().encodeForBase64( local.bytes, false );
				return local.encoded;
			}
			catch(java.security.NoSuchAlgorithmException e) {
				throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.EncryptionException" ).init( instance.ESAPI, "Internal error", "Can't find hash algorithm " & instance.hashAlgorithm, e ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encryptString" output="false">
		<cfargument required="true" type="String" name="plaintext"/>

		<cfscript>
			var local = {};

			// Note - Cipher is not threadsafe so we create one locally
			try {
				local.encrypter = getJava( "javax.crypto.Cipher" ).getInstance( instance.encryptAlgorithm );
				local.encrypter.init( getJava( "javax.crypto.Cipher" ).ENCRYPT_MODE, instance.secretKey, instance.parameterSpec );
				local.output = arguments.plaintext.getBytes( instance.encoding );
				local.enc = local.encrypter.doFinal( local.output );
				return instance.ESAPI.encoder().encodeForBase64( local.enc, false );
			}
			catch(java.lang.Exception e) {
				throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.EncryptionException" ).init( instance.ESAPI, "Encryption failure", "Encryption problem: " & e.getMessage(), e ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="decryptString" output="false">
		<cfargument required="true" type="String" name="ciphertext"/>

		<cfscript>
			var local = {};

			// Note - Cipher is not threadsafe so we create one locally
			try {
				local.decrypter = getJava( "javax.crypto.Cipher" ).getInstance( instance.encryptAlgorithm );
				local.decrypter.init( getJava( "javax.crypto.Cipher" ).DECRYPT_MODE, instance.secretKey, instance.parameterSpec );
				local.dec = instance.ESAPI.encoder().decodeFromBase64( arguments.ciphertext );
				local.output = local.decrypter.doFinal( local.dec );
				return getJava( "java.lang.String" ).init( local.output, instance.encoding );
			}
			catch(java.lang.Exception e) {
				throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.EncryptionException" ).init( instance.ESAPI, "Decryption failed", "Decryption problem: " & e.getMessage(), e ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="sign" output="false">
		<cfargument required="true" type="String" name="data"/>

		<cfscript>
			var local = {};

			try {
				local.signer = getJava( "java.security.Signature" ).getInstance( instance.signatureAlgorithm );
				local.signer.initSign( instance.privateKey );
				local.signer.update( getJava( "java.lang.String" ).init( arguments.data ).getBytes() );
				local.bytes = local.signer.sign();
				return instance.ESAPI.encoder().encodeForBase64( local.bytes, true );
			}
			catch(java.lang.Exception e) {
				throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.EncryptionException" ).init( instance.ESAPI, "Signature failure", "Can't find signature algorithm " & instance.signatureAlgorithm, e ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="verifySignature" output="false">
		<cfargument required="true" type="String" name="signature"/>
		<cfargument required="true" type="String" name="data"/>

		<cfscript>
			var local = {};

			try {
				local.bytes = instance.ESAPI.encoder().decodeFromBase64( arguments.signature );
				local.signer = getJava( "java.security.Signature" ).getInstance( instance.signatureAlgorithm );
				local.signer.initVerify( instance.publicKey );
				local.signer.update( getJava( "java.lang.String" ).init( arguments.data ).getBytes() );
				return local.signer.verify( local.bytes );
			}
			catch(java.lang.Exception e) {
				createObject( "component", "esapi4cf.org.owasp.esapi.errors.EncryptionException" ).init( instance.ESAPI, "Invalid signature", "Problem verifying signature: " & e.getMessage(), e );
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="seal" output="false">
		<cfargument required="true" type="String" name="data"/>
		<cfargument required="true" type="numeric" name="timestamp"/>

		<cfscript>
			var local = {};

			try {
				// mix in some random data so even identical data and timestamp produces different seals
				local.random = instance.ESAPI.randomizer().getRandomString( 10, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
				return this.encryptString( arguments.timestamp & ":" & local.random & ":" & arguments.data );
			}
			catch(esapi4cf.org.owasp.esapi.errors.EncryptionException e) {
				throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.IntegrityException" ).init( instance.ESAPI, e.message, e.detail, e ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="unseal" output="false">
		<cfargument required="true" type="String" name="seal"/>

		<cfscript>
			var local = {};

			local.plaintext = "";
			try {
				local.plaintext = decryptString( arguments.seal );
			}
			catch(esapi4cf.org.owasp.esapi.errors.EncryptionException e) {
				throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.EncryptionException" ).init( instance.ESAPI, "Invalid seal", "Seal did not decrypt properly", e ) );
			}

			local.index = local.plaintext.indexOf( ":" );
			if(local.index == -1) {
				throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.EncryptionException" ).init( instance.ESAPI, "Invalid seal", "Seal did not contain properly formatted separator" ) );
			}

			local.timestring = local.plaintext.substring( 0, local.index );
			local.now = getJava( "java.util.Date" ).init().getTime();
			local.expiration = getJava( "java.lang.Long" ).init( local.timestring );
			if(local.now > local.expiration) {
				throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.EncryptionException" ).init( instance.ESAPI, "Invalid seal", "Seal expiration date has expired" ) );
			}

			local.index = local.plaintext.indexOf( ":", local.index + 1 );
			local.sealedValue = local.plaintext.substring( local.index + 1 );
			return local.sealedValue;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="verifySeal" output="false">
		<cfargument required="true" type="String" name="seal"/>

		<cfscript>
			try {
				unseal( arguments.seal );
				return true;
			}
			catch(esapi4cf.org.owasp.esapi.errors.EncryptionException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getTimeStamp" output="false">

		<cfscript>
			return javaCast( "long", getJava( "java.util.Date" ).init().getTime() );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getRelativeTimeStamp" output="false">
		<cfargument required="true" type="numeric" name="offset"/>

		<cfscript>
			return javaCast( "long", getJava( "java.util.Date" ).init().getTime() + arguments.offset );
		</cfscript>

	</cffunction>

</cfcomponent>