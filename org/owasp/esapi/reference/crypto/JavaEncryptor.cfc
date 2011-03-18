<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.Encryptor" output="false">

	<cfscript>
		importClass("javax.crypto.Cipher");

		instance.ESAPI = "";

		instance.initialized = false;

	    // encryption
	    instance.secretKeySpec = ""; // DISCUSS: Why static? Implies one key?!?
	    instance.encryptAlgorithm = "AES";
	    instance.encoding = "UTF-8";
	    //instance.encryptionKeyLength = 128;

	    // digital signatures
	    instance.privateKey = "";
		instance.publicKey = "";
		instance.signatureAlgorithm = "SHA1withDSA";
	    instance.randomAlgorithm = "SHA1PRNG";
		instance.signatureKeyLength = 1024;

    	// hashing
    	instance.hashAlgorithm = "SHA-512";
    	instance.hashIterations = 1024;

		instance.logger = "";

	    // Used to print out warnings about deprecated methods.
		instance.encryptCounter = 0;
		instance.decryptCounter = 0;

		instance.logEveryNthUse = 25;

    	static.DECRYPTION_FAILED = "Decryption failed; see logs for details.";
    	static.N_SECS = 2;
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Encryptor" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("JavaEncryptor");

			CryptoHelper = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI);

			local.salt = instance.ESAPI.securityConfiguration().getMasterSalt();
	        local.skey = instance.ESAPI.securityConfiguration().getMasterKey();

			if (isNull(local.salt)) {
				throw(message="Can't obtain master salt, Encryptor.MasterSalt");
			}
	        if (!len(local.salt) >= 16) {
	       		throw(message="Encryptor.MasterSalt must be at least 16 bytes. Length is: " & local.salt.length & " bytes.");
	        }
	        if (isNull(local.skey)) {
	        	throw(message="Can't obtain master key, Encryptor.MasterKey");
	        }
	        if (!len(local.skey) >= 7) {
	        	throw(message="Encryptor.MasterKey must be at least 7 bytes. Length is: " & local.skey.length & " bytes.");
	        }

	        // Set up secretKeySpec for use for symmetric encryption and decryption,
	        // and set up the public/private keys for asymmetric encryption /
	        // decryption.
	        // TODO: Note: If we dump ESAPI 1.4 crypto backward compatibility,
	        //       then we probably will ditch the Encryptor.EncryptionAlgorithm
	        //       property. If so, encryptAlgorithm should probably use
	        //       Encryptor.CipherTransformation and just pull off the cipher
	        //       algorithm name so we can use it here.
            if ( ! instance.initialized ) {
                //
                // For symmetric encryption
                //
                //      NOTE: FindBugs complains about this
                //            (ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD) but
                //            it should be OK since it is synchronized and only
                //            done once. While we could separate this out and
                //            handle in a static initializer, it just seems to
                //            fit better here.
                instance.secretKeySpec = createObject("java", "javax.crypto.spec.SecretKeySpec").init(local.skey, instance.encryptAlgorithm );

                //
                // For asymmetric encryption (i.e., public/private key)
                //
                try {
                    local.prng = createObject("java", "java.security.SecureRandom").getInstance(instance.randomAlgorithm);

                    // Because hash() is not static (but it could be were in not
                    // for the interface method specification in Encryptor), we
                    // cannot do this initialization in a static method or static
                    // initializer.
                    local.seed = this.hash(createObject("java", "java.lang.String").init(local.skey, instance.encoding), createObject("java", "java.lang.String").init(local.salt, instance.encoding)).getBytes(instance.encoding);
                    local.prng.setSeed(local.seed);
                    initKeyPair(local.prng);
                } catch (java.lang.Exception e) {
                    cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption failure", "Error creating Encryptor", e);
	           		throw(message=cfex.getMessage(), type=cfex.getType());
                }

                // Mark everything as initialized.
                instance.initialized = true;
            }

	        return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="hash" output="false" hint="Hashes the data using the specified algorithm and the Java MessageDigest class. This method first adds the salt, a separator (':'), and the data, and then rehashes the specified number of iterations in order to help strengthen weak passwords.">
		<cfargument type="String" name="plaintext" required="true">
		<cfargument type="String" name="salt" required="true">
		<cfargument type="numeric" name="iterations" required="false" default="#instance.hashIterations#">
		<cfscript>
			local.bytes = "";
			try {
				local.digest = createObject("java", "java.security.MessageDigest").getInstance(instance.hashAlgorithm);
				local.digest.reset();
				local.digest.update(instance.ESAPI.securityConfiguration().getMasterSalt());
				local.digest.update(arguments.salt.getBytes(instance.encoding));
				local.digest.update(arguments.plaintext.getBytes(instance.encoding));

				// rehash a number of times to help strengthen weak passwords
				local.bytes = local.digest.digest();
				for (local.i = 0; local.i < arguments.iterations; local.i++) {
					local.digest.reset();
					local.bytes = local.digest.digest(local.bytes);
				}
				local.encoded = instance.ESAPI.encoder().encodeForBase64(local.bytes,false);
				return local.encoded;
			} catch (java.security.NoSuchAlgorithmException e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Internal error", "Can't find hash algorithm " & instance.hashAlgorithm, e);
				throw(message=cfex.getMessage(), type=cfex.getType());
			} catch (java.io.UnsupportedEncodingException ex) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Internal error", "Can't find encoding for " & instance.encoding, ex);
				throw(message=cfex.getMessage(), type=cfex.getType());
			}
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="void" name="initKeyPair" output="false" hint="Set up signing key pair using the master password and salt. Called (once) from the JavaEncryptor CTOR.">
		<cfargument type="any" name="prng" required="true" hint="java.security.SecureRandom">
		<cfscript>
	        local.sigAlg = instance.signatureAlgorithm.toLowerCase();
	        if ( local.sigAlg.endsWith("withdsa") ) {
	            //
	            // Admittedly, this is a kludge. However for Sun JCE, even though
	            // "SHA1withDSA" is a valid signature algorithm name, if one calls
	            //      KeyPairGenerator kpg = KeyPairGenerator.getInstance("SHA1withDSA");
	            // that will throw a NoSuchAlgorithmException with an exception
	            // message of "SHA1withDSA KeyPairGenerator not available". Since
	            // SHA1withDSA and DSA keys should be identical, we use "DSA"
	            // in the case that SHA1withDSA or SHAwithDSA was specified. This is
	            // all just to make these 2 work as expected. Sigh. (Note:
	            // this was tested with JDK 1.6.0_21, but likely fails with earlier
	            // versions of the JDK as well.)
	            //
	            local.sigAlg = "DSA";
	        } else if ( local.sigAlg.endsWith("withrsa") ) {
	            // Ditto for RSA.
	            local.sigAlg = "RSA";
	        }
	        local.keyGen = createObject("java", "java.security.KeyPairGenerator").getInstance(local.sigAlg);
	        local.keyGen.initialize(instance.signatureKeyLength, prng);
	        local.pair = local.keyGen.generateKeyPair();
	        instance.privateKey = local.pair.getPrivate();
	        instance.publicKey = local.pair.getPublic();
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="encrypt" output="false" hint="Convenience method that encrypts plaintext strings the new way (default is CBC mode and PKCS5 padding). This encryption method uses the master encryption key specified by the Encryptor.MasterKey property in ESAPI.properties.">
		<cfargument type="any" name="key" required="false" hint="javax.crypto.SecretKey">
		<cfargument type="any" name="plain" required="true" hint="A String to be encrypted">
		<cfscript>
			if (!structKeyExists(arguments, "key")) {
				if (isInstanceOf(arguments.plain, "cfesapi.org.owasp.esapi.crypto.PlainText")) {
					// Now more of a convenience function for using the master key.
			 		return this.encrypt(instance.secretKeySpec, arguments.plain);
				}
				else {
					logWarning("encrypt", "Calling deprecated encrypt() method.");
					local.ct = this.encrypt(plain=createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, arguments.plain) );
					return local.ct.getEncodedIVCipherText();
				}
			}

	        local.plaintext = arguments.plain.asBytes();
			local.overwritePlaintext = instance.ESAPI.securityConfiguration().overwritePlainText();
			assert(!isNull(arguments.key), "(Master) encryption key may not be null");

			local.success = false;	// Used in 'finally' clause.
			local.xform = "";
			local.keySize = len(arguments.key.getEncoded()) * 8;	// Convert to # bits

			try {
				local.xform = instance.ESAPI.securityConfiguration().getCipherTransformation();
				local.parts = local.xform.split("/");
				assert(arrayLen(local.parts) == 3, "Malformed cipher transformation: " & local.xform);
				local.cipherMode = local.parts[2];

				// This way we can prevent modes like OFB and CFB where the IV should never
				// be repeated with the same encryption key (at least until we support
				// Encryptor.ChooseIVMethod=specified and allow us to specify some mechanism
				// to ensure the IV will never be repeated (such as a time stamp or other
				// monotonically increasing function).
				// DISCUSS: Should we include the permitted cipher modes in the exception msg?

				if ( ! CryptoHelper.isAllowedCipherMode(local.cipherMode) ) {
				    cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption failure: invalid cipher mode (" & local.cipherMode & ") for encryption", "Encryption failure: Cipher transformation " & local.xform & " specifies invalid cipher mode " & local.cipherMode);
					throw(message=cfex.getMessage(), type=cfex.getType());
				}

				 // Note - Cipher is not thread-safe so we create one locally
				 //        Also, we need to change this eventually so other algorithms can
				 //        be supported. Eventually, there will be an encrypt() method that
				 //        takes a (new class) CryptoControls, as something like this:
				 //          public CipherText encrypt(CryptoControls ctrl, SecretKey skey, PlainText plaintext)
				 //        and this method will just call that one.
				 local.encrypter = createObject("java", "javax.crypto.Cipher").getInstance(local.xform);
				 local.cipherAlg = local.encrypter.getAlgorithm();
				 local.keyLen = instance.ESAPI.securityConfiguration().getEncryptionKeyLength();

				 // DISCUSS: OK, what do we want to do here if keyLen != keySize? If use keyLen, encryption
				 //		     could fail with an exception, but perhaps that's what we want. Or we may just be
				 //			 OK with silently using keySize as long as keySize >= keyLen, which then interprets
				 //			 ESAPI.EncryptionKeyLength as the *minimum* key size, but as long as we have something
				 //			 stronger it's OK to use it. For now, I am just going to log warning if different, but use
				 //			 keySize unless keySize is SMALLER than ESAPI.EncryptionKeyLength, in which case I'm going
				 //			 to log an error.
				 //
				 //			 IMPORTANT NOTE:	When we generate key sizes for both DES and DESede the result of
				 //								SecretKey.getEncoding().length includes the TRUE key size (i.e.,
				 //								*with* the even parity bits) rather than the EFFECTIVE key size
				 //								(which incidentally is what KeyGenerator.init() expects for DES
				 //								and DESede; duh! Nothing like being consistent). This leads to
				 //								the following dilemma:
				 //
				 //													EFFECTIVE Key Size		TRUE Key Size
				 //													(KeyGenerator.init())	(SecretKey.getEncoding().length)
				 //									========================================================================
				 //									For DES:			56 bits					64 bits
				 //									For DESede:			112 bits / 168 bits		192 bits (always)
				 //
				 //								We are trying to automatically determine the key size from SecretKey
				 //								based on 8 * SecretKey.getEncoding().length, but as you can see, the
				 //								2 key 3DES and the 3 key 3DES both use the same key size (192 bits)
				 //								regardless of what is passed to KeyGenerator.init(). There are no advertised
				 //								methods to get the key size specified by the init() method so I'm not sure how
				 //								this is actually working internally. However, it does present a problem if we
				 //								wish to communicate the 3DES key size to a recipient for later decryption as
				 //								they would not be able to distinguish 2 key 3DES from 3 key 3DES.
				 //
				 //								The only workaround I know is to pass the explicit key size down. However, if
				 //								we are going to do that, I'd propose passing in a CipherSpec object so we could
				 //								tell what cipher transformation to use as well instead of just the key size. Then
				 //								we would extract keySize from the CipherSpec object of from the SecretKey object.
				 //
				 if ( local.keySize != local.keyLen ) {
					 // DISCUSS: Technically this is not a security "failure" per se, but not really a "success" either.
					 instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Encryption key length mismatch. ESAPI.EncryptionKeyLength is " & local.keyLen & " bits, but length of actual encryption key is " & local.keySize & " bits.  Did you remember to regenerate your master key (if that is what you are using)???");
				 }
				 // DISCUSS: Reconsider these warnings. If thousands of encryptions are done in tight loop, no one needs
				 //          more than 1 warning. Should we do something more intelligent here?
				 if ( local.keySize < local.keyLen ) {
					 // ESAPI.EncryptionKeyLength defaults to 128, but that means that we could not use DES (as weak as it
					 // is), even for legacy code. Therefore, this has been changed to simple log a warning rather than
					 //	throw the following exception.
					 //				 throw new ConfigurationException("Actual key size of " + keySize + " bits smaller than specified " +
					 //						  "encryption key length (ESAPI.EncryptionKeyLength) of " + keyLen + " bits.");
					 instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Actual key size of " & local.keySize & " bits SMALLER THAN specified encryption key length (ESAPI.EncryptionKeyLength) of " & local.keyLen & " bits with cipher algorithm " & local.cipherAlg);
				 }
				 if ( local.keySize < 112 ) {		// NIST Special Pub 800-57 considers 112-bits to be the minimally safe key size from 2010-2030.
					 instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Potentially unsecure encryption. Key size of " & local.keySize & "bits not sufficiently long for " & local.cipherAlg & ". Should use appropriate algorithm with key size of *at least* 112 bits except when required by legacy apps. See NIST Special Pub 800-57.");
				 }
				 // Check if algorithm mentioned in SecretKey is same as that being used for Cipher object.
				 // They should be the same. If they are different, things could fail. (E.g., DES and DESede
				 // require keys with even parity. Even if key was sufficient size, if it didn't have the correct
				 // parity it could fail.)
				 //
				 local.skeyAlg = arguments.key.getAlgorithm();
				 if ( !( local.cipherAlg.startsWith( local.skeyAlg & "/" ) || local.cipherAlg.equals( local.skeyAlg ) ) ) {
					 // DISCUSS: Should we thrown a ConfigurationException here or just log a warning??? I'm game for
					 //			 either, but personally I'd prefer the squeaky wheel to the annoying throwing of
					 //			 a ConfigurationException (which is a RuntimeException). Less likely to upset
					 //			 the development community.
					 instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Encryption mismatch between cipher algorithm (" & local.cipherAlg & ") and SecretKey algorithm (" & local.skeyAlg & "). Cipher will use algorithm " & local.cipherAlg);
				 }

				 local.ivBytes = "";
				 local.cipherSpec = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherSpec").init(instance.ESAPI, local.encrypter, local.keySize);	// Could pass the ACTUAL (intended) key size

				 // Using cipher mode that supports *both* confidentiality *and* authenticity? If so, then
				 // use the specified SecretKey as-is rather than computing a derived key from it. We also
				 // don't expect a separate MAC in the specified CipherText object so therefore don't try
				 // to validate it.
				 local.preferredCipherMode = CryptoHelper.isCombinedCipherMode( local.cipherMode );
				 local.encKey = "";
				 if ( local.preferredCipherMode ) {
				     local.encKey = arguments.key;
				 } else {
				     local.encKey = CryptoHelper.computeDerivedKey( arguments.key, local.keySize, "encryption");	// Recommended by David A. Wagner
				 }

				 if ( local.cipherSpec.requiresIV() ) {
					 local.ivType = instance.ESAPI.securityConfiguration().getIVType();
					 local.ivSpec = "";
					 if ( local.ivType.equalsIgnoreCase("random") ) {
						 local.ivBytes = instance.ESAPI.randomizer().getRandomBytes(local.encrypter.getBlockSize());
					 } else if ( local.ivType.equalsIgnoreCase("fixed") ) {
						 local.fixedIVAsHex = instance.ESAPI.securityConfiguration().getFixedIV();
						 local.ivBytes = Hex.decode(local.fixedIVAsHex);
						 /* FUTURE		 } else if ( ivType.equalsIgnoreCase("specified")) {
				 		// FUTURE - TODO  - Create instance of specified class to use for IV generation and
				 		//					 use it to create the ivBytes. (The intent is to make sure that
				 		//				     1) IVs are never repeated for cipher modes like OFB and CFB, and
				 		//					 2) to screen for weak IVs for the particular cipher algorithm.
				 		//		In meantime, use 'random' for block cipher in feedback mode. Unlikely they will
				 		//		be repeated unless you are salting SecureRandom with same value each time. Anything
				 		//		monotonically increasing should be suitable, like a counter, but need to remember
				 		//		it across JVM restarts. Was thinking of using System.currentTimeMillis(). While
				 		//		it's not perfect it probably is good enough. Could even all (advanced) developers
				 		//      to define their own class to create a unique IV to allow them some choice, but
				 		//      definitely need to provide a safe, default implementation.
				  */
					 } else {
						// TODO: Update to add 'specified' once that is supported and added above.
						cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ConfigurationException").ini("Property Encryptor.ChooseIVMethod must be set to 'random' or 'fixed'");
						throw(message=cfex.getMessage(), type=cfex.getType());
					 }
					 local.ivSpec = createObject("java", "javax.crypto.spec.IvParameterSpec").init(local.ivBytes);
					 local.cipherSpec.setIV(local.ivBytes);
					 local.encrypter.init(Cipher.ENCRYPT_MODE, local.encKey, local.ivSpec);
				 } else {
					 local.encrypter.init(Cipher.ENCRYPT_MODE, local.encKey);
				 }
				 instance.logger.debug(javaLoader().create("org.owasp.esapi.Logger").EVENT_SUCCESS, "Encrypting with " & local.cipherSpec.toString());
				 local.raw = local.encrypter.doFinal(local.plaintext);
		         // Convert to CipherText.
		         local.ciphertext = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherText").init(ESAPI=instance.ESAPI, cipherSpec=local.cipherSpec, cipherText=local.raw);

				 // If we are using a "preferred" cipher mode--i.e., one that supports *both* confidentiality and
				 // authenticity, there is no point to store a separate MAC in the CipherText object. Thus we only
			           // do this when we are not using such a cipher mode.
				 if ( !local.preferredCipherMode ) {
				     // Compute derived key, and then use it to compute and store separate MAC in CipherText object.
				     local.authKey = CryptoHelper.computeDerivedKey( arguments.key, local.keySize, "authenticity");
				     local.ciphertext.computeAndStoreMAC(  local.authKey );
				 }
				 instance.logger.debug(javaLoader().create("org.owasp.esapi.Logger").EVENT_SUCCESS, "JavaEncryptor.encrypt(SecretKey,byte[],boolean,boolean) -- success!");
				 local.success = true;	// W00t!!!
				 return local.ciphertext;
			} catch (java.security.InvalidKeyException ike) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption failure: Invalid key exception.", "Requested key size: " & local.keySize & "bits greater than 128 bits. Must install unlimited strength crypto extension from Sun: " & ike.getMessage(), ike);
				throw(message=cfex.getMessage(), type=cfex.getType());
			} catch (cfesapi.org.owasp.esapi.errors.ConfigurationException cex) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption failure: Configuration error. Details in log.", "Key size mismatch or unsupported IV method. Check encryption key size vs. ESAPI.EncryptionKeyLength or Encryptor.ChooseIVMethod property.", cex);
				throw(message=cfex.getMessage(), type=cfex.getType());
			} catch (java.security.InvalidAlgorithmParameterException e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption failure (invalid IV)", "Encryption problem: Invalid IV spec: " & e.getMessage(), e);
				throw(message=cfex.getMessage(), type=cfex.getType());
			} catch (javax.crypto.IllegalBlockSizeException e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption failure (no padding used; invalid input size)", "Encryption problem: Invalid input size without padding (" & local.xform & "). " & e.getMessage(), e);
				throw(message=cfex.getMessage(), type=cfex.getType());
			} catch (javax.crypto.BadPaddingException e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption failure", "[Note: Should NEVER happen in encryption mode.] Encryption problem: " & e.getMessage(), e);
				throw(message=cfex.getMessage(), type=cfex.getType());
			} catch (java.security.NoSuchAlgorithmException e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption failure (unavailable cipher requested)", "Encryption problem: specified algorithm in cipher xform " & local.xform & " not available: " & e.getMessage(), e);
				throw(message=cfex.getMessage(), type=cfex.getType());
			} catch (javax.crypto.NoSuchPaddingException e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption failure (unavailable padding scheme requested)", "Encryption problem: specified padding scheme in cipher xform " & local.xform & " not available: " & e.getMessage(), e);
				throw(message=cfex.getMessage(), type=cfex.getType());
			} finally {
				// Don't overwrite anything in the case of exceptions because they may wish to retry.
				if ( local.success && local.overwritePlaintext ) {
					 arguments.plain.overwrite();		// Note: Same as overwriting 'plaintext' byte array.
				}
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="decrypt" output="false">
		<cfargument type="any" name="key" required="false" hint="javax.crypto.SecretKey">
		<cfargument type="any" name="ciphertext" required="true">
		<cfscript>
			if (!structKeyExists(arguments, "key")) {
				if (isInstanceOf(arguments.ciphertext, "cfesapi.org.owasp.esapi.crypto.CipherText")) {
					// Now more of a convenience function for using the master key.
		 			return this.decrypt(instance.secretKeySpec, arguments.ciphertext);
				}
				else {
					logWarning("decrypt", "Calling deprecated decrypt() method.");
					local.ct = "";
					try {
						// We assume that the default cipher transform was used to encrypt this.
						local.ct = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherText").init(instance.ESAPI);

						// Need to base64 decode the IV+ciphertext and extract the IV to set it in CipherText object.
						local.ivPlusRawCipherText = instance.ESAPI.encoder().decodeFromBase64(arguments.ciphertext);
						local.blockSize = local.ct.getBlockSize();	// Size in bytes.
						local.iv = newByte( local.blockSize );
						CryptoHelper.copyByteArray(local.ivPlusRawCipherText, local.iv, local.blockSize);	// Copy the first blockSize bytes into iv array
						local.cipherTextSize = len(local.ivPlusRawCipherText) - local.blockSize;
						local.rawCipherText = newByte( local.cipherTextSize );
						System.arraycopy(local.ivPlusRawCipherText, local.blockSize, local.rawCipherText, 0, local.cipherTextSize);
						local.ct.setIVandCiphertext(local.iv, local.rawCipherText);

						// Now the CipherText object should be prepared to use it to decrypt.
						local.plaintext = this.decrypt(ciphertext=local.ct);
						return local.plaintext.toString();	// Convert back to a Java String
					} catch (java.io.UnsupportedEncodingException e) {
						// Should never happen; UTF-8 should be in rt.jar.
						instance.logger.error(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "UTF-8 encoding not available! Decryption failed.", e);
						return "";	// CHECKME: Or re-throw or what? Could also use native encoding, but that's
						// likely to cause unexpected and undesired effects far downstream.
					} catch (java.ui.IOException e) {
						instance.logger.error(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Base64 decoding of IV+ciphertext failed. Decryption failed.", e);
						return "";
					}
				}
			}

		    local.start = System.nanoTime();  // Current time in nanosecs; used to prevent timing attacks
		    if ( isNull(arguments.key) ) {
		        throw(object=createObject("java", "java.lang.IllegalArgumentException").init("SecretKey arg may not be null"));
		    }
		    if ( isNull(arguments.ciphertext) ) {
		        throw(object=createObject("java", "java.lang.IllegalArgumentException").init("Ciphertext may arg not be null"));
		    }

		    if ( ! CryptoHelper.isAllowedCipherMode(arguments.ciphertext.getCipherMode()) ) {
		        // This really should be an illegal argument exception, but it could
		        // mean that a partner encrypted something using a cipher mode that
		        // you do not accept, so it's a bit more complex than that. Also
		        // throwing an IllegalArgumentException doesn't allow us to provide
		        // the two separate error messages or automatically log it.
		        cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, static.DECRYPTION_FAILED, "Invalid cipher mode " & arguments.ciphertext.getCipherMode() & " not permitted for decryption or encryption operations.");
				throw(message=cfex.getMessage(), type=cfex.getType());
		    }
		    instance.logger.debug(javaLoader().create("org.owasp.esapi.Logger").EVENT_SUCCESS, "Args valid for JavaEncryptor.decrypt(SecretKey,CipherText): " & arguments.ciphertext.toString());

		    local.plaintext = "";
		    local.caughtException = false;
		    local.progressMark = 0;
		    try {
		        // First we validate the MAC.
		        local.valid = CryptoHelper.isCipherTextMACvalid(arguments.key, arguments.ciphertext);
		        if ( !local.valid ) {
		            try {
		                // This is going to fail, but we want the same processing
		                // to occur as much as possible so as to prevent timing
		                // attacks. We _could_ just be satisfied by the additional
		                // sleep in the 'finally' clause, but an attacker on the
		                // same server who can run something like 'ps' can tell
		                // CPU time versus when the process is sleeping. Hence we
		                // try to make this as close as possible. Since we know
		                // it is going to fail, we ignore the result and ignore
		                // the (expected) exception.
		                handleDecryption(arguments.key, arguments.ciphertext); // Ignore return (should fail).
		            } catch(java.lang.Exception ex) {
		                ;   // Ignore
		            }
		            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, static.DECRYPTION_FAILED, "Decryption failed because MAC invalid for " & arguments.ciphertext.toString());
					throw(message=cfex.getMessage(), type=cfex.getType());
		        }
		        local.progressMark++;
		        // The decryption only counts if the MAC was valid.
		        local.plaintext = handleDecryption(arguments.key, arguments.ciphertext);
		        local.progressMark++;
		    } catch(cfesapi.org.owasp.esapi.errors.EncryptionException ex) {
		        local.caughtException = true;
		        local.logMsg = "";
		        switch( local.progressMark ) {
		        case 1:
		            local.logMsg = "Decryption failed because MAC invalid. See logged exception for details.";
		            break;
		        case 2:
		            local.logMsg = "Decryption failed because handleDecryption() failed. See logged exception for details.";
		            break;
		        default:
		            local.logMsg = "Programming error: unexpected progress mark == " & local.progressMark;
		        break;
		        }
		        instance.logger.error(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, local.logMsg);
		        cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, ex); // Re-throw
				throw(message=cfex.getMessage(), type=cfex.getType());
		    }
		    finally {
		        if ( local.caughtException ) {
		            // The rest of this code is to try to account for any minute differences
		            // in the time it might take for the various reasons that decryption fails
		            // in order to prevent any other possible timing attacks. Perhaps it is
		            // going overboard. If nothing else, if N_SECS is large enough, it might
		            // deter attempted repeated attacks by making them take much longer.
		            local.now = System.nanoTime();
		            local.elapsed = local.now - local.start;
		            local.NANOSECS_IN_SEC = 10*-9;//1000000000L; // nanosec is 10**-9 sec
		            local.nSecs = static.N_SECS * local.NANOSECS_IN_SEC;  // N seconds in nano seconds
		            if ( local.elapsed < local.nSecs ) {
		                // Want to sleep so total time taken is N seconds.
		                local.extraSleep = local.nSecs - local.elapsed;

		                // 'extraSleep' is in nanoseconds. Need to convert to a millisec
		                // part and nanosec part. Nanosec is 10**-9, millsec is
		                // 10**-3, so divide by (10**-9 / 10**-3), or 10**6 to
		                // convert to from nanoseconds to milliseconds.
		                local.millis = local.extraSleep / 10*6;//1000000L;
		                local.nanos  = (local.extraSleep - (local.millis * 10*6));//1000000L
		                assert(local.nanos >= 0 && local.nanos <= Integer.MAX_VALUE, "Nanosecs out of bounds; nanos = " & local.nanos);
		                try {
		                    //Thread.sleep(local.millis, local.nanos);
		                    sleep(local.millis);
		                } catch(java.lang.InterruptedException ex) {
		                    ;   // Ignore
		                }
		            } // Else ... time already exceeds N_SECS sec, so do not sleep.
		        }
		    }
		    return local.plaintext;
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="cfesapi.org.owasp.esapi.crypto.PlainText" name="handleDecryption" output="false" hint="Handle the actual decryption portion. At this point it is assumed that any MAC has already been validated. (But see 'DISCUSS' issue, below.)">
		<cfargument type="any" name="key" required="true" hint="javax.crypto.SecretKey">
		<cfargument type="cfesapi.org.owasp.esapi.crypto.CipherText" name="ciphertext" required="true">
		<cfscript>
	        local.keySize = 0;
	        try {
	            local.decrypter = createObject("java", "javax.crypto.Cipher").getInstance(arguments.ciphertext.getCipherTransformation());
	            local.keySize = len(arguments.key.getEncoded()) * 8;  // Convert to # bits

	            // Using cipher mode that supports *both* confidentiality *and* authenticity? If so, then
	            // use the specified SecretKey as-is rather than computing a derived key from it. We also
	            // don't expect a separate MAC in the specified CipherText object so therefore don't try
	            // to validate it.
	            local.preferredCipherMode = CryptoHelper.isCombinedCipherMode( arguments.ciphertext.getCipherMode() );
	            local.encKey = "";
	            if ( local.preferredCipherMode ) {
	                local.encKey = arguments.key;
	            } else {
	                // TODO: PERFORMANCE: Calculate avg time this takes and consider caching for very short interval
	                //       (e.g., 2 to 5 sec tops). Otherwise doing lots of encryptions in a loop could take a LOT longer.
	                //       But remember Jon Bentley's "Rule #1 on performance: First make it right, then make it fast."
	                local.encKey = CryptoHelper.computeDerivedKey( arguments.key, local.keySize, "encryption");   // Recommended by David A. Wagner
	            }
	            if ( arguments.ciphertext.requiresIV() ) {
	                local.decrypter.init(Cipher.DECRYPT_MODE, local.encKey, createObject("java", "javax.crypto.spec.IvParameterSpec").init(arguments.ciphertext.getIV()));
	            } else {
	                local.decrypter.init(Cipher.DECRYPT_MODE, local.encKey);
	            }
	            local.output = local.decrypter.doFinal(arguments.ciphertext.getRawCipherText());
	            return createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, local.output);

	        } catch (java.security.InvalidKeyException ike) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, DECRYPTION_FAILED, "Must install JCE Unlimited Strength Jurisdiction Policy Files from Sun", ike);
				throw(message=cfex.getMessage(), type=cfex.getType());
	        } catch (java.security.NoSuchAlgorithmException e) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, DECRYPTION_FAILED, "Invalid algorithm for available JCE providers - " & arguments.ciphertext.getCipherTransformation() & ": " & e.getMessage(), e);
				throw(message=cfex.getMessage(), type=cfex.getType());
	        } catch (javax.crypto.NoSuchPaddingException e) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, DECRYPTION_FAILED, "Invalid padding scheme (" & arguments.ciphertext.getPaddingScheme() & ") for cipher transformation " & arguments.ciphertext.getCipherTransformation() & ": " & e.getMessage(), e);
				throw(message=cfex.getMessage(), type=cfex.getType());
	        } catch (java.security.InvalidAlgorithmParameterException e) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, DECRYPTION_FAILED, "Decryption problem: " & e.getMessage(), e);
				throw(message=cfex.getMessage(), type=cfex.getType());
	        } catch (javax.crypto.IllegalBlockSizeException e) {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, DECRYPTION_FAILED, "Decryption problem: " & e.getMessage(), e);
				throw(message=cfex.getMessage(), type=cfex.getType());
	        } catch (javax.crypto.BadPaddingException e) {
	            //DISCUSS: This needs fixed. Already validated MAC in CryptoHelper.isCipherTextMACvalid() above.
	            //So only way we could get a padding exception is if invalid padding were used originally by
	            //the party doing the encryption. (This might happen with a buggy padding scheme for instance.)
	            //It *seems* harmless though, so will leave it for now, and technically, we need to either catch it
	            //or declare it in a throws class. Clearly we don't want to do the later. This should be discussed
	            //during a code inspection.
	            try {
	                local.authKey = CryptoHelper.computeDerivedKey( arguments.key, local.keySize, "authenticity");
	            } catch (java.lang.Exception e1) {
	                cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, DECRYPTION_FAILED, "Decryption problem -- failed to compute derived key for authenticity: " & e1.getMessage(), e1);
					throw(message=cfex.getMessage(), type=cfex.getType());
	            }
	            local.success = arguments.ciphertext.validateMAC( local.authKey );
	            if ( local.success ) {
	                cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, DECRYPTION_FAILED, "Decryption problem: " & e.getMessage(), e);
					throw(message=cfex.getMessage(), type=cfex.getType());
	            } else {
	                cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, DECRYPTION_FAILED, "Decryption problem: WARNING: Adversary may have tampered with CipherText object orCipherText object mangled in transit: " & e.getMessage(), e);
					throw(message=cfex.getMessage(), type=cfex.getType());
	            }
	        }
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="sign" output="false">
		<cfargument type="String" name="data" required="true">
		<cfscript>
			try {
				local.signer = createObject("java", "java.security.Signature").getInstance(instance.signatureAlgorithm);
				local.signer.initSign(instance.privateKey);
				local.signer.update(arguments.data.getBytes(instance.encoding));
				local.bytes = local.signer.sign();
				return instance.ESAPI.encoder().encodeForBase64(local.bytes, false);
			} catch (java.security.InvalidKeyException ike) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption failure", "Must install unlimited strength crypto extension from Sun", ike);
				throw(message=cfex.getMessage(), type=cfex.getType());
			} catch (java.lang.Exception e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Signature failure", "Can't find signature algorithm " & instance.signatureAlgorithm, e);
				throw(message=cfex.getMessage(), type=cfex.getType());
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="verifySignature" output="false">
		<cfargument type="String" name="signature" required="true">
		<cfargument type="String" name="data" required="true">
		<cfscript>
			try {
				local.bytes = instance.ESAPI.encoder().decodeFromBase64(arguments.signature);
				local.signer = createObject("java", "java.security.Signature").getInstance(instance.signatureAlgorithm);
				local.signer.initVerify(instance.publicKey);
				local.signer.update(arguments.data.getBytes(instance.encoding));
				return local.signer.verify(local.bytes);
			} catch (java.lang.Exception e) {
			    // NOTE: EncryptionException constructed *only* for side-effect of causing logging.
			    // FindBugs complains about this and since it examines byte-code, there's no way to
			    // shut it up.
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Invalid signature", "Problem verifying signature: " & e.getMessage(), e);
				throw(message=cfex.getMessage(), type=cfex.getType());
				return false;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="seal" output="false">
		<cfargument type="String" name="data" required="true">
		<cfargument type="numeric" name="timestamp" required="true">
		<cfscript>
			try {
			    local.b64data = "";
	            try {
	                local.b64data = instance.ESAPI.encoder().encodeForBase64(arguments.data.getBytes("UTF-8"), false);
	            } catch (java.io.UnsupportedEncodingException e) {
	                ; // Ignore; should never happen since UTF-8 built into rt.jar
	            }
				// mix in some random data so even identical data and timestamp produces different seals
				local.nonce = instance.ESAPI.randomizer().getRandomString(10, javaLoader().create("org.owasp.esapi.EncoderConstants").CHAR_ALPHANUMERICS);
				local.plaintext = arguments.timestamp & ":" & local.nonce & ":" & local.b64data;
				// add integrity check; signature is already base64 encoded.
				local.sig = this.sign( local.plaintext );
				local.ciphertext = this.encrypt( plain=createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, local.plaintext & ":" & local.sig) );
				local.sealedData = instance.ESAPI.encoder().encodeForBase64(local.ciphertext.asPortableSerializedByteArray(), false);
				return local.sealedData;
			} catch( cfesapi.org.owasp.esapi.errors.EncryptionException e ) {
				throw(object=createObject("java", "java.lang.IntegrityException").init( e.getUserMessage(), e.getLogMessage(), e ));
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="unseal" output="false">
		<cfargument type="String" name="seal" required="true">
		<cfscript>
			local.plaintext = "";
			try {
			    local.encryptedBytes = instance.ESAPI.encoder().decodeFromBase64(arguments.seal);
			    local.cipherText = "";
			    try {
			        local.cipherText = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherText").init(instance.ESAPI).fromPortableSerializedBytes(local.encryptedBytes);
			    } catch( java.lang.AssertionError e) {
		            // Some of the tests in EncryptorTest.testVerifySeal() are examples of this if assertions are enabled.
			        cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Invalid seal", "Seal passed garbarge data resulting in AssertionError: " & e);
					throw(message=cfex.getMessage(), type=cfex.getType());
		        }
				local.plaintext = this.decrypt(ciphertext=local.cipherText);

				local.parts = local.plaintext.toString().split(":");
				if (arrayLen(local.parts) != 4) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Invalid seal", "Seal was not formatted properly.");
					throw(message=cfex.getMessage(), type=cfex.getType());
				}

				local.timestring = local.parts[1];
				local.now = createObject("java", "java.util.Date").init().getTime();
				local.expiration = createObject("java", "java.lang.Long").parseLong(local.timestring);
				if (local.now > local.expiration) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Invalid seal", "Seal expiration date of " & createObject("java", "java.util.Date").init(local.expiration) & " has past.");
					throw(message=cfex.getMessage(), type=cfex.getType());
				}
				local.nonce = local.parts[2];
				local.b64data = local.parts[3];
				local.sig = local.parts[4];
				if (!this.verifySignature(local.sig, local.timestring & ":" & local.nonce & ":" & local.b64data ) ) {
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Invalid seal", "Seal integrity check failed");
					throw(message=cfex.getMessage(), type=cfex.getType());
				}
				return createObject("java", "java.lang.String").init(instance.ESAPI.encoder().decodeFromBase64(local.b64data), "UTF-8");
			} catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
				throw(message=e.getMessage(), type=e.getType());
			} catch (java.lang.Exception e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Invalid seal", "Invalid seal:" & e.getMessage(), e);
				throw(message=cfex.getMessage(), type=cfex.getType());
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="verifySeal" output="false">
		<cfargument type="String" name="seal" required="true">
		<cfscript>
			try {
				unseal( arguments.seal );
				return true;
			} catch( cfesapi.org.owasp.esapi.errors.EncryptionException e ) {
				return false;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getTimeStamp" output="false">
		<cfscript>
			return createObject("java", "java.util.Date").init().getTime();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getRelativeTimeStamp" output="false">
		<cfargument type="numeric" name="offset" required="true">
		<cfscript>
			return newLong(createObject("java", "java.util.Date").init().getTime() + arguments.offset).longValue();
		</cfscript>
	</cffunction>

	<cffunction access="private" returntype="void" name="logWarning" output="false" hint="Log a security warning every Nth time one of the deprecated encrypt or decrypt methods are called. ('N' is hard-coded to be 25 by default, but may be changed via the system property ESAPI.Encryptor.warnEveryNthUse.) In other words, we nag them until the give in and change it. ;-)">
		<cfargument type="String" name="where" required="true" hint="The string 'encrypt' or 'decrypt', corresponding to the method that is being logged.">
		<cfargument type="String" name="msg" required="true" hint="The message to log.">
		<cfscript>
	        local.counter = 0;
	        if ( arguments.where.equals("encrypt") ) {
	            local.counter = instance.encryptCounter++;
	            arguments.where = "JavaEncryptor.encrypt(): [count=" & local.counter &"]";
	        } else if ( arguments.where.equals("decrypt") ) {
	            local.counter = instance.decryptCounter++;
	            arguments.where = "JavaEncryptor.decrypt(): [count=" & local.counter &"]";
	        } else {
	            arguments.where = "JavaEncryptor: Unknown method: ";
	        }
	        // We log the very first time (note the use of post-increment on the
	        // counters) and then every Nth time thereafter. Logging every single
	        // time is likely to be way too much logging.
	        if ( (local.counter % instance.logEveryNthUse) == 0 ) {
	            instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, arguments.where & arguments.msg);
	        }
    	</cfscript>
	</cffunction>

	<!--- setupAlgorithms --->
	<!--- initKeyPair --->

</cfcomponent>
