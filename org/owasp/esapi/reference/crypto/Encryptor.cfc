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
import "org.owasp.esapi.errors.EncryptionException";
import "org.owasp.esapi.crypto.CryptoHelper";
import "org.owasp.esapi.crypto.CipherSpec";
import "org.owasp.esapi.crypto.CipherText";
import "org.owasp.esapi.crypto.PlainText";
import "org.owasp.esapi.crypto.KeyDerivationFunction";
import "org.owasp.esapi.crypto.SecurityProviderLoader";

/**
 * Reference implementation of the {@code Encryptor} interface. This implementation
 * layers on the JCE provided cryptographic package. Algorithms used are
 * configurable in the {@code ESAPI.properties} file. The main property
 * controlling the selection of this class is {@code ESAPI.Encryptor}. Most of
 * the other encryption related properties have property names that start with
 * the string "Encryptor.".
 */
component implements="org.owasp.esapi.Encryptor" extends="org.owasp.esapi.util.Object" {

	variables.ESAPI = "";
	variables.logger = "";

	 // encryption
	variables.secretKeySpec = "";
	variables.encryptAlgorithm = "AES";
	variables.encoding = "UTF-8";
	variables.encryptionKeyLength = 128;

	// digital signatures
	variables.privateKey = "";
	variables.publicKey = "";
	variables.signatureAlgorithm = "SHA1withDSA";
	variables.randomAlgorithm = "SHA1PRNG";
	variables.signatureKeyLength = 1024;

	// hashing
	variables.hashAlgorithm = "SHA-512";
	variables.hashIterations = 1024;


	    // Used to print out warnings about deprecated methods.
	variables.encryptCounter = 0;
	variables.decryptCounter = 0;
        // DISCUSS: OK to not have a property for this to set the frequency?
        //          The desire is to persuade people to move away from these
	    //          two deprecated encrypt(String) / decrypt(String) methods,
        //          so perhaps the annoyance factor of not being able to
        //          change it will help. For now, it is just hard-coded here.
        //          We could be mean and just print a warning *every* time.
	variables.logEveryNthUse = 25;

    // *Only* use this string for user messages for EncryptionException when
    // decryption fails. This is to prevent information leakage that may be
    // valuable in various forms of ciphertext attacks, such as the
	// Padded Oracle attack described by Rizzo and Duong.
    variables.DECRYPTION_FAILED = "Decryption failed; see logs for details.";

    // # of seconds that all failed decryption attempts will take. Used to
    // help prevent side-channel timing attacks.
    variables.N_SECS = 2;

	public org.owasp.esapi.Encryptor function init(required org.owasp.esapi.ESAPI ESAPI) {
		variables.ESAPI = arguments.ESAPI;
		variables.logger = variables.ESAPI.getLogger("Encryptor");

		// Load the preferred JCE provider if one has been specified.
	    try {
	        new SecurityProviderLoader(variables.ESAPI).loadESAPIPreferredJCEProvider();
	    }
	    catch (java.security.NoSuchProviderException ex) {
	    	// Note that audit logging is done elsewhere in called method.
	        variables.logger.fatal(Logger.SECURITY_FAILURE, "JavaEncryptor failed to load preferred JCE provider.", ex);
	        raiseException(createObject("java", "java.lang.ExceptionInInitializerError").init(ex));
	    }
	    setupAlgorithms();

		var salt = variables.ESAPI.securityConfiguration().getMasterSalt();
        var skey = variables.ESAPI.securityConfiguration().getMasterKey();

        if (isNull(salt)) {
        	raiseException("Can't obtain master salt, Encryptor.MasterSalt");
        }
        else if (arrayLen(salt) < 16) {
        	raiseException("Encryptor.MasterSalt must be at least 16 bytes. Length is: " & arrayLen(salt) & " bytes.");
        }
        if (isNull(skey)) {
        	raiseException("Can't obtain master key, Encryptor.MasterKey");
        }
        else if (arrayLen(skey) < 7) {
        	raiseException("Encryptor.MasterKey must be at least 7 bytes. Length is: " & arrayLen(skey) & " bytes.");
        }

        // Set up secretKeySpec for use for symmetric encryption and decryption,
        // and set up the public/private keys for asymmetric encryption /
        // decryption.
        //
        // For symmetric encryption
        //
        //      NOTE: FindBugs complains about this
        //            (ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD) but
        //            it should be OK since it is synchronized and only
        //            done once. While we could separate this out and
        //            handle in a static initializer, it just seems to
        //            fit better here.
        variables.secretKeySpec = createObject("java", "javax.crypto.spec.SecretKeySpec").init(skey, variables.encryptAlgorithm);

        //
        // For asymmetric encryption (i.e., public/private key)
        //
        try {
            var prng = createObject("java", "java.security.SecureRandom").getInstance(variables.randomAlgorithm);

            // Because hash() is not static (but it could be were in not
            // for the interface method specification in Encryptor), we
            // cannot do this initialization in a static method or static
            // initializer.
            var seed = this.hash(toString(skey, variables.encoding), toString(salt, variables.encoding)).getBytes(variables.encoding);
            prng.setSeed(seed);
            initKeyPair(prng);
        }
        catch (Exception ex) {
            raiseException(new EncryptionException(variables.ESAPI, "Encryption failure", "Error creating Encryptor", ex));
        }

		return this;
	}

	/**
	 * Hashes the data using the specified algorithm and the Java MessageDigest class. This method
	 * first adds the salt, a separator (":"), and the data, and then rehashes the specified number of iterations
	 * in order to help strengthen weak passwords.
	 */
	public string function hash(required string plaintext, required string salt, numeric iterations=variables.hashIterations) {
		var bytes = "";
		try {
			var digest = createObject("java", "java.security.MessageDigest").getInstance(variables.hashAlgorithm);
			digest.reset();
			digest.update(variables.ESAPI.securityConfiguration().getMasterSalt());
			digest.update(arguments.salt.getBytes(variables.encoding));
			digest.update(arguments.plaintext.getBytes(variables.encoding));

			// rehash a number of times to help strengthen weak passwords
			bytes = digest.digest();
			for (var i = 0; i < arguments.iterations; i++) {
				digest.reset();
				bytes = digest.digest(bytes);
			}
			var encoded = variables.ESAPI.encoder().encodeForBase64(bytes,false);
			return encoded;
		}
		catch (java.security.NoSuchAlgorithmException ex) {
			raiseException(new EncryptionException(variables.ESAPI, "Internal error", "Can't find hash algorithm " & variables.hashAlgorithm, ex));
		}
		catch (java.io.UnsupportedEncodingException ex) {
			raiseException(new EncryptionException(variables.ESAPI, "Internal error", "Can't find encoding for " & variables.encoding, ex));
		}
	}

	public CipherText function encrypt(required PlainText plain, key=variables.secretKeySpec) {
		 if (isNull(arguments.key)) {
			 raiseException(createObject("java", "java.lang.IllegalArgumentException").init("(Master) encryption key arg may not be null. Is Encryptor.MasterKey set?"));
		 }
		 if (isNull(arguments.plain)) {
			 raiseException(createObject("java", "java.lang.IllegalArgumentException").init("PlainText argument may not be null"));
		 }
		 var plaintext = arguments.plain.asBytes();
		 var overwritePlaintext = variables.ESAPI.securityConfiguration().overwritePlainText();

		 var success = false;	// Used in 'finally' clause.
		 var xform = "";
		 var keySize = arrayLen(arguments.key.getEncoded()) * 8;	// Convert to # bits

		try {
			 xform = variables.ESAPI.securityConfiguration().getCipherTransformation();
             var parts = listToArray(xform, "/");
             if (arrayLen(parts) != 3) {
             	raiseException("Malformed cipher transformation: " & xform);
             }
             var cipherMode = parts[1];

             var CryptoHelper = new CryptoHelper(variables.ESAPI);

             // This way we can prevent modes like OFB and CFB where the IV should never
             // be repeated with the same encryption key (at least until we support
             // Encryptor.ChooseIVMethod=specified and allow us to specify some mechanism
             // to ensure the IV will never be repeated (such as a time stamp or other
             // monotonically increasing function).
             // DISCUSS: Should we include the permitted cipher modes in the exception msg?
             if (!CryptoHelper.isAllowedCipherMode(cipherMode)) {
                 raiseException(new EncryptionException(variables.ESAPI, "Encryption failure: invalid cipher mode (" & cipherMode & ") for encryption", "Encryption failure: Cipher transformation " & xform & " specifies invalid " & "cipher mode " & cipherMode));
             }

			 // Note - Cipher is not thread-safe so we create one locally
			 //        Also, we need to change this eventually so other algorithms can
			 //        be supported. Eventually, there will be an encrypt() method that
			 //        takes a (new class) CryptoControls, as something like this:
			 //          public CipherText encrypt(CryptoControls ctrl, SecretKey skey, PlainText plaintext)
			 //        and this method will just call that one.
			 var encrypter = createObject("java", "javax.crypto.Cipher").getInstance(xform);
			 var cipherAlg = encrypter.getAlgorithm();
			 var keyLen = variables.ESAPI.securityConfiguration().getEncryptionKeyLength();

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
			 if ( keySize != keyLen ) {
				 // DISCUSS: Technically this is not a security "failure" per se, but not really a "success" either.
				 logger.warning(Logger.SECURITY_FAILURE, "Encryption key length mismatch. ESAPI.EncryptionKeyLength is " &
						 keyLen & " bits, but length of actual encryption key is " & keySize &
				 		" bits.  Did you remember to regenerate your master key (if that is what you are using)???");
			 }
			 // DISCUSS: Reconsider these warnings. If thousands of encryptions are done in tight loop, no one needs
			 //          more than 1 warning. Should we do something more intelligent here?
			 if ( keySize < keyLen ) {
				 // ESAPI.EncryptionKeyLength defaults to 128, but that means that we could not use DES (as weak as it
				 // is), even for legacy code. Therefore, this has been changed to simple log a warning rather than
				 //	throw the following exception.
				 //				 throw new ConfigurationException("Actual key size of " & keySize & " bits smaller than specified " &
				 //						  "encryption key length (ESAPI.EncryptionKeyLength) of " & keyLen & " bits.");
				 logger.warning(Logger.SECURITY_FAILURE, "Actual key size of " & keySize & " bits SMALLER THAN specified " &
						 "encryption key length (ESAPI.EncryptionKeyLength) of " & keyLen & " bits with cipher algorithm " & cipherAlg);
			 }
			 if ( keySize < 112 ) {		// NIST Special Pub 800-57 considers 112-bits to be the minimally safe key size from 2010-2030.
				 						// Note that 112 bits 'just happens' to be size of 2-key Triple DES!
				 logger.warning(Logger.SECURITY_FAILURE, "Potentially unsecure encryption. Key size of " & keySize & "bits " &
				                "not sufficiently long for " & cipherAlg & ". Should use appropriate algorithm with key size " &
				                "of *at least* 112 bits except when required by legacy apps. See NIST Special Pub 800-57.");
			 }
			 // Check if algorithm mentioned in SecretKey is same as that being used for Cipher object.
			 // They should be the same. If they are different, things could fail. (E.g., DES and DESede
			 // require keys with even parity. Even if key was sufficient size, if it didn't have the correct
			 // parity it could fail.)
			 //
			 var skeyAlg = arguments.key.getAlgorithm();
			 if ( !( cipherAlg.startsWith( skeyAlg & "/" ) || cipherAlg.equals( skeyAlg ) ) ) {
				 // DISCUSS: Should we thrown a ConfigurationException here or just log a warning??? I'm game for
				 //			 either, but personally I'd prefer the squeaky wheel to the annoying throwing of
				 //			 a ConfigurationException (which is a RuntimeException). Less likely to upset
				 //			 the development community.
				 logger.warning(Logger.SECURITY_FAILURE, "Encryption mismatch between cipher algorithm (" &
						 cipherAlg & ") and SecretKey algorithm (" & skeyAlg & "). Cipher will use algorithm " & cipherAlg);
			 }

			 var ivBytes = "";
			 var cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipher=encrypter, keySize=keySize);	// Could pass the ACTUAL (intended) key size

             // Using cipher mode that supports *both* confidentiality *and* authenticity? If so, then
             // use the specified SecretKey as-is rather than computing a derived key from it. We also
             // don't expect a separate MAC in the specified CipherText object so therefore don't try
             // to validate it.
             var preferredCipherMode = CryptoHelper.isCombinedCipherMode( cipherMode );
             var encKey = "";
			 var KeyDerivationFunction = new KeyDerivationFunction(variables.ESAPI);
			 if ( preferredCipherMode ) {
			     encKey = arguments.key;
			 }
			 else {
			     encKey = computeDerivedKey(KeyDerivationFunction.kdfVersion, getDefaultPRF(), arguments.key, keySize, "encryption");
			 }

			 var Cipher = createObject("java", "javax.crypto.Cipher");
			 if ( cipherSpec.requiresIV() ) {
				 var ivType = variables.ESAPI.securityConfiguration().getIVType();
				 if ( ivType.equalsIgnoreCase("random") ) {
					 ivBytes = variables.ESAPI.randomizer().getRandomBytes(encrypter.getBlockSize());
				 }
				 else if ( ivType.equalsIgnoreCase("fixed") ) {
					 var fixedIVAsHex = variables.ESAPI.securityConfiguration().getFixedIV();
					 ivBytes = Hex.decode(fixedIVAsHex);
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
					 throw new ConfigurationException("Property Encryptor.ChooseIVMethod must be set to 'random' or 'fixed'");
				 }
				 var ivSpec = createObject("java", "javax.crypto.spec.IvParameterSpec").init(ivBytes);
				 cipherSpec.setIV(ivBytes);
				 encrypter.init(Cipher.ENCRYPT_MODE, encKey, ivSpec);
			 } else {
				 encrypter.init(Cipher.ENCRYPT_MODE, encKey);
			 }
			 variables.logger.debug(variables.Logger.EVENT_SUCCESS, "Encrypting with " & cipherSpec.toString());
			 var raw = encrypter.doFinal(plaintext);
                 // Convert to CipherText.
             var ciphertext = new CipherText(variables.ESAPI, cipherSpec, raw);

			 // If we are using a "preferred" cipher mode--i.e., one that supports *both* confidentiality and
			 // authenticity, there is no point to store a separate MAC in the CipherText object. Thus we only
             // do this when we are not using such a cipher mode.
			 if ( !preferredCipherMode ) {
			     // Compute derived key, and then use it to compute and store separate MAC in CipherText object.
			     var authKey = computeDerivedKey(KeyDerivationFunction.kdfVersion, getDefaultPRF(),
			    		 							   arguments.key, keySize, "authenticity");
			     ciphertext.computeAndStoreMAC(  authKey );
			 }
			 logger.debug(Logger.EVENT_SUCCESS, "JavaEncryptor.encrypt(SecretKey,byte[],boolean,boolean) -- success!");
			 success = true;	// W00t!!!
			 return ciphertext;
		} catch (InvalidKeyException ike) {
			 raiseException(new EncryptionException(variables.ESAPI, "Encryption failure: Invalid key exception.",
					 "Requested key size: " & keySize & "bits greater than 128 bits. Must install unlimited strength crypto extension from Sun: " &
					 ike.getMessage(), ike));
		 } catch (ConfigurationException cex) {
			 raiseException(new EncryptionException(variables.ESAPI, "Encryption failure: Configuration error. Details in log.", "Key size mismatch or unsupported IV method. " &
					 "Check encryption key size vs. ESAPI.EncryptionKeyLength or Encryptor.ChooseIVMethod property.", cex));
		 } catch (InvalidAlgorithmParameterException e) {
			 raiseException(new EncryptionException(variables.ESAPI, "Encryption failure (invalid IV)",
					 "Encryption problem: Invalid IV spec: " & e.getMessage(), e));
		 } catch (IllegalBlockSizeException e) {
			 raiseException(new EncryptionException(variables.ESAPI, "Encryption failure (no padding used; invalid input size)",
					 "Encryption problem: Invalid input size without padding (" & xform & "). " & e.getMessage(), e));
		 } catch (BadPaddingException e) {
			 raiseException(new EncryptionException(variables.ESAPI, "Encryption failure",
					 "[Note: Should NEVER happen in encryption mode.] Encryption problem: " & e.getMessage(), e));
		 } catch (java.security.NoSuchAlgorithmException e) {
			 raiseException(new EncryptionException(variables.ESAPI, "Encryption failure (unavailable cipher requested)",
					 "Encryption problem: specified algorithm in cipher xform " & xform & " not available: " & e.getMessage(), e));
		 } catch (NoSuchPaddingException e) {
			 raiseException(new EncryptionException(variables.ESAPI, "Encryption failure (unavailable padding scheme requested)",
					 "Encryption problem: specified padding scheme in cipher xform " & xform & " not available: " & e.getMessage(), e));
		 } finally {
			 // Don't overwrite anything in the case of exceptions because they may wish to retry.
			 if ( success && overwritePlaintext ) {
				 arguments.plain.overwrite();		// Note: Same as overwriting 'plaintext' byte array.
		}
	}
	}

	public PlainText function decrypt(required CipherText ciphertext, key=variables.secretKeySpec) {
	    var start = createObject("java", "java.lang.System").nanoTime();  // Current time in nanosecs; used to prevent timing attacks
	    if (isNull(arguments.key)) {
	        raiseException(createObject("java", "java.lang.IllegalArgumentException").init("SecretKey arg may not be null"));
	    }
	    if (isNull(arguments.ciphertext)) {
	        raiseException(createObject("java", "java.lang.IllegalArgumentException").init("Ciphertext may arg not be null"));
	    }

		var CryptoHelper = new CryptoHelper(variables.ESAPI);

	    if ( ! CryptoHelper.isAllowedCipherMode(arguments.ciphertext.getCipherMode()) ) {
	        // This really should be an illegal argument exception, but it could
	        // mean that a partner encrypted something using a cipher mode that
	        // you do not accept, so it's a bit more complex than that. Also
	        // throwing an IllegalArgumentException doesn't allow us to provide
	        // the two separate error messages or automatically log it.
	        raiseException(new EncryptionException(variables.ESAPI, variables.DECRYPTION_FAILED, "Invalid cipher mode " & arguments.ciphertext.getCipherMode() & " not permitted for decryption or encryption operations."));
	    }
	    variables.logger.debug(variables.Logger.EVENT_SUCCESS,
	            "Args valid for JavaEncryptor.decrypt(SecretKey,CipherText): " &
	            arguments.ciphertext.toString());

	    var plaintext = "";
	    var caughtException = false;
	    var progressMark = 0;
	    try {
	        // First we validate the MAC.
	        var valid = CryptoHelper.isCipherTextMACvalid(arguments.key, arguments.ciphertext);
	        if ( !valid ) {
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
	            } catch(Exception ex) {
	                ;   // Ignore
	            }
	            raiseException(new EncryptionException(variables.ESAPI, variables.DECRYPTION_FAILED, "Decryption failed because MAC invalid for " & arguments.ciphertext));
	        }
	        progressMark++;
	        // The decryption only counts if the MAC was valid.
	        plaintext = handleDecryption(arguments.key, arguments.ciphertext);
	        progressMark++;
	    } catch(org.owasp.esapi.errors.EncryptionException ex) {
	        caughtException = true;
	        var logMsg = "";
	        switch( progressMark ) {
	        case 1:
	            logMsg = "Decryption failed because MAC invalid. See logged exception for details.";
	            break;
	        case 2:
	            logMsg = "Decryption failed because handleDecryption() failed. See logged exception for details.";
	            break;
	        default:
	            logMsg = "Programming error: unexpected progress mark == " & progressMark;
	        break;
	        }
	        variables.logger.error(variables.Logger.SECURITY_FAILURE, logMsg);
	        throw ex;           // Re-throw
	    }
	    finally {
	        if ( caughtException ) {
	        	var Long = createObject("java", "java.lang.Long");
	            // The rest of this code is to try to account for any minute differences
	            // in the time it might take for the various reasons that decryption fails
	            // in order to prevent any other possible timing attacks. Perhaps it is
	            // going overboard. If nothing else, if N_SECS is large enough, it might
	            // deter attempted repeated attacks by making them take much longer.
	            var now = System.nanoTime();
	            var elapsed = now - start;
	            var NANOSECS_IN_SEC = Long.init("1000000000L"); // nanosec is 10**-9 sec
	            var nSecs = variables.N_SECS * NANOSECS_IN_SEC;  // N seconds in nano seconds
	            if ( elapsed < nSecs ) {
	                // Want to sleep so total time taken is N seconds.
	                var extraSleep = nSecs - elapsed;

	                // 'extraSleep' is in nanoseconds. Need to convert to a millisec
	                // part and nanosec part. Nanosec is 10**-9, millsec is
	                // 10**-3, so divide by (10**-9 / 10**-3), or 10**6 to
	                // convert to from nanoseconds to milliseconds.
	                var millis = extraSleep / Long.init("1000000L");
	                var nanos  = (extraSleep - (millis * Long.init("1000000L")));
	                if (nanos < 0 && nanos > Integer.MAX_VALUE) {
                            raiseException("Nanosecs out of bounds; nanos = " & nanos);
					}
	                try {
	                    Thread.sleep(millis, nanos);
	                } catch(InterruptedException ex) {
	                    ;   // Ignore
	                }
	            } // Else ... time already exceeds N_SECS sec, so do not sleep.
	        }
	    }
	    return plaintext;
	}


    // Handle the actual decryption portion. At this point it is assumed that
    // any MAC has already been validated. (But see "DISCUSS" issue, below.)
    private PlainText function handleDecryption(required key, required CipherText ciphertext) {
        var keySize = 0;
        try {
            var decrypter = createObject("java", "javax.crypto.Cipher").getInstance(arguments.ciphertext.getCipherTransformation());
            keySize = arrayLen(arguments.key.getEncoded()) * 8;  // Convert to # bits

            // Using cipher mode that supports *both* confidentiality *and* authenticity? If so, then
            // use the specified SecretKey as-is rather than computing a derived key from it. We also
            // don't expect a separate MAC in the specified CipherText object so therefore don't try
            // to validate it.
            var preferredCipherMode = new CryptoHelper(variables.ESAPI).isCombinedCipherMode( arguments.ciphertext.getCipherMode() );
            var encKey = "";
            if ( preferredCipherMode ) {
                encKey = arguments.key;
            } else {
                // TODO: PERFORMANCE: Calculate avg time this takes and consider caching for very short interval
                //       (e.g., 2 to 5 sec tops). Otherwise doing lots of encryptions in a loop could take a LOT longer.
                //       But remember Jon Bentley's "Rule #1 on performance: First make it right, then make it fast."
            	//		 This would be a security trade-off as it would leave keys in memory a bit longer, so it
            	//		 should probably be off by default and controlled via a property.
            	//
            	// TODO: Feed in some additional parms here to use as the 'context' for the
            	//		 KeyDerivationFunction...especially the KDF version. We would have to
            	//		 store that in the CipherText object. We *possibly* could make it
            	//		 transient so it would not be serialized with the CipherText object,
            	//		 otherwise we would have to implement readObject() and writeObject()
            	//		 methods there to support backward compatibility. Anyhow the intent
            	//		 is to prevent down grade attacks when we finally re-design and
            	//		 re-implement the MAC. Think about this in version 2.1.1.
                encKey = computeDerivedKey( arguments.ciphertext.getKDFVersion(), arguments.ciphertext.getKDF_PRF(),
                		                    arguments.key, keySize, "encryption");
            }
            var Cipher = createObject("java", "javax.crypto.Cipher");
            if ( arguments.ciphertext.requiresIV() ) {
                decrypter.init(Cipher.DECRYPT_MODE, encKey, createObject("java", "javax.crypto.spec.IvParameterSpec").init(arguments.ciphertext.getIV()));
            } else {
                decrypter.init(Cipher.DECRYPT_MODE, encKey);
            }
            var output = decrypter.doFinal(arguments.ciphertext.getRawCipherText());
            return new PlainText(variables.ESAPI, output);

        } catch (InvalidKeyException ike) {
            raiseException(new EncryptionException(variables.ESAPI, variables.DECRYPTION_FAILED, "Must install JCE Unlimited Strength Jurisdiction Policy Files from Sun", ike));
        } catch (java.security.NoSuchAlgorithmException e) {
            raiseException(new EncryptionException(variables.ESAPI, variables.DECRYPTION_FAILED, "Invalid algorithm for available JCE providers - " &
                    arguments.ciphertext.getCipherTransformation() & ": " & e.getMessage(), e));
        } catch (NoSuchPaddingException e) {
            raiseException(new EncryptionException(variables.ESAPI, variables.DECRYPTION_FAILED, "Invalid padding scheme (" &
                    arguments.ciphertext.getPaddingScheme() & ") for cipher transformation " & arguments.ciphertext.getCipherTransformation() &
                    ": " & e.getMessage(), e));
        } catch (InvalidAlgorithmParameterException e) {
            raiseException(new EncryptionException(variables.ESAPI, variables.DECRYPTION_FAILED, "Decryption problem: " & e.getMessage(), e));
        } catch (IllegalBlockSizeException e) {
            raiseException(new EncryptionException(variables.ESAPI, variables.DECRYPTION_FAILED, "Decryption problem: " & e.getMessage(), e));
        } catch (BadPaddingException e) {
            //DISCUSS: This needs fixed. Already validated MAC in CryptoHelper.isCipherTextMACvalid() above.
            //So only way we could get a padding exception is if invalid padding were used originally by
            //the party doing the encryption. (This might happen with a buggy padding scheme for instance.)
            //It *seems* harmless though, so will leave it for now, and technically, we need to either catch it
            //or declare it in a throws class. Clearly we don't want to do the later. This should be discussed
            //during a code inspection.
            var authKey = "";
            try {
                authKey = computeDerivedKey( arguments.ciphertext.getKDFVersion(), arguments.ciphertext.getKDF_PRF(),
                		                     arguments.key, keySize, "authenticity");
            } catch (Exception e1) {
                raiseException(new EncryptionException(variables.ESAPI, variables.DECRYPTION_FAILED,
                        "Decryption problem -- failed to compute derived key for authenticity: " & e1.getMessage(), e1));
            }
            var success = arguments.ciphertext.validateMAC( authKey );
            if ( success ) {
                raiseException(new EncryptionException(variables.ESAPI, variables.DECRYPTION_FAILED, "Decryption problem: " & e.getMessage(), e));
            } else {
                raiseException(new EncryptionException(variables.ESAPI, variables.DECRYPTION_FAILED,
                        "Decryption problem: WARNING: Adversary may have tampered with " &
                        "CipherText object orCipherText object mangled in transit: " & e.getMessage(), e));
            }
        }
    }

	public string function sign(required string data) {
		try {
			var signer = createObject("java", "java.security.Signature").getInstance(variables.signatureAlgorithm);
			signer.initSign(variables.privateKey);
			signer.update(arguments.data.getBytes(variables.encoding));
			var bytes = signer.sign();
			return variables.ESAPI.encoder().encodeForBase64(bytes, false);
		} catch (InvalidKeyException ike) {
			raiseException(new EncryptionException(variables.ESAPI, "Encryption failure", "Must install unlimited strength crypto extension from Sun", ike));
		} catch (Exception e) {
			raiseException(new EncryptionException(variables.ESAPI, "Signature failure", "Can't find signature algorithm " & variables.signatureAlgorithm, e));
		}
	}

	public boolean function verifySignature(required string signature, required string data) {
		try {
			var bytes = variables.ESAPI.encoder().decodeFromBase64(arguments.signature);
			var signer = createObject("java", "java.security.Signature").getInstance(variables.signatureAlgorithm);
			signer.initVerify(variables.publicKey);
			signer.update(arguments.data.getBytes(variables.encoding));
			return signer.verify(bytes);
		} catch (any e) {
		    // NOTE: EncryptionException constructed *only* for side-effect of causing logging.
		    // FindBugs complains about this and since it examines byte-code, there's no way to
		    // shut it up.
			new EncryptionException(variables.ESAPI, "Invalid signature", "Problem verifying signature: " & e.getMessage(), e);
			return false;
		}
	}

	/**
     * @param expiration
     * @throws IntegrityException
     */
	public string function seal(required string data, required numeric expiration) {
	    if (isNull(arguments.data)) {
	        raiseException(createObject("java", "java.lang.IllegalArgumentException").init("Data to be sealed may not be null."));
	    }

		try {
		    var b64data = "";
            try {
                b64data = variables.ESAPI.encoder().encodeForBase64(arguments.data.getBytes("UTF-8"), false);
            } catch (java.io.UnsupportedEncodingException e) {
                ; // Ignore; should never happen since UTF-8 built into rt.jar
            }
			// mix in some random data so even identical data and timestamp produces different seals
			var nonce = variables.ESAPI.randomizer().getRandomString(10, variables.ESAPI.encoder().CHAR_ALPHANUMERICS);
			var plaintext = arguments.expiration & ":" & nonce & ":" & b64data;
			// add integrity check; signature is already base64 encoded.
			var sig = this.sign( plaintext );
			var ciphertext = this.encrypt( new PlainText(variables.ESAPI, plaintext & ":" & sig) );
			var sealedData = variables.ESAPI.encoder().encodeForBase64(ciphertext.asPortableSerializedByteArray(), false);
			return sealedData;
		} catch(org.owasp.esapi.errors.EncryptionException e) {
			raiseException(new IntegrityException(variables.ESAPI, e.getUserMessage(), e.getLogMessage(), e ));
		}
	}

	public string function unseal(required string seal) {
		var plaintext = "";
		try {
		    var encryptedBytes = variables.ESAPI.encoder().decodeFromBase64(arguments.seal);
		    var cipherText = "";
		    try {
		        cipherText = new CipherText(variables.ESAPI).fromPortableSerializedBytes(encryptedBytes);
		    } catch( AssertionError e) {
	            // Some of the tests in EncryptorTest.testVerifySeal() are examples of
		        // this if assertions are enabled.
		        raiseException(new EncryptionException(variables.ESAPI, "Invalid seal", "Seal passed garbarge data resulting in AssertionError: " & e));
	        }
			plaintext = this.decrypt(cipherText);

			var parts = plaintext.toString().split(":");
			if (arrayLen(parts) != 4) {
				raiseException(new EncryptionException(variables.ESAPI, "Invalid seal", "Seal was not formatted properly."));
			}

			var timestring = parts[1];
			var now = now().getTime();
			var expiration = timestring;
			if (now > expiration) {
				raiseException(new EncryptionException(variables.ESAPI, "Invalid seal", "Seal expiration date of " & createObject("java", "java.util.Date").init(javaCast("long", expiration)) & " has past."));
			}
			var nonce = parts[2];
			var b64data = parts[3];
			var sig = parts[4];
			if (!this.verifySignature(sig, timestring & ":" & nonce & ":" & b64data ) ) {
				raiseException(new EncryptionException(variables.ESAPI, "Invalid seal", "Seal integrity check failed"));
			}
			return charsetEncode(variables.ESAPI.encoder().decodeFromBase64(b64data), "UTF-8");
		} catch (org.owasp.esapi.errors.EncryptionException e) {
			raiseException(e);
		} catch (any e) {
			raiseException(new EncryptionException(variables.ESAPI, "Invalid seal", "Invalid seal:" & e.getMessage(), e));
		}
	}


	public boolean function verifySeal(required string seal) {
		try {
			unseal(arguments.seal);
			return true;
		} catch(org.owasp.esapi.errors.EncryptionException ex) {
			return false;
		}
	}

	public numeric function getTimeStamp() {
		return now().getTime();
	}

	public numeric function getRelativeTimeStamp(required numeric offset) {
		return now().getTime() + arguments.offset;
	}

	// DISCUSS: Why experimental? Would have to be added to Encryptor interface
	//			but only 3 things I saw wrong with this was 1) it used HMacMD5 instead
	//			of HMacSHA1 (see discussion below), 2) that the HMac key is the
	//			same one used for encryption (also see comments), and 3) it caught
	//			overly broad exceptions. Here it is with these specific areas
	//			addressed, but no unit testing has been done at this point. -kww
   /**
    * Compute an HMAC for a String.  Experimental.
    * @param input	The input for which to compute the HMac.
    */
/********************
	public String computeHMAC( String input ) throws EncryptionException {
		try {
			Mac hmac = Mac.getInstance("HMacSHA1"); // DISCUSS: Changed to HMacSHA1. MD5 *badly* broken
												   //          SHA1 should really be avoided, but using
												   //		   for HMAC-SHA1 is acceptable for now. Plan
												   //		   to migrate to SHA-256 or NIST replacement for
												   //		   SHA1 in not too distant future.
			// DISCUSS: Also not recommended that the HMac key is the same as the one
			//			used for encryption (namely, Encryptor.MasterKey). If anything it
			//			would be better to use Encryptor.MasterSalt for the HMac key, or
			//			perhaps a derived key based on the master salt. (One could use
			//			KeyDerivationFunction.computeDerivedKey().)
			//
			byte[] salt = ESAPI.securityConfiguration().getMasterSalt();
			hmac.init( new SecretKeySpec(salt, "HMacSHA1") );	// Was:	hmac.init(variables.secretKeySpec)
			byte[] inBytes;
			try {
				inBytes = input.getBytes("UTF-8");
			} catch (java.io.UnsupportedEncodingException e) {
				logger.warning(Logger.SECURITY_FAILURE, "computeHMAC(): Can't find UTF-8 encoding; using default encoding", e);
				inBytes = input.getBytes();
			}
			byte[] bytes = hmac.doFinal( inBytes );
			return ESAPI.encoder().encodeForBase64(bytes, false);
		} catch (InvalidKeyException ike) {
			raiseException(new EncryptionException(variables.ESAPI, "Encryption failure", "Must install unlimited strength crypto extension from Sun", ike));
	    } catch (java.security.NoSuchAlgorithmException e) {
	    	raiseException(new EncryptionException(variables.ESAPI, "Could not compute HMAC", "Can't find HMacSHA1 algorithm. " &
	    															"Problem computing HMAC for " & input, e ));
	    }
	}
********************/

    /**
     * Log a security warning every Nth time one of the deprecated encrypt or
     * decrypt methods are called. ('N' is hard-coded to be 25 by default, but
     * may be changed via the system property
     * {@code ESAPI.Encryptor.warnEveryNthUse}.) In other words, we nag
     * them until the give in and change it. ;-)
     *
     * @param where The string "encrypt" or "decrypt", corresponding to the
     *              method that is being logged.
     * @param msg   The message to log.
     */
    private void function logWarning(required string where, required string msg) {
        var counter = 0;
        if ( arguments.where.equals("encrypt") ) {
            counter = variables.encryptCounter++;
            arguments.where = "JavaEncryptor.encrypt(): [count=" & counter &"]";
        } else if ( arguments.where.equals("decrypt") ) {
            counter = variables.decryptCounter++;
            arguments.where = "JavaEncryptor.decrypt(): [count=" & counter &"]";
        } else {
            arguments.where = "JavaEncryptor: Unknown method: ";
        }
        // We log the very first time (note the use of post-increment on the
        // counters) and then every Nth time thereafter. Logging every single
        // time is likely to be way too much logging.
        if ( (counter % variables.logEveryNthUse) == 0 ) {
            logger.warning(Logger.SECURITY_FAILURE, arguments.where & arguments.msg);
        }
    }

    private function getPRF(required string name) {
		var prfName = "";
		if ( isNull(arguments.name) ) {
			prfName = variables.ESAPI.securityConfiguration().getKDFPseudoRandomFunction();
		} else {
			prfName = arguments.name;
		}
		var prf = new KeyDerivationFunction(variables.ESAPI).convertNameToPRF(prfName);
		return prf;
    }

    private function getDefaultPRF() {
		var prfName = variables.ESAPI.securityConfiguration().getKDFPseudoRandomFunction();
		return getPRF(prfName);
    }

    // Private interface to call ESAPI's KDF to get key for encryption or authenticity.
    private function computeDerivedKey(required numeric kdfVersion, required prf, required kdk, required numeric keySize, required string purpose) {
    	// These really should be turned into actual runtime checks and an
    	// IllegalArgumentException should be thrown if they are violated.
    	// But this should be OK since this is a private method. Also, this method will
    	// be called quite often so assertions are a big win as they can be disabled or
    	// enabled at will.
    	if (isNull(arguments.prf)) raiseException("Pseudo Random Function for KDF cannot be null");
    	if (isNull(arguments.kdk)) raiseException("Key derivation key cannot be null.");
    	// We would choose a larger minimum key size, but we want to be
    	// able to accept DES for legacy encryption needs. NIST says 112-bits is min. If less than that,
    	// we print warning.
    	if (arguments.keySize < 56) raiseException("Key has size of " & arguments.keySize & ", which is less than minimum of 56-bits.");
    	if ((arguments.keySize % 8) != 0) raiseException("Key size (" & arguments.keySize & ") must be a even multiple of 8-bits.");
    	if (isNull(arguments.purpose)) raiseException("Purpose cannot be null. Should be 'encryption' or 'authenticity'.");
    	if (arguments.purpose != "encryption" && arguments.purpose !="authenticity") raiseException("Purpose must be ""encryption"" or ""authenticity"".");

    	var kdf = new KeyDerivationFunction(variables.ESAPI, arguments.prf);
    	if ( arguments.kdfVersion != 0 ) {
    		kdf.setVersion(arguments.kdfVersion);
    	}
    	return kdf.computeDerivedKey(arguments.kdk, arguments.keySize, arguments.purpose);
    }

    // Get all the algorithms we will be using from ESAPI.properties.
    private void function setupAlgorithms() {
        // setup algorithms
        variables.encryptAlgorithm = variables.ESAPI.securityConfiguration().getEncryptionAlgorithm();
        variables.signatureAlgorithm = variables.ESAPI.securityConfiguration().getDigitalSignatureAlgorithm();
        variables.randomAlgorithm = variables.ESAPI.securityConfiguration().getRandomAlgorithm();
        variables.hashAlgorithm = variables.ESAPI.securityConfiguration().getHashAlgorithm();
        variables.hashIterations = variables.ESAPI.securityConfiguration().getHashIterations();
        variables.encoding = variables.ESAPI.securityConfiguration().getCharacterEncoding();
        variables.encryptionKeyLength = variables.ESAPI.securityConfiguration().getEncryptionKeyLength();
        variables.signatureKeyLength = variables.ESAPI.securityConfiguration().getDigitalSignatureKeyLength();
    }

    // Set up signing key pair using the master password and salt. Called (once)
    // from the JavaEncryptor CTOR.
    private void function initKeyPair(required prng) {
        var sigAlg = variables.signatureAlgorithm.toLowerCase();
        if ( sigAlg.endsWith("withdsa") ) {
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
            sigAlg = "DSA";
        } else if ( sigAlg.endsWith("withrsa") ) {
            // Ditto for RSA.
            sigAlg = "RSA";
        }
        var keyGen = createObject("java", "java.security.KeyPairGenerator").getInstance(sigAlg);
        keyGen.initialize(variables.signatureKeyLength, arguments.prng);
        var pair = keyGen.generateKeyPair();
        variables.privateKey = pair.getPrivate();
        variables.publicKey = pair.getPublic();
    }

}