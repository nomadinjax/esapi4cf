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

/**
 * Class to provide some convenience methods for encryption, decryption, etc.
 * </p><p>
 * All the cryptographic operations use the default cryptographic properties;
 * e.g., default cipher transformation, default key size, default IV type (where
 * applicable), etc.
 */
component extends="org.owasp.esapi.util.Object" {

	variables.ESAPI = "";
	variables.logger = "";

	public CryptoHelper function init(required org.owasp.esapi.ESAPI ESAPI) {
		variables.ESAPI = arguments.ESAPI;
		variables.logger = variables.ESAPI.getLogger(getMetaData(this).fullName);

		return this;
	}

	// TODO: Also consider supplying implementation of RFC 2898 / PKCS#5 PBKDF2
	//		 in this file as well??? Maybe save for ESAPI 2.1 or 3.0.
	/**
	 * Generate a random secret key appropriate to the specified cipher algorithm
	 * and key size.
	 * @param alg	The cipher algorithm or cipher transformation. (If the latter is
	 * 				passed, the cipher algorithm is determined from it.) Cannot be
	 * 				null or empty.
	 * @param keySize	The key size, in bits.
	 * @return	A random {@code SecretKey} is returned.
	 * @throws EncryptionException Thrown if cannot create secret key conforming to
	 * 				requested algorithm with requested size. Typically this is caused by
	 * 				specifying an unavailable algorithm or invalid key size.
	 */
	public function generateSecretKey(required string alg, required numeric keySize) {
		if (isNull(arguments.alg)) raiseException("Algorithm must not be null.");			// NPE if null and assertions disabled.
		if (arguments.alg == "") raiseException("Algorithm must not be empty");	// NoSuchAlgorithmExeption if empty & assertions disabled.
		if (arguments.keySize <= 0) raiseException("Key size must be positive.");	// Usually should be even multiple of 8, but not strictly required by alg.
		// Don't use CipherSpec here to get algorithm as this may cause assertion
		// to fail (when enabled) if only algorithm name is passed to us.
		var cipherSpec = arguments.alg.split("/");
		var cipherAlg = cipherSpec[1];
		try {
		    // Special case for things like PBEWithMD5AndDES or PBEWithSHA1AndDESede.
		    // In such cases, the key generator should only request an instance of "PBE".
		    if ( cipherAlg.toUpperCase().startsWith("PBEWITH") ) {
		        cipherAlg = "PBE";
		    }
			var kgen = createObject("java", "javax.crypto.KeyGenerator").getInstance( cipherAlg );
			kgen.init(arguments.keySize);
			return kgen.generateKey();
		} catch (java.security.NoSuchAlgorithmException e) {
			raiseException(new EncryptionException(variables.ESAPI, "Failed to generate random secret key", "Invalid algorithm. Failed to generate secret key for " & arguments.alg & " with size of " & arguments.keySize & " bits.", e));
		} catch (java.security.InvalidParameterException e) {
			raiseException(new EncryptionException(variables.ESAPI, "Failed to generate random secret key - invalid key size specified.", "Invalid key size. Failed to generate secret key for " & arguments.alg & " with size of " & arguments.keySize & " bits.", e));
		}
	}

	/**
	 * The method is ESAPI's Key Derivation Function (KDF) that computes a
	 * derived key from the {@code keyDerivationKey} for either
	 * encryption / decryption or for authentication.
	 * <p>
	 * <b>CAUTION:</b> If this algorithm for computing derived keys from the
	 * key derivation key is <i>ever</i> changed, we risk breaking backward compatibility of being
	 * able to decrypt data previously encrypted with earlier / different versions
	 * of this method. Therefore, do not change this unless you are 100% certain that
	 * what you are doing will NOT change either of the derived keys for
	 * ANY "key derivation key" AT ALL!!!
	 * <p>
	 * <b>NOTE:</b> This method is generally not intended to be called separately.
	 * It is used by ESAPI's reference crypto implementation class {@code JavaEncryptor}
	 * and might be useful for someone implementing their own replacement class, but
	 * generally it is not something that is useful to application client code.
	 *
	 * @param keyDerivationKey  A key used as an input to a key derivation function
	 *                          to derive other keys. This is the key that generally
	 *                          is created using some key generation mechanism such as
	 *                          {@link #generateSecretKey(String, int)}. The
	 *                          "input" key from which the other keys are derived.
	 * 							The derived key will have the same algorithm type
	 * 							as this key.
	 * @param keySize		The cipher's key size (in bits) for the {@code keyDerivationKey}.
	 * 						Must have a minimum size of 56 bits and be an integral multiple of 8-bits.
	 * 						<b>Note:</b> The derived key will have the same size as this.
	 * @param purpose		The purpose for the derived key. Must be either the
	 * 						string "encryption" or "authenticity". Use "encryption" for
     *                      creating a derived key to use for confidentiality, and "authenticity"
     *                      for a derived key to use with a MAC to ensure message authenticity.
	 * @return				The derived {@code SecretKey} to be used according
	 * 						to the specified purpose. Note that this serves the same purpose
	 * 						as "label" in section 5.1 of NIST SP 800-108.
	 * @throws NoSuchAlgorithmException		The {@code keyDerivationKey} has an unsupported
	 * 						encryption algorithm or no current JCE provider supports
	 * 						"HmacSHA1".
	 * @throws EncryptionException		If "UTF-8" is not supported as an encoding, then
	 * 						this is thrown with the original {@code UnsupportedEncodingException}
	 * 						as the cause. (NOTE: This should never happen as "UTF-8" is supposed to
	 * 						be a common encoding supported by all Java implementations. Support
	 * 					    for it is usually in rt.jar.)
	 * @throws InvalidKeyException 	Likely indicates a coding error. Should not happen.
	 * @throws EncryptionException  Throw for some precondition violations.
	 * @deprecated Use{@code KeyDerivationFunction} instead. This method will be removed as of
	 * 			   ESAPI release 2.1 so if you are using this, please change your code.
	 */
	public function computeDerivedKey(required keyDerivationKey, required numeric keySize, required string purpose) {
        // These really should be turned into actual runtime checks and an
        // IllegalArgumentException should be thrown if they are violated.
		if (isNull(arguments.keyDerivationKey)) raiseException("Key derivation key cannot be null.");
			// We would choose a larger minimum key size, but we want to be
			// able to accept DES for legacy encryption needs.
		if (arguments.keySize < 56) raiseException("Key has size of " & arguments.keySize & ", which is less than minimum of 56-bits.");
		if ((arguments.keySize % 8) != 0) raiseException("Key size (" & arguments.keySize & ") must be a even multiple of 8-bits.");
		if (isNull(arguments.purpose)) raiseException("purpose cannot be null");
		if (arguments.purpose != "encryption" && arguments.purpose != "authenticity") raiseException("Purpose must be ""encryption"" or ""authenticity"".");

		// DISCUSS: Should we use HmacSHA1 (what we were using) or the HMAC defined by
		//			Encryptor.KDF.PRF instead? Either way, this is not compatible with
		//			previous ESAPI versions. JavaEncryptor doesn't use this any longer.
		var KeyDerivationFunction = createObject("KeyDerivationFunction");
		var kdf = new KeyDerivationFunction(variables.ESAPI, KeyDerivationFunction.PRF_ALGORITHMS.HmacSHA1);
		return kdf.computeDerivedKey(arguments.keyDerivationKey, arguments.keySize, arguments.purpose);
	}

	/**
	 * Return true if specified cipher mode is one of those specified in the
	 * {@code ESAPI.properties} file that supports both confidentiality
	 * <b>and</b> authenticity (i.e., a "combined cipher mode" as NIST refers
	 * to it).
	 * @param cipherMode The specified cipher mode to be used for the encryption
	 *                   or decryption operation.
	 * @return true if the specified cipher mode is in the comma-separated list
	 *         of cipher modes supporting both confidentiality and authenticity;
	 *         otherwise false.
	 * @see org.owasp.esapi.SecurityConfiguration#getCombinedCipherModes()
	 */
	public boolean function isCombinedCipherMode(required string cipherMode) {
	    if (isNull(arguments.cipherMode)) raiseException("Cipher mode may not be null");
	    if (arguments.cipherMode == "") raiseException("Cipher mode may not be empty string");
	    var combinedCipherModes = variables.ESAPI.securityConfiguration().getCombinedCipherModes();
	    return combinedCipherModes.contains( arguments.cipherMode );
	}

	/**
     * Return true if specified cipher mode is one that may be used for
     * encryption / decryption operations via {@link org.owasp.esapi.Encryptor}.
     * @param cipherMode The specified cipher mode to be used for the encryption
     *                   or decryption operation.
     * @return true if the specified cipher mode is in the comma-separated list
     *         of cipher modes supporting both confidentiality and authenticity;
     *         otherwise false.
     * @see #isCombinedCipherMode(String)
     * @see org.owasp.esapi.SecurityConfiguration#getCombinedCipherModes()
     * @see org.owasp.esapi.SecurityConfiguration#getAdditionalAllowedCipherModes()
     */
	public boolean function isAllowedCipherMode(required string cipherMode) {
	    if ( isCombinedCipherMode(arguments.cipherMode) ) {
	        return true;
	    }
	    // FIXME: this is temp; remove once this validates correctly
	    return true;
	    // END
	    var extraCipherModes = variables.ESAPI.securityConfiguration().getAdditionalAllowedCipherModes();
	    return extraCipherModes.contains( arguments.cipherMode );
	}

    /**
     * Check to see if a Message Authentication Code (MAC) is required
     * for a given {@code CipherText} object and the current ESAPI.property
     * settings. A MAC is considered "required" if the specified
     * {@code CipherText} was not encrypted by one of the preferred
     * "combined" cipher modes (e.g., CCM or GCM) and the setting of the
     * current ESAPI properties for the property
     * {@code Encryptor.CipherText.useMAC} is set to {@code true}. (Normally,
     * the setting for {@code Encryptor.CipherText.useMAC} should be set to
     * {@code true} unless FIPS 140-2 compliance is required. See
     * <a href="http://owasp-esapi-java.googlecode.com/svn/trunk/documentation/esapi4java-core-2.0-symmetric-crypto-user-guide.html">
     * User Guide for Symmetric Encryption in ESAPI 2.0</a> and the section
     * on using ESAPI with FIPS for further details.
     *
     * @param ct    The specified {@code CipherText} object to check to see if
     *              it requires a MAC.
     * @return      True if a MAC is required, false if it is not required.
     */
    public boolean function isMACRequired(required ct) {
        var preferredCipherMode = isCombinedCipherMode( arguments.ct.getCipherMode() );
        var wantsMAC = variables.ESAPI.securityConfiguration().useMACforCipherText();

        // The preferred "combined" cipher modes such as CCM, GCM, etc. do
        // not require a MAC as a MAC would be superfluous and just require
        // additional computing time.
        return ( !preferredCipherMode && wantsMAC );
    }

    /**
     * If a Message Authentication Code (MAC) is required for the specified
     * {@code CipherText} object, then attempt to validate the MAC that
     * should be embedded within the {@code CipherText} object by using a
     * derived key based on the specified {@code SecretKey}.
     *
     * @param sk    The {@code SecretKey} used to derived a key to check
     *              the authenticity via the MAC.
     * @param ct    The {@code CipherText} that we are checking for a
     *              valid MAC.
     *
     * @return  True is returned if a MAC is required and it is valid as
     *          verified using a key derived from the specified
     *          {@code SecretKey} or a MAC is not required. False is returned
     *          otherwise.
     */
    public boolean function isCipherTextMACvalid(required sk, required ct) {
        if ( isMACRequired( arguments.ct ) ) {
            try {
                var authKey = computeDerivedKey( arguments.sk, arguments.ct.getKeySize(), "authenticity");
                var validMAC = arguments.ct.validateMAC( authKey );
                return validMAC;
            } catch (Exception ex) {
                // Error on side of security. If this fails and can't verify MAC
                // assume it is invalid. Note that CipherText.toString() does not
                // print the actual ciphertext.
                variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Unable to validate MAC for ciphertext " & arguments.ct, ex);
                return false;
            }
        }
        return true;
    }

	/**
	 * Overwrite a byte array with a specified byte. This is frequently done
	 * to a plaintext byte array so the sensitive data is not lying around
	 * exposed in memory.
	 * @param bytes	The byte array to be overwritten.
	 * @param x The byte array {@code bytes} is overwritten with this byte.
	 */
	public void function overwrite(required binary bytes, x="*") {
		createObject("java", "java.util.Arrays").fill(arguments.bytes, javaCast("byte", asc(arguments.x)));
	}

	// These provide for a bit more type safety when copying bytes around.
	/**
	 * Same as {@code System.arraycopy(src, 0, dest, 0, length)}.
	 *
     * @param      src      the source array.
     * @param      dest     the destination array.
     * @param      length   the number of array elements to be copied.
     * @exception  IndexOutOfBoundsException  if copying would cause
     *               access of data outside array bounds.
     * @exception  NullPointerException if either <code>src</code> or
     *               <code>dest</code> is <code>null</code>.
	 */
	public void function copyByteArray(required binary src, required binary dest, numeric length=arrayLen(arguments.src)) {
		createObject("java", "java.lang.System").arraycopy(arguments.src, 0, arguments.dest, 0, arguments.length);
	}

	/**
	 * A "safe" array comparison that is not vulnerable to side-channel
	 * "timing attacks". All comparisons of non-null, equal length bytes should
	 * take same amount of time. We use this for cryptographic comparisons.
	 *
	 * @param b1   A byte array to compare.
	 * @param b2   A second byte array to compare.
	 * @return     {@code true} if both byte arrays are null or if both byte
	 *             arrays are identical or have the same value; otherwise
	 *             {@code false} is returned.
	 */
	public boolean function arrayCompare(required binary b1, required binary b2) {
	    if(charsetEncode(arguments.b1, "utf-8") == charsetEncode(arguments.b2, "utf-8")) {
	        return true;
	    }
	    if (isNull(arguments.b1) || isNull(arguments.b2)) {
	        return (charsetEncode(arguments.b1, "utf-8") == charsetEncode(arguments.b2, "utf-8"));
	    }
	    if (arrayLen(arguments.b1) != arrayLen(arguments.b2)) {
	        return false;
	    }

	    var result = 0;
	    // Make sure to go through ALL the bytes. We use the fact that if
	    // you XOR any bit stream with itself the result will be all 0 bits,
	    // which in turn yields 0 for the result.
	    for(var i = 1; i <= arrayLen(arguments.b1); i++) {
	        // XOR the 2 current bytes and then OR with the outstanding result.
	        result = bitOr(result, bitXor(arguments.b1[i], arguments.b2[i]));
	    }
	    return (result == 0) ? true : false;
	}

	/**
	 * Is this particular KDF version number one that is sane? For that, we
	 * just make sure it is inbounds of the valid range which is:
	 * <pre>
	 *     [20110203, 99991231]
	 * </pre>
	 * @param kdfVers	KDF version # that we are checking. Generally this is
	 * 				extracted from the serialized {@code CipherText}.
	 * @param restrictToCurrent	If this is set, we do an additional check
	 *				to see if the KDF version is a later version than the
	 *				one that this current ESAPI version supports.
	 * @param throwIfError	Instead of returning {@code false} in the case of
	 * 				an error, throw an {@code IllegalArgumentException}
	 * @return	True if in range, false otherwise (except if {@code throwIfError}
	 * 			is true.}
	 */
	public boolean function isValidKDFVersion(required numeric kdfVers, required boolean restrictToCurrent, required boolean throwIfError) {
		var ret = true;
		var KeyDerivationFunction = new KeyDerivationFunction(variables.ESAPI);

		if ( arguments.kdfVers < KeyDerivationFunction.originalVersion || arguments.kdfVers > 99991231 ) {
			ret = false;
		} else if ( arguments.restrictToCurrent ) {
			ret = ( arguments.kdfVers <= KeyDerivationFunction.kdfVersion );
		}
		if ( ret ) {
			return ret;				// True
		} else {					// False, so throw or not.
			variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Possible data tampering. Encountered invalid KDF version ##. " & ( arguments.throwIfError ? "Throwing IllegalArgumentException" : "" ));
			if ( arguments.throwIfError ) {
				raiseException(createObject("java", "java.lang.IllegalArgumentException").init("Version (" & arguments.kdfVers & ") invalid. " & "Must be date in format of YYYYMMDD between " & KeyDerivationFunction.originalVersion & " and 99991231."));
			}
		}
		return false;
	}

}
