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
import "org.owasp.esapi.util.Utils";

// CHECKME: Some of these assertions probably should be actual runtime checks
//          with suitable exceptions to account for cases where programmers
//          accidentally pass in byte arrays that are not really serialized
//          CipherText objects (note: as per asPortableSerializedByteArra()).
//          However, not sure what exception time is really suitable here.
//          It probably should be a sub-class of RuntimeException, but
//          IllegalArguementException doesn't really make sense here. Suggestions?

/**
 * A {@code Serializable} interface representing the result of encrypting
 * plaintext and some additional information about the encryption algorithm,
 * the IV (if pertinent), and an optional Message Authentication Code (MAC).
 * </p><p>
 * Note that while this class is {@code Serializable} in the usual Java sense,
 * ESAPI uses {@link #asPortableSerializedByteArray()} for serialization. Not
 * only is this serialization somewhat more compact, it is also portable
 * across other ESAPI programming language implementations. However, Java
 * serialization is supported in the event that one wishes to store
 * {@code CipherText} in an {@code HttpSession} object.
 * </p><p>
 * Copyright &copy; 2009 - The OWASP Foundation
 * </p>
 */
component extends="org.owasp.esapi.util.Object" {
    // NOTE: Do NOT change this in future versions, unless you are knowingly
    //       making changes to the class that will render this class incompatible
    //       with previously serialized objects from older versions of this class.
	//		 If this is done, that you must provide for supporting earlier ESAPI versions.
    //       Be wary making incompatible changes as discussed at:
    //          http://java.sun.com/javase/6/docs/platform/serialization/spec/version.html#6678
    //       Any incompatible change in the serialization of CipherText *must* be
    //       reflected in the class CipherTextSerializer.
    // This should be *same* version as in CipherTextSerializer and KeyDerivationFunction.
	// If one changes, the other should as well to accommodate any differences.
	//		Previous versions:	20110203 - Original version (ESAPI releases 2.0 & 2.0.1)
	//						    20130830 - Fix to issue #306 (release 2.1.0)
	this.cipherTextVersion = 20130830; // Format: YYYYMMDD, max is 99991231.
		// Required by Serializable classes.
	variables.serialVersionUID = this.cipherTextVersion; // Format: YYYYMMDD

	variables.logger = "";

    variables.cipherSpec_           = "";
    variables.raw_ciphertext_       = "";
    variables.separate_mac_         = "";
    variables.encryption_timestamp_ = 0;
    variables.kdfVersion_           = "";
    variables.kdfPrfSelection_      = "";

    // All the various pieces that can be set, either directly or indirectly
    // via CipherSpec.
    variables.CipherTextFlags = {
        "ALGNAME": 1,
        "CIPHERMODE": 2,
        "PADDING": 3,
        "KEYSIZE": 4,
        "BLOCKSIZE": 5,
        "CIPHERTEXT": 6,
        "INITVECTOR": 7
    };

    // If we have everything set, we compare it to this using '==' which javac
    // specially overloads for this.
    variables.allCtFlags = [
		variables.CipherTextFlags.ALGNAME,
		variables.CipherTextFlags.CIPHERMODE,
		variables.CipherTextFlags.PADDING,
		variables.CipherTextFlags.KEYSIZE,
		variables.CipherTextFlags.BLOCKSIZE,
		variables.CipherTextFlags.CIPHERTEXT,
		variables.CipherTextFlags.INITVECTOR
	];

    // These are all the pieces we collect when passed a CipherSpec object.
    variables.fromCipherSpec = [
		variables.CipherTextFlags.ALGNAME,
		variables.CipherTextFlags.CIPHERMODE,
		variables.CipherTextFlags.PADDING,
		variables.CipherTextFlags.KEYSIZE,
		variables.CipherTextFlags.BLOCKSIZE
	];

    // How much we've collected so far. We start out with having collected nothing.
    variables.progress = [getMetaData(variables.CipherTextFlags).name];

    ///////////////////////////  C O N S T R U C T O R S  /////////////////////////

    /**
     * Default CTOR. Takes all the defaults from the ESAPI.properties, or
     * default values from initial values from this class (when appropriate)
     * when they are not set in ESAPI.properties.
     *
     * @param cipherSpec The cipher specification to use.
     * @param cipherText The raw ciphertext bytes to use.
     */
    public CipherText function init(required org.owasp.esapi.ESAPI ESAPI, CipherSpec cipherSpec, binary cipherText) {
    	variables.ESAPI = arguments.ESAPI;
    	variables.logger = variables.ESAPI.getLogger(getMetaData(this).fullName);

    	var KeyDerivationFunction = new KeyDerivationFunction(variables.ESAPI);

    	variables.kdfVersion_           = KeyDerivationFunction.kdfVersion;
    	variables.kdfPrfSelection_      = KeyDerivationFunction.getDefaultPRFSelection();

        if (structKeyExists(arguments, "cipherSpec") && structKeyExists(arguments, "cipherText")) {
			variables.cipherSpec_ = arguments.cipherSpec;
	        setCiphertext(arguments.cipherText);
	        receivedMany(variables.fromCipherSpec);
	        if (!isNull(arguments.cipherSpec.getIV())) {
	            received(variables.CipherTextFlags.INITVECTOR);
	        }
        }
        else if (structKeyExists(arguments, "cipherSpec")) {
        	variables.cipherSpec_ = arguments.cipherSpec;
        	receivedMany(variables.fromCipherSpec);
        	if (!isNull(arguments.cipherSpec.getIV())) {
	            received(variables.CipherTextFlags.INITVECTOR);
	        }
        }
        else {
        	variables.cipherSpec_ = new CipherSpec(variables.ESAPI); // Uses default for everything but IV.
        	receivedMany(variables.fromCipherSpec);
        }

        return this;
    }

    /** Create a {@code CipherText} object from what is supposed to be a
     *  portable serialized byte array, given in network byte order, that
     *  represents a valid, previously serialized {@code CipherText} object
     *  using {@link #asPortableSerializedByteArray()}.
     * @param bytes A byte array created via
     *              {@code CipherText.asPortableSerializedByteArray()}
     * @return A {@code CipherText} object reconstructed from the byte array.
     * @throws EncryptionException
     * @see #asPortableSerializedByteArray()
     */     // DISCUSS: BTW, I detest this name. Suggestions???
    public CipherText function fromPortableSerializedBytes(required binary bytes) {
        var cts = new CipherTextSerializer(variables.ESAPI, arguments.bytes);
        return cts.asCipherText();
    }

    /////////////////////////  P U B L I C   M E T H O D S  ////////////////////

	/**
	 * Obtain the String representing the cipher transformation used to encrypt
	 * the plaintext. The cipher transformation represents the cipher algorithm,
	 * the cipher mode, and the padding scheme used to do the encryption. An
	 * example would be "AES/CBC/PKCS5Padding". See Appendix A in the
	 * <a href="http://java.sun.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#AppA">
	 * Java Cryptography Architecture Reference Guide</a>
	 * for information about standard supported cipher transformation names.
	 * <p>
	 * The cipher transformation name is usually sufficient to be passed to
	 * {@link javax.crypto.Cipher#getInstance(String)} to create a
	 * <code>Cipher</code> object to decrypt the ciphertext.
	 *
	 * @return The cipher transformation name used to encrypt the plaintext
	 * 		   resulting in this ciphertext.
	 */
    public string function getCipherTransformation() {
        return variables.cipherSpec_.getCipherTransformation();
    }

	/**
	 * Obtain the name of the cipher algorithm used for encrypting the
	 * plaintext.
	 *
	 * @return The name as the cryptographic algorithm used to perform the
	 * 		   encryption resulting in this ciphertext.
	 */
    public string function getCipherAlgorithm() {
        return variables.cipherSpec_.getCipherAlgorithm();
    }

	/**
	 * Retrieve the key size used with the cipher algorithm that was used to
	 * encrypt data to produce this ciphertext.
	 *
	 * @return The key size in bits. We work in bits because that's the crypto way!
	 */
    public numeric function getKeySize() {
        return variables.cipherSpec_.getKeySize();
    }

	/**
	 * Retrieve the block size (in bytes!) of the cipher used for encryption.
	 * (Note: If an IV is used, this will also be the IV length.)
	 *
	 * @return The block size in bytes. (Bits, bytes! It's confusing I know. Blame
	 * 									the cryptographers; we've just following
	 * 									convention.)
	 */
    public numeric function getBlockSize() {
        return variables.cipherSpec_.getBlockSize();
    }

	/**
	 * Get the name of the cipher mode used to encrypt some plaintext.
	 *
	 * @return The name of the cipher mode used to encrypt the plaintext
	 *         resulting in this ciphertext. E.g., "CBC" for "cipher block
	 *         chaining", "ECB" for "electronic code book", etc.
	 */
    public string function getCipherMode() {
        return variables.cipherSpec_.getCipherMode();
    }

	/**
	 * Get the name of the padding scheme used to encrypt some plaintext.
	 *
	 * @return The name of the padding scheme used to encrypt the plaintext
	 * 		   resulting in this ciphertext. Example: "PKCS5Padding". If no
	 * 		   padding was used "None" is returned.
	 */
    public string function getPaddingScheme() {
        return variables.cipherSpec_.getPaddingScheme();
    }

	/**
	 * Return the initialization vector (IV) used to encrypt the plaintext
	 * if applicable.
	 *
	 * @return	The IV is returned if the cipher mode used to encrypt the
	 * 			plaintext was not "ECB". ECB mode does not use an IV so in
	 * 			that case, <code>null</code> is returned.
	 */
    public binary function getIV() {
        if ( isCollected(variables.CipherTextFlags.INITVECTOR) ) {
            return variables.cipherSpec_.getIV();
        } else {
            variables.logger.error(variables.Logger.SECURITY_FAILURE, "IV not set yet; unable to retrieve; returning null");
            return "";
        }
    }

	/**
	 * Return true if the cipher mode used requires an IV. Usually this will
	 * be true unless ECB mode (which should be avoided whenever possible) is
	 * used.
	 */
    public boolean function requiresIV() {
        return variables.cipherSpec_.requiresIV();
    }

	/**
	 * Get the raw ciphertext byte array resulting from encrypting some
	 * plaintext.
	 *
	 * @return A copy of the raw ciphertext as a byte array.
	 */
	public function getRawCipherText() {
	    if ( isCollected(variables.CipherTextFlags.CIPHERTEXT) ) {
	        var copy = new Utils().newByte(arrayLen(variables.raw_ciphertext_));
	        createObject("java", "java.lang.System").arraycopy(variables.raw_ciphertext_, 0, copy, 0, arrayLen(variables.raw_ciphertext_));
	        return copy;
	    } else {
	        variables.logger.error(variables.Logger.SECURITY_FAILURE, "Raw ciphertext not set yet; unable to retrieve; returning null");
	        return;
	    }
	}

	/**
	 * Get number of bytes in raw ciphertext. Zero is returned if ciphertext has not
	 * yet been stored.
	 *
	 * @return The number of bytes of raw ciphertext; 0 if no raw ciphertext has been stored.
	 */
	public numeric function getRawCipherTextByteLength() {
	    if (isBinary(variables.raw_ciphertext_)) {
	        return arrayLen(variables.raw_ciphertext_);
	    } else {
	        return 0;
	    }
	}

	/**
	 * Return a base64-encoded representation of the raw ciphertext alone. Even
	 * in the case where an IV is used, the IV is not prepended before the
	 * base64-encoding is performed.
	 * <p>
	 * If there is a need to store an encrypted value, say in a database, this
	 * is <i>not</i> the method you should use unless you are using a <i>fixed</i>
	 * IV or are planning on retrieving the IV and storing it somewhere separately
	 * (e.g., a different database column). If you are <i>not</i> using a fixed IV
	 * (which is <strong>highly</strong> discouraged), you should normally use
	 * {@link #getEncodedIVCipherText()} instead.
	 * </p>
	 * @see #getEncodedIVCipherText()
	 */
	public string function getBase64EncodedRawCipherText() {
	    return variables.ESAPI.encoder().encodeForBase64(getRawCipherText(),false);
	}

	/**
	 * Return the ciphertext as a base64-encoded <code>String</code>. If an
	 * IV was used, the IV if first prepended to the raw ciphertext before
	 * base64-encoding. If an IV is not used, then this method returns the same
	 * value as {@link #getBase64EncodedRawCipherText()}.
	 * <p>
	 * Generally, this is the method that you should use unless you only
	 * are using a fixed IV and a storing that IV separately, in which case
	 * using {@link #getBase64EncodedRawCipherText()} can reduce the storage
	 * overhead.
	 * </p>
	 * @return The base64-encoded ciphertext or base64-encoded IV + ciphertext.
	 * @see #getBase64EncodedRawCipherText()
	 */
	public string function getEncodedIVCipherText() {
	    if ( isCollected(variables.CipherTextFlags.INITVECTOR) && isCollected(variables.CipherTextFlags.CIPHERTEXT) ) {
	        // First concatenate IV + raw ciphertext
	        var iv = getIV();
	        var raw = getRawCipherText();
	        var ivPlusCipherText = new Utils().newByte(arrayLen(iv) + arrayLen(raw));
	        createObject("java", "java.lang.System").arraycopy(iv, 0, ivPlusCipherText, 0, arrayLen(iv));
	        createObject("java", "java.lang.System").arraycopy(raw, 0, ivPlusCipherText, arrayLen(iv), arrayLen(raw));
	        // Then return the base64 encoded result
	        return variables.ESAPI.encoder().encodeForBase64(ivPlusCipherText, false);
	    } else {
	        variables.logger.error(variables.Logger.SECURITY_FAILURE, "Raw ciphertext and/or IV not set yet; unable to retrieve; returning null");
	        return "";
	    }
	}

	/**
	 * Compute and store the Message Authentication Code (MAC) if the ESAPI property
	 * {@code Encryptor.CipherText.useMAC} is set to {@code true}. If it
	 * is, the MAC is conceptually calculated as:
	 * <pre>
	 * 		authKey = DerivedKey(secret_key, "authenticate")
	 * 		HMAC-SHA1(authKey, IV + secret_key)
	 * </pre>
	 * where derived key is an HMacSHA1, possibly repeated multiple times.
	 * (See {@link org.owasp.esapi.crypto.CryptoHelper#computeDerivedKey(SecretKey, int, String)}
	 * for details.)
	 * </p><p>
	 * <b>Perceived Benefits</b>: There are certain cases where if an attacker
	 * is able to change the IV. When one uses a authenticity key that is
	 * derived from the "master" key, it also makes it possible to know when
	 * the incorrect key was attempted to be used to decrypt the ciphertext.
	 * </p><p>
	 * <b>NOTE:</b> The purpose of this MAC (which is always computed by the
	 * ESAPI reference model implementing {@code Encryptor}) is to ensure the
	 * authenticity of the IV and ciphertext. Among other things, this prevents
	 * an adversary from substituting the IV with one of their own choosing.
	 * Because we don't know whether or not the recipient of this {@code CipherText}
	 * object will want to validate the authenticity or not, the reference
	 * implementation of {@code Encryptor} always computes it and includes it.
	 * The recipient of the ciphertext can then choose whether or not to validate
	 * it.
	 *
	 * @param authKey The secret key that is used for proving authenticity of
	 * 				the IV and ciphertext. This key should be derived from
	 * 				the {@code SecretKey} passed to the
	 * 				{@link Encryptor#encrypt(javax.crypto.SecretKey, PlainText)}
	 *				and
	 *				{@link Encryptor#decrypt(javax.crypto.SecretKey, CipherText)}
	 *				methods or the "master" key when those corresponding
	 *				encrypt / decrypt methods are used. This authenticity key
	 *				should be the same length and for the same cipher algorithm
	 *				as this {@code SecretKey}. The method
	 *				{@link org.owasp.esapi.crypto.CryptoHelper#computeDerivedKey(SecretKey, int, String)}
	 *				is a secure way to produce this derived key.
	 */		// DISCUSS - Cryptographers David Wagner, Ian Grigg, and others suggest
			// computing authenticity using derived key and HmacSHA1 of IV + ciphertext.
			// However they also argue that what should be returned and treated as
			// (i.e., stored as) ciphertext would be something like this:
			//		len_of_raw_ciphertext + IV + raw_ciphertext + MAC
			// TODO: Need to do something like this for custom serialization and then
	        // document order / format so it can be used by other ESAPI implementations.
	public void function computeAndStoreMAC(required authKey) {
	    if (macComputed()) throws("Programming error: Can't store message integrity code while encrypting; computeAndStoreMAC() called multiple times.");
	    if (!collectedAll()) throws("Have not collected all required information to compute and store MAC.");
	    var result = computeMAC(arguments.authKey);
	    if (!isNull(result)) {
	        storeSeparateMAC(result);
	    }
	    // If 'result' is null, we already logged this in computeMAC().
	}

	/**
	 * Same as {@link #computeAndStoreMAC(SecretKey)} but this is only used by
	 * {@code CipherTextSerializeer}. (Has package level access.)
	 */ // CHECKME: For this to be "safe", it requires ESAPI jar to be sealed.
	public void function storeSeparateMAC(required binary macValue) {
	    if ( !macComputed() ) {
	        variables.separate_mac_ = new Utils().newByte(arrayLen(arguments.macValue));
	        new CryptoHelper(variables.ESAPI).copyByteArray(arguments.macValue, variables.separate_mac_);
	        if (!macComputed()) throws("");
	    }
	}

	/**
	 * Validate the message authentication code (MAC) associated with the ciphertext.
	 * This is mostly meant to ensure that an attacker has not replaced the IV
	 * or raw ciphertext with something arbitrary. Note however that it will
	 * <i>not</i> detect the case where an attacker simply substitutes one
	 * valid ciphertext with another ciphertext.
	 *
	 * @param authKey The secret key that is used for proving authenticity of
	 * 				the IV and ciphertext. This key should be derived from
	 * 				the {@code SecretKey} passed to the
	 * 				{@link Encryptor#encrypt(javax.crypto.SecretKey, PlainText)}
	 *				and
	 *				{@link Encryptor#decrypt(javax.crypto.SecretKey, CipherText)}
	 *				methods or the "master" key when those corresponding
	 *				encrypt / decrypt methods are used. This authenticity key
	 *				should be the same length and for the same cipher algorithm
	 *				as this {@code SecretKey}. The method
	 *				{@link org.owasp.esapi.crypto.CryptoHelper#computeDerivedKey(SecretKey, int, String)}
	 *				is a secure way to produce this derived key.
	 * @return True if the ciphertext has not be tampered with, and false otherwise.
	 */
	public boolean function validateMAC(required authKey) {
	    var requiresMAC = variables.ESAPI.securityConfiguration().useMACforCipherText();

	    if (  requiresMAC && macComputed() ) {  // Uses MAC and it was computed
	        // Calculate MAC from HMAC-SHA1(nonce, IV + plaintext) and
	        // compare to stored value (separate_mac_). If same, then return true,
	        // else return false.
	        var mac = computeMAC(arguments.authKey);
	        if (arrayLen(mac) != arrayLen(variables.separate_mac_)) throws("MACs are of differnt lengths. Should both be the same.");
	        return new CryptoHelper(variables.ESAPI).arrayCompare(mac, variables.separate_mac_); // Safe compare!!!
	    } else if ( ! requiresMAC ) {           // Doesn't require a MAC
	        return true;
	    } else {
	    		// This *used* to be the case (for versions 2.0 and 2.0.1) where we tried to
	    		// accomodate the deprecated decrypt() method from ESAPI 1.4. Unfortunately,
	    		// that was an EPIC FAIL. (See Google Issue # 306 for details.)
	        variables.logger.warning(variables.Logger.SECURITY_FAILURE, "MAC may have been tampered with (e.g., length set to 0).");
	        return false;    // Deprecated decrypt() method removed, so now return false.
	    }
	}

	/**
	 * Return this {@code CipherText} object as a portable (i.e., network byte
	 * ordered) serialized byte array. Note this is <b>not</b> the same as
	 * returning a serialized object using Java serialization. Instead this
	 * is a representation that all ESAPI implementations will use to pass
	 * ciphertext between different programming language implementations.
	 *
	 * @return A network byte-ordered serialized representation of this object.
	 * @throws EncryptionException
	 */    // DISCUSS: This method name sucks too. Suggestions???
	public binary function asPortableSerializedByteArray() {
        // Check if this CipherText object is "complete", i.e., all
        // mandatory has been collected.
	    if ( ! collectedAll() ) {
	        var msg = "Can't serialize this CipherText object yet as not all mandatory information has been collected";
	        throws(new EncryptionException(variables.ESAPI, "Can't serialize incomplete ciphertext info", msg));
	    }

	    // If we are supposed to be using a (separate) MAC, also make sure
	    // that it has been computed/stored.
	    var requiresMAC = variables.ESAPI.securityConfiguration().useMACforCipherText();
	    if (  requiresMAC && ! macComputed() ) {
	        var msg = "Programming error: MAC is required for this cipher mode (" &
	                     getCipherMode() & "), but MAC has not yet been " &
	                     "computed and stored. Call the method " &
	                     "computeAndStoreMAC(SecretKey) first before " &
	                     "attempting serialization.";
	        throws(new EncryptionException(variables.ESAPI, "Can't serialize ciphertext info: Data integrity issue.", msg));
	    }

	    // OK, everything ready, so give it a shot.
	    return new CipherTextSerializer(variables.ESAPI, this).asSerializedByteArray();
	}

    ///// Setters /////
    /**
     * Set the raw ciphertext.
     * @param ciphertext    The raw ciphertext.
     * @throws EncryptionException  Thrown if the MAC has already been computed
     *              via {@link #computeAndStoreMAC(SecretKey)}.
     */
    public void function setCiphertext(required binary ciphertext) {
        if ( ! macComputed() ) {
            if ( isNull(arguments.ciphertext) || arrayLen(arguments.ciphertext) == 0 ) {
                throws(new EncryptionException("Encryption faled; no ciphertext", "Ciphertext may not be null or 0 length!"));
            }
            if ( isCollected(variables.CipherTextFlags.CIPHERTEXT) ) {
                variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Raw ciphertext was already set; resetting.");
            }
            variables.raw_ciphertext_ = new Utils().newByte(arrayLen(arguments.ciphertext));
            new CryptoHelper(variables.ESAPI).copyByteArray(arguments.ciphertext, variables.raw_ciphertext_);
            received(variables.CipherTextFlags.CIPHERTEXT);
            setEncryptionTimestamp();
        } else {
            var logMsg = "Programming error: Attempt to set ciphertext after MAC already computed.";
            variables.logger.error(variables.Logger.SECURITY_FAILURE, logMsg);
            throws(new EncryptionException("MAC already set; cannot store new raw ciphertext", logMsg));
        }
    }

    /**
     * Set the IV and raw ciphertext.
     * @param iv            The initialization vector.
     * @param ciphertext    The raw ciphertext.
     * @throws EncryptionException
     */
    public void function setIVandCiphertext(required binary iv, required binary ciphertext) {
        if ( isCollected(variables.CipherTextFlags.INITVECTOR) ) {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "IV was already set; resetting.");
        }
        if ( isCollected(variables.CipherTextFlags.CIPHERTEXT) ) {
            variables.logger.warning(variables.Logger.SECURITY_FAILURE, "Raw ciphertext was already set; resetting.");
        }
        if ( ! macComputed() ) {
            if (isNull(arguments.ciphertext) || arrayLen(arguments.ciphertext) == 0 ) {
                throws(new EncryptionException("Encryption faled; no ciphertext", "Ciphertext may not be null or 0 length!"));
            }
            if ( isNull(arguments.iv) || arrayLen(arguments.iv) == 0 ) {
                if ( requiresIV() ) {
                    throws(new EncryptionException("Encryption failed -- mandatory IV missing", // DISCUSS - also log? See below.
                                                  "Cipher mode " & getCipherMode() & " has null or empty IV"));
                }
            } else if ( arrayLen(arguments.iv) != getBlockSize() ) {
                    throws(new EncryptionException("Encryption failed -- bad parameters passed to encrypt",  // DISCUSS - also log? See below.
                                                  "IV length does not match cipher block size of " & getBlockSize()));
            }
            variables.cipherSpec_.setIV(arguments.iv);
            received(variables.CipherTextFlags.INITVECTOR);
            setCiphertext( arguments.ciphertext );
        } else {
            var logMsg = "MAC already computed from previously set IV and raw ciphertext; may not be reset -- object is immutable.";
            variables.logger.error(variables.Logger.SECURITY_FAILURE, logMsg);  // Discuss: By throwing, this gets logged as warning, but it's really error! Why is an exception only a warning???
            throws(new EncryptionException(variables.ESAPI, "Validation of decryption failed.", logMsg));
        }
    }

    public numeric function getKDFVersion() {
    	return variables.kdfVersion_;
    }

    public void function setKDFVersion(required numeric vers) {
    	new CryptoHelper(variables.ESAPI).isValidKDFVersion(arguments.vers, false, true);
    	variables.encryption_timestamp_ = arguments.vers;
    }

    public function getKDF_PRF() {
    	return new KeyDerivationFunction(variables.ESAPI).convertIntToPRF(variables.kdfPrfSelection_);
    }

    private numeric function kdfPRFAsInt() {
    	return variables.kdfPrfSelection_;
    }

    public void function setKDF_PRF(required numeric prfSelection) {
        if (arguments.prfSelection < 0 && arguments.prfSelection > 15) throws("kdfPrf == " & arguments.prfSelection & " must be between 0 and 15.");
    	variables.kdfPrfSelection_ = arguments.prfSelection;
    }

    /** Get stored time stamp representing when data was encrypted. */
    public numeric function getEncryptionTimestamp() {
        return variables.encryption_timestamp_;
    }

    /**
     * Set the encryption timestamp to the time stamp specified by the parameter.
     * </p><p>
     * This method is intended for use only by {@code CipherTextSerializer}.
     *
     * @param timestamp The time in milliseconds since epoch time (midnight,
     *                  January 1, 1970 GMT).
     */ // Package level access. ESAPI jar should be sealed and signed.
    public void function setEncryptionTimestamp(numeric timestamp) {
    	if (structKeyExists(arguments, "timestamp")) {
	        if (arguments.timestamp <= 0) throws("Timestamp must be greater than zero.");
	        if ( variables.encryption_timestamp_ == 0 ) {     // Only set it if it's not yet been set.
	            variables.logger.warning(variables.Logger.EVENT_FAILURE, "Attempt to reset non-zero CipherText encryption timestamp to " & new Date(arguments.timestamp) & "!");
	        }
	        variables.encryption_timestamp_ = arguments.timestamp;
		}
		else {
			// We want to skip this when it's already been set via the package
	        // level call setEncryptionTimestamp(long) done via CipherTextSerializer
	        // otherwise it gets reset to the current time. But when it's restored
	        // from a serialized CipherText object, we want to keep the original
	        // encryption timestamp.
	        if ( variables.encryption_timestamp_ != 0 ) {
	            variables.logger.warning(variables.Logger.EVENT_FAILURE, "Attempt to reset non-zero CipherText encryption timestamp to current time!");
	        }
	        variables.encryption_timestamp_ = now().getTime();
		}
    }

    /** Used in supporting {@code CipherText} serialization.
     * @deprecated	Use {@code CipherText.cipherTextVersion} instead. Will
     * 				disappear as of ESAPI 2.1.
     */
    public numeric function getSerialVersionUID() {
        return variables.serialVersionUID;
    }

    /** Return the separately calculated Message Authentication Code (MAC) that
     * is computed via the {@code computeAndStoreMAC(SecretKey authKey)} method.
     * @return The copy of the computed MAC, or {@code null} if one is not used.
     */
    public binary function getSeparateMAC() {
        if (!isBinary(variables.separate_mac_)) {
            return "";
        }
        var copy = new Utils().newByte(arrayLen(variables.separate_mac_));
        createObject("java", "java.lang.System").arraycopy(variables.separate_mac_, 0, copy, 0, arrayLen(variables.separate_mac_));
        return copy;
    }

    /**
     * More useful {@code toString()} method.
     */
    public string function toString() {
        var sb = createObject("java", "java.lang.StringBuilder").init( "CipherText: " );
        var creationTime = (( getEncryptionTimestamp() == 0) ? "No timestamp available" : createObject("java", "java.util.Date").init(javaCast("long", getEncryptionTimestamp())).toString());
        var n = getRawCipherTextByteLength();
        var rawCipherText = (( n > 0 ) ? "present (" & n & " bytes)" : "absent");
        var mac = (isBinary(variables.separate_mac_) ? "present" : "absent");
        sb.append("Creation time: ").append(creationTime);
        sb.append(", raw ciphertext is ").append(rawCipherText);
        sb.append(", MAC is ").append(mac).append("; ");
        sb.append( variables.cipherSpec_.toString() );
        return sb.toString();
    }

    public boolean function isEquals(required other) {
        var result = false;
        if ( super.isEquals(arguments.other) )
            return true;
        if (isNull(arguments.other))
            return false;
        if ( isInstanceOf(arguments.other, "CipherText")) {
            var that = arguments.other;
            if ( this.collectedAll() && that.collectedAll() ) {
                result = (that.canEqual(this) &&
                          variables.cipherSpec_.equals(that.cipherSpec_) &&
                            // Safe comparison, resistant to timing attacks
                          new CryptoHelper(variables.ESAPI).arrayCompare(variables.raw_ciphertext_, that.raw_ciphertext_) &&
                          new CryptoHelper(variables.ESAPI).arrayCompare(variables.separate_mac_, that.separate_mac_) &&
                          variables.encryption_timestamp_ == that.encryption_timestamp_ );
            } else {
                variables.logger.warning(variables.Logger.EVENT_FAILURE, "CipherText.equals(): Cannot compare two CipherText objects that are not complete, and therefore immutable!");
                variables.logger.info(variables.Logger.EVENT_FAILURE, "This CipherText: " & this.collectedAll() & ";other CipherText: " & that.collectedAll());
                variables.logger.info(variables.Logger.EVENT_FAILURE, "CipherText.equals(): Progress comparison: " & ((variables.progress == that.progress) ? "Same" : "Different"));
                variables.logger.info(variables.Logger.EVENT_FAILURE, "CipherText.equals(): Status this: " & variables.progress & "; status other CipherText object: " & that.progress);
                // CHECKME: Perhaps we should throw a RuntimeException instead???
                return false;
            }
        }
        return result;
    }

    public numeric function hashCode() {
        if ( this.collectedAll() ) {
                variables.logger.warning(variables.Logger.EVENT_FAILURE, "CipherText.hashCode(): Cannot compute hachCode() of incomplete CipherText object; object not immutable- returning 0.");
                // CHECKME: Throw RuntimeException instead?
                return 0;
        }
        var sb = new StringBuilder();
        sb.append( variables.cipherSpec_.hashCode() );
        sb.append( variables.encryption_timestamp_ );
        var raw_ct = "";
        var mac = "";
        try {
            raw_ct = new String(variables.raw_ciphertext_, "UTF-8");
                // Remember, MAC is optional even when CipherText is complete.
            mac = charsetEncode(isBinary(variables.separate_mac_) ? variables.separate_mac_ : new Utils().newByte(), "utf-8");
        } catch(UnsupportedEncodingException ex) {
            // Should never happen as UTF-8 encode supported by rt.jar,
            // but it it does, just use default encoding.
            raw_ct = new String(variables.raw_ciphertext_);
            mac = toString(isBinary(variables.separate_mac_) ? variables.separate_mac_ : new Utils().newByte());
        }
        sb.append( raw_ct );
        sb.append( mac );
        return sb.toString().hashCode();
    }

    /**
     * Needed for correct definition of equals for general classes.
     * (Technically not needed for 'final' classes though like this class
     * though; this will just allow it to work in the future should we
     * decide to allow * sub-classing of this class.)
     * </p><p>
     * See {@link http://www.artima.com/lejava/articles/equality.html}
     * for full explanation.
     * </p>
     */
    private boolean function canEqual(required other) {
        return (isInstanceOf(arguments.other, "CipherText"));
    }

    ////////////////////////////////////  P R I V A T E  /////////////////////////////////////////

    /**
     * Compute a MAC, but do not store it. May set the nonce value as a
     * side-effect.  The MAC is calculated as:
     * <pre>
     *      HMAC-SHA1(nonce, IV + plaintext)
     * </pre>
     * @param ciphertext    The ciphertext value for which the MAC is computed.
     * @return The value for the MAC.
     */
    private binary function computeMAC(required authKey) {
        if (isNull(variables.raw_ciphertext_) || arrayLen(variables.raw_ciphertext_) == 0) throws("Raw ciphertext may not be null or empty.");
        if (isNull(authKey) || arrayLen(authKey.getEncoded()) == 0) throws("Authenticity secret key may not be null or zero length.");
        try {
        	// IMPORTANT NOTE: The NSA review was (apparently) OK with using HmacSHA1
        	// to calculate the MAC that ensures authenticity of the IV+ciphertext.
        	// (Not true of calculation of the use HmacSHA1 for the KDF though.) Therefore,
        	// we did not make this configurable. Note also that choosing an improved
        	// MAC algorithm here would cause the overall length of the serialized ciphertext
        	// to be just that much longer, which is probably unacceptable when encrypting
        	// short strings.
            var sk = createObject("java", "javax.crypto.spec.SecretKeySpec").init(arguments.authKey.getEncoded(), "HmacSHA1");
            var mac = createObject("java", "javax.crypto.Mac").getInstance("HmacSHA1");
            mac.init(sk);
            if ( requiresIV() ) {
                mac.update( getIV() );
            }
            var result = mac.doFinal( getRawCipherText() );
            return result;
        } catch (NoSuchAlgorithmException e) {
            variables.logger.error(variables.Logger.SECURITY_FAILURE, "Cannot compute MAC w/out HmacSHA1.", e);
            return "";
        } catch (InvalidKeyException e) {
            variables.logger.error(variables.Logger.SECURITY_FAILURE, "Cannot comput MAC; invalid 'key' for HmacSHA1.", e);
            return "";
        }
    }

    /**
     * Return true if the MAC has already been computed (i.e., not null).
     */
    private boolean function macComputed() {
        return (isBinary(variables.separate_mac_));
    }

    /**
     * Return true if we've collected all the required pieces; otherwise false.
     */
    private boolean function collectedAll() {
        var ctFlags = "";
        if ( requiresIV() ) {
            ctFlags = allCtFlags;
        } else {
            var initVector = EnumSet.of(variables.CipherTextFlags.INITVECTOR);
            ctFlags = EnumSet.complementOf(initVector);
        }
        var result = variables.progress.containsAll(ctFlags);
        return result;
    }

    /** Check if we've collected a specific flag type.
     * @param flag  The flag type; e.g., {@code CipherTextFlags.INITVECTOR}, etc.
     * @return  Return true if we've collected a specific flag type; otherwise false.
     */
    private boolean function isCollected(required flag) {
        return variables.progress.contains(arguments.flag);
    }

    /**
     * Add the flag to the set of what we've already collected.
     * @param flag  The flag type to be added; e.g., {@code CipherTextFlags.INITVECTOR}.
     */
    private void function received(required flag) {
        variables.progress.add(arguments.flag);
    }

    /**
     * Add all the flags from the specified set to that we've collected so far.
     * @param ctSet A {@code EnumSet<CipherTextFlags>} containing all the flags
     *              we wish to add.
     */
    private void function receivedMany(required ctSet) {
        var it = arguments.ctSet.iterator();
        while ( it.hasNext() ) {
            received( it.next() );
        }
    }

    /**
     * Based on the KDF version and the selected MAC algorithm for the KDF PRF,
     * calculate the 32-bit quantity representing these.
     * @return	A 4-byte (octet) quantity representing the KDF version and the
     * 			MAC algorithm used for the KDF's Pseudo-Random Function.
     * @see <a href="http://owasp-esapi-java.googlecode.com/svn/trunk/documentation/esapi4java-core-2.0-ciphertext-serialization.pdf">Format of portable serialization of org.owasp.esapi.crypto.CipherText object (pg 2)</a>
     */
	public numeric function getKDFInfo() {
		var unusedBit28 = 134217728;  // 1000000000000000000000000000

		// 		kdf version is bits 1-27, bit 28 (reserved) should be 0, and
		//		bits 29-32 are the MAC algorithm indicating which PRF to use for the KDF.
		var kdfVers = this.getKDFVersion();
		if (!new CryptoHelper(variables.ESAPI).isValidKDFVersion(kdfVers, true, false)) throws("");
		var kdfInfo = kdfVers;
		var macAlg = kdfPRFAsInt();
		if (macAlg < 0 && macAlg > 15) throws("MAC algorithm indicator must be between 0 to 15 inclusion; value is: " & macAlg);

	    // Make sure bit28 is cleared. (Reserved for future use.)
	    kdfInfo = bitAnd(kdfInfo, bitNot(unusedBit28));

	    // Set MAC algorithm bits in high (MSB) nibble.
	    kdfInfo = bitOr(kdfInfo, bitSHLN(macAlg, 28));

		return kdfInfo;
	}
}
