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
import "org.owasp.esapi.util.Utils";

/**
 * Specifies all the relevant configuration data needed in constructing and
 * using a {@link javax.crypto.Cipher} except for the encryption key.
 * </p><p>
 * The "setters" all return a reference to {@code this} so that they can be
 * strung together.
 * </p><p>
 * Note: While this is a useful class in it's own right, it should primarily be
 * regarded as an implementation class to use with ESAPI encryption, especially
 * the reference implementation. It is <i>not</i> intended to be used directly
 * by application developers, but rather only by those either extending ESAPI
 * or in the ESAPI reference implementation. Use <i>directly</i> by application
 * code is not recommended or supported.
 */
component extends="org.owasp.esapi.util.Object" {

	variables.serialVersionUID = 20090822;	// version, in YYYYMMDD format

	variables.cipher_xform_   = "";
	variables.keySize_        = ""; // In bits
	variables.blockSize_      = 16;   // In bytes! I.e., 128 bits!!!
	variables.iv_             = "";

	// Cipher transformation component. Format is ALG/MODE/PADDING
    variables.CipherTransformationComponent = {"ALG": 1, "MODE": 2, "PADDING": 3};

	/**
	 * CTOR that explicitly sets everything.
	 * @param cipherXform	The cipher transformation
	 * @param keySize		The key size (in bits).
	 * @param blockSize		The block size (in bytes).
	 * @param iv			The initialization vector. Null if not applicable.
	 */
	public CipherSpec function init(required org.owasp.esapi.ESAPI ESAPI, cipher, string cipherXform, numeric keySize, numeric blockSize, binary iv) {
		variables.ESAPI = arguments.ESAPI;
		variables.cipher_xform_ = variables.ESAPI.securityConfiguration().getCipherTransformation();
		variables.keySize_ = variables.ESAPI.securityConfiguration().getEncryptionKeyLength(); // In bits

		if (structKeyExists(arguments, "cipher") && !isNull(arguments.cipher)) {
			setCipherTransformation(arguments.cipher.getAlgorithm(), true);
			setBlockSize(arguments.cipher.getBlockSize());
			var cipherIV = "";
			try {
				cipherIV = arguments.cipher.getIV();
			}
			catch (any e) {}
			if (!isNull(cipherIV) && isObject(cipherIV)) {
				setIV(cipherIV);
			}
		}
		else {
			if (structKeyExists(arguments, "cipherXform") && !isNull(arguments.cipherXform)) setCipherTransformation(arguments.cipherXform);
			if (structKeyExists(arguments, "blockSize") && !isNull(arguments.blockSize)) setBlockSize(arguments.blockSize);
			if (structKeyExists(arguments, "iv") && !isNull(arguments.iv)) setIV(arguments.iv);
		}
		if (structKeyExists(arguments, "keySize") && !isNull(arguments.keySize)) setKeySize(arguments.keySize);

		return this;
	}

	/**
	 * Set the cipher transformation for this {@code CipherSpec}. This is only
	 * used by the CTOR {@code CipherSpec(Cipher)} and {@code CipherSpec(Cipher, int)}.
	 * @param cipherXform	The cipher transformation string; e.g.,
	 * 						"DESede/CBC/PKCS5Padding". May not be null or empty.
	 * @param fromCipher If true, the cipher transformation was set via
	 * 					 {@code Cipher.getAlgorithm()} which may only return the
	 * 					 actual algorithm. In that case we check and if all 3 parts
	 * 					 were not specified, then we specify the parts that were
	 * 					 based on "ECB" as the default cipher mode and "NoPadding"
	 * 					 as the default padding scheme.
	 * @return	This current {@code CipherSpec} object.
	 */
	public CipherSpec function setCipherTransformation(required string cipherXform, boolean fromCipher=false) {
		if ( !createObject("java", "org.owasp.esapi.StringUtilities").notNullOrEmpty(arguments.cipherXform, true) ) {	// Yes, really want '!' here.
			throws(createObject("java", "java.lang.IllegalArgumentException").init("Cipher transformation may not be null or empty string (after trimming whitespace)."));
		}
		var parts = arrayLen(listToArray(arguments.cipherXform, "/"));
		if (!arguments.fromCipher && parts != 3) throws("Malformed cipherXform (" & arguments.cipherXform & "); must have form: ""alg/mode/paddingscheme""");
		if ( arguments.fromCipher && parts != 3  ) {
				// Indicates cipherXform was set based on Cipher.getAlgorithm()
				// and thus may not be a *complete* cipher transformation.
			if ( parts == 1 ) {
				// Only algorithm was given.
				arguments.cipherXform &= "/ECB/NoPadding";
			} else if ( parts == 2 ) {
				// Only algorithm and mode was given.
				arguments.cipherXform &= "/NoPadding";
			} else if ( parts == 3 ) {
				// All three parts provided. Do nothing. Could happen if not compiled with
				// assertions enabled.
				;	// Do nothing - shown only for completeness.
			} else {
				// Should never happen unless Cipher implementation is totally screwed up.
				throws(createObject("java", "java.lang.IllegalArgumentException").init("Cipher transformation '" & arguments.cipherXform & "' must have form ""alg/mode/paddingscheme"""));
			}
		} else if ( !arguments.fromCipher && parts != 3 ) {
			throws(createObject("java", "java.lang.IllegalArgumentException").init("Malformed cipherXform (" & arguments.cipherXform & "); must have form: ""alg/mode/paddingscheme"""));
		}
		if (arrayLen(listToArray(arguments.cipherXform, "/")) != 3) throws("Implementation error setCipherTransformation()");
		variables.cipher_xform_ = arguments.cipherXform;
		return this;
	}

	/**
	 * Get the cipher transformation.
	 * @return	The cipher transformation {@code String}.
	 */
	public string function getCipherTransformation() {
		return variables.cipher_xform_;
	}

	/**
	 * Set the key size for this {@code CipherSpec}.
	 * @param keySize	The key size, in bits. Must be positive integer.
	 * @return	This current {@code CipherSpec} object.
	 */
	public CipherSpec function setKeySize(required numeric keySize) {
		if (arguments.keySize <= 0) throws("keySize must be > 0; keySize=" & arguments.keySize);
		variables.keySize_ = arguments.keySize;
		return this;
	}

	/**
	 * Retrieve the key size, in bits.
	 * @return	The key size, in bits, is returned.
	 */
	public numeric function getKeySize() {
		return variables.keySize_;
	}

	/**
	 * Set the block size for this {@code CipherSpec}.
	 * @param blockSize	The block size, in bytes. Must be positive integer.
	 * @return	This current {@code CipherSpec} object.
	 */
	public CipherSpec function setBlockSize(required numeric blockSize) {
		if (arguments.blockSize <= 0) throws("blockSize must be > 0; blockSize=" & arguments.blockSize);
		variables.blockSize_ = arguments.blockSize;
		return this;
	}

	/**
	 * Retrieve the block size, in bytes.
	 * @return	The block size, in bytes, is returned.
	 */
	public numeric function getBlockSize() {
		return variables.blockSize_;
	}

	/**
	 * Retrieve the cipher algorithm.
	 * @return	The cipher algorithm.
	 */
	public string function getCipherAlgorithm() {
		return getFromCipherXform(variables.CipherTransformationComponent.ALG);
	}

	/**
	 * Retrieve the cipher mode.
	 * @return	The cipher mode.
	 */
	public string function getCipherMode() {
		return getFromCipherXform(variables.CipherTransformationComponent.MODE);
	}

	/**
	 * Retrieve the cipher padding scheme.
	 * @return	The padding scheme is returned.
	 */
	public string function getPaddingScheme() {
		return getFromCipherXform(variables.CipherTransformationComponent.PADDING);
	}

	/**
	 * Retrieve the initialization vector (IV).
	 * @return	The IV as a byte array.
	 */
	public function getIV() {
		return variables.iv_;
	}

	/**
	 * Set the initialization vector (IV).
	 * @param iv	The byte array to set as the IV. A copy of the IV is saved.
	 * 				This parameter is ignored if the cipher mode does not
	 * 				require an IV.
	 * @return		This current {@code CipherSpec} object.
	 */
	public CipherSpec function setIV(required binary iv) {
		if (requiresIV() && (isNull(arguments.iv) || arrayLen(arguments.iv) == 0)) throws("Required IV cannot be null or 0 length");
		// Don't store a reference, but make a copy!
		if (!isNull(arguments.iv) && isBinary(arguments.iv)) {	// Allow null IV for ECB mode.
			variables.iv_ = new Utils().newByte(arrayLen(arguments.iv));
			new CryptoHelper(variables.ESAPI).copyByteArray(arguments.iv, variables.iv_);
		}
		else if (isSimpleValue(arguments.iv)) {
			variables.iv_ = "";
		}
		return this;
	}

	/**
	 * Return true if the cipher mode requires an IV.
	 * @return True if the cipher mode requires an IV, otherwise false.
	 * */
	public boolean function requiresIV() {
		var cm = getCipherMode();

		// Add any other cipher modes supported by JCE but not requiring IV.
		// ECB is the only one I'm aware of that doesn't. Mode is not case
		// sensitive.
		if ("ECB" == cm) {
			return false;
		}
		return true;
	}

	/**
	 * Override {@code Object.toString()} to provide something more useful.
	 * @return A meaningful string describing this object.
	 */
	public string function toString() {
		var sb = createObject("java", "java.lang.StringBuilder").init("CipherSpec: ");
		sb.append( getCipherTransformation() );
		sb.append("; keysize= ");
		sb.append( toString(getKeySize()) );
		sb.append(" bits; blocksize= ");
		sb.append( toString(getBlockSize()) );
		sb.append(" bytes");
		var iv = getIV();
		var ivLen = "";
		if (isBinary(iv)) {
			ivLen = "" & arrayLen(iv);	// Convert length to a string
		} else {
			ivLen = "[No IV present (not set or not required)]";
		}
		sb.append("; IV length = ").append( ivLen ).append(" bytes.");
		return sb.toString();
	}

    public boolean function isEquals(required other) {
        var result = false;
        if ( this == arguments.other )
            return true;
        if ( arguments.other == null )
            return false;
        if ( isInstanceOf(arguments.other, "CipherSpec")) {
            var that = arguments.other;
            result = (that.canEqual(this) &&
                      NullSafe.equals(variables.cipher_xform_, that.cipher_xform_) &&
                      variables.keySize_ == that.keySize_ &&
                      variables.blockSize_ == that.blockSize_ &&
                        // Comparison safe from timing attacks.
                      CryptoHelper.arrayCompare(variables.iv_, that.iv_) );
        }
        return result;
    }

    public numeric function hashCode() {
        var sb = new StringBuilder();
        sb.append( getCipherTransformation() );
        sb.append( "" & getKeySize() );
        sb.append( "" & getBlockSize() );
        var iv = getIV();
        if ( iv != null && iv.length > 0 ) {
            var ivStr = null;
            try {
                ivStr = new String(iv, "UTF-8");
            }
            catch(UnsupportedEncodingException ex) {
                // Should never happen as UTF-8 encode supported by rt.jar,
                // but it it does, just use default encoding.
                ivStr = new String(iv);
            }
            sb.append( ivStr );
        }
        return sb.toString().hashCode();
    }

    /**
     * Needed for correct definition of equals for general classes.
     * (Technically not needed for 'final' classes like this class though; this
     * will just allow it to work in the future should we decide to allow
     * sub-classing of this class.)
     * </p><p>
     * See <a href="http://www.artima.com/lejava/articles/equality.html">
     * How to write an Equality Method in Java</a>
     * for full explanation.
     * </p>
     */
    private boolean function canEqual(required other) {
        return (isInstanceOf(arguments.other, "CipherSpec"));
    }

	/**
	 * Split the current cipher transformation and return the requested part.
	 * @param component The component of the cipher transformation to return.
	 * @return The cipher algorithm, cipher mode, or padding, as requested.
	 */
	private string function getFromCipherXform(required numeric comp) {
        var part = arguments.comp;
		var parts = listToArray(getCipherTransformation(), "/");
		if (arrayLen(parts) != 3) throws("Invalid cipher transformation: " & getCipherTransformation());
		return parts[part];
	}
}
