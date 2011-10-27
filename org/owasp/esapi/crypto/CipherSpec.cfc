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
component CipherSpec extends="cfesapi.org.owasp.esapi.lang.Object" {

	instance.serialVersionUID = 20090822;// version, in YYYYMMDD format
	instance.ESAPI = "";

	this.cipher_xform_ = "";
	this.keySize_ = "";// In bits
	this.blockSize_ = 16;// In bytes! I.e., 128 bits!!!
	this.iv_ = toBinary("");

	// Cipher transformation component. Format is ALG/MODE/PADDING
	CipherTransformationComponent = {ALG=new CipherTransformationComponent(1), 
                                  MODE=new CipherTransformationComponent(2),
                                  PADDING=new CipherTransformationComponent(3)};

	/**
	 * CTOR that explicitly sets everything.
	 * @param cipherXform    The cipher transformation
	 * @param keySize        The key size (in bits).
	 * @param blockSize        The block size (in bytes).
	 * @param iv            The initialization vector. Null if not applicable.
	 */
	
	public CipherSpec function init(required cfesapi.org.owasp.esapi.ESAPI ESAPI, 
	                                cipher,String cipherXform, numeric keySize, 
	                                numeric blockSize,binary iv) {
		instance.ESAPI = arguments.ESAPI;
	
		CryptoHelper = new cfesapi.org.owasp.esapi.crypto.CryptoHelper(instance.ESAPI);
	
		if(structKeyExists(arguments, "cipher")) {
			setCipherTransformation(arguments.cipher.getAlgorithm(), true);
			setBlockSize(arguments.cipher.getBlockSize());
			if(!isNull(arguments.cipher.getIV())) {
				setIV(arguments.cipher.getIV());
			}
		}
		else { 
			if(structKeyExists(arguments, "cipherXform")) {
				setCipherTransformation(arguments.cipherXform);
			}
			else {
				setCipherTransformation(instance.ESAPI.securityConfiguration().getCipherTransformation());
			}
			if(structKeyExists(arguments, "blockSize")) {
				setBlockSize(arguments.blockSize);
			}
			if(structKeyExists(arguments, "iv")) {
				setIV(arguments.iv);
			}
		}
		if(structKeyExists(arguments, "keySize")) {
			setKeySize(arguments.keySize);
		}
		else {
			setKeySize(instance.ESAPI.securityConfiguration().getEncryptionKeyLength());
		}
	
		return this;
	}
	
	private binary function newByte(required numeric len) {
		StringBuilder = newJava("java.lang.StringBuilder").init();
		StringBuilder.setLength(arguments.len);
		return StringBuilder.toString().getBytes();
	}
	
	/**
	 * Set the cipher transformation for this {@code CipherSpec}. This is only
	 * used by the CTOR {@code CipherSpec(Cipher)} and {@code CipherSpec(Cipher, int)}.
	 * @param cipherXform    The cipher transformation string; e.g.,
	 *                         "DESede/CBC/PKCS5Padding". May not be null or empty.
	 * @param fromCipher If true, the cipher transformation was set via
	 *                      {@code Cipher.getAlgorithm()} which may only return the
	 *                      actual algorithm. In that case we check and if all 3 parts
	 *                      were not specified, then we specify the parts that were
	 *                      based on "ECB" as the default cipher mode and "NoPadding"
	 *                      as the default padding scheme.
	 * @return    This current {@code CipherSpec} object.
	 */
	
	public CipherSpec function setCipherTransformation(required String cipherXform, 
	                                                   boolean fromCipher=false) {
		if(!newJava("org.owasp.esapi.StringUtilities").notNullOrEmpty(arguments.cipherXform, true)) {// Yes, really want '!' here.
			throwError(newJava("java.lang.IllegalArgumentException").init("Cipher transformation may not be null or empty string (after trimming whitespace)."));
		}
		local.parts = arrayLen(arguments.cipherXform.split("/"));
		assert((!arguments.fromCipher ? (local.parts == 3) : true), "Malformed cipherXform (" & arguments.cipherXform & '); must have form: "alg/mode/paddingscheme"');
		if(arguments.fromCipher && (local.parts != 3)) {
			// Indicates cipherXform was set based on Cipher.getAlgorithm()
			// and thus may not be a *complete* cipher transformation.
			if(local.parts == 1) {
				// Only algorithm was given.
				arguments.cipherXform &= "/ECB/NoPadding";
			}
			else if(local.parts == 2) {
				// Only algorithm and mode was given.
				arguments.cipherXform &= "/NoPadding";
			}
			else if(local.parts == 3) {
				// All three parts provided. Do nothing. Could happen if not compiled with
				// assertions enabled.// Do nothing - shown only for completeness.
			}
			else {
				// Should never happen unless Cipher implementation is totally screwed up.
				throwError(newJava("java.lang.IllegalArgumentException").init('Cipher transformation "' & arguments.cipherXform & '" must have form "alg/mode/paddingscheme"'));
			}
		}
		else if(!arguments.fromCipher && local.parts != 3) {
			throwError(newJava("java.lang.IllegalArgumentException").init("Malformed cipherXform (" & arguments.cipherXform & '); must have form: "alg/mode/paddingscheme"'));
		}
		assert(arrayLen(arguments.cipherXform.split("/")) == 3, "Implementation error setCipherTransformation()");
		this.cipher_xform_ = arguments.cipherXform;
		return this;
	}
	
	/**
	 * Get the cipher transformation.
	 * @return    The cipher transformation {@code String}.
	 */
	
	public String function getCipherTransformation() {
		return this.cipher_xform_;
	}
	
	/**
	 * Set the key size for this {@code CipherSpec}.
	 * @param keySize    The key size, in bits. Must be positive integer.
	 * @return    This current {@code CipherSpec} object.
	 */
	
	public CipherSpec function setKeySize(required numeric keySize) {
		assert(keySize > 0, "keySize must be > 0; keySize=" & keySize);
		this.keySize_ = arguments.keySize;
		return this;
	}
	
	/**
	 * Retrieve the key size, in bits.
	 * @return    The key size, in bits, is returned.
	 */
	
	public numeric function getKeySize() {
		return this.keySize_;
	}
	
	/**
	 * Set the block size for this {@code CipherSpec}.
	 * @param blockSize    The block size, in bytes. Must be positive integer.
	 * @return    This current {@code CipherSpec} object.
	 */
	
	public CipherSpec function setBlockSize(required numeric blockSize) {
		assert(blockSize > 0, "blockSize must be > 0; blockSize=" & blockSize);
		this.blockSize_ = arguments.blockSize;
		return this;
	}
	
	/**
	 * Retrieve the block size, in bytes.
	 * @return    The block size, in bytes, is returned.
	 */
	
	public numeric function getBlockSize() {
		return this.blockSize_;
	}
	
	/**
	 * Retrieve the cipher algorithm.
	 * @return    The cipher algorithm.
	 */
	
	public String function getCipherAlgorithm() {
		return getFromCipherXform(CipherTransformationComponent.ALG);
	}
	
	/**
	 * Retrieve the cipher mode.
	 * @return    The cipher mode.
	 */
	
	public String function getCipherMode() {
		return getFromCipherXform(CipherTransformationComponent.MODE);
	}
	
	/**
	 * Retrieve the cipher padding scheme.
	 * @return    The padding scheme is returned.
	 */
	
	public String function getPaddingScheme() {
		return getFromCipherXform(CipherTransformationComponent.PADDING);
	}
	
	/**
	 * Retrieve the initialization vector (IV).
	 * @return    The IV as a byte array.
	 */
	
	public binary function getIV() {
		return this.iv_;
	}
	
	/**
	 * Set the initialization vector (IV).
	 * @param iv    The byte array to set as the IV. A copy of the IV is saved.
	 *                 This parameter is ignored if the cipher mode does not
	 *                 require an IV.
	 * @return        This current {@code CipherSpec} object.
	 */
	
	public CipherSpec function setIV(required binary iv) {
		assert(requiresIV() && (!isNull(arguments.iv) && arrayLen(arguments.iv) != 0), "Required IV cannot be null or 0 length");
		// Don't store a reference, but make a copy!
		if(!isNull(arguments.iv)) {// Allow null IV for ECB mode.
			this.iv_ = newByte(arrayLen(arguments.iv));
			CryptoHelper.copyByteArray(arguments.iv, this.iv_);
		}
		return this;
	}
	
	/**
	 * Return true if the cipher mode requires an IV.
	 * @return True if the cipher mode requires an IV, otherwise false.
	 * */
	
	public boolean function requiresIV() {
		local.cm = getCipherMode();
	
		// Add any other cipher modes supported by JCE but not requiring IV.
		// ECB is the only one I'm aware of that doesn't. Mode is not case
		// sensitive.
		if("ECB" == local.cm) {
			return false;
		}
		return true;
	}
	
	/**
	 * Override {@code Object.toString()} to provide something more useful.
	 * @return A meaningful string describing this object.
	 */
	//@Override
	
	public String function toString() {
		local.sb = newJava("java.lang.StringBuilder").init("CipherSpec: ");
		local.sb.append(getCipherTransformation()).append("; keysize= ").append(javaCast("int", getKeySize()));
		local.sb.append(" bits; blocksize= ").append(javaCast("int", getBlockSize())).append(" bytes");
		local.iv = getIV();
		local.ivLen = "";
		if(!isNull(local.iv)) {
			local.ivLen = "" & arrayLen(local.iv);// Convert length to a string
		}
		else {
			local.ivLen = "[No IV present (not set or not required)]";
		}
		local.sb.append("; IV length = ").append(local.ivLen).append(" bytes.");
		return local.sb.toString();
	}
	
	/**
	 * {@inheritDoc}
	 */
	//@Override
	
	public boolean function equalsObj(required other) {
		local.result = false;
		/* throws error - anyway to make this work?
		if(this == other) {
			return true;
		} */
		if(!isObject(arguments.other)) {
			return false;
		}
		if(isInstanceOf(arguments.other, "cfesapi.org.owasp.esapi.crypto.CipherSpec")) {
			NullSafe = newJava("org.owasp.esapi.util.NullSafe");
			local.that = arguments.other;
			local.result = (local.that.canEqual(this) && NullSafe.equals(this.cipher_xform_, local.that.cipher_xform_) 
		&& this.keySize_ == local.that.keySize_ && this.blockSize_ == local.that.blockSize_ 
		&& CryptoHelper.arrayCompare(this.iv_, local.that.iv_));// Comparison safe from timing attacks.
		}
		return local.result;
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public int function hashCode() {
		local.sb = newJava("java.lang.StringBuilder").init();
		local.sb.append(getCipherTransformation());
		local.sb.append("" & getKeySize());
		local.sb.append("" & getBlockSize());
		local.iv = getIV();
		if(!isNull(local.iv) && local.iv.length > 0) {
			local.ivStr = "";
			try {
				local.ivStr = newJava("java.lang.String").init(local.iv, "UTF-8");
			}
			catch(java.io.UnsupportedEncodingException ex) {
				// Should never happen as UTF-8 encode supported by rt.jar,
				// but it it does, just use default encoding.
				local.ivStr = newJava("java.lang.String").init(local.iv);
			}
			local.sb.append(local.ivStr);
		}
		return local.sb.toString().hashCode();
	}
	
	/**
	 * Needed for correct definition of equals for general classes.
	 * (Technically not needed for 'final' classes like this class though; this
	 * will just allow it to work in the future should we decide to allow
	 * sub-classing of this class.)
	 * </p><p>
	 * See {@link http://www.artima.com/lejava/articles/equality.html}
	 * for full explanation.
	 * </p>
	 */
	
	package boolean function canEqual(required other) {
		return isInstanceOf(arguments.other, "cfesapi.org.owasp.esapi.crypto.CipherSpec");
	}
	
	/**
	 * Split the current cipher transformation and return the requested part. 
	 * @param component The component of the cipher transformation to return.
	 * @return The cipher algorithm, cipher mode, or padding, as requested.
	 */
	
	private String function getFromCipherXform(required cfesapi.org.owasp.esapi.crypto.CipherTransformationComponent obj) {
		local.part = arguments.obj.ordinal();
		local.parts = getCipherTransformation().split("/");
		assert(arrayLen(local.parts) == 3, "Invalid cipher transformation: " & getCipherTransformation());
		return local.parts[local.part];
	}
	
}