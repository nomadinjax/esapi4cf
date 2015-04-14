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

/**
 * The Encryptor interface provides a set of methods for performing common
 * encryption, random number, and hashing operations. Implementations should
 * rely on a strong cryptographic implementation, such as JCE or BouncyCastle.
 * Implementors should take care to ensure that they initialize their
 * implementation with a strong "master key", and that they protect this secret
 * as much as possible.
 * <P>
 * The main property controlling the selection of the implementation class is the
 * property {@code ESAPI.Encryptor} in {@code ESAPI.properties}. Most of the
 * the other encryption related properties have property names that start with
 * the string "Encryptor.". These properties all you to do things such as
 * select the encryption algorithms, the preferred JCE provider, etc.
 * </P><P>
 * In addition, there are two important properties (initially delivered as unset
 * from the ESAPI download) named {@code Encryptor.MasterKey} and
 * {@code Encryptor.MasterSalt} that must be set before using ESAPI encryption.
 * There is a <i>bash</i>(1) shell script provided with the standard ESAPI distribution
 * called 'setMasterKey.sh' that will assist you in setting these two properties. The
 * script is in 'src/examples/scripts/setMasterKey.sh'.
 * </P><P>
 * Possible future enhancements (depending on feedback) are discussed in
 * section 4 of
 * <a href="http://owasp-esapi-java.googlecode.com/svn/trunk/documentation/esapi4java-core-2.0-crypto-design-goals.doc">
 * Design Goals in OWASP ESAPI Cryptography</a>.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see <a href="http://owasp-esapi-java.googlecode.com/svn/trunk/documentation/esapi4java-core-2.0-symmetric-crypto-user-guide.html">User Guide for Symmetric Encryption in ESAPI 2.0</a>
 */
interface {

	/**
	 * Returns a string representation of the hash of the provided plaintext and
	 * salt. The salt helps to protect against a rainbow table attack by mixing
	 * in some extra data with the plaintext. Some good choices for a salt might
	 * be an account name or some other string that is known to the application
	 * but not to an attacker.
	 * See <a href="http://www.matasano.com/log/958/enough-with-the-rainbow-tables-what-you-need-to-know-about-secure-password-schemes/">
	 * this article</a> for more information about hashing as it pertains to password schemes.
	 *
	 * @param plaintext
	 * 		the plaintext String to encrypt
	 * @param salt
	 *      the salt to add to the plaintext String before hashing
	 * @param iterations
	 *      the number of times to iterate the hash
	 *
	 * @return
	 * 		the encrypted hash of 'plaintext' stored as a String
	 *
	 * @throws EncryptionException
	 *      if the specified hash algorithm could not be found or another problem exists with
	 *      the hashing of 'plaintext'
	 */
	public string function hash(required string plaintext, required string salt, numeric iterations);

	 /**
	  * Encrypts the provided plaintext bytes using the cipher transformation
	  * specified by the property <code>Encryptor.CipherTransformation</code>
	  * as defined in the <code>ESAPI.properties</code> file and the
	  * <i>specified secret key</i>.
	  * </p><p>
	  * This method is similar to {@link #encrypt(PlainText)} except that it
	  * permits a specific {@code SecretKey} to be used for encryption.
	  *
	  * @param key		The {@code SecretKey} to use for encrypting the plaintext.
	  * @param plaintext	The byte stream to be encrypted. Note if a Java
	  * 				{@code String} is to be encrypted, it should be converted
	  * 				using {@code "some string".getBytes("UTF-8")}.
	  * @return the {@code CipherText} object from which the raw ciphertext, the
	  * 				IV, the cipher transformation, and many other aspects about
	  * 				the encryption detail may be extracted.
	  * @throws EncryptionException Thrown if something should go wrong such as
	  * 				the JCE provider cannot be found, the cipher algorithm,
	  * 				cipher mode, or padding scheme not being supported, specifying
	  * 				an unsupported key size, specifying an IV of incorrect length,
	  * 				etc.
	  * @see #encrypt(PlainText)
	  * @since 2.0
	  */
	 public CipherText function encrypt(required PlainText plain, key);

	/**
	 * Decrypts the provided {@link CipherText} using the information from it
	 * and the <i>specified secret key</i>.
	 * </p><p>
	 * This decrypt method is similar to {@link #decrypt(CipherText)} except that
	 * it allows decrypting with a secret key other than the <i>master secret key</i>.
	 * </p>
	 * @param key		The {@code SecretKey} to use for encrypting the plaintext.
	 * @param ciphertext The {@code CipherText} object to be decrypted.
	 * @return The {@code PlainText} object resulting from decrypting the specified
	 * 		   ciphertext. Note that it it is desired to convert the returned
	 * 		   plaintext byte array to a Java String is should be done using
	 * 		   {@code new String(byte[], "UTF-8");} rather than simply using
	 * 		   {@code new String(byte[]);} which uses native encoding and may
	 * 		   not be portable across hardware and/or OS platforms.
	 * @throws EncryptionException  Thrown if something should go wrong such as
	 * 				the JCE provider cannot be found, the cipher algorithm,
	 * 				cipher mode, or padding scheme not being supported, specifying
	 * 				an unsupported key size, or incorrect encryption key was
	 * 				specified or a {@code PaddingException} occurs.
	 * @see #decrypt(CipherText)
	 */
	public PlainText function decrypt(required CipherText ciphertext, key);

	/**
	 * Create a digital signature for the provided data and return it in a
	 * string.
	 * <p>
	 * <b>Limitations:</b> A new public/private key pair used for ESAPI 2.0 digital
	 * signatures with this method and {@link #verifySignature(String, String)}
	 * are dynamically created when the default reference implementation class,
	 * {@link org.owasp.esapi.reference.crypto.JavaEncryptor} is first created.
	 * Because this key pair is not persisted nor is the public key shared,
	 * this method and the corresponding {@link #verifySignature(String, String)}
	 * can not be used with expected results across JVM instances. This limitation
	 * will be addressed in ESAPI 2.1.
	 * </p>
	 *
	 * @param data
	 *      the data to sign
	 *
	 * @return
	 * 		the digital signature stored as a String
	 *
	 * @throws EncryptionException
	 * 		if the specified signature algorithm cannot be found
	 */
	public string function sign(required string data);

	/**
	 * Verifies a digital signature (created with the sign method) and returns
	 * the boolean result.
     * <p>
     * <b>Limitations:</b> A new public/private key pair used for ESAPI 2.0 digital
     * signatures with this method and {@link #sign(String)}
     * are dynamically created when the default reference implementation class,
     * {@link org.owasp.esapi.reference.crypto.JavaEncryptor} is first created.
     * Because this key pair is not persisted nor is the public key shared,
     * this method and the corresponding {@link #sign(String)}
     * can not be used with expected results across JVM instances. This limitation
     * will be addressed in ESAPI 2.1.
     * </p>
	 * @param signature
	 *      the signature to verify against 'data'
	 * @param data
	 *      the data to verify against 'signature'
	 *
	 * @return
	 * 		true, if the signature is verified, false otherwise
	 *
	 */
	public boolean function verifySignature(required string signature, required string data);

	/**
	 * Creates a seal that binds a set of data and includes an expiration timestamp.
	 *
	 * @param data
	 *      the data to seal
	 * @param timestamp
	 *      the absolute expiration date of the data, expressed as seconds since the epoch
	 *
	 * @return
     * 		the seal
     * @throws IntegrityException
	 *
	 */
	public string function seal(required string data, required numeric expiration);

	/**
	 * Unseals data (created with the seal method) and throws an exception
	 * describing any of the various problems that could exist with a seal, such
	 * as an invalid seal format, expired timestamp, or decryption error.
	 *
	 * @param seal
	 *      the sealed data
	 *
	 * @return
	 * 		the original (unsealed) data
	 *
	 * @throws EncryptionException
	 * 		if the unsealed data cannot be retrieved for any reason
	 */
	public string function unseal(required string seal);

	/**
	 * Verifies a seal (created with the seal method) and throws an exception
	 * describing any of the various problems that could exist with a seal, such
	 * as an invalid seal format, expired timestamp, or data mismatch.
	 *
	 * @param seal
	 *      the seal to verify
	 *
	 * @return
	 * 		true, if the seal is valid.  False otherwise
	 */
	public boolean function verifySeal(required string seal);

	/**
	 * Gets an absolute timestamp representing an offset from the current time to be used by
	 * other functions in the library.
	 *
	 * @param offset
	 * 		the offset to add to the current time
	 *
	 * @return
	 * 		the absolute timestamp
	 */
	public numeric function getRelativeTimeStamp(required numeric offset);

	/**
	 * Gets a timestamp representing the current date and time to be used by
	 * other functions in the library.
	 *
	 * @return
	 * 		a timestamp representing the current time
	 */
	public numeric function getTimeStamp();

}