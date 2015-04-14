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
import "org.owasp.esapi.errors.EncryptionException";

/**
 * Helper class to assist with programming language and platform independent
 * serialization of {@link CipherText} objects. The serialization is done in
 * network-byte order which is the same as big-endian byte order.
 * <p>
 * This serialization scheme is documented in
 * <a href="http://owasp-esapi-java.googlecode.com/svn/trunk/documentation/esapi4java-core-2.0-ciphertext-serialization.pdf">
 * <code>Format of Portable Serialization of org.owasp.esapi.crypto.CipherText Objects</code>.</a>
 * Other serialization schemes may be desirable and could be supported (notably, RFC 5083 - Cryptographic
 * Message Syntax (CMS) Authenticated-Enveloped-Data Content Type, or CMS' predecessor,
 * PKCS#7 (RFC 2315)), but these serialization schemes are by comparison very complicated,
 * and do not have extensive support for the various implementation languages which ESAPI
 * supports. (Perhaps wishful thinking that other ESAPI implementations such as
 * ESAPI for .NET, ESAPI for C, ESAPI for C++, etc. will all support a single, common
 * serialization technique so they could exchange encrypted data.)
 */
component extends="org.owasp.esapi.util.Object" {
    // This should be *same* version as in CipherText & KeyDerivationFunction as
	// these versions all need to work together.  Therefore, when one changes one
	// one these versions, the other should be reviewed and changed as well to
	// accommodate any differences.
	//		Previous versions:	20110203 - Original version (ESAPI releases 2.0 & 2.0.1)
	//						    20130830 - Fix to issue #306 (release 2.1.0)
	// We check that in an static initialization block (when assertions are enabled)
	// below.
	variables.cipherTextSerializerVersion = 20130830; // Current version. Format: YYYYMMDD, max is 99991231.
    variables.serialVersionUID = variables.cipherTextSerializerVersion;

    variables.logger = "";

    variables.cipherText_ = "";

    // Check if versions of KeyDerivationFunction, CipherText, and
    // CipherTextSerializer are all the same.
	// Ignore error about comparing identical versions and dead code.
	// We expect them to be, but the point is to catch us if they aren't.
	//assert variables.cipherTextSerializerVersion == CipherText.cipherTextVersion : "Versions of CipherTextSerializer and CipherText are not compatible.";
	//assert variables.cipherTextSerializerVersion == KeyDerivationFunction.kdfVersion : "Versions of CipherTextSerializer and KeyDerivationFunction are not compatible.";

    public CipherTextSerializer function init(required org.owasp.esapi.ESAPI ESAPI, required cipherTextObj) {
    	variables.ESAPI = arguments.ESAPI;
    	variables.logger = variables.ESAPI.getLogger("CipherTextSerializer");

    	if (isNull(arguments.cipherTextObj)) {
    		raiseException(createObject("java", "java.lang.IllegalArgumentException").init("CipherText object must not be null."));
    	}
    	if (isBinary(arguments.cipherTextObj)) {
			variables.cipherText_ = convertToCipherText(arguments.cipherTextObj);
        }
        else {
        	variables.cipherText_ = arguments.cipherTextObj;
        }

        return this;
    }

    /** Return this {@code CipherText} object as a specialized, portable
     *  serialized byte array.
     * @return A serialization of this object. Note that this is <i>not</i> the
     * Java serialization.
     */
    public binary function asSerializedByteArray() {
    	var Short = createObject("java", "java.lang.Short");
        var kdfInfo = variables.cipherText_.getKDFInfo();
        debug("asSerializedByteArray: kdfInfo = " & kdfInfo);
        var timestamp = variables.cipherText_.getEncryptionTimestamp();
        var cipherXform = variables.cipherText_.getCipherTransformation();
        if (variables.cipherText_.getKeySize() >= Short.MAX_VALUE) raiseException("Key size too large. Max is " & Short.MAX_VALUE);
        var keySize = variables.cipherText_.getKeySize();
        if (variables.cipherText_.getBlockSize() >= Short.MAX_VALUE) raiseException("Block size too large. Max is " & Short.MAX_VALUE);
        var blockSize = variables.cipherText_.getBlockSize();
        var iv = variables.cipherText_.getIV();
        if (arrayLen(iv) >= Short.MAX_VALUE) raiseException("IV size too large. Max is " & Short.MAX_VALUE);
        var ivLen = arrayLen(iv);
        var rawCiphertext = variables.cipherText_.getRawCipherText();
        var ciphertextLen = arrayLen(rawCiphertext);
        if (ciphertextLen < 1) raiseException("Raw ciphertext length must be >= 1 byte.");
        var mac = variables.cipherText_.getSeparateMAC();
        if (arrayLen(mac) >= Short.MAX_VALUE) raiseException("MAC length too large. Max is " & Short.MAX_VALUE);
        var macLen = arrayLen(mac);

        var serializedObj = computeSerialization(kdfInfo,
                                                    timestamp,
                                                    cipherXform,
                                                    keySize,
                                                    blockSize,
                                                    ivLen,
                                                    iv,
                                                    ciphertextLen,
                                                    rawCiphertext,
                                                    macLen,
                                                    mac
                                                   );

        return serializedObj;
    }

    /**
     * Return the actual {@code CipherText} object.
     * @return The {@code CipherText} object that we are serializing.
     */
    public CipherText function asCipherText() {
        return variables.cipherText_;
    }

    /**
     * Take all the individual elements that make of the serialized ciphertext
     * format and put them in order and return them as a byte array.
     * @param kdfInfo	Info about the KDF... which PRF and the KDF version {@link #asCipherText()}.
     * @param timestamp	Timestamp when the data was encrypted. Intended to help
     * 					facilitate key change operations and nothing more. If it is meaningless,
     * 					then the expectations are just that the recipient should ignore it. Mostly
     * 					intended when encrypted data is kept long term over a period of many
     * 					key change operations.
     * @param cipherXform	Details of how the ciphertext was encrypted. The format used
     * 						is the same as used by {@code javax.crypto.Cipher}, namely,
     * 						"cipherAlg/cipherMode/paddingScheme".
     * @param keySize	The key size used for encrypting. Intended for cipher algorithms
     * 					supporting multiple key sizes such as triple DES (DESede) or
     * 					Blowfish.
     * @param blockSize	The cipher block size. Intended to support cipher algorithms
     * 					that support variable block sizes, such as Rijndael.
     * @param ivLen		The length of the IV.
     * @param iv		The actual IV (initialization vector) bytes.
     * @param ciphertextLen	The length of the raw ciphertext.
     * @param rawCiphertext	The actual raw ciphertext itself
     * @param macLen	The length of the MAC (message authentication code).
     * @param mac		The MAC itself.
     * @return	A byte array representing the serialized ciphertext.
     */
    private binary function computeSerialization(required numeric kdfInfo, required numeric timestamp,
                                        required string cipherXform, required numeric keySize,
                                        required numeric blockSize,
                                        required numeric ivLen, required binary iv,
                                        required numeric ciphertextLen, required binary rawCiphertext,
                                        required numeric macLen, required binary mac
                                       )
    {
        debug("computeSerialization: kdfInfo = " & arguments.kdfInfo);
        debug("computeSerialization: timestamp = " & createObject("java", "java.util.Date").init(javaCast("long", arguments.timestamp)));
        debug("computeSerialization: cipherXform = " & arguments.cipherXform);
        debug("computeSerialization: keySize = " & arguments.keySize);
        debug("computeSerialization: blockSize = " & arguments.blockSize);
        debug("computeSerialization: ivLen = " & arguments.ivLen);
        debug("computeSerialization: ciphertextLen = " & arguments.ciphertextLen);
        debug("computeSerialization: macLen = " & arguments.macLen);

        var baos = createObject("java", "java.io.ByteArrayOutputStream").init();
        writeInt(baos, arguments.kdfInfo);
        writeLong(baos, arguments.timestamp);
        var parts = arguments.cipherXform.split("/");
        if (arrayLen(parts) != 3) raiseException("Malformed cipher transformation");
        writeString(baos, arguments.cipherXform); // Size of string is prepended to string
        writeShort(baos, arguments.keySize);
        writeShort(baos, arguments.blockSize);
        writeShort(baos, arguments.ivLen);
        if ( arguments.ivLen > 0 ) baos.write(arguments.iv, 0, arrayLen(arguments.iv));
        writeInt(baos, arguments.ciphertextLen);
        baos.write(arguments.rawCiphertext, 0, arrayLen(arguments.rawCiphertext));
        writeShort(baos, arguments.macLen);
        if ( arguments.macLen > 0 ) baos.write(arguments.mac, 0, arrayLen(arguments.mac));
        return baos.toByteArray();
    }

    // All strings are written as UTF-8 encoded byte streams with the
    // length prepended before it as a short. The prepended length is
    // more for the benefit of languages like C so they can pre-allocate
    // char arrays without worrying about buffer overflows.
    private void function writeString(required baos, required string str) {
        var bytes = "";
        try {
            if (isNull(arguments.str) || len(arguments.str) == 0) raiseException("");
            bytes = arguments.str.getBytes("UTF8");
            if (arrayLen(bytes) >= createObject("java", "java.lang.Short").MAX_VALUE) raiseException("writeString: String exceeds max length");
            writeShort(arguments.baos, arrayLen(bytes));
            arguments.baos.write(bytes, 0, arrayLen(bytes));
        } catch (UnsupportedEncodingException e) {
            // Should never happen. UTF8 is built into the rt.jar. We don't use native encoding as
            // a fall-back because that simply is not guaranteed to be portable across Java
            // platforms and could cause really bizarre errors way downstream.
            variables.logger.error(variables.Logger.EVENT_FAILURE, "Ignoring caught UnsupportedEncodingException converting string to UTF8 encoding. Results suspect. Corrupt rt.jar????");
        }
    }

    private string function readString(required bais, required numeric sz) {
        var bytes = new Utils().newByte(sz);
        var ret = arguments.bais.read(bytes, 0, sz);
        if (ret != sz) raiseException("readString: Failed to read " & sz & " bytes.");
        return charsetEncode(bytes, "UTF-8");
    }

    private void function writeShort(required baos, required numeric s) {
        var shortAsByteArray = createObject("java", "org.owasp.esapi.util.ByteConversionUtil").fromShort(javaCast("short", arguments.s));
        if (arrayLen(shortAsByteArray) != 2) raiseException("Error");
        arguments.baos.write(shortAsByteArray, 0, 2);
    }

    private numeric function readShort(required bais) {
        var shortAsByteArray = new Utils().newByte(2);
        var ret = arguments.bais.read(shortAsByteArray, 0, 2);
        if (ret != 2) raiseException("readShort: Failed to read 2 bytes.");
        return createObject("java", "org.owasp.esapi.util.ByteConversionUtil").toShort(shortAsByteArray);
    }

    private void function writeInt(required baos, required numeric i) {
        var intAsByteArray = createObject("java", "org.owasp.esapi.util.ByteConversionUtil").fromInt(javaCast("int", arguments.i));
        arguments.baos.write(intAsByteArray, 0, 4);
    }

    private numeric function readInt(required bais) {
        var intAsByteArray = new Utils().newByte(4);
        var ret = arguments.bais.read(intAsByteArray, 0, 4);
        if (ret != 4) raiseException("readInt: Failed to read 4 bytes.");
        return createObject("java", "org.owasp.esapi.util.ByteConversionUtil").toInt(intAsByteArray);
    }

    private void function writeLong(required baos, required numeric l) {
        var longAsByteArray = createObject("java", "org.owasp.esapi.util.ByteConversionUtil").fromLong(javaCast("long", arguments.l));
        if (arrayLen(longAsByteArray) != 8) raiseException("error");
        arguments.baos.write(longAsByteArray, 0, 8);
    }

    private numeric function readLong(required bais) {
        var longAsByteArray = new Utils().newByte(8);
        var ret = arguments.bais.read(longAsByteArray, 0, 8);
        if (ret != 8) raiseException("readLong: Failed to read 8 bytes.");
        return createObject("java", "org.owasp.esapi.util.ByteConversionUtil").toLong(longAsByteArray);
    }

    /** Convert the serialized ciphertext byte array to a {@code CipherText}
     * object.
     * @param cipherTextSerializedBytes	The serialized ciphertext as a byte array.
     * @return The corresponding {@code CipherText} object.
     * @throws EncryptionException	Thrown if the byte array data is corrupt or
     * 				there are version mismatches, etc.
     */
    private CipherText function convertToCipherText(required binary cipherTextSerializedBytes) {
    	var Utils = new Utils();
    	var CryptoHelper = new CryptoHelper(variables.ESAPI);
    	var KeyDerivationFunction = new KeyDerivationFunction(variables.ESAPI);
        try {
        	if (isNull(arguments.cipherTextSerializedBytes)) raiseException("cipherTextSerializedBytes cannot be null.");
        	if (arrayLen(arguments.cipherTextSerializedBytes) == 0) raiseException("cipherTextSerializedBytes must be > 0 in length.");
            var bais = createObject("java", "java.io.ByteArrayInputStream").init(arguments.cipherTextSerializedBytes);
            var kdfInfo = readInt(bais);
            debug("kdfInfo: " & kdfInfo);
            // FIXME: can CF do a bitSHRN() + left zero-fill?
            /* ORIGINAL LINE: var kdfPrf = (kdfInfo >>> 28); */
            var kdfPrf = bitSHRN(kdfInfo, 28);
            debug("kdfPrf: " & kdfPrf);
            if (kdfPrf < 0 || kdfPrf > 15) raiseException("kdfPrf == " & kdfPrf & " must be between 0 and 15.");
            /* ORIGINAL LINE: var kdfVers = ( kdfInfo & 0x07ffffff); */
            var kdfVers = bitAnd(kdfInfo, 134217727);

            // First do a quick sanity check on the argument. Previously this was an assertion.
            if ( ! CryptoHelper.isValidKDFVersion(kdfVers, false, false) ) {
            	// TODO: Clean up. Use StringBuilder. Good enough for now.
            	var logMsg = "KDF version read from serialized ciphertext (" & kdfVers & ") is out of range. Valid range for KDF version is [" & KeyDerivationFunction.originalVersion & ", 99991231].";
            	// This should never happen under actual circumstances (barring programming errors; but we've
            	// tested the code, right?), so it is likely an attempted attack. Thus don't get the originator
            	// of the suspect ciphertext too much info. They ought to know what they sent anyhow.
            	raiseException(new EncryptionException(variables.ESAPI, "Version info from serialized ciphertext not in valid range.", "Likely tampering with KDF version on serialized ciphertext." & logMsg));
            }

            debug("convertToCipherText: kdfPrf = " & kdfPrf & ", kdfVers = " & kdfVers);
            if ( ! versionIsCompatible( kdfVers) ) {
            	raiseException(new EncryptionException(variables.ESAPI, "This version of ESAPI does is not compatible with the version of ESAPI that encrypted your data.", "KDF version " & kdfVers & " from serialized ciphertext not compatibile with current KDF version of " & KeyDerivationFunction.kdfVersion));
            }
            var timestamp = readLong(bais);
            debug("convertToCipherText: timestamp = " & createObject("java", "java.util.Date").init(javaCast("long", timestamp)));
            var strSize = readShort(bais);
            debug("convertToCipherText: length of cipherXform = " & strSize);
            var cipherXform = readString(bais, strSize);
            debug("convertToCipherText: cipherXform = " & cipherXform);
            var parts = cipherXform.split("/");
            if (arrayLen(parts) != 3) raiseException("Malformed cipher transformation");
            var cipherMode = parts[2];
            if ( ! CryptoHelper.isAllowedCipherMode(cipherMode) ) {
                var msg = "Cipher mode " & cipherMode & " is not an allowed cipher mode";
                raiseException(new EncryptionException(variables.ESAPI, msg, msg));
            }
            var keySize = readShort(bais);
            debug("convertToCipherText: keySize = " & keySize);
            var blockSize = readShort(bais);
            debug("convertToCipherText: blockSize = " & blockSize);
            var ivLen = readShort(bais);
            debug("convertToCipherText: ivLen = " & ivLen);
            var iv = "";
            if ( ivLen > 0 ) {
                iv = Utils.newByte(ivLen);
                bais.read(iv, 0, arrayLen(iv));
            }
            var ciphertextLen = readInt(bais);
            debug("convertToCipherText: ciphertextLen = " & ciphertextLen);
            if (ciphertextLen <= 0) raiseException("convertToCipherText: Invalid cipher text length");
            var rawCiphertext = Utils.newByte(ciphertextLen);
            bais.read(rawCiphertext, 0, arrayLen(rawCiphertext));
            var macLen = readShort(bais);
            debug("convertToCipherText: macLen = " & macLen);
            var mac = "";
            if ( macLen > 0 ) {
                mac = Utils.newByte(macLen);
                bais.read(mac, 0, arrayLen(mac));
            }

            var cipherSpec = new CipherSpec(ESAPI=variables.ESAPI, cipherXform=cipherXform, keySize=keySize);
            cipherSpec.setBlockSize(blockSize);
            cipherSpec.setIV(iv);
            debug("convertToCipherText: CipherSpec: " & cipherSpec.toString());
            var ct = new CipherText(variables.ESAPI, cipherSpec);
            if ( ! (ivLen > 0 && ct.requiresIV()) ) {
                    raiseException(new EncryptionException(variables.ESAPI, "convertToCipherText: Mismatch between IV length and cipher mode.", "Possible tampering of serialized ciphertext?"));
            }
            ct.setCiphertext(rawCiphertext);
              // Set this *AFTER* setting raw ciphertext because setCiphertext()
              // method also sets encryption time.
            ct.setEncryptionTimestamp(timestamp);
            if ( macLen > 0 ) {
                ct.storeSeparateMAC(mac);
            }
            	// Fixed in ESAPI crypto version 20130839. Previously is didn't really matter
            	// because there was only one version (20110203) and it defaulted to that
            	// version, which was the current version. But we don't want that as now there
            	// are two versions and we could be decrypting data encrypted using the previous
            	// version.
            ct.setKDF_PRF(kdfPrf);
            ct.setKDFVersion(kdfVers);
            return ct;
        } catch(org.owaspi.esapi.errors.EncryptionException ex) {
            raiseException(new EncryptionException(variables.ESAPI, "Cannot deserialize byte array into CipherText object", "Cannot deserialize byte array into CipherText object", ex));
        } catch (java.io.IOException e) {
            raiseException(new EncryptionException(variables.ESAPI, "Cannot deserialize byte array into CipherText object", "Cannot deserialize byte array into CipherText object", e));
        }
    }

    /** Check to see if we can support the KSF version that was extracted from
     *  the serialized ciphertext. In particular, we assume that if we have a
     *  newer version of KDF than we can support it as we assume that we have
     *  built in backward compatibility.
     *
     *  At this point (ESAPI 2.1.0, KDF version 20130830), all we need to check
     *  if the version is either the current version or the previous version as
     *  both versions work the same. This checking may get more complicated in
     *  the future.
     *
     *  @param readKdfVers	The version information extracted from the serialized
     *  					ciphertext.
     */
    private boolean function versionIsCompatible(required numeric readKdfVers) {
    	// We've checked elsewhere for this, so assertion is OK here.
    	if (arguments.readKdfVers <= 0) raiseException("Extracted KDF version is negative!");

		var KeyDerivationFunction = new KeyDerivationFunction(variables.ESAPI);

		switch ( arguments.readKdfVers ) {
		case KeyDerivationFunction.originalVersion:		// First version
			return true;
		// Add new versions here; hard coding is OK...
		// case YYYYMMDD:
		//	return true;
		case KeyDerivationFunction.kdfVersion:			// Current version
			return true;
		default:
			return false;
		}
	}

	private void function debug(required string msg) {
        if ( variables.logger.isDebugEnabled() ) {
            variables.logger.debug(variables.Logger.EVENT_SUCCESS, arguments.msg);
        }
    }
}
