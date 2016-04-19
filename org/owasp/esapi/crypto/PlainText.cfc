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
 * A class representing plaintext (versus ciphertext) as related to
 * cryptographic systems.  This class embodies UTF-8 byte-encoding to
 * translate between byte arrays and {@code String}s. Once constructed, this
 * object is immutable.
 * <p>
 * Note: Conversion to/from UTF-8 byte-encoding can, in theory, throw
 * an {@code UnsupportedEncodingException}. However, UTF-8 encoding
 * should be a standard encoding for all Java installations, so an
 * {@code UnsupportedEncodingException} never actually be thrown. Therefore,
 * in order to to keep client code uncluttered, any possible
 * {@code UnsupportedEncodingException}s will be first logged, and then
 * re-thrown as a {@code RuntimeException} with the original
 * {@code UnsupportedEncodingException} as the cause.
 */
component extends="org.owasp.esapi.util.Object" {

	variables.serialVersionUID = 20090921;
	variables.logger = "";

	variables.rawBytes = "";

	/**
	 * Construct a {@code PlainText} object from a {@code String} or {@code byte} array.
	 * @param str	The {@code String} that is converted to a UTF-8 encoded
	 * 				byte array to create the {@code PlainText} object.
	 * @throws IllegalArgumentException	If {@code str} argument is null.
	 */
	public PlainText function init(required org.owasp.esapi.ESAPI ESAPI, required str) {
		variables.ESAPI = arguments.ESAPI;
		variables.logger = variables.ESAPI.getLogger(getMetaData(this).fullName);

		if (isNull(arguments.str)) {
	    	throws(createObject("java", "java.lang.IllegalArgumentException").init("String representing plaintext cannot be null."));
	    }

		if (isBinary(arguments.str)) {
			// Must allow 0 length arrays though, to represent empty strings.
		    // Make copy so mutable byte array b can't change PlainText.
			variables.rawBytes = new Utils().newByte(arrayLen(arguments.str));
			createObject("java", "java.lang.System").arraycopy(arguments.str, 0, variables.rawBytes, 0, arrayLen(arguments.str));
		}
		else {
			try {
				variables.rawBytes = arguments.str.getBytes("UTF-8");
			}
			catch (UnsupportedEncodingException e) {
				// Should never happen.
				variables.logger.error(variables.Logger.EVENT_FAILURE, "PlainText(String) CTOR failed: Can't find UTF-8 byte-encoding!", e);
				throws(createObject("java", "java.lang.RuntimeException").init("Can't find UTF-8 byte-encoding!", e));
			}
		}

		return this;
	}

	/**
	 * Convert the {@code PlainText} object to a UTF-8 encoded {@code String}.
	 * @return	A {@code String} representing the {@code PlainText} object.
	 */
	public string function toString() {
		try {
			return charsetEncode(variables.rawBytes, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// Should never happen.
			variables.logger.error(variables.Logger.EVENT_FAILURE, "PlainText.toString() failed: Can't find UTF-8 byte-encoding!", e);
			throws(createObject("java", "java.lang.RuntimeException").init("Can't find UTF-8 byte-encoding!", e));
		}
	}

	/**
	 * Convert the {@code PlainText} object to a byte array.
	 * @return	A byte array representing the {@code PlainText} object.
	 */
	public binary function asBytes() {
	    var bytes = new Utils().newByte(arrayLen(variables.rawBytes));
	    createObject("java", "java.lang.System").arraycopy(variables.rawBytes, 0, bytes, 0, arrayLen(variables.rawBytes));
		return bytes;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean function isEquals(required anObject) {
        if (super.isEquals(arguments.anObject)) return true;
        if (isNull(arguments.anObject)) return false;
        var result = false;
        if ( isInstanceOf(arguments.anObject, "PlainText") ) {
            var that = arguments.anObject;
            result = ( that.canEqual(this) &&
                    ( this.toString() == that.toString() )
                  );
        }
        return result;
	}

	/**
	 * Same as {@code this.toString().hashCode()}.
	 * @return	{@code this.toString().hashCode()}.
	 */
	public numeric function hashCode() {
		return this.toString().hashCode();
	}

	/**
	 * Return the length of the UTF-8 encoded byte array representing this
	 * object. Note that if this object was constructed with the constructor
	 * {@code PlainText(String str)}, then this length might not necessarily
	 * agree with {@code str.length()}.
	 *
	 * @return	The length of the UTF-8 encoded byte array representing this
	 * 			object.
	 */
	public numeric function length() {
		return arrayLen(variables.rawBytes);
	}

	// DISCUSS: Should we set 'rawBytes' to null??? Won't make it eligible for
	//			GC unless this PlainText object is set to null which can't do
	//			from here. If we set it to null, most methods will cause
	//			NullPointerException to be thrown. Also will have to change a
	//			lot of JUnit tests.
	/**
	 * First overwrite the bytes of plaintext with the character '*'.
	 */
	public void function overwrite() {
		new CryptoHelper(variables.ESAPI).overwrite(variables.rawBytes);
		// variables.rawBytes = null;					// See above comment re: discussion.
	}

    /**
     * Needed for correct definition of equals for general classes.
     * (Technically not needed for 'final' classes though like this class
     * though; this will just allow it to work in the future should we
     * decide to allow * sub-classing of this class.)
     * </p><p>
     * See <a href="http://www.artima.com/lejava/articles/equality.html">
     * How to write an Equality Method in Java</a>
     * for full explanation.
     * </p>
     */
    package boolean function canEqual(required other) {
        return (isInstanceOf(other, "PlainText"));
    }
}