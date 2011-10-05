<!---
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
	--->
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" output="false" hint="Class to provide some convenience methods for encryption, decryption, etc.">

	<cfscript>
		instance.ESAPI = "";
		instance.logger = "";
	</cfscript>
 
	<cffunction access="public" returntype="CryptoHelper" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("CryptoHelper");

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="generateSecretKey" output="false" hint="javax.crypto.SecretKey: Generate a random secret key appropriate to the specified cipher algorithm and key size.">
		<cfargument type="String" name="alg" required="true" hint="The cipher algorithm or cipher transformation. (If the latter is passed, the cipher algorithm is determined from it.)">
		<cfargument type="numeric" name="keySize" required="true" hint="The key size, in bits.">
		<cfscript>
			assert( arguments.keySize > 0 );	// Usually should be even multiple of 8, but not strictly required by alg.

			// Don't use CipherSpec here to get algorithm as this may cause assertion
			// to fail (when enabled) if only algorithm name is passed to us.
			local.cipherSpec = arguments.alg.split("/");
			local.cipherAlg = local.cipherSpec[1];
			try {
			    // Special case for things like PBEWithMD5AndDES or PBEWithSHA1AndDESede.
			    // In such cases, the key generator should only request an instance of "PBE".
			    if ( local.cipherAlg.toUpperCase().startsWith("PBEWITH") ) {
			        local.cipherAlg = "PBE";
			    }
				local.kgen = createObject("java", "javax.crypto.KeyGenerator").getInstance( local.cipherAlg );
				local.kgen.init(arguments.keySize);
				return local.kgen.generateKey();
			} catch (java.security.NoSuchAlgorithmException e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Failed to generate random secret key", "Failed to generate secret key for " & arguments.alg & " with size of " & arguments.keySize & " bits.", e);
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="computeDerivedKey" output="false" hint="javax.crypto.SecretKey: Compute a derived key from the keyDerivationKey for either encryption / decryption or for authentication.">
		<cfargument type="any" name="keyDerivationKey" required="true" hint="javax.crypto.SecretKey: A key used as an input to a key derivation function to derive other keys. This is the key that generally is created using some key generation mechanism such as generateSecretKey(String, int).">
		<cfargument type="numeric" name="keySize" required="true" hint="The cipher's key size (in bits) for the keyDerivationKey. Must have a minimum size of 56 bits and be an integral multiple of 8-bits. The derived key will have the same size as this.">
		<cfargument type="String" name="purpose" required="true" hint="The purpose for the derived key. Must be either the string 'encryption' or 'authenticity'.">
		<cfscript>
			assert(!isNull(arguments.keyDerivationKey), "Master key cannot be null.");
			// We would choose a larger minimum key size, but we want to be
			// able to accept DES for legacy encryption needs.
			assert(arguments.keySize >= 56, "Master key has size of " & arguments.keySize & ", which is less than minimum of 56-bits.");
			assert((arguments.keySize % 8) == 0, "Key size (" & arguments.keySize & ") must be a even multiple of 8-bits.");
			assert(!isNull(arguments.purpose));
			assert(arguments.purpose.equals("encryption") || arguments.purpose.equals("authenticity"), 'Purpose must be "encryption" or "authenticity".');

			arguments.keySize = calcKeySize( arguments.keySize );	// Safely convert to whole # of bytes.
			local.derivedKey = newByte( arguments.keySize );
			local.tmpKey = "";
			local.inputBytes = "";
			try {
				local.inputBytes = arguments.purpose.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption failure (internal encoding error: UTF-8)", "UTF-8 encoding is NOT supported as a standard byte encoding: " & e.message, e);
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}

			// Note that keyDerivationKey is going to be some SecretKey like an AES or
			// DESede key, but not an HmacSHA1 key. That means it is not likely
			// going to be 20 bytes but something different. Experiments show
			// that doesn't really matter though as the SecretKeySpec CTOR on
			// the following line still returns the appropriate sized key for
			// HmacSHA1.
			local.sk = createObject("java", "javax.crypto.spec.SecretKeySpec").init(arguments.keyDerivationKey.getEncoded(), "HmacSHA1");
			local.mac = "";

			try {
				local.mac = createObject("java", "javax.crypto.Mac").getInstance("HmacSHA1");
				local.mac.init(local.sk);
			} catch( InvalidKeyException ex ) {
				instance.logger.error(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Created HmacSHA1 Mac but SecretKey sk has alg " & local.sk.getAlgorithm(), ex);
				throw(object=ex);
			}

			// Repeatedly call of HmacSHA1 hash until we've collected enough bits
			// for the derived key. The first time through, we calculate the HmacSHA1
			// on the "purpose" string, but subsequent calculations are performed
			// on the previous result.
			local.totalCopied = 0;
			local.destPos = 0;
			local.len = 0;
			do {
	            // According to the Javadoc for Mac.doFinal(byte[]),
	            // "A call to this method resets this Mac object to the state it was
	            // in when previously initialized via a call to init(Key) or
	            // init(Key, AlgorithmParameterSpec). That is, the object is reset
	            // and available to generate another MAC from the same key, if
	            // desired, via new calls to update and doFinal."
				local.tmpKey = local.mac.doFinal(local.inputBytes);
				if ( arrayLen(local.tmpKey) >= arguments.keySize ) {
					local.len = arguments.keySize;
				} else {
					local.len = min(arrayLen(local.tmpKey), arguments.keySize - local.totalCopied);
				}
				System.arraycopy(local.tmpKey, 0, local.derivedKey, local.destPos, local.len);
				local.inputBytes = local.tmpKey;
				local.totalCopied += arrayLen(local.tmpKey);
				local.destPos += local.len;
			} while( local.totalCopied < arguments.keySize );

			return createObject("java", "javax.crypto.spec.SecretKeySpec").init(local.derivedKey, arguments.keyDerivationKey.getAlgorithm());
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isCombinedCipherMode" output="false" hint="Return true if specified cipher mode is one of those specified in the ESAPI.properties file that supports both confidentiality AND authenticity (i.e., a 'combined cipher mode' as NIST refers to it).">
		<cfargument type="String" name="cipherMode" required="true" hint="The specified cipher mode to be used for the encryption or decryption operation.">
		<cfscript>
		    assert(!isNull(arguments.cipherMode), "Cipher mode may not be null");
		    assert(!arguments.cipherMode == "", "Cipher mode may not be empty string");
		    local.combinedCipherModes = instance.ESAPI.securityConfiguration().getCombinedCipherModes();
		    return arrayFind( local.combinedCipherModes, arguments.cipherMode ) ? true : false;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isAllowedCipherMode" output="false" hint="Return true if specified cipher mode is one that may be used for encryption / decryption operations via org.owasp.esapi.Encryptor.">
		<cfargument type="String" name="cipherMode" required="true" hint="The specified cipher mode to be used for the encryption or decryption operation.">
		<cfscript>
		    if ( isCombinedCipherMode(arguments.cipherMode) ) {
		        return true;
		    }
		    local.extraCipherModes = instance.ESAPI.securityConfiguration().getAdditionalAllowedCipherModes();
		    return arrayFind( local.extraCipherModes, arguments.cipherMode ) ? true : false;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isMACRequired" output="false" hint="Check to see if a Message Authentication Code (MAC) is required for a given CipherText object and the current ESAPI.property settings. A MAC is considered 'required' if the specified CipherText was not encrypted by one of the preferred 'combined' cipher modes (e.g., CCM or GCM) and the setting of the current ESAPI properties for the property Encryptor.CipherText.useMAC is set to true. (Normally, the setting for Encryptor.CipherText.useMAC should be set to true unless FIPS 140-2 compliance is required. See User Guide for Symmetric Encryption in ESAPI 2.0 and the section on using ESAPI with FIPS for further details.">
		<cfargument type="cfesapi.org.owasp.esapi.crypto.CipherText" name="ct" required="true" hint="The specified CipherText object to check to see if it requires a MAC.">
		<cfscript>
	        local.preferredCipherMode = isCombinedCipherMode( arguments.ct.getCipherMode() );
	        local.wantsMAC = instance.ESAPI.securityConfiguration().useMACforCipherText();

	        // The preferred "combined" cipher modes such as CCM, GCM, etc. do
	        // not require a MAC as a MAC would be superfluous and just require
	        // additional computing time.
	        return ( !local.preferredCipherMode && local.wantsMAC );
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isCipherTextMACvalid" output="false" hint="If a Message Authentication Code (MAC) is required for the specified CipherText object, then attempt to validate the MAC that should be embedded within the CipherText object by using a derived key based on the specified SecretKey.">
		<cfargument type="any" name="sk" required="true" hint="javax.crypto.SecretKey: The SecretKey used to derived a key to check the authenticity via the MAC.">
		<cfargument type="cfesapi.org.owasp.esapi.crypto.CipherText" name="ct" required="true" hint="The CipherText that we are checking for a valid MAC.">
		<cfscript>
	        if ( isMACRequired( arguments.ct ) ) {
	            try {
	                local.authKey = computeDerivedKey( arguments.sk, arguments.ct.getKeySize(), "authenticity");
	                local.validMAC = arguments.ct.validateMAC( local.authKey );
	                return local.validMAC;
	            } catch (Exception ex) {
	                // Error on side of security. If this fails and can't verify MAC
	                // assume it is invalid. Note that CipherText.toString() does not
	                // print the actual ciphertext.
	                instance.logger.warning(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Unable to validate MAC for ciphertext " & arguments.ct, ex);
	                return false;
	            }
	        }
	        return true;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="overwrite" output="false" hint="Overwrite a byte array with a specified byte. This is frequently done to a plaintext byte array so the sensitive data is not lying around exposed in memory.">
		<cfargument type="binary" name="bytes" required="true" hint="The byte array to be overwritten.">
		<cfargument type="String" name="x" required="false" default="*" hint="The byte array bytes is overwritten with this byte.">
		<cfscript>
			createObject("java", "java.util.Arrays").fill(arguments.bytes, javaCast("byte", asc(arguments.x)));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="copyByteArray" output="false" hint="These provide for a bit more type safety when copying bytes around.">
		<cfargument type="binary" name="src" required="true" hint="the source array.">
		<cfargument type="binary" name="dest" required="true" hint="the destination array.">
		<cfargument type="numeric" name="length" required="false" default="#arrayLen(arguments.src)#" hint="the number of array elements to be copied.">
		<cfscript>
			try {
				System.arraycopy(arguments.src, 0, arguments.dest, 0, arguments.length);
			} catch(java.lang.ArrayIndexOutOfBoundsException e) {
				throw(object=e);
			} catch(java.lang.NullPointerException e) {
				throw(object=e);
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="arrayCompare" output="false" hint="A 'safe' array comparison that is not vulnerable to side-channel 'timing attacks'. All comparisons of non-null, equal length bytes should take same amount of time. We use this for cryptographic comparisons.">
		<cfargument type="binary" name="b1" required="true" hint="A byte array to compare.">
		<cfargument type="binary" name="b2" required="true" hint="A second byte array to compare.">
		<cfscript>
		    if ( charsetEncode(arguments.b1, 'utf-8') == charsetEncode(arguments.b2, 'utf-8') ) {
		        return true;
		    }
		    if ( isNull(arguments.b1) || isNull(arguments.b2) ) {
		        return (arguments.b1 == arguments.b2);
		    }
		    if ( arrayLen(arguments.b1) != arrayLen(arguments.b2) ) {
		        return false;
		    }

		    local.result = 0;
		    // Make sure to go through ALL the bytes. We use the fact that if
		    // you XOR any bit stream with itself the result will be all 0 bits,
		    // which in turn yields 0 for the result.
		    for(local.i = 1; local.i <= arrayLen(arguments.b1); local.i++) {
		        // XOR the 2 current bytes and then OR with the outstanding result.
		        if (local.result == 0) {
		        	local.result = (arguments.b1[local.i] XOR arguments.b2[local.i]);
		        }
		    }
		    return (local.result == 0) ? true : false;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="numeric" name="calcKeySize" output="false" hint="Calculate the size of a key. The key size is given in bits, but we can only allocate them by octets (i.e., bytes), so make sure we round up to the next whole number of octets to have room for all the bits. For example, a key size of 9 bits would require 2 octets to store it.">
		<cfargument type="numeric" name="ks" required="true" hint="The key size, in bits.">
		<cfscript>
	        assert(ks > 0, "Key size must be > 0 bits.");
	        local.numBytes = 0;
	        local.n = ks/8;
	        local.rem = ks % 8;
	        if ( local.rem == 0 ) {
	            local.numBytes = local.n;
	        } else {
	            local.numBytes = local.n + 1;
	        }
	        return local.numBytes;
    	</cfscript> 
	</cffunction>


</cfcomponent>
