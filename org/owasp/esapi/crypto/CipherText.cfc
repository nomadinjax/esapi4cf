<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" output="false">

	<cfscript>
		instance.serialVersionUID = 20100122; // Format: YYYYMMDD

		instance.ESAPI = "";
		instance.logger = "";

	    instance.cipherSpec_     = "";
	    instance.raw_ciphertext_ = "";
	    instance.separate_mac_   = "";
	    instance.encryption_timestamp_ = 0;

	    // All the various pieces that can be set, either directly or indirectly via CipherSpec.
		CipherTextFlags = {
			ALGNAME = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherTextFlags").init(1),
			CIPHERMODE = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherTextFlags").init(2),
			PADDING = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherTextFlags").init(3),
			KEYSIZE = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherTextFlags").init(4),
			BLOCKSIZE = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherTextFlags").init(5),
			CIPHERTEXT = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherTextFlags").init(6),
			INITVECTOR = createObject("component", "cfesapi.org.owasp.esapi.crypto.CipherTextFlags").init(7)
		};

	    // If we have everything set, we compare it to this using '==' which javac specially overloads for this.
	    instance.allCtFlags = [
			CipherTextFlags.ALGNAME,
			CipherTextFlags.CIPHERMODE,
			CipherTextFlags.PADDING,
			CipherTextFlags.KEYSIZE,
			CipherTextFlags.BLOCKSIZE,
			CipherTextFlags.CIPHERTEXT,
			CipherTextFlags.INITVECTOR
		];

	    // These are all the pieces we collect when passed a CipherSpec object.
	    instance.fromCipherSpec = [
			CipherTextFlags.ALGNAME,
			CipherTextFlags.CIPHERMODE,
			CipherTextFlags.PADDING,
			CipherTextFlags.KEYSIZE,
			CipherTextFlags.BLOCKSIZE
		];

	    // How much we've collected so far. We start out with having collected nothing.
	    instance.progress = [];
    </cfscript>

	<cffunction access="public" returntype="CipherText" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.crypto.CipherSpec" name="cipherSpec" required="false" hint="The cipher specification to use.">
		<cfargument type="binary" name="cipherText" required="false" hint="The raw ciphertext bytes to use.">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("CipherText");

			CryptoHelper = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoHelper").init(instance.ESAPI);

			if (structKeyExists(arguments, "cipherSpec")) {
				instance.cipherSpec_ = arguments.cipherSpec;
				if (structKeyExists(arguments, "cipherText")) {
		        	setCiphertext(arguments.cipherText);
				}
		        receivedMany(instance.fromCipherSpec);
		        if ( !isNull(arguments.cipherSpec.getIV()) ) {
		            received(CipherTextFlags.INITVECTOR);
		        }
			}
			else {
		        instance.cipherSpec_ = createObject("component", "CipherSpec").init(instance.ESAPI); // Uses default for everything but IV.
		        receivedMany(instance.fromCipherSpec);
			}

			return this;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="CipherText" name="fromPortableSerializedBytes" output="false" hint="Create a CipherText object from what is supposed to be a portable serialized byte array, given in network byte order, that represents a valid, previously serialized CipherText object using asPortableSerializedByteArray().">
		<cfargument type="binary" name="bytes" required="true" hint="A byte array created via CipherText.asPortableSerializedByteArray()">
		<cfscript>
	        local.cts = createObject("component", "CipherTextSerializer").init(ESAPI=instance.ESAPI, cipherTextSerializedBytes=arguments.bytes);
	        return local.cts.asCipherText();
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getCipherTransformation" output="false" hint="Obtain the String representing the cipher transformation used to encrypt the plaintext. The cipher transformation represents the cipher algorithm, the cipher mode, and the padding scheme used to do the encryption. An example would be 'AES/CBC/PKCS5Padding'.">
		<cfscript>
        	return instance.cipherSpec_.getCipherTransformation();
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getCipherAlgorithm" output="false" hint="Obtain the name of the cipher algorithm used for encrypting the plaintext.">
		<cfscript>
        	return instance.cipherSpec_.getCipherAlgorithm();
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getKeySize" output="false" hint="Retrieve the key size used with the cipher algorithm that was used to encrypt data to produce this ciphertext.">
		<cfscript>
        	return instance.cipherSpec_.getKeySize();
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getBlockSize" output="false" hint="Retrieve the block size (in bytes!) of the cipher used for encryption. (Note: If an IV is used, this will also be the IV length.)">
		<cfscript>
        	return instance.cipherSpec_.getBlockSize();
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getCipherMode" output="false" hint="Get the name of the cipher mode used to encrypt some plaintext.">
		<cfscript>
        	return instance.cipherSpec_.getCipherMode();
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getPaddingScheme" output="false" hint="Get the name of the padding scheme used to encrypt some plaintext.">
		<cfscript>
        	return instance.cipherSpec_.getPaddingScheme();
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="binary" name="getIV" required="true" hint="Return the initialization vector (IV) used to encrypt the plaintext if applicable.">
		<cfscript>
	        if ( isCollected(CipherTextFlags.INITVECTOR) ) {
	            return instance.cipherSpec_.getIV();
	        } else {
	            instance.logger.error(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "IV not set yet; unable to retrieve; returning null");
	            return toBinary("");
	        }
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="requiresIV" output="false" hint="Return true if the cipher mode used requires an IV. Usually this will be true unless ECB mode (which should be avoided whenever possible) is used.">
		<cfscript>
        	return instance.cipherSpec_.requiresIV();
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="binary" name="getRawCipherText" output="false" hint="Get the raw ciphertext byte array resulting from encrypting some plaintext.">
		<cfscript>
		    if ( isCollected(CipherTextFlags.CIPHERTEXT) ) {
		        local.copy = newByte( len(instance.raw_ciphertext_) );
		        System.arraycopy(instance.raw_ciphertext_, 0, local.copy, 0, len(instance.raw_ciphertext_));
		        return local.copy;
		    } else {
		        instance.logger.error(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Raw ciphertext not set yet; unable to retrieve; returning null");
		        return toBinary("");
		    }
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="numeric" name="getRawCipherTextByteLength" output="false" hint="Get number of bytes in raw ciphertext. Zero is returned if ciphertext has not yet been stored.">
		<cfscript>
		    if ( len(instance.raw_ciphertext_) ) {
		        return len(instance.raw_ciphertext_);
		    } else {
		        return 0;
		    }
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getBase64EncodedRawCipherText" output="false" hint="Return a base64-encoded representation of the raw ciphertext alone. Even in the case where an IV is used, the IV is not prepended before the base64-encoding is performed. If there is a need to store an encrypted value, say in a database, this is NOT the method you should use unless you are using a 'fixed' IV. If you are NOT using a fixed IV, you should normally use getEncodedIVCipherText() instead.">
		<cfscript>
	    	return instance.ESAPI.encoder().encodeForBase64(getRawCipherText(),false);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getEncodedIVCipherText" output="false" hint="Return the ciphertext as a base64-encoded String. If an IV was used, the IV if first prepended to the raw ciphertext before base64-encoding. If an IV is not used, then this method returns the same value as getBase64EncodedRawCipherText(). Generally, this is the method that you should use unless you only are using a fixed IV and a storing that IV separately, in which case using getBase64EncodedRawCipherText() can reduce the storage overhead.">
		<cfscript>
		    if ( isCollected(CipherTextFlags.INITVECTOR) && isCollected(CipherTextFlags.CIPHERTEXT) ) {
		        // First concatenate IV + raw ciphertext
		        local.iv = getIV();
		        local.raw = getRawCipherText();
		        local.ivPlusCipherText = newByte( len(local.iv) + len(local.raw) );
		        System.arraycopy(local.iv, 0, local.ivPlusCipherText, 0, len(local.iv));
		        System.arraycopy(local.raw, 0, local.ivPlusCipherText, len(local.iv), len(local.raw));
		        // Then return the base64 encoded result
		        return instance.ESAPI.encoder().encodeForBase64(local.ivPlusCipherText, false);
		    } else {
		        instance.logger.error(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Raw ciphertext and/or IV not set yet; unable to retrieve; returning null");
		        return "";
		    }
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="computeAndStoreMAC" output="false" hint="Compute and store the Message Authentication Code (MAC) if the ESAPI property Encryptor.CipherText.useMAC is set to true. If it is, the MAC is conceptually calculated as: authKey = DerivedKey(secret_key, 'authenticate'); HMAC-SHA1(authKey, IV + secret_key) where derived key is an HMacSHA1, possibly repeated multiple times.">
		<cfargument type="any" name="authKey" required="true" hint="javax.crypto.SecretKey">
		<cfscript>
		    assert(!macComputed(), "Programming error: Can't store message integrity code while encrypting; computeAndStoreMAC() called multiple times.");
		    assert(collectedAll(), "Have not collected all required information to compute and store MAC.");
		    local.result = computeMAC(arguments.authKey);
		    if ( !isNull(local.result) ) {
		        storeSeparateMAC(local.result);
		    }
	   		// If 'result' is null, we already logged this in computeMAC().
		</cfscript>
	</cffunction>


	<cffunction access="package" returntype="void" name="storeSeparateMAC" output="false" hint="Same as computeAndStoreMAC(SecretKey) but this is only used by CipherTextSerializeer. (Has package level access.)">
		<cfargument type="binary" name="macValue" required="true">
		<cfscript>
		    if ( !macComputed() ) {
		        instance.separate_mac_ = newByte( len(arguments.macValue) );
		        CryptoHelper.copyByteArray(arguments.macValue, instance.separate_mac_);
		        assert(macComputed());
		    }
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="validateMAC" output="false" hint="Validate the message authentication code (MAC) associated with the ciphertext. This is mostly meant to ensure that an attacker has not replaced the IV or raw ciphertext with something arbitrary. Note however that it will NOT detect the case where an attacker simply substitutes one valid ciphertext with another ciphertext.">
		<cfargument type="any" name="authKey" required="true" hint="javax.crypto.SecretKey: The secret key that is used for proving authenticity of the IV and ciphertext. This key should be derived from the SecretKey passed to the Encryptor##encrypt(javax.crypto.SecretKey, PlainText) and Encryptor##decrypt(javax.crypto.SecretKey, CipherText) methods or the 'master' key when those corresponding encrypt / decrypt methods are used. This authenticity key should be the same length and for the same cipher algorithm as this SecretKey. The method org.owasp.esapi.crypto.CryptoHelper##computeDerivedKey(SecretKey, int, String) is a secure way to produce this derived key.">
		<cfscript>
		    local.usesMAC = instance.ESAPI.securityConfiguration().useMACforCipherText();

		    if (  local.usesMAC && macComputed() ) {  // Uses MAC and it was computed
		        // Calculate MAC from HMAC-SHA1(nonce, IV + plaintext) and
		        // compare to stored value (separate_mac_). If same, then return true,
		        // else return false.
		        local.mac = computeMAC(authKey);
		        assert(len(local.mac) == len(instance.separate_mac_), "MACs are of different lengths. Should both be the same.");
		        return CryptoHelper.arrayCompare(local.mac, instance.separate_mac_); // Safe compare!!!
		    } else if ( ! local.usesMAC ) {           // Doesn't use MAC
		        return true;
		    } else {                            // Uses MAC but it has not been computed / stored.
		        instance.logger.warning(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Cannot validate MAC as it was never computed and stored. Decryption result may be garbage even when decryption succeeds.");
		        return true;    // Need to return 'true' here because of encrypt() / decrypt() methods don't support this.
		    }
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="binary" name="asPortableSerializedByteArray" output="false" hint="Return this CipherText object as a portable (i.e., network byte ordered) serialized byte array. Note this is NOT the same as returning a serialized object using Java serialization. Instead this is a representation that all ESAPI implementations will use to pass ciphertext between different programming language implementations.">
		<cfscript>
	        // Check if this CipherText object is "complete", i.e., all
	        // mandatory has been collected.
		    if ( ! collectedAll() ) {
		        local.msg = "Can't serialize this CipherText object yet as not all mandatory information has been collected";
		        cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Can't serialize incomplete ciphertext info", local.msg);
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
		    }

		    // If we are supposed to be using a (separate) MAC, also make sure
		    // that it has been computed/stored.
		    local.usesMAC = instance.ESAPI.securityConfiguration().useMACforCipherText();
		    if (  local.usesMAC && ! macComputed() ) {
		        local.msg = "Programming error: MAC is required for this cipher mode (" & getCipherMode() & "), but MAC has not yet been computed and stored. Call the method computeAndStoreMAC(SecretKey) first before attempting serialization.";
		        cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Can't serialize ciphertext info: Data integrity issue.", local.msg);
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
		    }

		    // OK, everything ready, so give it a shot.
		    return createObject("component", "CipherTextSerializer").init(ESAPI=instance.ESAPI, cipherTextObj=this).asSerializedByteArray();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setCiphertext" output="false" hint="Set the raw ciphertext.">
		<cfargument type="binary" name="ciphertext" required="true" hint="The raw ciphertext.">
		<cfscript>
	        if ( ! macComputed() ) {
	            if ( isNull(arguments.ciphertext) || len(arguments.ciphertext) == 0 ) {
	                cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption faled; no ciphertext", "Ciphertext may not be null or 0 length!");
	           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	            }
	            if ( isCollected(CipherTextFlags.CIPHERTEXT) ) {
	                instance.logger.warning(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Raw ciphertext was already set; resetting.");
	            }
	            instance.raw_ciphertext_ = newByte( len(arguments.ciphertext) );
	            CryptoHelper.copyByteArray(arguments.ciphertext, instance.raw_ciphertext_);
	            received(CipherTextFlags.CIPHERTEXT);
	            setEncryptionTimestampCurrent();
	        } else {
	            local.logMsg = "Programming error: Attempt to set ciphertext after MAC already computed.";
	            instance.logger.error(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, local.logMsg);
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "MAC already set; cannot store new raw ciphertext", local.logMsg);
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setIVandCiphertext" output="false" hint="Set the IV and raw ciphertext.">
		<cfargument type="binary" name="iv" required="true" hint="The initialization vector.">
		<cfargument type="binary" name="ciphertext" required="true" hint="The raw ciphertext.">
		<cfscript>
	        if ( isCollected(CipherTextFlags.INITVECTOR) ) {
	            instance.logger.warning(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "IV was already set; resetting.");
	        }
	        if ( isCollected(CipherTextFlags.CIPHERTEXT) ) {
	            instance.logger.warning(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Raw ciphertext was already set; resetting.");
	        }
	        if ( ! macComputed() ) {
	            if ( isNull(arguments.ciphertext) || len(arguments.ciphertext) == 0 ) {
	                cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption faled; no ciphertext", "Ciphertext may not be null or 0 length!");
	           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	            }
	            if ( isNull(arguments.iv) || len(arguments.iv) == 0 ) {
	                if ( requiresIV() ) {
	                    cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption failed -- mandatory IV missing", "Cipher mode " & getCipherMode() & " has null or empty IV");
		           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	                }
	            } else if ( len(arguments.iv) != getBlockSize() ) {
                    cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Encryption failed -- bad parameters passed to encrypt", "IV length does not match cipher block size of " & getBlockSize());
	           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	            }
	            instance.cipherSpec_.setIV(arguments.iv);
	            received(CipherTextFlags.INITVECTOR);
	            setCiphertext( arguments.ciphertext );
	        } else {
	            local.logMsg = "MAC already computed from previously set IV and raw ciphertext; may not be reset -- object is immutable.";
	            instance.logger.error(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, local.logMsg);  // Discuss: By throwing, this gets logged as warning, but it's really error! Why is an exception only a warning???
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Validation of decryption failed.", local.logMsg);
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getEncryptionTimestamp" output="false" hint="Get stored timestamp representing when data was encrypted.">
		<cfscript>
        	return instance.encryption_timestamp_;
    	</cfscript>
	</cffunction>


	<cffunction access="private" returntype="void" name="setEncryptionTimestampCurrent" output="false" hint="Set the encryption timestamp to the current system time as determined by getTickCount(), but only if it has not been previously set. That is, this method ony has an effect the first time that it is called for this object.">
		<cfscript>
	        // We want to skip this when it's already been set via the package
	        // level call setEncryptionTimestamp(long) done via CipherTextSerializer
	        // otherwise it gets reset to the current time. But when it's restored
	        // from a serialized CipherText object, we want to keep the original
	        // encryption timestamp.
	        if ( instance.encryption_timestamp_ != 0 ) {
	            instance.logger.warning(createObject("java", "org.owasp.esapi.Logger").EVENT_FAILURE, "Attempt to reset non-zero CipherText encryption timestamp to current time!");
	        }
	        instance.encryption_timestamp_ = getTickCount();
    	</cfscript>
	</cffunction>


	<cffunction access="package" returntype="void" name="setEncryptionTimestamp" output="false" hint="Set the encryption timestamp to the time stamp specified by the parameter. This method is intended for use only by CipherTextSerializer.">
		<cfargument type="numeric" name="timestamp" required="true" hint="The time in milliseconds since epoch time (midnight, January 1, 1970 GMT).">
		<cfscript>
	        assert(arguments.timestamp > 0, "Timestamp must be greater than zero.");
	        if ( instance.encryption_timestamp_ == 0 ) {     // Only set it if it's not yet been set.
	            instance.logger.warning(createObject("java", "org.owasp.esapi.Logger").EVENT_FAILURE, "Attempt to reset non-zero CipherText encryption timestamp to " & createObject("java", "java.util.Date").init( javaCast("long", arguments.timestamp) ) + "!");
	        }
	        instance.encryption_timestamp_ = arguments.timestamp;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getSerialVersionUID" output="false" hint="Used in supporting CipherText serialization.">
		<cfscript>
        	return instance.serialVersionUID;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="binary" name="getSeparateMAC" output="false" hint="Return the separately calculated Message Authentication Code (MAC) that is computed via the computeAndStoreMAC(SecretKey authKey) method.">
		<cfscript>
	        if ( !len(instance.separate_mac_) ) {
	            return toBinary("");
	        }
	        local.copy = newByte( len(instance.separate_mac_) );
	        System.arraycopy(instance.separate_mac_, 0, local.copy, 0, len(instance.separate_mac_));
	        return local.copy;
    	</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="toString" output="false">
		<cfscript>
	        local.sb = createObject("java", "java.lang.StringBuilder").init( "CipherText: " );
	        local.creationTime = (( getEncryptionTimestamp() == 0) ? "No timestamp available" : createObject("java", "java.util.Date").init( javaCast("long", getEncryptionTimestamp()) ).toString());
	        local.n = getRawCipherTextByteLength();
	        local.rawCipherText = (( local.n > 0 ) ? "present (" & local.n & " bytes)" : "absent");
	        local.mac = (( len(instance.separate_mac_) ) ? "present" : "absent");
	        local.sb.append("Creation time: ").append(local.creationTime);
	        local.sb.append(", raw ciphertext is ").append(local.rawCipherText);
	        local.sb.append(", MAC is ").append(local.mac).append("; ");
	        local.sb.append( instance.cipherSpec_.toString() );
	        return local.sb.toString();
    	</cfscript>
	</cffunction>

	<cffunction access="public" returntype="boolean" name="equals" output="false">
		<cfargument type="any" name="other" required="true">
		<cfscript>
	        local.result = false;
	        local.otherStr = arguments.other;
	        if ( isCustomFunction(local.otherStr.toString) ) {
	       		local.otherStr = local.otherStr.toString();
	        }
	        if ( this.toString() == local.otherStr )
	            return true;
	        if ( isNull(arguments.other) )
	            return false;
	        if ( isInstanceOf(arguments.other, "cfesapi.org.owasp.esapi.crypto.CipherText")) {
	            local.that = arguments.other;
	            if ( this.collectedAll() && local.that.collectedAll() ) {
	                local.result = (local.that.canEqual(this) &&
						this.cipherSpec_.equals(local.that.cipherSpec_) &&
						// Safe comparison, resistant to timing attacks
						CryptoHelper.arrayCompare(this.raw_ciphertext_, local.that.raw_ciphertext_) &&
						CryptoHelper.arrayCompare(this.separate_mac_, local.that.separate_mac_) &&
						this.encryption_timestamp_ == local.that.encryption_timestamp_ );
	            } else {
	                instance.logger.warning(createObject("java", "org.owasp.esapi.Logger").EVENT_FAILURE, "CipherText.equals(): Cannot compare two CipherText objects that are not complete, and therefore immutable!");
	                instance.logger.info(createObject("java", "org.owasp.esapi.Logger").EVENT_FAILURE, "This CipherText: " & this.collectedAll() & ";other CipherText: " & local.that.collectedAll());
	                instance.logger.info(createObject("java", "org.owasp.esapi.Logger").EVENT_FAILURE, "CipherText.equals(): Progress comparison: " & ((this.progress == local.that.progress) ? "Same" : "Different"));
	                instance.logger.info(createObject("java", "org.owasp.esapi.Logger").EVENT_FAILURE, "CipherText.equals(): Status this: " & this.progress & "; status other CipherText object: " & local.that.progress);
	                // CHECKME: Perhaps we should throw a RuntimeException instead???
	                return false;
	            }
	        }
	        return local.result;
    	</cfscript>
	</cffunction>

	<!--- hashCode --->
	<!--- canEqual --->

	<cffunction access="private" returntype="binary" name="computeMAC" output="false" hint="Compute a MAC, but do not store it. May set the nonce value as a side-effect.  The MAC is calculated as: HMAC-SHA1(nonce, IV + plaintext)">
		<cfargument type="any" name="authKey" required="true" hint="javax.crypto.SecretKey: The ciphertext value for which the MAC is computed.">
		<cfscript>
	        assert(!isNull(instance.raw_ciphertext_) && len(instance.raw_ciphertext_) != 0, "Raw ciphertext may not be null or empty.");
	        assert(!isNull(arguments.authKey) && len(arguments.authKey.getEncoded()) != 0, "Authenticity secret key may not be null or zero length.");
	        try {
	            local.sk = createObject("java", "javax.crypto.spec.SecretKeySpec").init(arguments.authKey.getEncoded(), "HmacSHA1");
	            local.mac = createObject("java", "javax.crypto.Mac").getInstance("HmacSHA1");
	            local.mac.init(local.sk);
	            if ( requiresIV() ) {
	                local.mac.update( getIV() );
	            }
	            local.result = local.mac.doFinal( getRawCipherText() );
	            return local.result;
	        } catch (java.security.NoSuchAlgorithmException e) {
	            instance.logger.error(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Cannot compute MAC w/out HmacSHA1.", e);
	            return "";
	        } catch (java.security.InvalidKeyException e) {
	            instance.logger.error(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Cannot comput MAC; invalid 'key' for HmacSHA1.", e);
	            return "";
	        }
    	</cfscript>
	</cffunction>


	<cffunction access="private" returntype="boolean" name="macComputed" output="false" hint="Return true if the MAC has already been computed (i.e., not null).">
		<cfscript>
        	return len(instance.separate_mac_) ? true : false;
    	</cfscript>
	</cffunction>


	<cffunction access="private" returntype="boolean" name="collectedAll" output="false" hint="Return true if we've collected all the required pieces; otherwise false.">
		<cfscript>
	        local.ctFlags = "";
	        if ( requiresIV() ) {
	            local.ctFlags = instance.allCtFlags;
	        } else {
	        	// NOTE: not understanding this; hopefully just throwing the 1 element in an array is correct ??
	            //local.initVector = EnumSet.of(CipherTextFlags.INITVECTOR);
	            //local.ctFlags = EnumSet.complementOf(local.initVector);
	            local.ctFlags = [CipherTextFlags.INITVECTOR];
	        }
	        local.result = instance.progress.containsAll(local.ctFlags);
	        return local.result;
    	</cfscript>
	</cffunction>


	<cffunction access="private" returntype="boolean" name="isCollected" output="false" hint="Check if we've collected a specific flag type.">
		<cfargument type="cfesapi.org.owasp.esapi.crypto.CipherTextFlags" name="flag" required="true" hint="The flag type; e.g., CipherTextFlags.INITVECTOR, etc.">
		<cfscript>
        	return yesNoFormat(arrayFind(instance.progress, arguments.flag));
    	</cfscript>
	</cffunction>


	<cffunction access="private" returntype="void" name="received" output="false" hint="Add the flag to the set of what we've already collected.">
		<cfargument type="cfesapi.org.owasp.esapi.crypto.CipherTextFlags" name="flag" required="true" hint="The flag type to be added; e.g., CipherTextFlags.INITVECTOR.">
		<cfscript>
        	instance.progress.add(arguments.flag);
    	</cfscript>
	</cffunction>


	<cffunction access="private" returntype="void" name="receivedMany" output="false" hint="Add all the flags from the specified set to that we've collected so far.">
		<cfargument type="Array" name="ctSet" required="true" hint="A EnumSet&lt;CipherTextFlags&gt; containing all the flags we wish to add.">
		<cfscript>
	        local.it = arguments.ctSet.iterator();
	        while ( local.it.hasNext() ) {
	            received( local.it.next() );
	        }
    	</cfscript>
	</cffunction>


</cfcomponent>
