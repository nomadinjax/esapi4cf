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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" output="false">

	<cfscript>
		/* Represents an anonymous user. */
	    this.ANONYMOUS_USER = "<anonymous>";
	    
	    // Default expiration time
	    static.DEFAULT_EXP_TIME = 5 * 60 * 1000;  // 5 min == 300000 milliseconds
	    static.DELIM = ";";                     // field delimiter
	    static.DELIM_CHAR = ';';                  // field delim as a char
	    static.QUOTE_CHAR = '\';                 // char used to quote delimiters, '=' and itself.
	    
	    // OPEN ISSUE: Should we make these 2 regex's properties in ESAPI.properties???
	    static.ATTR_NAME_REGEX = "[A-Za-z0-9_.-]+"; // One or more alphanumeric, underscore, periods, or hyphens.
	    static.USERNAME_REGEX = "[a-z][a-z0-9_.@-]*";
	    
	    instance.ESAPI = "";
	    instance.logger = "";
	
	    instance.username = this.ANONYMOUS_USER;        // Default user name if not set. Always lower case.
	    instance.expirationTime = 0;
        // This probably needed be sorted. A HashMap would do as well.
        // But this might make debugging a bit easier, so why not?
	    instance.attributes = {};
	    instance.secretKey = "";
	    instance.attrNameRegex = createObject("java", "java.util.regex.Pattern").compile(static.ATTR_NAME_REGEX);
	    instance.userNameRegex = createObject("java", "java.util.regex.Pattern").compile(static.USERNAME_REGEX);
	</cfscript>
 
	<cffunction access="public" returntype="CryptoToken" name="init" output="false" hint="Create a cryptographic token using specified SecretKey.">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="any" name="skey" required="false" hint="javax.crypto.SecretKey: The specified SecretKey to use to encrypt the token. Default to secret key from the ESAPI.properties property Encryptor.MasterKey.">
		<cfargument type="String" name="token" required="false">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("CryptoToken");
			
			if (structKeyExists(arguments, "skey")) {
				instance.secretKey = arguments.skey;
			}
			else {
	        	instance.secretKey = getDefaultSecretKey(instance.ESAPI.securityConfiguration().getEncryptionAlgorithm());
			}
			
			if (structKeyExists(arguments, "token")) {
				try {
		            decryptToken(instance.secretKey, arguments.token);
		        } catch (EncodingException e) {
		            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Decryption of token failed. Token improperly encoded.", "Can't decrypt token because not correctly encoded.", e);
	           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
		        }
		        assert(!isNull(instance.username), "Programming error: Decrypted token found username null.");
		        assert(instance.expirationTime > 0, "Programming error: Decrypted token found expirationTime <= 0.");
			}
			else {
		        instance.expirationTime = javaCast("long", getTickCount() + static.DEFAULT_EXP_TIME);
			}
	        
	        return this;
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getUserAccountName" output="false" hint="Retrieve the user account name associated with this CryptoToken object.">
		<cfscript>
       		return ( (!isNull(instance.username)) ? instance.username : this.ANONYMOUS_USER );
       	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setUserAccountName" output="false" hint="Set the user account name associated with this cryptographic token object. The user account name is converted to lower case.">
		<cfargument type="String" name="userAccountName" required="true" hint="The user account name.">
		<cfscript>
	        assert(!isNull(arguments.userAccountName), "User account name may not be null.");
	        
	        // Converting to lower case first allows a simpler regex.
	        local.userAcct = arguments.userAccountName.toLowerCase();
	        
	        // Check to make sure that attribute name is valid as per our regex.
	        local.userNameChecker = instance.userNameRegex.matcher(local.userAcct);
	        if ( local.userNameChecker.matches() ) {
	            instance.username = local.userAcct;
	        } else {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, "Invalid user account name encountered.", "User account name " & arguments.userAccountName & " does not match regex " & static.USERNAME_REGEX & " after conversion to lowercase.");
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isExpired" output="false" hint="Check if token has expired yet.">
		<cfscript>
	        return getTickCount() > instance.expirationTime;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setExpiration" output="false" hint="Set expiration time for a specific date/time or to expire in 'interval' seconds (NOT milliseconds).">
		<cfargument type="date" name="expirationDate" required="false" hint="The date/time at which the token will fail. Must be after the current date/time.">
		<cfargument type="numeric" name="intervalSecs" required="false" hint="Number of seconds in the future from current date/time to set expiration. Must be positive.">
		<cfscript>
			if (structKeyExists(arguments, "expirationDate")) {
		        local.curTime = getTickCount();
		        local.expTime = arguments.expirationDate.getTime();
		        if ( local.expTime <= local.curTime ) {
		            throw(object=createObject("java", "java.lang.IllegalArgumentException").init("Expiration date must be after current date/time."));
		        }
		        instance.expirationTime = local.expTime;
			}
			else if (structKeyExists(arguments, "intervalSecs")) {
		        local.intervalMillis = arguments.intervalSecs * 1000;   // Need to convert secs to millisec.
		        
		        // Don't want to use assertion here, because if they are disabled,
		        // this would result in setting the expiration time prior to the
		        // current time, hence it would already be expired.
		        if ( local.intervalMillis <= 0) {
		            throw(object=createObject("java", "java.lang.IllegalArgumentException").init("intervalSecs argument, converted to millisecs, must be > 0."));
		        }
		        // Check for arithmetic overflow here. In reality, this condition
		        // should never happen, but we want to avoid it--even theoretically--
		        // since otherwise, it could have security implications.
		        local.now = getTickCount();
		        preAdd(local.now, local.intervalMillis);
		        instance.expirationTime = javaCast("long", local.now + local.intervalMillis);
			}
			else {
				throw(object=createObject("java", "java.lang.IllegalArgumentException").init("You must specify either an expirationDate or intervalSecs argument."));
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getExpiration" output="false" hint="Return the expiration time in milliseconds since epoch time (midnight, January 1, 1970 UTC).">
		<cfscript>
	        assert(instance.expirationTime > 0, "Programming error: Expiration time <= 0");
	        return instance.expirationTime;
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Date" name="getExpirationDate" output="false" hint="Return the expiration time as a Date.">
		<cfscript>
       		return createObject("component", "java.util.Date").init( getExpiration() );
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setAttribute" output="false" hint="Set a name/value pair as an attribute.">
		<cfargument type="String" name="name" required="true" hint="The attribute name">
		<cfargument type="String" name="value" required="true" hint="The attribute value">
		<cfscript>
	        if ( isNull(arguments.name) || arguments.name.length() == 0 ) {
	            // CHECKME: Should this be an IllegalArgumentException instead? I
	            // would prefer an assertion here and state this as a precondition
	            // in the Javadoc.
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, "Null or empty attribute NAME encountered", "Attribute NAMES may not be null or empty string.");
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
	        if ( isNull(arguments.value) ) {
	            // CHECKME: Should this be an IllegalArgumentException instead? I
	            // would prefer an assertion here and state this as a precondition
	            // in the Javadoc.
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, "Null attribute VALUE encountered for attr name " & arguments.name, "Attribute VALUE may not be null; attr name: " & arguments.name);            
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
	        // NOTE: OTOH, it *is* VALID if the _value_ is empty! Null values cause too much trouble
	        // to make it worth the effort of getting it to work consistently.
	
	        // Check to make sure that attribute name is valid as per our regex.
	        local.attrNameChecker = instance.attrNameRegex.matcher(arguments.name);
	        if ( local.attrNameChecker.matches() ) {
	            instance.attributes.put(arguments.name, arguments.value);
	        } else {
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, "Invalid attribute name encountered.", "Attribute name " & arguments.name & " does not match regex " & static.ATTR_NAME_REGEX);
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="addAttributes" output="false" hint="Add the specified collection of attributes to the current attributes. If there are duplicate attributes specified, they will replace any existing ones.">
		<cfargument type="Struct" name="attrs" required="true" hint="Name/value pairs of attributes to add or replace the existing attributes. Map must be non-null, but may be empty.">
		<cfscript>
	        // CHECKME: Assertion vs. IllegalArgumentException
	        assert(!isNull(arguments.attrs), "Attribute map may not be null.");
	        local.keyValueSet = arguments.attrs.entrySet();
	        local.it = local.keyValueSet.iterator();
	        while( local.it.hasNext() ) {
	            local.entry = local.it.next();
	            local.key = local.entry.getKey();
	            local.value = local.entry.getValue();
	            setAttribute(local.key, local.value);
	        }
	        return;
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getAttribute" output="false" hint="Retrieve the attribute with the specified name.">
		<cfargument type="String" name="name" required="true" hint="The attribute name.">
		<cfscript>
       		return instance.attributes.get(arguments.name);
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Struct" name="getAttributes" output="false" hint="Retrieve a Map that is a clone of all the attributes. A copy is returned so that the attributes in CrytpToken are unaffected by alterations made the returned Map. (Otherwise, multi-threaded code could get trick.">
		<cfscript>
	        // Unfortunately, this requires a cast, which requires us to supress warnings.
	        return instance.attributes.clone();
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="clearAttributes" output="false" hint="Removes all the attributes (if any) associated with this token. Note that this does not clear / reset the user account name or expiration time.">
		<cfscript>
        	instance.attributes.clear();
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getToken" output="false" hint="Return the new encrypted token as a base64-encoded string, encrypted with the specified SecretKey which may be a different key than what the token was originally encrypted with or defaults to SecretKey which this object was constructed.">
		<cfargument type="any" name="skey" required="false" default="#instance.secretKey#" hint="javax.crypto.SecretKey: The specified key to (re)encrypt the token.">
		<cfscript>
        	return createEncryptedToken(arguments.skey);
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="updateToken" output="false">
		<cfargument type="numeric" name="additionalSecs" required="true">
		<cfscript>
	        if ( arguments.additionalSecs < 0) {
	            throw(object=createObject("java", "java.lang.IllegalArgumentException").init("additionalSecs argument must be >= 0."));
	        }
	        
	        // Avoid integer overflow. This could happen if one first calls
	        // setExpiration(Date) with a date far into the future. We want
	        // to avoid overflows as they might lead to security vulnerabilities.
	        local.curExpTime = getExpiration();
	        preAdd(local.curExpTime, arguments.additionalSecs * 1000);
	            // Note: Can't use setExpiration(int) here was this needs a
	            //       'long'. Could convert to Date first, and use
	            //       setExpiration(Date) but that hardly seems worth the trouble.
	        instance.expirationTime = javaCast("long", local.curExpTime + (arguments.additionalSecs * 1000));
	        
	        if ( isExpired() ) {
	            // Too bad there is no ProcrastinationException ;-)
	            instance.expirationTime = local.curExpTime;    // Restore the original value (which still may be expired.
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, "Token timed out.", "Cryptographic token not increased to sufficient value to prevent timeout.");
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
	        // Don't change anything else (user acct name, attributes, skey, etc.)
	        return this.getToken();
        </cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="createEncryptedToken" output="false" hint="Create the actual encrypted token based on the specified SecretKey. This method will ensure that the decrypted token always ends with an unquoted delimiter.">
		<cfargument type="any" name="skey" required="true" hint="javax.crypto.SecretKey">
		<cfscript>
	        local.sb = createObject("java", "java.lang.StringBuilder").init( getUserAccountName() & static.DELIM);
	        // CHECKME: Should we check here to see if token has already expired
	        //          and refuse to encrypt it (by throwing exception) if it has???
	        //          If so, then updateToken() should also be revisited.
	        local.sb.append( getExpiration() ).append( static.DELIM );
	        local.sb.append( getQuotedAttributes() );
	        
	        local.encryptor = instance.ESAPI.encryptor();
	        local.ct = local.encryptor.encrypt(arguments.skey, createObject("component", "cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, local.sb.toString() ) );
	        local.b64 = instance.ESAPI.encoder().encodeForBase64(local.ct.asPortableSerializedByteArray(), false);
	        return local.b64;
        </cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="getQuotedAttributes" output="false" hint="Return a string of all the attributes, properly quoted. This is used in creating the encrypted token. Note that this method ensures that the quoted attribute string always ends with an (quoted) delimiter.">
		<cfscript>
	        local.sb = createObject("java", "java.lang.StringBuilder").init();
	        local.keyValueSet = instance.attributes.entrySet();
	        local.it = local.keyValueSet.iterator();
	        while( local.it.hasNext() ) {
	            local.entry = local.it.next();
	            local.key = local.entry.getKey();
	            local.value = local.entry.getValue();
	            // Because attribute values may be confidential, we don't want to log them!
	            instance.logger.debug(createObject("java", "org.owasp.esapi.Logger").EVENT_UNSPECIFIED, "   " & local.key & " -> <not shown>");
	            local.sb.append(local.key & "=" & quoteAttributeValue( local.value ) & static.DELIM);
	        }
	        return local.sb.toString();
        </cfscript> 
	</cffunction>

	<!---
		// Do NOT define a toString() method as there may be sensitive
		// information contained in the attribute names. If we absolutely
		// need this, then only return the username and expiration time, and
		// _maybe_ the attribute names, but not there values. And obviously,
		// we NEVER want to include the SecretKey should we decide to do this.
		/*
		* public String toString() { return null; }
		*/
		--->

	<cffunction access="private" returntype="String" name="quoteAttributeValue" output="false" hint="Quote any special characters in value.">
		<cfargument type="String" name="value" required="true">
		<cfscript>
	        assert(!isNull(arguments.value), "Program error: Value should not be null."); // Empty is OK.
	        local.sb = createObject("java", "java.lang.StringBuilder").init();
	        local.charArray = value.toCharArray();
	        for( local.i = 1; local.i <= arrayLen(local.charArray); local.i++ ) {
	            local.c = local.charArray[local.i];
	            if ( local.c == static.QUOTE_CHAR || local.c == "=" || local.c == static.DELIM_CHAR ) {
	                local.sb.append(static.QUOTE_CHAR).append(local.c);
	            } else {
	                local.sb.append(local.c);
	            }
	        }
	        return local.sb.toString();
        </cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="parseQuotedValue" output="false" hint="Parse the possibly quoted value and return the unquoted value.">
		<cfargument type="String" name="quotedValue" required="true">
		<cfscript>
	        local.sb = createObject("java", "java.lang.StringBuilder").init();
	        local.charArray = quotedValue.toCharArray();
	        for( local.i = 1; local.i <= arrayLen(local.charArray); local.i++ ) {
	            local.c = local.charArray[local.i];
	            if ( local.c == static.QUOTE_CHAR ) {
	                local.i++;    // Skip past quote character.
	                local.sb.append( local.charArray[local.i] );
	            } else {
	                local.sb.append(local.c);
	            }
	        }
	        return local.sb.toString();
        </cfscript> 
	</cffunction>


	<cffunction access="private" returntype="void" name="decryptToken" output="false" hint="Decrypt the encrypted token and parse it into the individual components. The string should always end with a semicolon (;) even when there are no attributes set.">
		<cfargument type="any" name="skey" required="true" hint="javax.crypto.SecretKey">
		<cfargument type="String" name="b64token" required="true">
		<cfscript>
	        local.token = "";
	        try {
	            local.token = instance.ESAPI.encoder().decodeFromBase64(arguments.b64token);
	        } catch (IOException e) {
	            // CHECKME: Not clear if we should log the actual token itself. It's encrypted,
	            //          but could be arbitrarily long, especially since it is not valid
	            //          encoding. OTOH, it may help debugging as sometimes it may be a simple
	            //          case like someone failing to apply some other type of encoding
	            //          consistently (e.g., URL encoding), in which case logging this should
	            //          make this pretty obvious once a few of these are logged.
	            cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncodingException").init(instance.ESAPI, "Invalid base64 encoding.", "Invalid base64 encoding. Encrypted token was: " & arguments.b64token);
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	        }
	        local.ct = new CipherText(instance.ESAPI).fromPortableSerializedBytes(local.token);
	        local.encryptor = instance.ESAPI.encryptor();
	        local.pt = local.encryptor.decrypt(arguments.skey, local.ct);
	        local.str = local.pt.toString();
	        assert(local.str.endsWith(static.DELIM), "Programming error: Expecting decrypted token to end with delim char, " & static.DELIM_CHAR);
	        local.charArray = local.str.toCharArray();
	        local.prevPos = -1;                // Position of previous unquoted delimiter.
	        local.fieldNo = 0;
	        local.fields = [];
	        local.lastPos = arrayLen(local.charArray);
	        for ( local.curPos = 1; local.curPos <= local.lastPos; local.curPos++ ) {
	            local.quoted = false;
	            local.curChar = local.charArray[local.curPos];
	            if ( local.curChar == static.QUOTE_CHAR ) {
	                // Found a case where we have quoted character. We need to skip
	                // over this and set the current character to the next character.
	                local.curPos++;
	                if ( local.curChar != local.lastPos ) {
	                    local.curChar = local.charArray[ local.curPos + 1 ];
	                    local.quoted = true;
	                } else {
	                    // Last position will always be a delimiter character that
	                    // should be treated as unquoted.
	                    local.curChar = static.DELIM_CHAR;
	                }
	            }
	            if ( local.curChar == static.DELIM_CHAR && !local.quoted ) {
	                // We found an actual (unquoted) field delimiter.
	                local.record = local.str.substring(local.prevPos + 1, local.curPos - 1);
	                local.fields.add( local.record );
	                local.fieldNo++;
	                local.prevPos = local.curPos - 1;
	            } 
	        }
	        
	        assert(local.fieldNo == arrayLen(local.fields), "Program error: Mismatch of delimited field count.");
	        instance.logger.debug(createObject("java", "org.owasp.esapi.Logger").EVENT_UNSPECIFIED, "Found " & arrayLen(local.fields) & " fields.");
	        assert(arrayLen(local.fields) >= 2, "Missing mandatory fields from decrypted token (username &/or expiration time).");
	        local.username = local.fields[1].toLowerCase();
	        local.expTime = local.fields[2];
	        instance.expirationTime = createObject("java", "java.lang.Long").parseLong(local.expTime);
	        
	        for( local.i = 3; local.i <= arrayLen(local.fields); local.i++ ) {
	            local.nvpair = local.fields[local.i];
	            local.equalsAt = local.nvpair.indexOf("=");
	            if ( local.equalsAt == -1 ) {
	                cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Invalid attribute encountered in decrypted token.", "Malformed attribute name/value pair (" & local.nvpair & ") found in decrypted token.");
	           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	            }
	            local.name = local.nvpair.substring(0, local.equalsAt);
	            local.quotedValue = local.nvpair.substring(local.equalsAt + 1);
	            local.value = parseQuotedValue( local.quotedValue );
	            // Because attribute values may be confidential, we don't want to log them!
	            instance.logger.debug(createObject("java", "org.owasp.esapi.Logger").EVENT_UNSPECIFIED, "Attribute[" & i & "]: name=" & local.name & ", value=<not shown>");
	
	            // Check to make sure that attribute name is valid as per our regex.
	            local.attrNameChecker = instance.attrNameRegex.matcher(local.name);
	            if ( local.attrNameChecker.matches() ) {
	                instance.attributes.put(local.name, local.value);
	            } else {
	                cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Invalid attribute name encountered in decrypted token.", "Invalid attribute name encountered in decrypted token; attribute name " & local.name & " does not match regex " & static.ATTR_NAME_REGEX);
	           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
	            }
	            instance.attributes.put(local.name, local.value);
	        }
	        return;
	    </cfscript> 
	</cffunction>


	<cffunction access="private" returntype="any" name="getDefaultSecretKey" output="false" hint="javax.crypto.spec.SecretKeySpec">
		<cfargument type="String" name="encryptAlgorithm" required="true">
		<cfscript>
	        assert(!isNull(arguments.encryptAlgorithm), "Encryption algorithm cannot be null");
	        local.skey = instance.ESAPI.securityConfiguration().getMasterKey();
	        assert(!isNull(local.skey), "Can't obtain master key, Encryptor.MasterKey");
	        assert(arrayLen(local.skey) >= 7, "Encryptor.MasterKey must be at least 7 bytes. Length is: " & arrayLen(local.skey) & " bytes.");
	        // Set up secretKeySpec for use for symmetric encryption and decryption,
	        // and set up the public/private keys for asymmetric encryption /
	        // decryption.
	        return createObject("java", "javax.crypto.spec.SecretKeySpec").init(local.skey, arguments.encryptAlgorithm );
        </cfscript> 
	</cffunction>


	<cffunction access="private" returntype="void" name="preAdd" output="false" hint="Check precondition to see if addition of two operands will result in arithmetic overflow. Note that the operands are of two different integral types.">
		<cfargument type="numeric" name="leftLongValue" required="true">
		<cfargument type="numeric" name="rightIntValue" required="true">
		<cfscript>
	        if ( arguments.rightIntValue > 0 && ( javaCast("long", arguments.leftLongValue + arguments.rightIntValue) < arguments.leftLongValue) ) {
	            throw(object=createObject("java", "java.lang.ArithmeticException").init("Arithmetic overflow for addition."));
	        }
	        if ( arguments.rightIntValue < 0 && ( javaCast("long", arguments.leftLongValue + arguments.rightIntValue) > arguments.leftLongValue) ) {
	            throw(object=createObject("java", "java.lang.ArithmeticException").init("Arithmetic underflow for addition."));
	        }
        </cfscript> 
	</cffunction>


</cfcomponent>
