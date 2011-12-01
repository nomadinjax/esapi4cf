<!--- /**
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
 */ --->
<cfcomponent displayname="CryptoToken" extends="cfesapi.org.owasp.esapi.lang.Object" output="false" hint="Compute a cryptographically secure, encrypted token containing optional name/value pairs. The cryptographic token is computed like this: username;expiration_time;[&lt;attr1&gt;;&lt;attr2&gt;;...;&lt;attrN&gt;;] where username is a user account name. Defaults to &lt;anonymous&gt; if not set and it is always converted to lower case as per the rules of the default locale. (Note this lower case conversion is consistent with the default reference implementation of ESAPI's {@code User} interface.) expiration_time is time (in milliseconds) after which the encrypted token is considered invalid (i.e., expired). The time is stored as milliseconds since midnight, January 1, 1970 UTC, and optional attributes &lt;attr1&gt;;&lt;attr2&gt;;...&lt;attrN&gt;; are optional semicolon (';') separated name/value pairs, where each name/value pair has the form: name=[value] (value may be empty, but not null) The attribute value may contain any value. However, values containing either '=' or ';' will be quoted using '\'. Likewise, values containing '\' will also be quoted using '\'. Hence if original name/value pair were name=ab=xy\; this would be represented as name=ab\=xy\\\; To ensure things are 'safe' (from a security perspective), attribute names must conform the the Java regular expression [A-Za-z0-9_\.-]+ The attribute <i>value</i> on the other hand, may be any valid string. (That is, the value is not checked, so beware!) This entire semicolon-separated string is then encrypted via one of the {@code Encryptor.encrypt()} methods and then base64-encoded, serialized IV + ciphertext + MAC representation as determined by {@code CipherTextasPortableSerializedByteArray()} is used as the resulting cryptographic token. The attributes are sorted by attribute name and the attribute names must be unique. There are some restrictions on the attribute names. (See the {@link ##setAttribute(String, String)} method for details.)">

	<cfscript>
		/* Represents an anonymous user. */
		this.ANONYMOUS_USER = "<anonymous>";

		// Default expiration time
		instance.DEFAULT_EXP_TIME = 5 * 60 * 1000;// 5 min == 300000 milliseconds
		instance.DELIM = ";";// field delimiter
		instance.DELIM_CHAR = ';';// field delim as a char
		instance.QUOTE_CHAR = '\';// char used to quote delimiters, '=' and itself.
		// OPEN ISSUE: Should we make these 2 regex's properties in ESAPI.properties???
		instance.ATTR_NAME_REGEX = "[A-Za-z0-9_.-]+";// One or more alphanumeric, underscore, periods, or hyphens.
		instance.USERNAME_REGEX = "[a-z][a-z0-9_.@-]*";

		instance.ESAPI = "";
		instance.logger = "";

		instance.username = this.ANONYMOUS_USER;// Default user name if not set. Always lower case.
		instance.expirationTime = 0;
		// This probably needed be sorted. A HashMap would do as well.
		// But this might make debugging a bit easier, so why not?
		instance.attributes = {};
		instance.secretKey = "";
		instance.attrNameRegex = newJava("java.util.regex.Pattern").compile(instance.ATTR_NAME_REGEX);
		instance.userNameRegex = newJava("java.util.regex.Pattern").compile(instance.USERNAME_REGEX);
	</cfscript>

	<cffunction access="public" returntype="CryptoToken" name="init" output="false"
	            hint="Create a cryptographic token using default secret key from the ESAPI.properties property Encryptor.MasterKey.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument name="skey"/>
		<cfargument type="String" name="token"/>

		<cfset var local = {}/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("CryptoToken");

			if(structKeyExists(arguments, "skey") && structKeyExists(arguments, "token")) {
				initSecretKeyAndToken(arguments.skey, arguments.token);
			}
			else if(structKeyExists(arguments, "skey")) {
				initSecretKey(arguments.skey);
			}
			else if(structKeyExists(arguments, "token")) {
				initToken(arguments.token);
			}
			else {
				instance.secretKey = getDefaultSecretKey(instance.ESAPI.securityConfiguration().getEncryptionAlgorithm());
				local.now = newJava("java.lang.System").currentTimeMillis();
				instance.expirationTime = javaCast("long", local.now + instance.DEFAULT_EXP_TIME);
			}
			return this;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="initSecretKey" output="false"
	            hint="Create a cryptographic token using specified {@code SecretKey}.">
		<cfargument required="true" name="skey" hint="The specified {@code SecretKey} to use to encrypt the token."/>

		<cfset var local = {}/>

		<cfscript>
			assert(structKeyExists(arguments, "skey"), "SecretKey may not be null.");
			instance.secretKey = arguments.skey;
			local.now = newJava("java.lang.System").currentTimeMillis();
			instance.expirationTime = javaCast("long", local.now + instance.DEFAULT_EXP_TIME);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="initToken" output="false"
	            hint="Create using previously encrypted token encrypted with default secret key from ESAPI.properties.">
		<cfargument required="true" type="String" name="token" hint="A previously encrypted token returned by one of the {@code getToken()} or {@code updateToken()} methods. The token must have been previously encrypted using the using default secret key from the ESAPI.properties property Encryptor.MasterKey."/>

		<cfset var local = {}/>

		<cfscript>
			instance.secretKey = getDefaultSecretKey(instance.ESAPI.securityConfiguration().getEncryptionAlgorithm());
			try {
				decryptToken(instance.secretKey, arguments.token);
			}
			catch(cfesapi.org.owasp.esapi.errors.EncodingException e) {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.EncryptionException").init("Decryption of token failed. Token improperly encoded or encrypted with different key.", "Can't decrypt token because not correctly encoded or encrypted with different key.", e);
				throwError(local.exception);
			}
			assert(structKeyExists(instance, "username"), "Programming error: Decrypted token found username null.");
			assert(instance.expirationTime > 0, "Programming error: Decrypted token found expirationTime <= 0.");
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="initSecretKeyAndToken" output="false"
	            hint="Create cryptographic token using previously encrypted token that was encrypted with specified secret key.">
		<cfargument required="true" name="skey"/>
		<cfargument required="true" type="String" name="token" hint="A previously encrypted token returned by one of the {@code getToken()} or {@code updateToken()} methods."/>

		<cfset var local = {}/>

		<cfscript>
			assert(structKeyExists(arguments, "skey"), "SecretKey may not be null.");
			assert(structKeyExists(arguments, "token"), "Token may not be null");
			instance.secretKey = arguments.skey;
			try {
				decryptToken(instance.secretKey, arguments.token);
			}
			catch(cfesapi.org.owasp.esapi.errors.EncodingException e) {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.EncryptionException").init("Decryption of token failed. Token improperly encoded.", "Can't decrypt token because not correctly encoded.", e);
				throwError(local.exception);
			}
			assert(structKeyExists(instance, "username"), "Programming error: Decrypted token found username null.");
			assert(instance.expirationTime > 0, "Programming error: Decrypted token found expirationTime <= 0.");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getUserAccountName" output="false"
	            hint="Retrieve the user account name associated with this {@code CryptoToken} object.">

		<cfscript>
			return iif(instance.username != "", de(instance.username), de(this.ANONYMOUS_USER));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setUserAccountName" output="false"
	            hint="Set the user account name associated with this cryptographic token object. The user account name is converted to lower case.">
		<cfargument required="true" type="String" name="userAccountName" hint="The user account name."/>

		<cfset var local = {}/>

		<cfscript>
			assert(structKeyExists(arguments, "userAccountName"), "User account name may not be null.");

			// Converting to lower case first allows a simpler regex.
			local.userAcct = arguments.userAccountName.toLowerCase();

			// Check to make sure that attribute name is valid as per our regex.
			local.userNameChecker = instance.userNameRegex.matcher(local.userAcct);
			if(local.userNameChecker.matches()) {
				instance.username = local.userAcct;
			}
			else {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, "Invalid user account name encountered.", "User account name " & userAccountName & " does not match regex " & instance.USERNAME_REGEX & " after conversion to lowercase.");
				throwError(local.exception);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isExpired" output="false"
	            hint="Check if token has expired yet.">

		<cfscript>
			return getTickCount() > instance.expirationTime;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setExpirationAsSeconds" output="false"
	            hint="Set expiration time to expire in 'interval' seconds (NOT milliseconds).">
		<cfargument required="true" type="numeric" name="intervalSecs" hint="Number of seconds in the future from current date/time to set expiration. Must be positive."/>

		<cfset var local = {}/>

		<cfscript>
			local.intervalMillis = intervalSecs * 1000;// Need to convert secs to millisec.
			// Don't want to use assertion here, because if they are disabled,
			// this would result in setting the expiration time prior to the
			// current time, hence it would already be expired.
			if(local.intervalMillis <= 0) {
				throwError(newJava("java.lang.IllegalArgumentException").init("intervalSecs argument, converted to millisecs, must be > 0."));
			}
			// Check for arithmetic overflow here. In reality, this condition
			// should never happen, but we want to avoid it--even theoretically--
			// since otherwise, it could have security implications.
			local.now = newJava("java.lang.System").currentTimeMillis();
			preAdd(local.now, local.intervalMillis);
			instance.expirationTime = javaCast("long", local.now + local.intervalMillis);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setExpirationAsDate" output="false"
	            hint="Set expiration time for a specific date/time.">
		<cfargument required="true" type="Date" name="expirationDate" hint="The date/time at which the token will fail. Must be after the current date/time."/>

		<cfset var local = {}/>

		<cfscript>
			if(!structKeyExists(arguments, "expirationDate")) {
				throwError(newJava("java.lang.IllegalArgumentException").init("expirationDate may not be null."));
			}
			local.curTime = newJava("java.lang.System").currentTimeMillis();
			local.expTime = arguments.expirationDate.getTime();
			if(local.expTime <= local.curTime) {
				throwError(newJava("java.lang.IllegalArgumentException").init("Expiration date must be after current date/time."));
			}
			instance.expirationTime = local.expTime;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getExpiration" output="false"
	            hint="Return the expiration time in milliseconds since epoch time (midnight, January 1, 1970 UTC).">

		<cfscript>
			assert(instance.expirationTime > 0, "Programming error: Expiration time <= 0");
			return instance.expirationTime;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Date" name="getExpirationDate" output="false"
	            hint="Return the expiration time as a {@code Date}.">

		<cfscript>
			return newJava("java.util.Date").init(getExpiration());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAttribute" output="false"
	            hint="Set a name/value pair as an attribute.">
		<cfargument required="true" type="String" name="name" hint="The attribute name"/>
		<cfargument required="true" type="String" name="value" hint="The attribute value"/>

		<cfset var local = {}/>

		<cfscript>
			if(!structKeyExists(arguments, "name") || arguments.name.length() == 0) {
				// CHECKME: Should this be an IllegalArgumentException instead? I
				// would prefer an assertion here and state this as a precondition
				// in the Javadoc.
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, "Null or empty attribute NAME encountered", "Attribute NAMES may not be null or empty string.");
				throwError(local.exception);
			}
			if(!structKeyExists(arguments, "value")) {
				// CHECKME: Should this be an IllegalArgumentException instead? I
				// would prefer an assertion here and state this as a precondition
				// in the Javadoc.
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, "Null attribute VALUE encountered for attr name " & arguments.name, "Attribute VALUE may not be null; attr name: " & arguments.name);
				throwError(local.exception);
			}
			// NOTE: OTOH, it *is* VALID if the _value_ is empty! Null values cause too much trouble
			// to make it worth the effort of getting it to work consistently.
			// Check to make sure that attribute name is valid as per our regex.
			local.attrNameChecker = instance.attrNameRegex.matcher(arguments.name);
			if(local.attrNameChecker.matches()) {
				instance.attributes.put(arguments.name, arguments.value);
			}
			else {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, "Invalid attribute name encountered.", "Attribute name " & arguments.name & " does not match regex " & instance.ATTR_NAME_REGEX);
				throwError(local.exception);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addAttributes" output="false"
	            hint="Add the specified collection of attributes to the current attributes. If there are duplicate attributes specified, they will replace any existing ones.">
		<cfargument required="true" type="Struct" name="attrs" hint="Name/value pairs of attributes to add or replace the existing attributes. Map must be non-null, but may be empty."/>

		<cfset var local = {}/>

		<cfscript>
			// CHECKME: Assertion vs. IllegalArgumentException
			assert(structKeyExists(arguments, "attrs"), "Attribute map may not be null.");
			local.keyValueSet = arguments.attrs.entrySet();
			local.it = local.keyValueSet.iterator();
			while(local.it.hasNext()) {
				local.entry = local.it.next();
				local.key = local.entry.getKey();
				local.value = local.entry.getValue();
				setAttribute(local.key, local.value);
			}
			return;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getAttribute" output="false"
	            hint="Retrieve the attribute with the specified name.">
		<cfargument required="true" type="String" name="name" hint="The attribute name."/>

		<cfscript>
			return instance.attributes.get(arguments.name);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Struct" name="getAttributes" output="false"
	            hint="Retrieve a {@code Map} that is a clone of all the attributes. A copy is returned so that the attributes in {@code CrytpToken} are unaffected by alterations made the returned {@code Map}. (Otherwise, multi-threaded code could get trick.">

		<cfscript>
			// Unfortunately, this requires a cast, which requires us to supress warnings.
			return instance.attributes.clone();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="clearAttributes" output="false"
	            hint="Removes all the attributes (if any) associated with this token. Note that this does not clear / reset the user account name or expiration time.">

		<cfscript>
			instance.attributes.clear();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getTokenESAPI" output="false"
	            hint="Return the new encrypted token as a base64-encoded string, encrypted with the specified {@code SecretKey} which may be a different key than what the token was originally encrypted with.">
		<cfargument name="skey" default="#instance.secretKey#" hint="The specified key to (re)encrypt the token."/>

		<cfscript>
			return createEncryptedToken(arguments.skey);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="updateToken" output="false"
	            hint="Update the (current) expiration time by adding the specified number of seconds to it and then re-encrypting with the current {@code SecretKey} that was used to construct this object.">
		<cfargument required="true" type="numeric" name="additionalSecs" hint="The additional number of seconds to add to the current expiration time. This number must be &gt;= 0 or otherwise an {@code IllegalArgumentException} is thrown."/>

		<cfset var local = {}/>

		<cfscript>
			if(arguments.additionalSecs < 0) {
				throwError(newJava("java.lang.IllegalArgumentException").init("additionalSecs argument must be >= 0."));
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

			if(isExpired()) {
				// Too bad there is no ProcrastinationException ;-)
				instance.expirationTime = local.curExpTime;// Restore the original value (which still may be expired.
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ValidationException").init(instance.ESAPI, "Token timed out.", "Cryptographic token not increased to sufficient value to prevent timeout.");
				throwError(local.exception);
			}
			// Don't change anything else (user acct name, attributes, skey, etc.)
			return this.getTokenESAPI();
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="createEncryptedToken" output="false"
	            hint="Create the actual encrypted token based on the specified SecretKey. This method will ensure that the decrypted token always ends with an unquoted delimiter.">
		<cfargument required="true" name="skey"/>

		<cfset var local = {}/>

		<cfscript>
			local.sb = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init(getUserAccountName() & instance.DELIM);
			// CHECKME: Should we check here to see if token has already expired
			//  and refuse to encrypt it (by throwing exception) if it has???
			//  If so, then updateToken() should also be revisited.
			local.sb.append(getExpiration()).append(instance.DELIM);
			local.sb.append(getQuotedAttributes());

			local.encryptor = instance.ESAPI.encryptor();
			local.plain = newComponent("cfesapi.org.owasp.esapi.crypto.PlainText").init(instance.ESAPI, local.sb.toStringESAPI());
			local.ct = local.encryptor.encryptESAPI(arguments.skey, local.plain);
			local.b64 = instance.ESAPI.encoder().encodeForBase64(local.ct.asPortableSerializedByteArray(), false);
			return local.b64;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="getQuotedAttributes" output="false"
	            hint="Return a string of all the attributes, properly quoted. This is used in creating the encrypted token. Note that this method ensures that the quoted attribute string always ends with an (quoted) delimiter.">
		<cfset var local = {}/>

		<cfscript>
			local.sb = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init();
			local.keyValueSet = instance.attributes.entrySet();
			local.it = local.keyValueSet.iterator();
			while(local.it.hasNext()) {
				local.entry = local.it.next();
				local.key = local.entry.getKey();
				local.value = local.entry.getValue();
				// Because attribute values may be confidential, we don't want to log them!
				instance.logger.debug(newJava("org.owasp.esapi.Logger").EVENT_UNSPECIFIED, "   " & local.key & " -> <not shown>");
				local.sb.append(local.key & "=" & quoteAttributeValue(local.value) & instance.DELIM);
			}
			return local.sb.toStringESAPI();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="toStringESAPI" output="false"
	            hint="Do NOT define a toString() method as there may be sensitive information contained in the attribute names. If we absolutely need this, then only return the username and expiration time, and _maybe_ the attribute names, but not there values. And obviously, we NEVER want to include the SecretKey should we decide to do this.">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="quoteAttributeValue" output="false"
	            hint="Quote any special characters in value.">
		<cfargument required="true" type="String" name="value"/>

		<cfset var local = {}/>

		<cfscript>
			assert(structKeyExists(arguments, "value"), "Program error: Value should not be null.");// Empty is OK.
			local.sb = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init();
			local.charArray = value.toCharArray();
			for(local.i = 1; local.i <= arrayLen(local.charArray); local.i++) {
				local.c = local.charArray[local.i];
				if(local.c == instance.QUOTE_CHAR || local.c == "=" || local.c == instance.DELIM_CHAR) {
					local.sb.append(instance.QUOTE_CHAR).append(local.c);
				}
				else {
					local.sb.append(local.c);
				}
			}
			return local.sb.toStringESAPI();
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="parseQuotedValue" output="false"
	            hint="Parse the possibly quoted value and return the unquoted value.">
		<cfargument required="true" type="String" name="quotedValue"/>

		<cfset var local = {}/>

		<cfscript>
			local.sb = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init();
			local.charArray = quotedValue.toCharArray();
			for(local.i = 1; local.i <= arrayLen(local.charArray); local.i++) {
				local.c = local.charArray[local.i];
				if(local.c == instance.QUOTE_CHAR) {
					local.i++;// Skip past quote character.
					local.sb.append(local.charArray[local.i]);
				}
				else {
					local.sb.append(local.c);
				}
			}
			return local.sb.toStringESAPI();
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="decryptToken" output="false"
	            hint="Decrypt the encrypted token and parse it into the individual components. The string should always end with a semicolon (;) even when there are no attributes set.">
		<cfargument required="true" name="skey"/>
		<cfargument required="true" type="String" name="b64token"/>

		<cfset var local = {}/>

		<cfscript>
			local.token = "";
			try {
				local.token = instance.ESAPI.encoder().decodeFromBase64(arguments.b64token);
			}
			catch(java.io.IOException e) {
				// CHECKME: Not clear if we should log the actual token itself. It's encrypted,
				//          but could be arbitrarily long, especially since it is not valid
				//          encoding. OTOH, it may help debugging as sometimes it may be a simple
				//          case like someone failing to apply some other type of encoding
				//          consistently (e.g., URL encoding), in which case logging this should
				//          make this pretty obvious once a few of these are logged.
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.EncodingException").init(instance.ESAPI, "Invalid base64 encoding.", "Invalid base64 encoding. Encrypted token was: " & arguments.b64token);
				throwError(local.exception);
			}
			local.ct = newComponent("cfesapi.org.owasp.esapi.crypto.CipherText").init(instance.ESAPI).fromPortableSerializedBytes(local.token);
			local.encryptor = instance.ESAPI.encryptor();
			local.pt = local.encryptor.decryptESAPI(arguments.skey, local.ct);
			local.str = local.pt.toStringESAPI();
			assert(local.str.endsWith(instance.DELIM), "Programming error: Expecting decrypted token to end with delim char, " & instance.DELIM_CHAR);
			local.charArray = local.str.toCharArray();
			local.prevPos = -1;// Position of previous unquoted delimiter.
			local.fieldNo = 0;
			local.fields = [];
			local.lastPos = arrayLen(local.charArray);
			for(local.curPos = 1; local.curPos <= local.lastPos; local.curPos++) {
				local.quoted = false;
				local.curChar = local.charArray[local.curPos];
				if(local.curChar == instance.QUOTE_CHAR) {
					// Found a case where we have quoted character. We need to skip
					// over this and set the current character to the next character.
					local.curPos++;
					if(local.curChar != local.lastPos) {
						local.curChar = local.charArray[local.curPos + 1];
						local.quoted = true;
					}
					else {
						// Last position will always be a delimiter character that
						// should be treated as unquoted.
						local.curChar = instance.DELIM_CHAR;
					}
				}
				if(local.curChar == instance.DELIM_CHAR && !local.quoted) {
					// We found an actual (unquoted) field delimiter.
					local.record = local.str.substring(local.prevPos + 1, local.curPos - 1);
					local.fields.add(local.record);
					local.fieldNo++;
					local.prevPos = local.curPos - 1;
				}
			}

			assert(local.fieldNo == arrayLen(local.fields), "Program error: Mismatch of delimited field count.");
			instance.logger.debug(newJava("org.owasp.esapi.Logger").EVENT_UNSPECIFIED, "Found " & arrayLen(local.fields) & " fields.");
			assert(arrayLen(local.fields) >= 2, "Missing mandatory fields from decrypted token (username &/or expiration time).");
			instance.username = local.fields[1].toLowerCase();
			local.expTime = local.fields[2];
			instance.expirationTime = newJava("java.lang.Long").parseLong(local.expTime);

			for(local.i = 3; local.i <= arrayLen(local.fields); local.i++) {
				local.nvpair = local.fields[local.i];
				local.equalsAt = local.nvpair.indexOf("=");
				if(local.equalsAt == -1) {
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.EncryptionException").init("Invalid attribute encountered in decrypted token.", "Malformed attribute name/value pair (" & local.nvpair & ") found in decrypted token.");
					throwError(local.exception);
				}
				local.name = local.nvpair.substring(0, local.equalsAt);
				local.quotedValue = local.nvpair.substring(local.equalsAt + 1);
				local.value = parseQuotedValue(local.quotedValue);
				// Because attribute values may be confidential, we don't want to log them!
				instance.logger.debug(newJava("org.owasp.esapi.Logger").EVENT_UNSPECIFIED, "Attribute[" & local.i & "]: name=" & local.name & ", value=<not shown>");

				// Check to make sure that attribute name is valid as per our regex.
				local.attrNameChecker = instance.attrNameRegex.matcher(local.name);
				if(local.attrNameChecker.matches()) {
					instance.attributes.put(local.name, local.value);
				}
				else {
					local.exception = newComponent("cfesapi.org.owsap.esapi.errors.EncryptionException").init("Invalid attribute name encountered in decrypted token.", "Invalid attribute name encountered in decrypted token; attribute name " & local.name & " does not match regex " & instance.ATTR_NAME_REGEX);
					throwError(local.exception);
				}
				instance.attributes.put(local.name, local.value);
			}
			return;
		</cfscript>

	</cffunction>

	<cffunction access="private" name="getDefaultSecretKey" output="false">
		<cfargument required="true" type="String" name="encryptAlgorithm"/>

		<cfset var local = {}/>

		<cfscript>
			assert(structKeyExists(arguments, "encryptAlgorithm"), "Encryption algorithm cannot be null");
			local.skey = instance.ESAPI.securityConfiguration().getMasterKey();
			assert(structKeyExists(local, "skey"), "Can't obtain master key, Encryptor.MasterKey");
			assert(arrayLen(local.skey) >= 7, "Encryptor.MasterKey must be at least 7 bytes. Length is: " & arrayLen(local.skey) & " bytes.");
			// Set up secretKeySpec for use for symmetric encryption and decryption,
			// and set up the public/<cffunction access="private" returntype="keys for asymmetric encryption /
			// decryption.
			return newJava("javax.crypto.spec.SecretKeySpec").init(local.skey, arguments.encryptAlgorithm);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="preAdd" output="false"
	            hint="Check precondition to see if addition of two operands will result in arithmetic overflow. Note that the operands are of two different integral types. I.e., check to see if: long result = leftLongValue + rightIntValue would cause arithmetic overflow. Note: We know that as we use it here, leftLongValue will always be > 0, so arithmetic underflow should never be possible, but we check for it anyhow. Package level access to allow this to be used by other classes in this package.">
		<cfargument required="true" type="numeric" name="leftLongValue"/>
		<cfargument required="true" type="numeric" name="rightIntValue"/>

		<cfscript>
			if(arguments.rightIntValue > 0 && (javaCast("long", arguments.leftLongValue + arguments.rightIntValue) < arguments.leftLongValue)) {
				throwError(newJava("java.lang.ArithmeticException").init("Arithmetic overflow for addition."));
			}
			if(arguments.rightIntValue < 0 && (javaCast("long", arguments.leftLongValue + arguments.rightIntValue) > arguments.leftLongValue)) {
				throwError(newJava("java.lang.ArithmeticException").init("Arithmetic underflow for addition."));
			}
		</cfscript>

	</cffunction>

</cfcomponent>