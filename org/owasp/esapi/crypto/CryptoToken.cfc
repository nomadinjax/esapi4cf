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
 * Compute a cryptographically secure, encrypted token containing
 * optional name/value pairs. The cryptographic token is computed
 * like this:
 * <pre>
 *     username;expiration_time;[&lt;attr1&gt;;&lt;attr2&gt;;...;&lt;attrN&gt;;]
 * </pre>
 * where
 * <i>username</i> is a user account name. Defaults to &lt;anonymous&gt; if
 * not set and it is always converted to lower case as per the rules of the
 * default locale. (Note this lower case conversion is consistent with the
 * default reference implementation of ESAPI's {@code User} interface.)
 * <br>
 * <i>expiration_time</i> is time (in milliseconds) after which the encrypted
 * token is considered invalid (i.e., expired). The time is stored as
 * milliseconds since midnight, January 1, 1970 UTC, and optional attributes
 * <br>
 * &nbsp;&nbsp;<i>&lt;attr1&gt;</i>;<i>&lt;attr2&gt;</i>;...<i>&lt;attrN&gt;</i>;
 * <br>
 * are optional semicolon (';') separated name/value pairs, where each
 * name/value pair has the form:
 * <pre>
 *         name=[value]        (value may be empty, but not null)
 * </pre>
 * The attribute value may contain any value. However, values containing
 * either '=' or ';' will be quoted using '\'. Likewise, values containing '\'
 * will also be quoted using '\'. Hence if original name/value pair were
 *             name=ab=xy\;
 *         this would be represented as
 *             name=ab\=xy\\\;
 * To ensure things are "safe" (from a security perspective), attribute
 * <i>names</i> must conform the the Java regular expression
 * <pre>
 *          [A-Za-z0-9_\.-]+
 * </pre>
 * The attribute <i>value</i> on the other hand, may be any valid string. (That
 * is, the value is not checked, so beware!)
 * <p>
 * This entire semicolon-separated string is then encrypted via one of the 
 * {@code Encryptor.encrypt()} methods and then base64-encoded, serialized
 * IV + ciphertext + MAC representation as determined by
 * {@code CipherTextasPortableSerializedByteArray()} is used as the
 * resulting cryptographic token.
 * <p>
 * The attributes are sorted by attribute name and the attribute names
 * must be unique. There are some restrictions on the attribute names.
 * (See the {@link #setAttribute(String, String)} method for details.)
 */
component CryptoToken extends="cfesapi.org.owasp.esapi.lang.Object" {

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

	/**
	 * Create a cryptographic token using default secret key from the
	 * <b>ESAPI.properties</b> property <b>Encryptor.MasterKey</b>. 
	 */
	
	public CryptoToken function init(required cfesapi.org.owasp.esapi.ESAPI ESAPI, skey, String token) {
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
	}
	
	// Create using specified SecretKey
	/**
	 * Create a cryptographic token using specified {@code SecretKey}.
	 * 
	 * @param skey  The specified {@code SecretKey} to use to encrypt the token.
	 */
	
	private void function initSecretKey(required skey) {
		assert(!isNull(arguments.skey), "SecretKey may not be null.");
		instance.secretKey = arguments.skey;
		local.now = newJava("java.lang.System").currentTimeMillis();
		instance.expirationTime = javaCast("long", local.now + instance.DEFAULT_EXP_TIME);
	}
	
	/** 
	 * Create using previously encrypted token encrypted with default secret
	 * key from <b>ESAPI.properties</b>.
	 * @param token A previously encrypted token returned by one of the
	 *              {@code getToken()} or {@code updateToken()} methods. The
	 *              token <i>must</i> have been previously encrypted using the
	 *              using default secret key from the <b>ESAPI.properties</b>
	 *              property <b>Encryptor.MasterKey</b>.
	 * @throws EncryptionException  Thrown if they are any problems while decrypting
	 *                              the token using the default secret key from
	 *                              <b>ESAPI.properties</b> or if the decrypted
	 *                              token is not properly formatted.
	 */
	
	private void function initToken(required String token) {
		instance.secretKey = getDefaultSecretKey(instance.ESAPI.securityConfiguration().getEncryptionAlgorithm());
		try {
			decryptToken(instance.secretKey, arguments.token);
		}
		catch(cfesapi.org.owasp.esapi.errors.EncodingException e) {
			local.exception = new cfesapi.org.owasp.esapi.errors.EncryptionException("Decryption of token failed. Token improperly encoded or encrypted with different key.", "Can't decrypt token because not correctly encoded or encrypted with different key.", e);
			throwError(local.exception);
		}
		assert(!isNull(instance.username), "Programming error: Decrypted token found username null.");
		assert(instance.expirationTime > 0, "Programming error: Decrypted token found expirationTime <= 0.");
	}
	
	/** 
	 * Create cryptographic token using previously encrypted token that was
	 * encrypted with specified secret key.
	 * 
	 * @param token A previously encrypted token returned by one of the
	 *              {@code getToken()} or {@code updateToken()} methods.
	 * @throws EncryptionException  Thrown if they are any problems while decrypting
	 *                              the token using the default secret key from
	 *                              <b>ESAPI.properties</b> or if the decrypted
	 *                              token is not properly formatted.
	 */
	// token is a previously encrypted token (i.e., CryptoToken.getToken())
	// with different SecretKey other than the one in ESAPI.properties
	
	private void function initSecretKeyAndToken(required skey, required String token) {
		assert(!isNull(arguments.skey), "SecretKey may not be null.");
		assert(!isNull(arguments.token), "Token may not be null");
		instance.secretKey = arguments.skey;
		try {
			decryptToken(instance.secretKey, arguments.token);
		}
		catch(cfesapi.org.owasp.esapi.errors.EncodingException e) {
			local.exception = new cfesapi.org.owasp.esapi.errors.EncryptionException("Decryption of token failed. Token improperly encoded.", "Can't decrypt token because not correctly encoded.", e);
			throwError(local.exception);
		}
		assert(!isNull(instance.username), "Programming error: Decrypted token found username null.");
		assert(instance.expirationTime > 0, "Programming error: Decrypted token found expirationTime <= 0.");
	}
	
	/**
	 * Retrieve the user account name associated with this {@code CryptoToken}
	 * object.
	 * @return  The user account name. The string represented by
	 *          {@link #ANONYMOUS_USER} is returned if
	 *          {@link #setUserAccountName(String)} was never called.
	 */
	
	public String function getUserAccountName() {
		return instance.username != "" ? instance.username : this.ANONYMOUS_USER;
	}
	
	/**
	 * Set the user account name associated with this cryptographic token
	 * object. The user account name is converted to lower case.
	 * @param userAccountName   The user account name.
	 * @throws ValidationException  Thrown if user account name is not valid, i.e.,
	 *                              if it doesn't conform to the regular expression
	 *                              given by "[a-z][a-z0-9_.@-]*". (Note that the
	 *                              parameter {@code userAccountName} is first converted
	 *                              to lower case before checked against the regular
	 *                              expression.)
	 */
	
	public void function setUserAccountName(required String userAccountName) {
		assert(!isNull(arguments.userAccountName), "User account name may not be null.");
	
		// Converting to lower case first allows a simpler regex.
		local.userAcct = arguments.userAccountName.toLowerCase();
	
		// Check to make sure that attribute name is valid as per our regex.
		local.userNameChecker = instance.userNameRegex.matcher(local.userAcct);
		if(local.userNameChecker.matches()) {
			instance.username = local.userAcct;
		}
		else {
			local.exception = new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, "Invalid user account name encountered.", "User account name " & userAccountName & " does not match regex " & instance.USERNAME_REGEX & " after conversion to lowercase.");
			throwError(local.exception);
		}
	}
	
	/** Check if token has expired yet.
	 * @return  True if token has expired; false otherwise.
	 */
	
	public boolean function isExpired() {
		return getTickCount() > instance.expirationTime;
	}
	
	/**
	 * Set expiration time to expire in 'interval' seconds (NOT milliseconds).
	 * @param interval  Number of seconds in the future from current date/time
	 *                  to set expiration. Must be positive.
	 */
	
	public void function setExpirationAsSeconds(required numeric intervalSecs) {
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
	}
	
	/**
	 * Set expiration time for a specific date/time.
	 * @param expirationDate    The date/time at which the token will fail. Must
	 *                          be after the current date/time.
	 * @throws IllegalArgumentException Thrown if the parameter is null.
	 */
	
	public void function setExpirationAsDate(required Date expirationDate) {
		if(isNull(arguments.expirationDate)) {
			throwError(newJava("java.lang.IllegalArgumentException").init("expirationDate may not be null."));
		}
		local.curTime = newJava("java.lang.System").currentTimeMillis();
		local.expTime = arguments.expirationDate.getTime();
		if(local.expTime <= local.curTime) {
			throwError(newJava("java.lang.IllegalArgumentException").init("Expiration date must be after current date/time."));
		}
		instance.expirationTime = local.expTime;
	}
	
	/**
	 * Return the expiration time in milliseconds since epoch time (midnight,
	 * January 1, 1970 UTC).
	 * @return  The current expiration time.
	 */
	
	public numeric function getExpiration() {
		assert(instance.expirationTime > 0, "Programming error: Expiration time <= 0");
		return instance.expirationTime;
	}
	
	/**
	 * Return the expiration time as a {@code Date}.
	 * @return The {@code Date} object representing the expiration time.
	 */
	
	public Date function getExpirationDate() {
		return newJava("java.util.Date").init(getExpiration());
	}
	
	/**
	 * Set a name/value pair as an attribute.
	 * @param name  The attribute name
	 * @param value The attribute value
	 * @throws ValidationException  Thrown if the attribute name is not properly
	 *                              formed. That is, the attribute name does not
	 *                              match the regular expression "[A-Za-z0-9_.-]+".
	 */
	
	public void function setAttribute(required String name, required String value) {
		if(isNull(arguments.name) || arguments.name.length() == 0) {
			// CHECKME: Should this be an IllegalArgumentException instead? I
			// would prefer an assertion here and state this as a precondition
			// in the Javadoc.
			local.exception = new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, "Null or empty attribute NAME encountered", "Attribute NAMES may not be null or empty string.");
			throwError(local.exception);
		}
		if(isNull(arguments.value)) {
			// CHECKME: Should this be an IllegalArgumentException instead? I
			// would prefer an assertion here and state this as a precondition
			// in the Javadoc.
			local.exception = new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, "Null attribute VALUE encountered for attr name " & arguments.name, "Attribute VALUE may not be null; attr name: " & arguments.name);
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
			local.exception = new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, "Invalid attribute name encountered.", "Attribute name " & arguments.name & " does not match regex " & instance.ATTR_NAME_REGEX);
			throwError(local.exception);
		}
	}
	
	/**
	 * Add the specified collection of attributes to the current attributes.
	 * If there are duplicate attributes specified, they will replace any
	 * existing ones.
	 * 
	 * @param attrs Name/value pairs of attributes to add or replace the existing
	 *              attributes. Map must be non-null, but may be empty.
	 * @throws ValidationException Thrown if one of the keys in the specified
	 *                             parameter {@code attrs} is not a valid name.
	 *                             That is, all attribute names must match the regular
	 *                             expression ""[A-Za-z0-9_.-]+".
	 * @see #setAttribute(String, String)
	 */
	
	public void function addAttributes(required Struct attrs) {
		// CHECKME: Assertion vs. IllegalArgumentException
		assert(!isNull(arguments.attrs), "Attribute map may not be null.");
		local.keyValueSet = arguments.attrs.entrySet();
		local.it = local.keyValueSet.iterator();
		while(local.it.hasNext()) {
			local.entry = local.it.next();
			local.key = local.entry.getKey();
			local.value = local.entry.getValue();
			setAttribute(local.key, local.value);
		}
		return;
	}
	
	/**
	 * Retrieve the attribute with the specified name.
	 * @param name  The attribute name.
	 * @return  The value associated with the attribute name. If attribute is not
	 *          set, then {@code null} is returned.
	 */
	
	public String function getAttribute(required String name) {
		return instance.attributes.get(arguments.name);
	}
	
	/**
	 * Retrieve a {@code Map} that is a clone of all the attributes. A <i>copy</i>
	 * is returned so that the attributes in {@code CrytpToken} are unaffected
	 * by alterations made the returned {@code Map}. (Otherwise, multi-threaded code
	 * could get trick.
	 * 
	 * @return  A {@code Map} of all the attributes.
	 * @see #getAttribute(String)
	 */
	// @SuppressWarnings("unchecked")
	
	public Struct function getAttributes() {
		// Unfortunately, this requires a cast, which requires us to supress warnings.
		return instance.attributes.clone();
	}
	
	/**
	 * Removes all the attributes (if any) associated with this token. Note
	 * that this does not clear / reset the user account name or expiration time.
	 */
	
	public void function clearAttributes() {
		instance.attributes.clear();
	}
	
	/**
	 * Return the new encrypted token as a base64-encoded string, encrypted with
	 * the specified {@code SecretKey} which may be a different key than what the
	 * token was originally encrypted with. E.g.,
	 * <pre>
	 *   Alice:
	 *      SecretKey aliceSecretKey = ...; // Shared with Bob
	 *      CryptoToken cryptoToken = new CryptoToken(skey1);
	 *      cryptoToken.setUserAccountName("kwwall");
	 *      cryptoToken.setAttribute("role", "admin");
	 *      cryptoToken.setAttribute("state", "Ohio");
	 *      String token = cryptoToken.getToken(); // Encrypted with skey1
	 *      // send token to Bob ...
	 *  --------------------------------------------------------------------
	 *  Bob:
	 *      ...
	 *      SecretKey aliceSecretKey = ...  // Shared with Alice
	 *      SecretKey bobSecretKey = ...;   // Shared with Carol
	 *      CryptoToken cryptoToken = new CryptoToken(aliceSecretKey, tokenFromAlice);
	 *      
	 *      // Re-encrypt for Carol using my (Bob's) key...
	 *      String tokenForCarol = cryptoToken.getToken(bobSecretKey);
	 *      // send tokenForCarol to Carol ...
	 *      // use token ourselves
	 *  --------------------------------------------------------------------
	 *  Carol:
	 *      ...
	 *      SecretKey bobSecretKey = ...;   // Shared with Bob.
	 *      CryptoToken cryptoToken = new CryptoToken(bobSecretKey, tokenFromBob);
	 *      if ( ! cryptoToken.isExpired() ) {
	 *          String userName = cryptoToken.getUserAccountName();
	 *          String roleName = cryptoToken.getAttribute("role");
	 *          if ( roleName != null && roleName.equalsIgnoreCase("admin") ) {
	 *              // grant admin access...
	 *              ...
	 *          }
	 *      }
	 *      ...
	 * </pre>
	 * @param skey  The specified key to (re)encrypt the token.
	 * @return The newly encrypted token.
	 */
	
	public String function getToken(skey=instance.secretKey) {
		return createEncryptedToken(arguments.skey);
	}
	
	/**
	 * Update the (current) expiration time by adding the specified number of
	 * seconds to it and then re-encrypting with the current {@code SecretKey}
	 * that was used to construct this object.
	 * 
	 * @param additionalSecs    The additional number of seconds to add to the
	 *                          current expiration time. This number must be
	 *                          &gt;= 0 or otherwise an {@code IllegalArgumentException}
	 *                          is thrown.
	 * @return  The re-encrypted token with the updated expiration time is returned.
	 * @throws  IllegalArgumentException    Thrown if parameter {@code additionalSecs}
	 *                                      is less than 0.
	 * @throws  EncryptionException         Thrown if the encryption fails.
	 * @throws ValidationException          Thrown if the token will have already expired
	 *                                      even after adding the specified number of
	 *                                      additional seconds.
	 * @throws  ArithmeticException         If additional seconds is large enough such
	 *                                      that it would cause an arithmetic overflow
	 *                                      with a long (the current expiration time)
	 *                                      when added to the {@code additionalSecs}
	 *                                      parameter.
	 */
	
	public String function updateToken(required numeric additionalSecs) {
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
			local.exception = new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, "Token timed out.", "Cryptographic token not increased to sufficient value to prevent timeout.");
			throwError(local.exception);
		}
		// Don't change anything else (user acct name, attributes, skey, etc.)
		return this.getToken();
	}
	
	// Create the actual encrypted token based on the specified SecretKey.
	// This method will ensure that the decrypted token always ends with an
	// unquoted delimiter.
	
	private String function createEncryptedToken(required skey) {
		local.sb = newJava("java.lang.StringBuilder").init(getUserAccountName() & instance.DELIM);
		// CHECKME: Should we check here to see if token has already expired
		//  and refuse to encrypt it (by throwing exception) if it has???
		//  If so, then updateToken() should also be revisited.
		local.sb.append(getExpiration()).append(instance.DELIM);
		local.sb.append(getQuotedAttributes());
	
		local.encryptor = instance.ESAPI.encryptor();
		local.plain = new cfesapi.org.owasp.esapi.crypto.PlainText(instance.ESAPI, local.sb.toString());
		local.ct = local.encryptor.encrypt(arguments.skey, local.plain);
		local.b64 = instance.ESAPI.encoder().encodeForBase64(local.ct.asPortableSerializedByteArray(), false);
		return local.b64;
	}
	
	// Return a string of all the attributes, properly quoted. This is used in
	// creating the encrypted token. Note that this method ensures that the
	// quoted attribute string always ends with an (quoted) delimiter.
	
	private String function getQuotedAttributes() {
		local.sb = newJava("java.lang.StringBuilder").init();
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
		return local.sb.toString();
	}
	
	// Do NOT define a toString() method as there may be sensitive
	// information contained in the attribute names. If we absolutely
	// need this, then only return the username and expiration time, and
	// _maybe_ the attribute names, but not there values. And obviously,
	// we NEVER want to include the SecretKey should we decide to do this.
	/*
	* public String toString() { return null; }
	*/
	// Quote any special characters in value.
	
	private String function quoteAttributeValue(required String value) {
		assert(!isNull(arguments.value), "Program error: Value should not be null.");// Empty is OK.
		local.sb = newJava("java.lang.StringBuilder").init();
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
		return local.sb.toString();
	}
	
	// Parse the possibly quoted value and return the unquoted value.
	
	private String function parseQuotedValue(required String quotedValue) {
		local.sb = newJava("java.lang.StringBuilder").init();
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
		return local.sb.toString();
	}
	
	/*
	 * Decrypt the encrypted token and parse it into the individual components.
	 * The string should always end with a semicolon (;) even when there are
	 * no attributes set.
	 * <p>
	 * Example of how quoted string might look:
	 * <pre>
	 *                            v              v  v            v     v
	 *  kwwall;1291183520293;abc=x\=yx;xyz=;efg=a\;a\;;bbb=quotes\\tuff\;;
	          |             |         |    |          |                  |
	 *
	 * </pre>
	 */
	
	private void function decryptToken(required skey, required String b64token) {
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
			local.exception = new cfesapi.org.owasp.esapi.errors.EncodingException(instance.ESAPI, "Invalid base64 encoding.", "Invalid base64 encoding. Encrypted token was: " & arguments.b64token);
			throwError(local.exception);
		}
		local.ct = new CipherText(instance.ESAPI).fromPortableSerializedBytes(local.token);
		local.encryptor = instance.ESAPI.encryptor();
		local.pt = local.encryptor.decrypt(arguments.skey, local.ct);
		local.str = local.pt.toString();
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
				local.exception = new cfesapi.org.owasp.esapi.errors.EncryptionException("Invalid attribute encountered in decrypted token.", "Malformed attribute name/value pair (" & local.nvpair & ") found in decrypted token.");
				throwError(local.exception);
			}
			local.name = local.nvpair.substring(0, local.equalsAt);
			local.quotedValue = local.nvpair.substring(local.equalsAt + 1);
			local.value = parseQuotedValue(local.quotedValue);
			// Because attribute values may be confidential, we don't want to log them!
			instance.logger.debug(newJava("org.owasp.esapi.Logger").EVENT_UNSPECIFIED, "Attribute[" & i & "]: name=" & local.name & ", value=<not shown>");
		
			// Check to make sure that attribute name is valid as per our regex.
			local.attrNameChecker = instance.attrNameRegex.matcher(local.name);
			if(local.attrNameChecker.matches()) {
				instance.attributes.put(local.name, local.value);
			}
			else {
				local.exception = new cfesapi.org.owsap.esapi.errors.EncryptionException("Invalid attribute name encountered in decrypted token.", "Invalid attribute name encountered in decrypted token; attribute name " & local.name & " does not match regex " & instance.ATTR_NAME_REGEX);
				throwError(local.exception);
			}
			instance.attributes.put(local.name, local.value);
		}
		return;
	}
	
	private function getDefaultSecretKey(required String encryptAlgorithm) {
		assert(!isNull(arguments.encryptAlgorithm), "Encryption algorithm cannot be null");
		local.skey = instance.ESAPI.securityConfiguration().getMasterKey();
		assert(!isNull(local.skey), "Can't obtain master key, Encryptor.MasterKey");
		assert(arrayLen(local.skey) >= 7, "Encryptor.MasterKey must be at least 7 bytes. Length is: " & arrayLen(local.skey) & " bytes.");
		// Set up secretKeySpec for use for symmetric encryption and decryption,
		// and set up the public/private keys for asymmetric encryption /
		// decryption.
		return newJava("javax.crypto.spec.SecretKeySpec").init(local.skey, arguments.encryptAlgorithm);
	}
	
	// Check precondition to see if addition of two operands will result in
	// arithmetic overflow. Note that the operands are of two different
	// integral types. I.e., check to see if:
	//  long result = leftLongValue + rightIntValue
	// would cause arithmetic overflow.
	// Note: We know that as we use it here, leftLongValue will always be > 0,
	//   so arithmetic underflow should never be possible, but we check for
	//   it anyhow.
	// Package level access to allow this to be used by other classes in this package.
	
	private void function preAdd(required numeric leftLongValue, required numeric rightIntValue) {
		if(arguments.rightIntValue > 0 && (javaCast("long", arguments.leftLongValue + arguments.rightIntValue) < arguments.leftLongValue)) {
			throwError(newJava("java.lang.ArithmeticException").init("Arithmetic overflow for addition."));
		}
		if(arguments.rightIntValue < 0 && (javaCast("long", arguments.leftLongValue + arguments.rightIntValue) > arguments.leftLongValue)) {
			throwError(newJava("java.lang.ArithmeticException").init("Arithmetic underflow for addition."));
		}
	}
	
}