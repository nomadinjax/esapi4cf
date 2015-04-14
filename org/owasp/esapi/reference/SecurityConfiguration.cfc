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
import "org.owasp.esapi.errors.ConfigurationException";

/**
 * The reference {@code SecurityConfiguration} manages all the settings used by the ESAPI in a single place. In this reference
 * implementation, resources can be put in several locations, which are searched in the following order:
 * <p>
 * 1) Inside a directory set with a call to SecurityConfiguration.setResourceDirectory( "C:\temp\resources" ).
 * <p>
 * 2) Inside the System.getProperty( "org.owasp.esapi.resources" ) directory.
 * You can set this on the java command line as follows (for example):
 * <pre>
 * 		java -Dorg.owasp.esapi.resources="C:\temp\resources"
 * </pre>
 * You may have to add this to the start-up script that starts your web server. For example, for Tomcat,
 * in the "catalina" script that starts Tomcat, you can set the JAVA_OPTS variable to the {@code -D} string above.
 * <p>
 * 3) Inside the {@code System.getProperty( "user.home" ) + "/.esapi"} directory (supported for backward compatibility) or
 * inside the {@code System.getProperty( "user.home" ) + "/esapi"} directory.
 * <p>
 * 4) The first ".esapi" or "esapi" directory on the classpath. (The former for backward compatibility.)
 * <p>
 * Once the Configuration is initialized with a resource directory, you can edit it to set things like master
 * keys and passwords, logging locations, error thresholds, and allowed file extensions.
 * <p>
 * WARNING: Do not forget to update ESAPI.properties to change the master key and other security critical settings.
 */
component implements="org.owasp.esapi.SecurityConfiguration" extends="org.owasp.esapi.util.Object" {

	// load ESAPI configuration defaults
	include "/org/owasp/esapi/conf/ESAPI-defaults.cfm";

    variables.ESAPI = "";

    variables.cipherXformFromESAPIProp = "";
    variables.cipherXformCurrent = "";

	variables.patternCache = {};

    /**
     * Instantiates a new configuration with the supplied properties.
     *
     * @param properties
     */
    public org.owasp.esapi.SecurityConfiguration function init(required org.owasp.esapi.ESAPI ESAPI, struct configuration) {
    	variables.ESAPI = arguments.ESAPI;

    	if (isNull(arguments.configuration)) {
        	loadConfiguration();
    	}
    	else {
    		loadConfiguration(arguments.configuration);
	    }
	    setCipherXProperties();
	    return this;
    }

    private void function setCipherXProperties() {
		// TODO: FUTURE: Replace by future CryptoControls class???
		// See SecurityConfiguration.setCipherTransformation() for
		// explanation of this.
        // (Propose this in 2.1 via future email to ESAPI-DEV list.)
		variables.cipherXformFromESAPIProp = getProperty("Encryptor.CipherTransformation", "AES/CBC/PKCS5Padding");
		variables.cipherXformCurrent = variables.cipherXformFromESAPIProp;
    }

    public string function getApplicationName() {
    	return getProperty("Logger.ApplicationName", getApplicationMetaData().name);
    }

    public string function getLogImplementation() {
    	return getProperty("ESAPI.Logger", "org.owasp.esapi.reference.LogFactory");
    }

    public string function getAuthenticationImplementation() {
    	return getProperty("ESAPI.Authenticator", "org.owasp.esapi.reference.Authenticator");
    }

    public string function getEncoderImplementation() {
    	return getProperty("ESAPI.Encoder", "org.owasp.esapi.reference.Encoder");
    }

    public string function getAccessControlImplementation() {
    	return getProperty("ESAPI.AccessControl", "org.owasp.esapi.reference.AccessController");
    }

    public string function getEncryptionImplementation() {
    	return getProperty("ESAPI.Encryptor", "org.owasp.esapi.reference.Encryptor");
    }

    public string function getIntrusionDetectionImplementation() {
    	return getProperty("ESAPI.IntrusionDetector", "org.owasp.esapi.reference.IntrusionDetector");
    }

    public string function getRandomizerImplementation() {
    	return getProperty("ESAPI.Randomizer", "org.owasp.esapi.reference.Randomizer");
    }

    public string function getExecutorImplementation() {
    	return getProperty("ESAPI.Executor", "org.owasp.esapi.reference.Executor");
    }

    public string function getHTTPUtilitiesImplementation() {
    	return getProperty("ESAPI.HTTPUtilities", "org.owasp.esapi.reference.HTTPUtilities");
    }

    public string function getValidationImplementation() {
    	return getProperty("ESAPI.Validator", "org.owasp.esapi.reference.Validator");
    }

    public string function getResourceImplementation() {
    	return getProperty("ESAPI.Resource", "org.owasp.esapi.reference.ResourceFactory");
    }

    public binary function getMasterKey() {
    	var key = getPropertyEncoded("Encryptor.MasterKey");
    	if (isNull(key) || arrayLen(key) == 0 ) {
    		raiseException(new ConfigurationException("Property 'Encryptor.MasterKey' missing or empty in configuration."));
   		}
    	return key;
    }

    public numeric function getEncryptionKeyLength() {
    	return getProperty("Encryptor.EncryptionKeyLength", 128);
    }

    public binary function getMasterSalt() {
    	var salt = getPropertyEncoded("Encryptor.MasterSalt");
    	if (isNull(salt) || arrayLen(salt) == 0 ) {
    		raiseException(new ConfigurationException("Property 'Encryptor.MasterSalt' missing or empty in configuration."));
    	}
    	return salt;
    }

	public array function getAllowedExecutables() {
    	var def = [];
        var exList = getProperty("Executor.ApprovedExecutables", def);
        return exList;
    }

	public array function getAllowedFileExtensions() {
    	var def = [".zip",".pdf",".tar",".gz",".xls",".properties",".txt",".xml"];
        var extList = getProperty("HttpUtilities.ApprovedUploadExtensions", def);
        return extList;
    }

    public numeric function getAllowedFileUploadSize() {
        return getProperty("HttpUtilities.MaxUploadFileBytes", 5000000);
    }



	private void function loadConfiguration(struct configuration, struct parent=variables.properties) {
		if (structKeyExists(arguments, "configuration")) {
			// merge provided properties with default properties
			for (var key in arguments.configuration) {
				if (isStruct(arguments.configuration[key])) {
					loadConfiguration(arguments.configuration[key], arguments.parent[key]);
				}
				else {
					arguments.parent[key] = arguments.configuration[key];
				}
			}
		}
	}

    /**
     * Used to log errors to the console during the loading of the properties file itself. Can't use
     * standard logging in this case, since the Logger may not be initialized yet. Output is sent to
     * {@code PrintStream} {@code variables.System.out}.
     *
     * @param message The message to send to the console.
     * @param e The error that occurred. (This value printed via {@code e.toString()}.)
     */
    private void function logSpecial(required string message, ex) {
    	var msg = createObject("java", "java.lang.StringBuffer").init(arguments.message);
    	if (structKeyExists(arguments, "ex")) {
    		msg.append(" Exception was: ").append(toString(arguments.ex));
    	}
		createObject("java", "java.lang.System").out.println(msg.toString());
		// if ( e != null) e.printStackTrace();		// TODO ??? Do we want this?
    }

    public string function getPasswordParameterName() {
        return getProperty("Authenticator.PasswordParameterName", "password");
    }

    public string function getUsernameParameterName() {
        return getProperty("Authenticator.UsernameParameterName", "username");
    }

    public string function getEncryptionAlgorithm() {
        return getProperty("Encryptor.EncryptionAlgorithm", "AES");
    }

    public string function getCipherTransformation() {
    	if (isNull(variables.cipherXformCurrent)) {
    		raiseException(createObject("java", "java.lang.RuntimeException").init("Current cipher transformation is null"));
    	}
    	return variables.cipherXformCurrent;
    }

    public string function setCipherTransformation(required string cipherXform) {
    	var previous = getCipherTransformation();
    	if (isNull(arguments.cipherXform) || trim(arguments.cipherXform) == "") {
    		// Special case... means set it to original value from ESAPI.properties
    		variables.cipherXformCurrent = variables.cipherXformFromESAPIProp;
    	}
    	else {
    		variables.cipherXformCurrent = arguments.cipherXform;	// Note: No other sanity checks!!!
    	}
    	return previous;
    }

    public boolean function useMACforCipherText() {
    	return getProperty("Encryptor.CipherText.useMAC", true);
    }

    public boolean function overwritePlainText() {
    	return getProperty("Encryptor.PlainText.overwrite", true);
    }

    public string function getIVType() {
    	var value = getProperty("Encryptor.ChooseIVMethod", "random");
    	if ( value.equalsIgnoreCase("fixed") || value.equalsIgnoreCase("random") ) {
    		return value;
    	} else if ( value.equalsIgnoreCase("specified") ) {
    		// This is planned for future implementation where setting
    		// Encryptor.ChooseIVMethod=specified   will require setting some
    		// other TBD property that will specify an implementation class that
    		// will generate appropriate IVs. The intent of this would be to use
    		// such a class with various feedback modes where it is imperative
    		// that for a given key, any particular IV is *NEVER* reused. For
    		// now, we will assume that generating a random IV is usually going
    		// to be sufficient to prevent this.
    		raiseException(new ConfigurationException("'Encryptor.ChooseIVMethod=specified' is not yet implemented. Use 'fixed' or 'random'"));
    	} else {
    		// TODO: Once 'specified' is legal, adjust exception msg, below.
    		// DISCUSS: Could just log this and then silently return "random" instead.
    		raiseException(new ConfigurationException(value & " is illegal value for Encryptor.ChooseIVMethod. Use 'random' (preferred) or 'fixed'."));
    	}
    }

    public string function getFixedIV() {
    	if ( getIVType().equalsIgnoreCase("fixed") ) {
    		var ivAsHex = getProperty("Encryptor.fixedIV", ""); // No default
    		if ( isNull(ivAsHex) || ivAsHex.trim() == "" ) {
    			raiseException(new ConfigurationException("Fixed IV requires property Encryptor.fixedIV to be set, but it is not."));
    		}
    		return ivAsHex;		// We do no further checks here as we have no context.
    	} else {
    		// DISCUSS: Should we just log a warning here and return null instead?
    		//			If so, may cause NullPointException somewhere later.
    		raiseException(new ConfigurationException("IV type not 'fixed' (set to '" & getIVType() & "'), so no fixed IV applicable."));
    	}
    }

    public string function getHashAlgorithm() {
        return getProperty("Encryptor.HashAlgorithm", "SHA-512");
    }

    public numeric function getHashIterations() {
    	return getProperty("Encryptor.HashIterations", 1024);
    }

	public string function getKDFPseudoRandomFunction() {
		return getProperty("Encryptor.KDF.PRF", "HmacSHA256");  // NSA recommended SHA2 or better.
	}

    public string function getCharacterEncoding() {
        return getProperty("Encryptor.CharacterEncoding", "UTF-8");
    }

	public boolean function getAllowMultipleEncoding() {
		return getProperty( "Encoder.AllowMultipleEncoding", false );
	}

	public boolean function getAllowMixedEncoding() {
		return getProperty( "Encoder.AllowMixedEncoding", false );
	}

	public array function getDefaultCanonicalizationCodecs() {
		var def = [];
		arrayAppend(def, "org.owasp.esapi.codecs.HTMLEntityCodec");
		arrayAppend(def, "org.owasp.esapi.codecs.PercentCodec");
		arrayAppend(def, "org.owasp.esapi.codecs.JavaScriptCodec");
		return getProperty("Encoder.DefaultCodecList", def);
	}

    public string function getDigitalSignatureAlgorithm() {
        return getProperty("Encryptor.DigitalSignatureAlgorithm", "SHAwithDSA");
    }

    public numeric function getDigitalSignatureKeyLength() {
        return getProperty("Encryptor.DigitalSignatureKeyLength", 1024);
    }

    public string function getRandomAlgorithm() {
        return getProperty("Encryptor.RandomAlgorithm", "SHA1PRNG");
    }

    public numeric function getAllowedLoginAttempts() {
        return getProperty("Authenticator.AllowedLoginAttempts", 5);
    }

    public numeric function getMaxOldPasswordHashes() {
        return getProperty("Authenticator.MaxOldPasswordHashes", 12);
    }

    public string function getUploadDirectory() {
    	return getProperty( "HttpUtilities.UploadDir", getTempDirectory());
    }

    public string function getUploadTempDirectory() {
    	return getProperty("HttpUtilities.UploadTempDir", getTempDirectory());
    }

	public boolean function getDisableIntrusionDetection() {
		return getProperty("IntrusionDetector.Disable", false);
	}

	public function getQuota(required string eventName) {
        var count = getProperty("IntrusionDetector." & arguments.eventName & ".count", 0);
        var interval = getProperty("IntrusionDetector." & arguments.eventName & ".interval", 0);
        var actions = [];
        var actionString = getProperty("IntrusionDetector." & arguments.eventName & ".actions", "");
        if (len(actionString)) {
            actions = listToArray(actionString);
        }
        if ( count > 0 && interval > 0 && arrayLen(actions) > 0 ) {
        	return createObject("java", "org.owasp.esapi.SecurityConfiguration$Threshold").init(javaCast("string", arguments.eventName), javaCast("int", count), javaCast("long", interval), actions);
        }
        return;
    }


    public numeric function getLogLevel() {
        var level = getProperty("Logger.LogLevel", "WARNING" );

        if (level.equalsIgnoreCase("OFF"))
            return 2147483647; //Logger.OFF;
        if (level.equalsIgnoreCase("FATAL"))
            return 1000; //Logger.FATAL;
        if (level.equalsIgnoreCase("ERROR"))
            return 800; //Logger.ERROR ;
        if (level.equalsIgnoreCase("WARNING"))
            return 600; //Logger.WARNING;
        if (level.equalsIgnoreCase("INFO"))
            return 400; //Logger.INFO;
        if (level.equalsIgnoreCase("DEBUG"))
            return 200; //Logger.DEBUG;
        if (level.equalsIgnoreCase("TRACE"))
            return 100; //Logger.TRACE;
        if (level.equalsIgnoreCase("ALL"))
            return -2147483648; //Logger.ALL;

		// This error is NOT logged the normal way because the logger constructor calls getLogLevel() and if this error occurred it would cause
		// an infinite loop.
        logSpecial("The LOG-LEVEL property in the ESAPI properties file has the unrecognized value: " & level & ". Using default: WARNING");
        return 600; //Logger.WARNING;  // Note: The default logging level is WARNING.
    }

    public string function getLogFileName() {
    	return getProperty( "Logger.LogFileName", "ESAPI_logging_file" );
    }

    public boolean function getLogEncodingRequired() {
    	return getProperty("Logger.LogEncodingRequired", false);
	}

    public boolean function getLogApplicationName() {
    	return getProperty("Logger.LogApplicationName", true);
	}

    public boolean function getLogServerIP() {
    	return getProperty("Logger.LogServerIP", true);
	}

    public boolean function getForceHttpOnlySession() {
    	return getProperty( "HttpUtilities.ForceHttpOnlySession", true );
    }

    public boolean function getForceSecureSession() {
    	return getProperty( "HttpUtilities.SecureSession", true );
    }

    public boolean function getForceHttpOnlyCookies() {
    	return getProperty( "HttpUtilities.ForceHttpOnlyCookies", true );
    }

    public boolean function getForceSecureCookies() {
    	return getProperty( "HttpUtilities.ForceSecureCookies", true );
    }

	public numeric function getMaxHttpHeaderSize() {
        return getProperty( "HttpUtilities.MaxHeaderSize", 4096 );
	}

	public string function getResponseContentType() {
        return getProperty( "HttpUtilities.ResponseContentType", "text/html; charset=UTF-8" );
    }

	public string function getHttpSessionIdName() {
        return getProperty( "HttpUtilities.HttpSessionIdName", "JSESSIONID" );
    }

    public numeric function getRememberTokenDuration() {
        var days = getProperty( "Authenticator.RememberTokenDuration", 14 );
        return 1000 * 60 * 60 * 24 * days;
    }

	public numeric function getSessionIdleTimeoutLength() {
        var minutes = getProperty( "Authenticator.IdleTimeoutDuration", 20 );
        return 1000 * 60 * minutes;
	}

	public numeric function getSessionAbsoluteTimeoutLength() {
        var minutes = getProperty("Authenticator.AbsoluteTimeoutDuration", 20 );
        return 1000 * 60 * minutes;
	}

   /**
    * getValidationPattern returns a single pattern based upon key
    *
    *  @param key
    *  			validation pattern name you'd like
    *  @return
    *  			if key exists, the associated validation pattern, null otherwise
	*/
    public function getValidationPattern(required string key) {
    	var value = getProperty("Validator.Patterns." & arguments.key, "");
    	// check cache
    	var p = "";
    	if (structKeyExists(variables.patternCache, value)) {
    		p = variables.patternCache[value];
    	}
    	if (isObject(p)) return p;

    	// compile a new pattern
    	if (!isDefined("value") || value == "") return;
    	try {
    		var q = createObject("java", "java.util.regex.Pattern").compile(value);
    		variables.patternCache.put(value, q);
    		return q;
    	}
    	catch (java.util.regex.PatternSyntaxException ex) {
    		logSpecial("SecurityConfiguration for " & arguments.key & " not a valid regex. Returning null");
    		return;
    	}
    }

    /**
     * getWorkingDirectory returns the default directory where processes will be executed
     * by the Executor.
     */
	public function getWorkingDirectory() {
		var dir = getProperty( "Executor.WorkingDirectory", createObject("java", "java.lang.System").getProperty( "user.dir") );
		if ( !isNull(dir) ) {
			return new File( dir );
		}
		return null;
	}

	public string function getPreferredJCEProvider() {
	    return getProperty("Encryptor.PreferredJCEProvider", ""); // No default!
	}

	public array function getCombinedCipherModes() {
	    var empty = [];     // Default is empty list
	    return getProperty("Encryptor.cipher_modes.combined_modes", empty);
	}

	public array function getAdditionalAllowedCipherModes() {
	    var empty = [];     // Default is empty list
	    return getProperty("Encryptor.cipher_modes.additional_allowed", empty);
	}

	public boolean function getLenientDatesAccepted() {
		return getProperty( "Validator.AcceptLenientDates", false);
	}

	/**
     * Returns a property representing the parsed setting.
     *
	 * @param key  The specified property name
	 * @param def  A default value for the property name to return if the property is not set.
	 */
	private function getProperty(required string key, required def) {
		var parsedKey = "[" & chr(34) & replace(arguments.key, ".", chr(34) & "][" & chr(34), "all") & chr(34) & "]";
		var property = "";
		try {
			property = evaluate("variables.properties" & parsedKey);
		}
		catch (expression e) {}
		if (isNull(property)) {
    		logSpecial("SecurityConfiguration for " & arguments.key & " not found. Using default: " & arguments.def);
    		return arguments.def;
		}

		// numeric
		if (isNumeric(arguments.def)) {
			try {
	            return val(property);
			}
			catch (NumberFormatException ex) {
	    		logSpecial("SecurityConfiguration for " & arguments.key & " not an integer. Using default: " & arguments.def);
				return arguments.def;
			}
		}

		// boolean
		else if (isBoolean(arguments.def)) {
			if (property == "true" || property == "yes") {
				return true;
			}
			if (property == "false" || property == "no") {
				return false;
			}
			logSpecial("SecurityConfiguration for " & arguments.key & " not either ""true"" or ""false"". Using default: " & arguments.def);
			return arguments.def;
		}

		// list
		else if (isArray(arguments.def)) {
			if (isArray(property)) {
				return property;
			}
		    return listToArray(property);
		}

		// string
		else if (isSimpleValue(arguments.def)) {
			return property;
		}

	}

	private binary function getPropertyEncoded(required string key, binary def) {
		var parsedKey = "[" & chr(34) & replace(arguments.key, ".", chr(34) & "][" & chr(34), "all") & chr(34) & "]";
		var property = "";
		try {
			property = evaluate("variables.properties" & parsedKey);
		}
		catch (expression e) {}
		if (isNull(property)) {
    		logSpecial("SecurityConfiguration for " & arguments.key & " not found. Using default: " & arguments.def);
    		return arguments.def;
		}
        try {
            return variables.ESAPI.encoder().decodeFromBase64(property);
        }
        catch (java.io.IOException ex) {
    		logSpecial("SecurityConfiguration for " & arguments.key & " not properly Base64 encoded. Using default: " & arguments.def);
            return;
        }
	}

	public function getResourceFile(required string filename) {
		var fileSeparator = createObject("java", "java.io.File").separator;

		logSpecial("Attempting to load " & arguments.filename & " via file io.");

		if(arguments.filename == "") {
			logSpecial("Failed to load properties via FileIO. Filename is empty.");
			return "";// not found.
		}

		// check specific setting first
		// (this defaults to SystemResource directory/RESOURCE_FILE)
		if(len(trim(variables.resourceDirectory))) {
			var fileLocation = expandPath(variables.resourceDirectory & fileSeparator & arguments.filename);
			if(fileExists(fileLocation)) {
				var f = createObject("java", "java.io.File").init(fileLocation);
				if(f.exists()) {
					logSpecial("Found in SystemResource Directory/resourceDirectory: " & f.getAbsolutePath());
					return f;
				}
				else {
					logSpecial("Not found in SystemResource Directory/resourceDirectory (this should never happen): " & f.getAbsolutePath());
				}
			}
			else {
				logSpecial("Not found in SystemResource Directory/resourceDirectory: " & fileLocation);
			}
		}

		// falls back on unit test resources location
		// NEVER allow this to occur in an actual application
		var fileLocation = expandPath(fileSeparator & "test" & fileSeparator & "resources" & fileSeparator & arguments.filename);
		if(fileExists(fileLocation)) {
			var f = createObject("java", "java.io.File").init(fileLocation);
			if(f.exists()) {
				logSpecial("UNIT TESTING ONLY: Found in Default Directory/resourceDirectory: " & f.getAbsolutePath());
				variables.resourceDirectory = fileSeparator & "test" & fileSeparator & "resources";
				return f;
			}
			else {
				logSpecial("UNIT TESTING ONLY: Not found in Default Directory/resourceDirectory (this should never happen): " & f.getAbsolutePath());
			}
		}
		else {
			logSpecial("UNIT TESTING ONLY: Not found in Default Directory/resourceDirectory: " & fileLocation);
		}

		// return empty if not found
		return "";
	}

	public boolean function isJavaEncoderPreferred() {
		return getProperty( "Encoder.isJavaEncoderPreferred", false );
	}

	public string function getUnsafeCookieMode() {
		return getProperty( "HttpUtilities.UnsafeCookieMode", "log" );
	}

	public string function getAntiSamyPolicyFile() {
		return getProperty("Validator.AntiSamyPolicyFile", expandPath("/org/owasp/esapi/conf/antisamy-esapi.xml"));
	}

	public string function getUserSessionKey() {
		return getProperty("Authenticator.UserSessionKey", "ESAPIUserSessionKey");
	}

	public string function getAccountNameLengthMax() {
		return getProperty("Authenticator.AccountNameLengthMax", 254);
	}

}
