<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.SecurityConfiguration" output="false">

	<cfscript>
		instance.ESAPI = "";

		instance.properties = "";
		instance.cipherXformFromESAPIProp = "";	// New in ESAPI 2.0
		instance.cipherXformCurrent = "";		// New in ESAPI 2.0

		/* The name of the ESAPI property file */
		static.RESOURCE_FILE = "ESAPI.properties";

		this.REMEMBER_TOKEN_DURATION = "Authenticator.RememberTokenDuration";
	    this.IDLE_TIMEOUT_DURATION = "Authenticator.IdleTimeoutDuration";
	    this.ABSOLUTE_TIMEOUT_DURATION = "Authenticator.AbsoluteTimeoutDuration";
	    this.ALLOWED_LOGIN_ATTEMPTS = "Authenticator.AllowedLoginAttempts";
	    this.USERNAME_PARAMETER_NAME = "Authenticator.UsernameParameterName";
	    this.PASSWORD_PARAMETER_NAME = "Authenticator.PasswordParameterName";
	    this.MAX_OLD_PASSWORD_HASHES = "Authenticator.MaxOldPasswordHashes";

		this.ALLOW_MULTIPLE_ENCODING = "Encoder.AllowMultipleEncoding";
    	this.CANONICALIZATION_CODECS = "Encoder.DefaultCodecList";

		this.DISABLE_INTRUSION_DETECTION = "IntrusionDetector.Disable";

		this.MASTER_KEY = "Encryptor.MasterKey";
	    this.MASTER_SALT = "Encryptor.MasterSalt";
	    this.KEY_LENGTH = "Encryptor.EncryptionKeyLength";
	    this.ENCRYPTION_ALGORITHM = "Encryptor.EncryptionAlgorithm";
	    this.HASH_ALGORITHM = "Encryptor.HashAlgorithm";
	    this.HASH_ITERATIONS = "Encryptor.HashIterations";
	    this.CHARACTER_ENCODING = "Encryptor.CharacterEncoding";
	    this.RANDOM_ALGORITHM = "Encryptor.RandomAlgorithm";
	    this.DIGITAL_SIGNATURE_ALGORITHM = "Encryptor.DigitalSignatureAlgorithm";
	    this.DIGITAL_SIGNATURE_KEY_LENGTH = "Encryptor.DigitalSignatureKeyLength";
		// New in ESAPI Java 2.0
		this.PREFERRED_JCE_PROVIDER = "Encryptor.PreferredJCEProvider";
	    this.CIPHERTEXT_USE_MAC = "Encryptor.CipherText.useMAC";
	    this.PLAINTEXT_OVERWRITE = "Encryptor.PlainText.overwrite";
	    this.IV_TYPE = "Encryptor.ChooseIVMethod";
	    this.FIXED_IV = "Encryptor.fixedIV";
	    this.COMBINED_CIPHER_MODES = "Encryptor.cipher_modes.combined_modes";
	    this.ADDITIONAL_ALLOWED_CIPHER_MODES = "Encryptor.cipher_modes.additional_allowed";

		this.WORKING_DIRECTORY = "Executor.WorkingDirectory";
    	this.APPROVED_EXECUTABLES = "Executor.ApprovedExecutables";

    	this.FORCE_HTTPONLYSESSION = "HttpUtilities.ForceHttpOnlySession";
	    this.FORCE_SECURESESSION = "HttpUtilities.SecureSession";
	    this.FORCE_HTTPONLYCOOKIES = "HttpUtilities.ForceHttpOnlyCookies";
	    this.FORCE_SECURECOOKIES = "HttpUtilities.ForceSecureCookies";
		this.MAX_HTTP_HEADER_SIZE = "HttpUtilities.MaxHeaderSize";
	    this.UPLOAD_DIRECTORY = "HttpUtilities.UploadDir";
	    this.UPLOAD_TEMP_DIRECTORY = "HttpUtilities.UploadTempDir";
	    this.APPROVED_UPLOAD_EXTENSIONS = "HttpUtilities.ApprovedUploadExtensions";
	    this.MAX_UPLOAD_FILE_BYTES = "HttpUtilities.MaxUploadFileBytes";
	    this.RESPONSE_CONTENT_TYPE = "HttpUtilities.ResponseContentType";

		this.APPLICATION_NAME = "Logger.ApplicationName";
	    this.LOG_LEVEL = "Logger.LogLevel";
	    this.LOG_FILE_NAME = "Logger.LogFileName";
	    this.MAX_LOG_FILE_SIZE = "Logger.MaxLogFileSize";
	    this.LOG_ENCODING_REQUIRED = "Logger.LogEncodingRequired";
	    this.LOG_APPLICATION_NAME = "Logger.LogApplicationName";
	    this.LOG_SERVER_IP = "Logger.LogServerIP";
	    this.VALIDATION_PROPERTIES = "Validator.ConfigurationFile";

		/*
		 * The default max log file size is set to 10,000,000 bytes (10 Meg). If the current log file exceeds the current
		 * max log file size, the logger will move the old log data into another log file. There currently is a max of
		 * 1000 log files of the same name. If that is exceeded it will presumably start discarding the oldest logs.
		 */
		this.DEFAULT_MAX_LOG_FILE_SIZE = 10000000;
	    //this.MAX_REDIRECT_LOCATION = 1000;
	    //this.MAX_FILE_NAME_LENGTH = 1000;

		/* Implementation Keys */
		this.LOG_IMPLEMENTATION = "ESAPI.Logger";
	    this.AUTHENTICATION_IMPLEMENTATION = "ESAPI.Authenticator";
	    this.ENCODER_IMPLEMENTATION = "ESAPI.Encoder";
	    this.ACCESS_CONTROL_IMPLEMENTATION = "ESAPI.AccessControl";
	    this.ENCRYPTION_IMPLEMENTATION = "ESAPI.Encryptor";
	    this.INTRUSION_DETECTION_IMPLEMENTATION = "ESAPI.IntrusionDetector";
	    this.RANDOMIZER_IMPLEMENTATION = "ESAPI.Randomizer";
		this.EXECUTOR_IMPLEMENTATION = "ESAPI.Executor";
		this.VALIDATOR_IMPLEMENTATION = "ESAPI.Validator";
		this.HTTP_UTILITIES_IMPLEMENTATION = "ESAPI.HTTPUtilities";
		// New in ESAPI Java 2.0
		// Not implementation classes!!!
		this.PRINT_PROPERTIES_WHEN_LOADED = "ESAPI.printProperties";
	    this.CIPHER_TRANSFORMATION_IMPLEMENTATION = "Encryptor.CipherTransformation";

		/* Default Implementations */
	    this.DEFAULT_LOG_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.JavaLogFactory";
	    this.DEFAULT_AUTHENTICATION_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.FileBasedAuthenticator";
	    this.DEFAULT_ENCODER_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.DefaultEncoder";
	    this.DEFAULT_ACCESS_CONTROL_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.accesscontrol.DefaultAccessController";
	    this.DEFAULT_ENCRYPTION_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.JavaEncryptor";
	    this.DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.DefaultIntrusionDetector";
	    this.DEFAULT_RANDOMIZER_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.DefaultRandomizer";
	    this.DEFAULT_EXECUTOR_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.DefaultExecutor";
	    this.DEFAULT_HTTP_UTILITIES_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.DefaultHTTPUtilities";
	    this.DEFAULT_VALIDATOR_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.DefaultValidator";

		instance.patternCache = {};

	    /*
	     * Relative path to the resourceDirectory. Relative to the classpath.
	     * Specifically, ClassLoader.getResource(resourceDirectory + filename) will be used to load the file.
	     */
	    instance.resourceDirectory = "/cfesapi/esapi/configuration/.esapi";
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.SecurityConfiguration" name="init" output="false" hint="Instantiates a new configuration with the optional supplied properties.">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="any" name="properties" required="false" hint="java.util.Properties">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			if (structKeyExists(arguments, "properties")) {
				instance.properties = arguments.properties;
				setCipherXProperties();
			}
			else {
				// load security configuration
		    	try {
		        	loadConfiguration();
		        	setCipherXProperties();
		        } catch( java.io.IOException e ) {
			        logSpecial("Failed to load security configuration", e );
		        }
			}

	        return this;
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="void" name="setCipherXProperties" output="false">
		<cfscript>
			// TODO: FUTURE: Replace by CryptoControls ???
			// See SecurityConfiguration.setCipherTransformation() for explanation of this.
	        // (Propose this in 2.1 via future email to ESAPI-DEV list.)
			instance.cipherXformFromESAPIProp = getESAPIProperty(this.CIPHER_TRANSFORMATION_IMPLEMENTATION, "AES/CBC/PKCS5Padding");
			instance.cipherXformCurrent = instance.cipherXformFromESAPIProp;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getApplicationName" output="false">
		<cfscript>
    		return getESAPIProperty(this.APPLICATION_NAME, "DefaultName");
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getLogImplementation" output="false">
		<cfscript>
    		return getESAPIProperty(this.LOG_IMPLEMENTATION, this.DEFAULT_LOG_IMPLEMENTATION);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getAuthenticationImplementation" output="false">
		<cfscript>
    		return getESAPIProperty(this.AUTHENTICATION_IMPLEMENTATION, this.DEFAULT_AUTHENTICATION_IMPLEMENTATION);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getEncoderImplementation" output="false">
		<cfscript>
			return getESAPIProperty(this.ENCODER_IMPLEMENTATION, this.DEFAULT_ENCODER_IMPLEMENTATION);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getAccessControlImplementation" output="false">
		<cfscript>
    		return getESAPIProperty(this.ACCESS_CONTROL_IMPLEMENTATION, this.DEFAULT_ACCESS_CONTROL_IMPLEMENTATION);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getEncryptionImplementation" output="false">
		<cfscript>
    		return getESAPIProperty(this.ENCRYPTION_IMPLEMENTATION, this.DEFAULT_ENCRYPTION_IMPLEMENTATION);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getIntrusionDetectionImplementation" output="false">
		<cfscript>
    		return getESAPIProperty(this.INTRUSION_DETECTION_IMPLEMENTATION, this.DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getRandomizerImplementation" output="false">
		<cfscript>
    		return getESAPIProperty(this.RANDOMIZER_IMPLEMENTATION, this.DEFAULT_RANDOMIZER_IMPLEMENTATION);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getExecutorImplementation" output="false">
		<cfscript>
    		return getESAPIProperty(this.EXECUTOR_IMPLEMENTATION, this.DEFAULT_EXECUTOR_IMPLEMENTATION);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getHTTPUtilitiesImplementation" output="false">
		<cfscript>
    		return getESAPIProperty(this.HTTP_UTILITIES_IMPLEMENTATION, this.DEFAULT_HTTP_UTILITIES_IMPLEMENTATION);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidationImplementation" output="false">
		<cfscript>
    		return getESAPIProperty(this.VALIDATOR_IMPLEMENTATION, this.DEFAULT_VALIDATOR_IMPLEMENTATION);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="binary" name="getMasterKey" output="false">
		<cfscript>
	    	local.key = getESAPIPropertyEncoded( this.MASTER_KEY, toBinary("") );
	    	if ( isNull(local.key) || len(local.key) == 0 ) {
	    		cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ConfigurationException").init(instance.ESAPI, "Property '" & this.MASTER_KEY & "' missing or empty in ESAPI.properties file.");
           		throw(message=cfex.getMessage(), type=cfex.getType());
	    	}
	    	return local.key;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getResourceDirectory" output="false">
		<cfscript>
			return instance.resourceDirectory;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setResourceDirectory" output="false">
		<cfargument type="String" name="dir" required="true">
		<cfscript>
	    	instance.resourceDirectory = dir;
	        logSpecial( "Reset resource directory to: " & arguments.dir, "" );

	        // reload configuration if necessary
	    	try {
	    		loadConfiguration();
	    	} catch( java.io.IOException e ) {
		        logSpecial("Failed to load security configuration from " & arguments.dir, e);
	    	}
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getEncryptionKeyLength" output="false">
		<cfscript>
    		return getESAPIProperty(this.KEY_LENGTH, 128 );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="binary" name="getMasterSalt" output="false">
		<cfscript>
	    	local.salt = getESAPIPropertyEncoded( this.MASTER_SALT, toBinary("") );
	    	if ( isNull(local.salt) || len(local.salt) == 0 ) {
	    		cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ConfigurationException").init(instance.ESAPI, "Property '" & this.MASTER_SALT & "' missing or empty in ESAPI.properties file.");
           		throw(message=cfex.getMessage(), type=cfex.getType());
	    	}
	    	return local.salt;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getAllowedExecutables" output="false">
		<cfscript>
	    	local.def = "";
	        local.exList = getESAPIProperty(this.APPROVED_EXECUTABLES,local.def).split(",");
	        return local.exList;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getAllowedFileExtensions" output="false">
		<cfscript>
	    	local.def = ".zip,.pdf,.tar,.gz,.xls,.properties,.txt,.xml";
	        local.extList = getESAPIProperty(this.APPROVED_UPLOAD_EXTENSIONS, local.def);
	        return listToArray(local.extList);
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getAllowedFileUploadSize" output="false">
		<cfscript>
       		return getESAPIProperty(this.MAX_UPLOAD_FILE_BYTES, 5000000);
    	</cfscript>
	</cffunction>


	<cffunction access="private" returntype="any" name="loadPropertiesFromStream" output="false" hint="java.util.Properties">
		<cfargument type="any" name="is" required="true" hint="java.io.InputStream">
		<cfargument type="String" name="name" required="true">
		<cfscript>
	    	local.config = createObject("java", "java.util.Properties").init();
	        try {
		        config.load(arguments.is);
		        logSpecial("Loaded '" & arguments.name & "' properties file");
	        } finally {
	            if ( !isNull(arguments.is) ) try { arguments.is.close(); } catch( Exception e ) {}
	        }
	        return config;
        </cfscript>
	</cffunction>


	<cffunction access="private" returntype="void" name="loadConfiguration" output="false" hint="Load configuration. Never prints properties.">
		<cfscript>
			try {
			    //first attempt file IO loading of properties
				logSpecial("Attempting to load " & static.RESOURCE_FILE & " via file io.");
				instance.properties = loadPropertiesFromStream(getResourceStream(static.RESOURCE_FILE), static.RESOURCE_FILE);

			} catch (Exception iae) {
			    //if file io loading fails, attempt classpath based loading next
			    logSpecial("Loading " & static.RESOURCE_FILE & " via file io failed.");
				logSpecial("Attempting to load " & static.RESOURCE_FILE & " via the classpath.");
				try {
					instance.properties = loadConfigurationFromClasspath(static.RESOURCE_FILE);
				} catch (Exception e) {
					logSpecial(static.RESOURCE_FILE & " could not be loaded by any means. fail.", e);
				}
			}

			// if properties loaded properly above, get validation properties and merge them into the main properties
			if (!isNull(instance.properties)) {

				local.validationPropFileName = getESAPIProperty(this.VALIDATION_PROPERTIES, "validation.properties");
				local.validationProperties = "";

				try {
				    //first attempt file IO loading of properties
					logSpecial("Attempting to load " & validationPropFileName & " via file io.");
					validationProperties = loadPropertiesFromStream(getResourceStream(validationPropFileName), validationPropFileName);

				} catch (Exception iae) {
				    //if file io loading fails, attempt classpath based loading next
				    logSpecial("Loading " & validationPropFileName & " via file io failed.");
					logSpecial("Attempting to load " & validationPropFileName & " via the classpath.");
					try {
						validationProperties = loadConfigurationFromClasspath(validationPropFileName);
					} catch (Exception e) {
						logSpecial(validationPropFileName & " could not be loaded by any means. fail.", e);
					}
				}

				if (!isNull(validationProperties)) {
			    	local.i = validationProperties.keySet().iterator();
			    	while( local.i.hasNext() ) {
			    		local.key = local.i.next();
			    		local.value = validationProperties.getProperty(local.key);
			    		instance.properties.put( local.key, local.value);
			    	}
				}

		        if ( shouldPrintProperties() ) {

		    	//FIXME - make this chunk configurable
		    	/*
		        logSpecial("  ========Master Configuration========", null);
		        //logSpecial( "  ResourceDirectory: " + DefaultSecurityConfiguration.resourceDirectory );
		        Iterator j = new TreeSet( instance.properties.keySet() ).iterator();
		        while (j.hasNext()) {
		            String key = (String)j.next();
		            // print out properties, but not sensitive ones like MasterKey and MasterSalt
		            if ( !key.contains( "Master" ) ) {
		            		logSpecial("  |   " + key + "=" + instance.properties.get(key), null);
		        	}
		        }
		        */

		        }
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getResourceStream" output="false" hint="java.io.InputStream: An InputStream associated with the specified file name as a resource stream.">
		<cfargument type="String" name="filename" required="true">
		<cfscript>
			if (isNull(arguments.filename)) {
				return "";
			}

			try {
				local.f = getResourceFile(arguments.filename);
				if (!isNull(local.f) && local.f.exists()) {
					return createObject("java", "java.io.FileInputStream").init(local.f);
				}
			} catch (java.lang.Exception e) {
			}

			throw("File '" & arguments.filename & "' could not be found.", "FileNotFoundException");
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getResourceFile" output="false" hint="java.io.File">
		<cfargument type="String" name="filename" required="true">
		<cfscript>
			logSpecial("Attempting to load " & filename & " via file io.");

			if (isNull(filename)) {
				logSpecial("Failed to load properties via FileIO. Filename is null.");
				return ""; // not found.
			}

			local.f = "";

			// programatically set resource directory
			// (this defaults to SystemResource directory/RESOURCE_FILE
			local.fileUrl = instance.resourceDirectory & "/" & filename;
			if (!isNull(local.fileUrl)) {
				local.fileLocation = expandPath(local.fileUrl);
				writelog(local.fileLocation);
				local.f = createObject("java", "java.io.File").init(local.fileLocation);
				if (local.f.exists()) {
					logSpecial("Found in SystemResource Directory/resourceDirectory: " & local.f.getAbsolutePath());
					return local.f;
				} else {
					logSpecial("Not found in SystemResource Directory/resourceDirectory (this should never happen): " & local.f.getAbsolutePath());
				}
			} else {
				logSpecial("Not found in SystemResource Directory/resourceDirectory: " & instance.resourceDirectory & File.separator & filename);
			}
		</cfscript>
	</cffunction>

	<!--- loadConfigurationFromClasspath --->

	<cffunction access="private" returntype="void" name="logSpecial" output="false" hint="Used to log errors to the console during the loading of the properties file itself. Can't use standard logging in this case, since the Logger is not initialized yet.">
		<cfargument type="String" name="message" required="true" hint="The message to send to the console.">
		<cfscript>
			writeLog(arguments.message);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getPasswordParameterName" output="false">
		<cfscript>
        	return getESAPIProperty(this.PASSWORD_PARAMETER_NAME, "password");
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getUsernameParameterName" output="false">
		<cfscript>
        	return getESAPIProperty(this.USERNAME_PARAMETER_NAME, "username");
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getEncryptionAlgorithm" output="false">
		<cfscript>
        	return getESAPIProperty(this.ENCRYPTION_ALGORITHM, "AES");
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getCipherTransformation" output="false">
		<cfscript>
			if (isNull(instance.cipherXformCurrent)) {
				throw(message="Current cipher transformation is null");
			}
	    	return instance.cipherXformCurrent;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="setCipherTransformation" output="false">
		<cfargument type="String" name="cipherXform" required="true">
		<cfscript>
	    	local.previous = getCipherTransformation();
	    	if ( isNull(arguments.cipherXform) || arguments.cipherXform == "" ) {
	    		// Special case... means set it to original value from ESAPI.properties
	    		instance.cipherXformCurrent = instance.cipherXformFromESAPIProp;
	    	} else {
	    		assert(!cipherXform.trim() == "", "Cipher transformation cannot be just white space or empty string");
	    		instance.cipherXformCurrent = arguments.cipherXform;	// Note: No other sanity checks!!!
	    	}
	    	return local.previous;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="useMACforCipherText" output="false">
		<cfscript>
    		return getESAPIProperty(this.CIPHERTEXT_USE_MAC, true);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="overwritePlainText" output="false">
		<cfscript>
    		return getESAPIProperty(this.PLAINTEXT_OVERWRITE, true);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getIVType" output="false">
		<cfscript>
	    	local.value = getESAPIProperty(this.IV_TYPE, "random");
	    	if ( local.value.equalsIgnoreCase("fixed") || local.value.equalsIgnoreCase("random") ) {
	    		return local.value;
	    	} else if ( local.value.equalsIgnoreCase("specified") ) {
	    		// This is planned for future implementation where setting
	    		// Encryptor.ChooseIVMethod=specified   will require setting some
	    		// other TBD property that will specify an implementation class that
	    		// will generate appropriate IVs. The intent of this would be to use
	    		// such a class with various feedback modes where it is imperative
	    		// that for a given key, any particular IV is *NEVER* reused. For
	    		// now, we will assume that generating a random IV is usually going
	    		// to be sufficient to prevent this.
	    		cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ConfigurationException").init(instance.ESAPI, "'" & this.IV_TYPE & "=specified' is not yet implemented. Use 'fixed' or 'random'");
           		throw(message=cfex.getMessage(), type=cfex.getType());
	    	} else {
	    		// TODO: Once 'specified' is legal, adjust exception msg, below.
	    		// DISCUSS: Could just log this and then silently return "random" instead.
	    		cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ConfigurationException").init(instance.ESAPI, local.value & " is illegal value for " & this.IV_TYPE & ". Use 'random' (preferred) or 'fixed'.");
           		throw(message=cfex.getMessage(), type=cfex.getType());
	    	}
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getFixedIV" output="false">
		<cfscript>
	    	if ( getIVType().equalsIgnoreCase("fixed") ) {
	    		local.ivAsHex = getESAPIProperty(this.FIXED_IV, ""); // No default
	    		if ( isNull(local.ivAsHex) || local.ivAsHex.trim() == "" ) {
	    			cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ConfigurationException").init(instance.ESAPI, "Fixed IV requires property " & this.FIXED_IV & " to be set, but it is not.");
	           		throw(message=cfex.getMessage(), type=cfex.getType());
	    		}
	    		return local.ivAsHex;		// We do no further checks here as we have no context.
	    	} else {
	    		// DISCUSS: Should we just log a warning here and return null instead?
	    		//			If so, may cause NullPointException somewhere later.
	    		cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ConfigurationException").init(instance.ESAPI, "IV type not 'fixed' (set to '" & getIVType() & "'), so no fixed IV applicable.");
           		throw(message=cfex.getMessage(), type=cfex.getType());
	    	}
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getHashAlgorithm" output="false">
		<cfscript>
        	return getESAPIProperty(this.HASH_ALGORITHM, "SHA-512");
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getHashIterations" output="false">
		<cfscript>
    		return getESAPIProperty(this.HASH_ITERATIONS, 1024);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false">
		<cfscript>
			return getESAPIProperty(this.CHARACTER_ENCODING, "UTF-8");
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getAllowMultipleEncoding" output="false">
		<cfscript>
			return getESAPIProperty( this.ALLOW_MULTIPLE_ENCODING, false );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getDefaultCanonicalizationCodecs" output="false">
		<cfscript>
			local.def = [];
			local.def.add( "org.owasp.esapi.codecs.HTMLEntityCodec" );
			local.def.add( "org.owasp.esapi.codecs.PercentCodec" );
			local.def.add( "org.owasp.esapi.codecs.JavaScriptCodec" );
			return getESAPIProperty( this.CANONICALIZATION_CODECS, local.def );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getDigitalSignatureAlgorithm" output="false">
		<cfscript>
        	return getESAPIProperty(this.DIGITAL_SIGNATURE_ALGORITHM, "SHAwithDSA");
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getDigitalSignatureKeyLength" output="false">
		<cfscript>
        	return getESAPIProperty(this.DIGITAL_SIGNATURE_KEY_LENGTH, 1024);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getRandomAlgorithm" output="false">
		<cfscript>
        	return getESAPIProperty(this.RANDOM_ALGORITHM, "SHA1PRNG");
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getAllowedLoginAttempts" output="false">
		<cfscript>
        	return getESAPIProperty(this.ALLOWED_LOGIN_ATTEMPTS, 5);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getMaxOldPasswordHashes" output="false">
		<cfscript>
        	return getESAPIProperty(this.MAX_OLD_PASSWORD_HASHES, 12);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getUploadDirectory" output="false" hint="java.io.File">
		<cfscript>
	    	local.dir = getESAPIProperty( this.UPLOAD_DIRECTORY, "UploadDir");
	    	return createObject("java", "java.io.File").init( local.dir );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getUploadTempDirectory" output="false" hint="java.io.File">
		<cfscript>
	    	local.dir = getESAPIProperty(this.UPLOAD_TEMP_DIRECTORY, System.getProperty("java.io.tmpdir", "UploadTempDir"));
	    	return createObject("java", "java.io.File").init( local.dir );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getDisableIntrusionDetection" output="false">
		<cfscript>
	    	local.value = instance.properties.getProperty( this.DISABLE_INTRUSION_DETECTION );
	    	if (!isNull(local.value) && "true" == local.value) {
				return true;
	    	}
	    	return false;	// Default result
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getQuota" output="false" hint="cfesapi.org.owasp.esapi.reference.Threshold">
		<cfargument type="String" name="eventName" required="true">
		<cfscript>
			local.count = getESAPIProperty("IntrusionDetector." & arguments.eventName & ".count", 0);
			local.interval = getESAPIProperty("IntrusionDetector." & arguments.eventName & ".interval", 0);
			local.actions = [];
			local.actionString = getESAPIProperty("IntrusionDetector." & arguments.eventName & ".actions", "");
			if (!isNull(local.actionString)) {
				local.actions = local.actionString.split(",");
			}
			if ( local.count > 0 && local.interval > 0 && arrayLen(local.actions) > 0 ) {
				return createObject("component", "cfesapi.org.owasp.esapi.reference.Threshold").init(arguments.eventName, local.count, local.interval, local.actions);
			}
			return "";
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getLogLevel" output="false">
		<cfscript>
			Logger = javaLoader().create("org.owasp.esapi.Logger");

	        local.level = getESAPIProperty(this.LOG_LEVEL, "WARNING" );

	        if (local.level.equalsIgnoreCase("OFF"))
	            return Logger.OFF;
	        if (local.level.equalsIgnoreCase("FATAL"))
	            return Logger.FATAL;
	        if (local.level.equalsIgnoreCase("ERROR"))
	            return Logger.ERROR ;
	        if (local.level.equalsIgnoreCase("WARNING"))
	            return Logger.WARNING;
	        if (local.level.equalsIgnoreCase("INFO"))
	            return Logger.INFO;
	        if (local.level.equalsIgnoreCase("DEBUG"))
	            return Logger.DEBUG;
	        if (local.level.equalsIgnoreCase("TRACE"))
	            return Logger.TRACE;
	        if (local.level.equalsIgnoreCase("ALL"))
	            return Logger.ALL;

			// This error is NOT logged the normal way because the logger constructor calls getLogLevel() and if this error occurred it would cause
			// an infinite loop.
	        logSpecial("The LOG-LEVEL property in the ESAPI properties file has the unrecognized value: " & local.level & ". Using default: WARNING");
	        return Logger.WARNING;  // Note: The default logging level is WARNING.
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getLogFileName" output="false">
		<cfscript>
    		return getESAPIProperty( this.LOG_FILE_NAME, "ESAPI_logging_file" );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getMaxLogFileSize" output="false">
		<cfscript>
    		return getESAPIProperty( this.MAX_LOG_FILE_SIZE, this.DEFAULT_MAX_LOG_FILE_SIZE );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getLogEncodingRequired" output="false">
		<cfscript>
    		return getESAPIProperty( this.LOG_ENCODING_REQUIRED, false );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getLogApplicationName" output="false">
		<cfscript>
    		return getESAPIProperty( this.LOG_APPLICATION_NAME, true );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getLogServerIP" output="false">
		<cfscript>
    		return getESAPIProperty( this.LOG_SERVER_IP, true );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getForceHttpOnlySession" output="false">
		<cfscript>
    		return getESAPIProperty( this.FORCE_HTTPONLYSESSION, true );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getForceSecureSession" output="false">
		<cfscript>
    		return getESAPIProperty( this.FORCE_SECURESESSION, true );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getForceHttpOnlyCookies" output="false">
		<cfscript>
    		return getESAPIProperty( this.FORCE_HTTPONLYCOOKIES, true );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getForceSecureCookies" output="false">
		<cfscript>
    		return getESAPIProperty( this.FORCE_SECURECOOKIES, true );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getMaxHttpHeaderSize" output="false">
		<cfscript>
        	return getESAPIProperty( this.MAX_HTTP_HEADER_SIZE, 4096 );
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getResponseContentType" output="false">
		<cfscript>
        	return getESAPIProperty( this.RESPONSE_CONTENT_TYPE, "text/html; charset=UTF-8" );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getRememberTokenDuration" output="false">
		<cfscript>
	        local.days = getESAPIProperty( this.REMEMBER_TOKEN_DURATION, 14 );
	        return (1000 * 60 * 60 * 24 * local.days);
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getSessionIdleTimeoutLength" output="false">
		<cfscript>
	        local.minutes = getESAPIProperty( this.IDLE_TIMEOUT_DURATION, 20 );
	        return 1000 * 60 * local.minutes;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getSessionAbsoluteTimeoutLength" output="false">
		<cfscript>
	        local.minutes = getESAPIProperty(this.ABSOLUTE_TIMEOUT_DURATION, 120 );
	        return 1000 * 60 * local.minutes;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getValidationPattern" output="false" hint="returns a single pattern based upon key">
		<cfargument type="String" name="key" required="true">
		<cfscript>
	    	local.value = getESAPIProperty( "Validator." & arguments.key, "" );
	    	// check cache
	    	local.p = instance.patternCache.get( local.value );
	    	if ( !isNull(local.p) ) {
				return local.p;
	    	}

	    	// compile a new pattern
	    	if ( isNull(local.value) || local.value.equals( "" ) ) {
				return "";
			}
	    	try {
	    		local.q = createObject("java", "java.util.regex.Pattern").compile(local.value);
	    		instance.patternCache.put( local.value, local.q );
	    		return local.q;
	    	} catch ( PatternSyntaxException e ) {
	    		logSpecial( "SecurityConfiguration for " & arguments.key & " not a valid regex in ESAPI.properties. Returning null", "" );
	    		return "";
	    	}
	    </cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getWorkingDirectory" output="false" hint="java.io.File: getWorkingDirectory returns the default directory where processes will be executed by the Executor.">
		<cfscript>
			local.dir = getESAPIProperty( this.WORKING_DIRECTORY, System.getProperty( "user.dir") );
			if ( !isNull(local.dir) ) {
				return createObject("java", "java.io.File").init( local.dir );
			}
			return "";
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getPreferredJCEProvider" output="false">
		<cfscript>
	   		return properties.getProperty(this.PREFERRED_JCE_PROVIDER); // No default!
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getCombinedCipherModes" output="false">
		<cfscript>
		    local.empty = [];     // Default is empty list
		    return getESAPIProperty(this.COMBINED_CIPHER_MODES, local.empty);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getAdditionalAllowedCipherModes" output="false">
		<cfscript>
		    local.empty = [];     // Default is empty list
		    return getESAPIProperty(this.ADDITIONAL_ALLOWED_CIPHER_MODES, local.empty);
		</cfscript>
	</cffunction>


	<cffunction access="package" returntype="any" name="getESAPIProperty" output="false">
		<cfargument type="String" name="key" required="true">
		<cfargument type="any" name="def" required="true">
		<cfscript>
			if (isArray(arguments.def)) {
				local.property = instance.properties.getProperty( arguments.key );
			    if ( isNull(local.property) ) {
			        logSpecial( "SecurityConfiguration for " & arguments.key & " not found in ESAPI.properties. Using default: " & arrayToList(arguments.def) );
			        return arguments.def;
			    }
			    local.parts = local.property.split(",");
			    return local.parts;
			}
			// numerics test true as boolean so we need to check default value as well
			else if (isBoolean(arguments.def) && (listFindNoCase("true,false", arguments.def))) {
				local.property = instance.properties.getProperty(arguments.key);
				if ( isNull(local.property) ) {
		    		logSpecial( "SecurityConfiguration for " & arguments.key & " not found in ESAPI.properties. Using default: " & arguments.def );
		    		return arguments.def;
				}
				if ( local.property.equalsIgnoreCase("true") || local.property.equalsIgnoreCase("yes" ) ) {
					return true;
				}
				if ( local.property.equalsIgnoreCase("false") || local.property.equalsIgnoreCase( "no" ) ) {
					return false;
				}
				logSpecial( "SecurityConfiguration for " & arguments.key & ' not either "true" or "false" in ESAPI.properties. Using default: ' & arguments.def );
				return arguments.def;
			}
			else if (isNumeric(arguments.def)) {
				local.property = instance.properties.getProperty(arguments.key);
				if ( isNull(local.property) ) {
		    		logSpecial( "SecurityConfiguration for " & arguments.key & " not found in ESAPI.properties. Using default: " & arguments.def );
		    		return arguments.def;
				}
				try {
		            return createObject("java", "java.lang.Integer").parseInt( local.property );
				} catch( java.lang.NumberFormatException e ) {
		    		logSpecial( "SecurityConfiguration for " & arguments.key & " not an integer in ESAPI.properties. Using default: " & arguments.def );
					return arguments.def;
				}
			}
			else if (isSimpleValue(arguments.def)) {
				local.value = instance.properties.getProperty(arguments.key);
				if ( isNull(local.value) ) {
		    		logSpecial( "SecurityConfiguration for " & arguments.key & " not found in ESAPI.properties. Using default: " & arguments.def );
		    		return arguments.def;
				}
				return local.value;
			}
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="binary" name="getESAPIPropertyEncoded" output="false">
		<cfargument type="String" name="key" required="true">
		<cfargument type="binary" name="def" required="true">
		<cfscript>
			local.property = instance.properties.getProperty(arguments.key);
			if ( isNull(local.property) ) {
	    		logSpecial( "SecurityConfiguration for " & arguments.key & " not found in ESAPI.properties. Using default: " & toString(arguments.def) );
	    		return arguments.def;
			}
	        try {
	            return instance.ESAPI.encoder().decodeFromBase64(local.property);
	        } catch( IOException e ) {
	    		logSpecial( "SecurityConfiguration for " & arguments.key & " not properly Base64 encoded in ESAPI.properties. Using default: " & arguments.def );
	            return toBinary("");
	        }
		</cfscript>
	</cffunction>


	<cffunction access="package" returntype="boolean" name="shouldPrintProperties" output="false">
		<cfscript>
	       return getESAPIProperty(this.PRINT_PROPERTIES_WHEN_LOADED, false);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getESAPIProperties" output="false" hint="java.util.Properties">
		<cfscript>
        	return instance.properties;
        </cfscript>
	</cffunction>


</cfcomponent>
