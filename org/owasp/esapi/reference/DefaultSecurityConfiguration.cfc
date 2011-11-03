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
 * The reference {@code SecurityConfiguration} manages all the settings used by the ESAPI in a single place. In this reference
 * implementation, resources can be put in several locations, which are searched in the following order:
 * <p>
 * 1) Inside a directory set with a call to SecurityConfiguration.setResourceDirectory( "C:\temp\resources" ).
 * <p>
 * 2) Inside the System.getProperty( "org.owasp.esapi.resources" ) directory.
 * You can set this on the java command line as follows (for example):
 * <pre>
 *         java -Dorg.owasp.esapi.resources="C:\temp\resources"
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
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Jim Manico (jim .at. manico.net) <a href="http://www.manico.net">Manico.net</a>
 * @author Kevin Wall (kevin.w.wall .at. gmail.com)
 */
component DefaultSecurityConfiguration extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.SecurityConfiguration" {

	instance.ESAPI = "";

	instance.properties = "";
	instance.cipherXformFromESAPIProp = "";// New in ESAPI 2.0
	instance.cipherXformCurrent = "";// New in ESAPI 2.0
	/** The name of the ESAPI property file */
	this.RESOURCE_FILE = "ESAPI.properties";

	this.REMEMBER_TOKEN_DURATION = "Authenticator.RememberTokenDuration";
	this.IDLE_TIMEOUT_DURATION = "Authenticator.IdleTimeoutDuration";
	this.ABSOLUTE_TIMEOUT_DURATION = "Authenticator.AbsoluteTimeoutDuration";
	this.ALLOWED_LOGIN_ATTEMPTS = "Authenticator.AllowedLoginAttempts";
	this.USERNAME_PARAMETER_NAME = "Authenticator.UsernameParameterName";
	this.PASSWORD_PARAMETER_NAME = "Authenticator.PasswordParameterName";
	this.MAX_OLD_PASSWORD_HASHES = "Authenticator.MaxOldPasswordHashes";

	this.ALLOW_MULTIPLE_ENCODING = "Encoder.AllowMultipleEncoding";
	this.ALLOW_MIXED_ENCODING = "Encoder.AllowMixedEncoding";
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
	// ==================================//
	//New in ESAPI Java 2.0 //
	// ================================= //
	this.PREFERRED_JCE_PROVIDER = "Encryptor.PreferredJCEProvider";
	this.CIPHER_TRANSFORMATION_IMPLEMENTATION = "Encryptor.CipherTransformation";
	this.CIPHERTEXT_USE_MAC = "Encryptor.CipherText.useMAC";
	this.PLAINTEXT_OVERWRITE = "Encryptor.PlainText.overwrite";
	this.IV_TYPE = "Encryptor.ChooseIVMethod";
	this.FIXED_IV = "Encryptor.fixedIV";
	this.COMBINED_CIPHER_MODES = "Encryptor.cipher_modes.combined_modes";
	this.ADDITIONAL_ALLOWED_CIPHER_MODES = "Encryptor.cipher_modes.additional_allowed";
	this.KDF_PRF_ALG = "Encryptor.KDF.PRF";
	this.PRINT_PROPERTIES_WHEN_LOADED = "ESAPI.printProperties";

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
	this.HTTP_SESSION_ID_NAME = "HttpUtilities.HttpSessionIdName";

	this.APPLICATION_NAME = "Logger.ApplicationName";
	this.LOG_LEVEL = "Logger.LogLevel";
	this.LOG_FILE_NAME = "Logger.LogFileName";
	this.MAX_LOG_FILE_SIZE = "Logger.MaxLogFileSize";
	this.LOG_ENCODING_REQUIRED = "Logger.LogEncodingRequired";
	this.LOG_APPLICATION_NAME = "Logger.LogApplicationName";
	this.LOG_SERVER_IP = "Logger.LogServerIP";
	this.VALIDATION_PROPERTIES = "Validator.ConfigurationFile";
	this.ACCEPT_LENIENT_DATES = "Validator.AcceptLenientDates";

	/**
	 * The default max log file size is set to 10,000,000 bytes (10 Meg). If the current log file exceeds the current
	 * max log file size, the logger will move the old log data into another log file. There currently is a max of
	 * 1000 log files of the same name. If that is exceeded it will presumably start discarding the oldest logs.
	 */
	this.DEFAULT_MAX_LOG_FILE_SIZE = 10000000;

	this.MAX_REDIRECT_LOCATION = 1000;

	/**
	 * @deprecated    It is not clear whether this is intended to be the max file name length for the basename(1) of
	 *                a file or the max full path name length of a canonical full path name. Since it is not used anywhere
	 *                in the ESAPI code it is being deprecated and scheduled to be removed in release 2.1.
	 */
	this.MAX_FILE_NAME_LENGTH = 1000;// DISCUSS: Is this for given directory or refer to canonicalized full path name?
	// Too long if the former! (Usually 255 is limit there.) Hard to tell since not used
	// here in this class and it's protected, so not sure what it's intent is. It's not
	// used anywhere in the ESAPI code base. I am going to deprecate it because of this. -kww
	/*
	 * Implementation Keys
	 */
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

	/*
	 * Default Implementations
	 */
	this.DEFAULT_LOG_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.JavaLogFactory";
	this.DEFAULT_AUTHENTICATION_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.FileBasedAuthenticator";
	this.DEFAULT_ENCODER_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.DefaultEncoder";
	this.DEFAULT_ACCESS_CONTROL_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.accesscontrol.DefaultAccessController";
	this.DEFAULT_ENCRYPTION_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.crypto.JavaEncryptor";
	this.DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.DefaultIntrusionDetector";
	this.DEFAULT_RANDOMIZER_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.DefaultRandomizer";
	this.DEFAULT_EXECUTOR_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.DefaultExecutor";
	this.DEFAULT_HTTP_UTILITIES_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.DefaultHTTPUtilities";
	this.DEFAULT_VALIDATOR_IMPLEMENTATION = "cfesapi.org.owasp.esapi.reference.DefaultValidator";

	instance.patternCache = {};

	/*
	 * Absolute path to the user.home. No longer includes the ESAPI portion as it used to.
	 */
	instance.userHome = newJava("java.lang.System").getProperty("user.home");

	/*
	 * Absolute path to the customDirectory
	 */
	instance.configurationDirectory = expandPath("\cfesapi\esapi\configuration\esapi\");

	/*
	 * Relative path to the resourceDirectory. Relative to the classpath.
	 * Specifically, ClassLoader.getResource(resourceDirectory + filename) will
	 * be used to load the file.
	 */
	instance.resourceDirectory = ".esapi";// For backward compatibility (vs. "esapi")
	//instance.lastModified = -1;
	/**
	 * Instantiates a new configuration with the supplied properties.
	 * 
	 * Warning - if the setResourceDirectory() method is invoked the properties will
	 * be re-loaded, replacing the supplied properties.
	 * 
	 * @param properties
	 */
	
	public DefaultSecurityConfiguration function init(required cfesapi.org.owasp.esapi.ESAPI ESAPI, properties) {
		instance.ESAPI = arguments.ESAPI;
	
		if(structKeyExists(arguments, "properties")) {
			super.init();
			instance.properties = arguments.properties;
			setCipherXProperties();
		}
		else {
			// load security configuration
			try {
				loadConfiguration();
				setCipherXProperties();
			}
			catch(java.io.IOException e) {
				logSpecial("Failed to load security configuration", e);
				local.exception = new cfesapi.org.owasp.esapi.errors.ConfigurationException("Failed to load security configuration", e);
				throwError(local.exception);
			}
		}
	
		return this;
	}
	
	private void function setCipherXProperties() {
		// TODO: FUTURE: Replace by future CryptoControls class???
		// See SecurityConfiguration.setCipherTransformation() for
		// explanation of this.
		// (Propose this in 2.1 via future email to ESAPI-DEV list.)
		instance.cipherXformFromESAPIProp = getESAPIProperty(this.CIPHER_TRANSFORMATION_IMPLEMENTATION, "AES/CBC/PKCS5Padding");
		instance.cipherXformCurrent = instance.cipherXformFromESAPIProp;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getApplicationName() {
		return getESAPIProperty(this.APPLICATION_NAME, "DefaultName");
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getLogImplementation() {
		return getESAPIProperty(this.LOG_IMPLEMENTATION, this.DEFAULT_LOG_IMPLEMENTATION);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getAuthenticationImplementation() {
		return getESAPIProperty(this.AUTHENTICATION_IMPLEMENTATION, this.DEFAULT_AUTHENTICATION_IMPLEMENTATION);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getEncoderImplementation() {
		return getESAPIProperty(this.ENCODER_IMPLEMENTATION, this.DEFAULT_ENCODER_IMPLEMENTATION);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getAccessControlImplementation() {
		return getESAPIProperty(this.ACCESS_CONTROL_IMPLEMENTATION, this.DEFAULT_ACCESS_CONTROL_IMPLEMENTATION);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getEncryptionImplementation() {
		return getESAPIProperty(this.ENCRYPTION_IMPLEMENTATION, this.DEFAULT_ENCRYPTION_IMPLEMENTATION);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getIntrusionDetectionImplementation() {
		return getESAPIProperty(this.INTRUSION_DETECTION_IMPLEMENTATION, this.DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getRandomizerImplementation() {
		return getESAPIProperty(this.RANDOMIZER_IMPLEMENTATION, this.DEFAULT_RANDOMIZER_IMPLEMENTATION);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getExecutorImplementation() {
		return getESAPIProperty(this.EXECUTOR_IMPLEMENTATION, this.DEFAULT_EXECUTOR_IMPLEMENTATION);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getHTTPUtilitiesImplementation() {
		return getESAPIProperty(this.HTTP_UTILITIES_IMPLEMENTATION, this.DEFAULT_HTTP_UTILITIES_IMPLEMENTATION);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getValidationImplementation() {
		return getESAPIProperty(this.VALIDATOR_IMPLEMENTATION, this.DEFAULT_VALIDATOR_IMPLEMENTATION);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public binary function getMasterKey() {
		local.key = getESAPIPropertyEncoded(this.MASTER_KEY, toBinary(""));
		if(isNull(local.key) || !isBinary(local.key) || arrayLen(local.key) == 0) {
			local.exception = new cfesapi.org.owasp.esapi.errors.ConfigurationException("Property '" & this.MASTER_KEY & "' missing or empty in ESAPI.properties file.");
			throwError(local.exception);
		}
		return local.key;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setResourceDirectory(required String dir) {
		// check whether we are changing this so we do not reload configuration unless we have to
		if(instance.resourceDirectory != arguments.dir) {
			instance.resourceDirectory = arguments.dir;
			logSpecial("Reset resource directory to: " & arguments.dir);
		
			// reload configuration if necessary
			try {
				loadConfiguration();
			}
			catch(java.io.IOException e) {
				logSpecial("Failed to load security configuration from " & arguments.dir, e);
			}
		}
	}
	
	public numeric function getEncryptionKeyLength() {
		return getESAPIProperty(this.KEY_LENGTH, 128);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public binary function getMasterSalt() {
		local.salt = getESAPIPropertyEncoded(this.MASTER_SALT, toBinary(""));
		if(isNull(local.salt) || !isBinary(local.salt) || arrayLen(local.salt) == 0) {
			local.exception = new cfesapi.org.owasp.esapi.errors.ConfigurationException("Property '" & this.MASTER_SALT & "' missing or empty in ESAPI.properties file.");
			throwError(local.exception);
		}
		return local.salt;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public Array function getAllowedExecutables() {
		local.def = "";
		local.exList = listToArray(getESAPIProperty(this.APPROVED_EXECUTABLES, local.def));
		return local.exList;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public Array function getAllowedFileExtensions() {
		local.def = ".zip,.pdf,.tar,.gz,.xls,.properties,.txt,.xml";
		local.extList = listToArray(getESAPIProperty(this.APPROVED_UPLOAD_EXTENSIONS, local.def));
		return local.extList;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public numeric function getAllowedFileUploadSize() {
		return getESAPIProperty(this.MAX_UPLOAD_FILE_BYTES, 5000000);
	}
	
	private function loadPropertiesFromStream(required input, required String name) {
		local.config = newJava("java.util.Properties").init();
		try {
			local.config.load(arguments.input);
			logSpecial("Loaded '" & arguments.name & "' properties file");
		}
		finally
		{
			if(!isNull(arguments.input))
				try {
					arguments.input.close();
				}
				catch(java.lang.Exception e) {
				}
		}
		return local.config;
	}
	
	/**
	 * Load configuration. Never prints properties.
	 * 
	 * @throws java.io.IOException
	 *             if the file is inaccessible
	 */
	
	private void function loadConfiguration() {
	
		try {
			//first attempt file IO loading of properties
			logSpecial("Attempting to load " & this.RESOURCE_FILE & " via file I/O.");
			instance.properties = loadPropertiesFromStream(getResourceStream(this.RESOURCE_FILE), this.RESOURCE_FILE);
		}
		catch(java.lang.Exception iae) {
			//if file I/O loading fails, attempt classpath based loading next
			logSpecial("Loading " & this.RESOURCE_FILE & " via file I/O failed. Exception was: " & iae.toString());
			logSpecial("Attempting to load " & this.RESOURCE_FILE & " via the classpath.");
			try {
				instance.properties = loadConfigurationFromClasspath(this.RESOURCE_FILE);
			}
			catch(java.lang.Exception e) {
				logSpecial(this.RESOURCE_FILE & " could not be loaded by any means. Fail.", e);
				local.exception = new cfesapi.org.owasp.esapi.errors.ConfigurationException(this.RESOURCE_FILE & " could not be loaded by any means. Fail.", e);
				throwError(local.exception);
			}
		}
		
		// if properties loaded properly above, get validation properties and merge them into the main properties
		if(!isNull(instance.properties)) {
		
			local.validationPropFileName = getESAPIProperty(this.VALIDATION_PROPERTIES, "validation.properties");
			local.validationProperties = "";
		
			//clear any cached validation patterns so they can be reloaded from validation.properties
			instance.patternCache.clear();
		
			try {
				//first attempt file IO loading of properties
				logSpecial("Attempting to load " & local.validationPropFileName & " via file I/O.");
				local.validationProperties = loadPropertiesFromStream(getResourceStream(local.validationPropFileName), local.validationPropFileName);
			}
			catch(java.lang.Exception iae) {
				//if file I/O loading fails, attempt classpath based loading next
				logSpecial("Loading " & local.validationPropFileName & " via file I/O failed.");
				logSpecial("Attempting to load " & local.validationPropFileName & " via the classpath.");
				try {
					local.validationProperties = loadConfigurationFromClasspath(local.validationPropFileName);
				}
				catch(java.lang.Exception e) {
					logSpecial(local.validationPropFileName & " could not be loaded by any means. fail.", e);
				}
			}
			
			if(!isNull(local.validationProperties)) {
				local.i = local.validationProperties.keySet().iterator();
				while(local.i.hasNext()) {
					local.key = local.i.next();
					local.value = local.validationProperties.getProperty(local.key);
					instance.properties.put(local.key, local.value);
				}
			}
		
			if(shouldPrintProperties()) {
			
				//FIXME - make this chunk configurable
				/*
				logSpecial("  ========Master Configuration========", null);
				//logSpecial( "  ResourceDirectory: " & DefaultSecurityConfiguration.resourceDirectory );
				Iterator j = new TreeSet( instance.properties.keySet() ).iterator();
				while (j.hasNext()) {
				    String key = (String)j.next();
				    // print out properties, but not sensitive ones like MasterKey and MasterSalt
				    if ( !key.contains( "Master" ) ) {
				            logSpecial("  |   " & key & "=" & properties.get(key), null);
				    }
				}
				*/
			}
		}
	}
	
	/**
	 * @param filename
	 * @return An {@code InputStream} associated with the specified file name as
	 *         a resource stream.
	 * @throws IOException
	 *             If the file cannot be found or opened for reading.
	 */
	
	public function getResourceStream(required String filename) {
		if(arguments.filename == "") {
			return "";
		}
	
		try {
			local.f = getResourceFile(arguments.filename);
			if(!isNull(local.f) && local.f.exists()) {
				return newJava("java.io.FileInputStream").init(local.f);
			}
		}
		catch(java.lang.Exception e) {
		}
		
		throwError(newJava("java.io.FileNotFoundException").init(arguments.filename & " file was not found."));
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public function getResourceFile(required String filename) {
		logSpecial("Attempting to load " & arguments.filename & " as resource file via file I/O.");
	
		if(arguments.filename == "") {
			logSpecial("Failed to load properties via FileIO. Filename is blank.");
			return "";// not found.
		}
	
		local.f = "";
	
		// first, try the programmatically set resource directory
		local.fileLocation = expandPath(instance.resourceDirectory & "/" & arguments.filename);
		if(!fileExists(local.fileLocation)) {
			local.fileLocation = expandPath("esapi/" & arguments.filename);
		}
	
		if(fileExists(local.fileLocation)) {
			local.f = newJava("java.io.File").init(local.fileLocation);
			if(local.f.exists()) {
				logSpecial("Found in SystemResource Directory/resourceDirectory: " & local.f.getAbsolutePath());
				return local.f;
			}
			else {
				logSpecial("Not found in SystemResource Directory/resourceDirectory (this should never happen): " & local.f.getAbsolutePath());
			}
		}
		else {
			logSpecial("Not found in SystemResource Directory/resourceDirectory: " & local.fileLocation);
		}
	
		// second, try immediately under user's home directory first in
		//userHome & "/.esapi"and secondly under
		//userHome & "/esapi"
		// We look in that order because of backward compatibility issues.
		local.homeDir = instance.userHome;
		if(isNull(local.homeDir)) {
			local.homeDir = "";// Without this,    homeDir & "/.esapi"    would produce
			// the string        "null/.esapi"        which surely is not intended.
		}
		// First look under ".esapi" (for reasons of backward compatibility).
		local.f = newJava("java.io.File").init(local.homeDir & "/.esapi", arguments.filename);
		if(local.f.canRead()) {
			logSpecial("[Compatibility] Found in 'user.home' directory: " & local.f.getAbsolutePath());
			return local.f;
		}
		else {
			// Didn't find it under old directory ".esapi" so now look under the "esapi" directory.
			local.f = newJava("java.io.File").init(local.homeDir & "/esapi", arguments.filename);
			if(local.f.canRead()) {
				logSpecial("Found in 'user.home' directory: " & local.f.getAbsolutePath());
				return local.f;
			}
			else {
				logSpecial("Not found in 'user.home' (" & homeDir & ") directory: " & local.f.getAbsolutePath());
			}
		}
	
		// third, fallback to the default configuration directory
		local.f = newJava("java.io.File").init(instance.configurationDirectory, arguments.filename);
		if(!isNull(instance.configurationDirectory) && local.f.canRead()) {
			logSpecial("Found in configuration directory: " & local.f.getAbsolutePath());
			return local.f;
		}
		else {
			logSpecial("Not found in configuration directory or file not readable: " & local.f.getAbsolutePath());
		}
	
		// return null if not found
		return "";
	}
	
	/**
	 * Used to load ESAPI.properties from a variety of different classpath locations.
	 *
	 * @param fileName The properties file filename.
	 */
	
	private function loadConfigurationFromClasspath(required String fileName) {
		local.result = "";
		local.in = "";
	
		local.loaders = newJava("java.lang.ClassLoader").init(Thread.currentThread().getContextClassLoader(), newJava("java.lang.ClassLoader").getSystemClassLoader(), getClass().getClassLoader());
		local.classLoaderNames = ["current thread context class loader", "system class loader", "class loader for DefaultSecurityConfiguration class"];
	
		local.currentLoader = "";
		for(local.i = 0; local.i < local.loaders.length; local.i++) {
			if(!isNull(local.loaders[local.i])) {
				local.currentLoader = local.loaders[local.i];
				try {
					// try root
					local.currentClasspathSearchLocation = "/ (root)";
					local.in = local.loaders[i].getResourceAsStream(arguments.fileName);
				
					// try resourceDirectory folder
					if(isNull(local.in)) {
						local.currentClasspathSearchLocation = instance.resourceDirectory & "/";
						local.in = local.currentLoader.getResourceAsStream(instance.resourceDirectory & "/" & arguments.fileName);
					}
				
					// try .esapi folder. Look here first for backward compatibility.
					if(isNull(local.in)) {
						local.currentClasspathSearchLocation = ".esapi/";
						local.in = local.currentLoader.getResourceAsStream(".esapi/" & arguments.fileName);
					}
				
					// try esapi folder (new directory)
					if(isNull(local.in)) {
						local.currentClasspathSearchLocation = "esapi/";
						local.in = local.currentLoader.getResourceAsStream("esapi/" & arguments.fileName);
					}
				
					// try resources folder
					if(isNull(local.in)) {
						local.currentClasspathSearchLocation = "resources/";
						local.in = local.currentLoader.getResourceAsStream("resources/" & arguments.fileName);
					}
				
					// now load the properties
					if(!isNull(local.in)) {
						local.result = newJava("java.util.Properties").init();
						local.result.load(local.in);// Can throw IOException
						logSpecial("SUCCESSFULLY LOADED " & arguments.fileName & " via the CLASSPATH from '" & local.currentClasspathSearchLocation & "' using " & local.classLoaderNames[i] & "!");
						break;// Outta here since we've found and loaded it.
					}
				}
				catch(java.lang.Exception e) {
					local.result = "";
				}
				finally
				{
					try {
						local.in.close();
					}
					catch(java.lang.Exception e) {
					}
				}
			}
		}
	
		if(isNull(local.result)) {
			// CHECKME: This is odd...why not ConfigurationException?
			throwError(IllegalArgumentException.init("Failed to load " & this.RESOURCE_FILE & " as a classloader resource."));
		}
	
		return local.result;
	}
	
	/**
	 * Used to log errors to the console during the loading of the properties file itself. Can't use
	 * standard logging in this case, since the Logger may not be initialized yet. Output is sent to
	 * {@code PrintStream} {@code System.out}.
	 *
	 * @param message The message to send to the console.
	 * @param e The error that occurred. (This value printed via {@code e.toString()}.)
	 */
	
	private void function logSpecial(required String message, e) {
		local.msg = newJava("java.lang.StringBuffer").init(javaCast("string", arguments.message));
		if(!isNull(arguments.e)) {
			local.msg.append(" Exception was: ").append(arguments.e.toString());
		}
		newJava("java.lang.System").out.println(local.msg.toString());
		// if ( e != null) e.printStackTrace();// TODO ??? Do we want this?
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getPasswordParameterName() {
		return getESAPIProperty(this.PASSWORD_PARAMETER_NAME, "password");
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getUsernameParameterName() {
		return getESAPIProperty(this.USERNAME_PARAMETER_NAME, "username");
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getEncryptionAlgorithm() {
		return getESAPIProperty(this.ENCRYPTION_ALGORITHM, "AES");
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getCipherTransformation() {
		assert(!isNull(instance.cipherXformCurrent), "Current cipher transformation is null");
		return instance.cipherXformCurrent;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function setCipherTransformation(required String cipherXform) {
		local.previous = getCipherTransformation();
		if(isNull(arguments.cipherXform) || arguments.cipherXform == "") {
			// Special case... means set it to original value from ESAPI.properties
			instance.cipherXformCurrent = instance.cipherXformFromESAPIProp;
		}
		else {
			assert(!arguments.cipherXform.trim() == "", "Cipher transformation cannot be just white space or empty string");
			instance.cipherXformCurrent = arguments.cipherXform;// Note: No other sanity checks!!!
		}
		return local.previous;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function useMACforCipherText() {
		return getESAPIProperty(this.CIPHERTEXT_USE_MAC, true);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function overwritePlainText() {
		return getESAPIProperty(this.PLAINTEXT_OVERWRITE, true);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getIVType() {
		local.value = getESAPIProperty(this.IV_TYPE, "random");
		if(local.value.equalsIgnoreCase("fixed") || local.value.equalsIgnoreCase("random")) {
			return local.value;
		}
		else if(local.value.equalsIgnoreCase("specified")) {
			// This is planned for future implementation where setting
			// Encryptor.ChooseIVMethod=specified   will require setting some
			// other TBD property that will specify an implementation class that
			// will generate appropriate IVs. The intent of this would be to use
			// such a class with various feedback modes where it is imperative
			// that for a given key, any particular IV is *NEVER* reused. For
			// now, we will assume that generating a random IV is usually going
			// to be sufficient to prevent this.
			local.exception = new cfesapi.org.owasp.esapi.errors.ConfigurationException("'" & this.IV_TYPE & "=specified' is not yet implemented. Use 'fixed' or 'random'");
			throwError(local.exception);
		}
		else {
			// TODO: Once 'specified' is legal, adjust exception msg, below.
			// DISCUSS: Could just log this and then silently return "random" instead.
			local.exception = new cfesapi.org.owasp.esapi.errors.ConfigurationException(value & " is illegal value for " & this.IV_TYPE & ". Use 'random' (preferred) or 'fixed'.");
			throwError(local.exception);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getFixedIV() {
		if(getIVType().equalsIgnoreCase("fixed")) {
			local.ivAsHex = getESAPIProperty(this.FIXED_IV, "");// No default
			if(isNull(local.ivAsHex) || local.ivAsHex.trim() == "") {
				local.exception = new cfesapi.org.owasp.esapi.errors.ConfigurationException("Fixed IV requires property " & this.FIXED_IV & " to be set, but it is not.");
				throwError(local.exception);
			}
			return local.ivAsHex;// We do no further checks here as we have no context.
		}
		else {
			// DISCUSS: Should we just log a warning here and return null instead?
			//If so, may cause NullPointException somewhere later.
			local.exception = new cfesapi.org.owasp.esapi.errors.ConfigurationException("IV type not 'fixed' (set to '" & getIVType() & "'), so no fixed IV applicable.");
			throwError(local.exception);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getHashAlgorithm() {
		return getESAPIProperty(this.HASH_ALGORITHM, "SHA-512");
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public numeric function getHashIterations() {
		return getESAPIProperty(this.HASH_ITERATIONS, 1024);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getKDFPseudoRandomFunction() {
		return getESAPIProperty(this.KDF_PRF_ALG, "HmacSHA256");// NSA recommended SHA2 or better.
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getCharacterEncoding() {
		return getESAPIProperty(this.CHARACTER_ENCODING, "UTF-8");
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function getAllowMultipleEncoding() {
		return getESAPIProperty(this.ALLOW_MULTIPLE_ENCODING, false);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function getAllowMixedEncoding() {
		return getESAPIProperty(this.ALLOW_MIXED_ENCODING, false);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public Array function getDefaultCanonicalizationCodecs() {
		local.def = [];
		local.def.add("org.owasp.esapi.codecs.HTMLEntityCodec");
		local.def.add("org.owasp.esapi.codecs.PercentCodec");
		local.def.add("org.owasp.esapi.codecs.JavaScriptCodec");
		return getESAPIProperty(this.CANONICALIZATION_CODECS, local.def);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getDigitalSignatureAlgorithm() {
		return getESAPIProperty(this.DIGITAL_SIGNATURE_ALGORITHM, "SHAwithDSA");
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public numeric function getDigitalSignatureKeyLength() {
		return getESAPIProperty(this.DIGITAL_SIGNATURE_KEY_LENGTH, 1024);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getRandomAlgorithm() {
		return getESAPIProperty(this.RANDOM_ALGORITHM, "SHA1PRNG");
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public numeric function getAllowedLoginAttempts() {
		return getESAPIProperty(this.ALLOWED_LOGIN_ATTEMPTS, 5);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public numeric function getMaxOldPasswordHashes() {
		return getESAPIProperty(this.MAX_OLD_PASSWORD_HASHES, 12);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public function getUploadDirectory() {
		local.dir = getESAPIProperty(this.UPLOAD_DIRECTORY, "UploadDir");
		return newJava("java.io.File").init(local.dir);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public function getUploadTempDirectory() {
		local.dir = getESAPIProperty(this.UPLOAD_TEMP_DIRECTORY, newJava("java.lang.System").getProperty("java.io.tmpdir", "UploadTempDir"));
		return newJava("java.io.File").init(local.dir);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function getDisableIntrusionDetection() {
		local.value = instance.properties.getProperty(this.DISABLE_INTRUSION_DETECTION);
		if(structKeyExists(local, "value") && "true" == local.value) {
			return true;
		}
		return false;// Default result
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public function getQuota(required String eventName) {
		local.count = getESAPIProperty("IntrusionDetector." & arguments.eventName & ".count", 0);
		local.interval = getESAPIProperty("IntrusionDetector." & arguments.eventName & ".interval", 0);
		local.actions = [];
		local.actionString = getESAPIProperty("IntrusionDetector." & arguments.eventName & ".actions", "");
		if(!isNull(local.actionString)) {
			local.actions = local.actionString.split(",");
		}
		if(local.count > 0 && local.interval > 0 && arrayLen(local.actions) > 0) {
			return new cfesapi.org.owasp.esapi.SecurityConfiguration$Threshold(arguments.eventName, local.count, local.interval, local.actions);
		}
		return "";
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public numeric function getLogLevel() {
		local.level = getESAPIProperty(this.LOG_LEVEL, "WARNING");
	
		if(local.level.equalsIgnoreCase("OFF"))
			return newJava("org.owasp.esapi.Logger").OFF;
		if(local.level.equalsIgnoreCase("FATAL"))
			return newJava("org.owasp.esapi.Logger").FATAL;
		if(local.level.equalsIgnoreCase("ERROR"))
			return newJava("org.owasp.esapi.Logger").ERROR;
		if(local.level.equalsIgnoreCase("WARNING"))
			return newJava("org.owasp.esapi.Logger").WARNING;
		if(local.level.equalsIgnoreCase("INFO"))
			return newJava("org.owasp.esapi.Logger").INFO;
		if(local.level.equalsIgnoreCase("DEBUG"))
			return newJava("org.owasp.esapi.Logger").DEBUG;
		if(local.level.equalsIgnoreCase("TRACE"))
			return newJava("org.owasp.esapi.Logger").TRACE;
		if(local.level.equalsIgnoreCase("ALL"))
			return newJava("org.owasp.esapi.Logger").ALL;
	
		// This error is NOT logged the normal way because the logger constructor calls getLogLevel() and if this error occurred it would cause
		// an infinite loop.
		logSpecial("The LOG-LEVEL property in the ESAPI properties file has the unrecognized value: " & local.level & ". Using default: WARNING");
		return newJava("org.owasp.esapi.Logger").WARNING;// Note: The default logging level is WARNING.
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getLogFileName() {
		return getESAPIProperty(this.LOG_FILE_NAME, "ESAPI_logging_file");
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public numeric function getMaxLogFileSize() {
		return getESAPIProperty(this.MAX_LOG_FILE_SIZE, this.DEFAULT_MAX_LOG_FILE_SIZE);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function getLogEncodingRequired() {
		return getESAPIProperty(this.LOG_ENCODING_REQUIRED, false);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function getLogApplicationName() {
		return getESAPIProperty(this.LOG_APPLICATION_NAME, true);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function getLogServerIP() {
		return getESAPIProperty(this.LOG_SERVER_IP, true);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function getForceHttpOnlySession() {
		return getESAPIProperty(this.FORCE_HTTPONLYSESSION, true);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function getForceSecureSession() {
		return getESAPIProperty(this.FORCE_SECURESESSION, true);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function getForceHttpOnlyCookies() {
		return getESAPIProperty(this.FORCE_HTTPONLYCOOKIES, true);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function getForceSecureCookies() {
		return getESAPIProperty(this.FORCE_SECURECOOKIES, true);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public numeric function getMaxHttpHeaderSize() {
		return getESAPIProperty(this.MAX_HTTP_HEADER_SIZE, 4096);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getResponseContentType() {
		return getESAPIProperty(this.RESPONSE_CONTENT_TYPE, "text/html; charset=UTF-8");
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getHttpSessionIdName() {
		return getESAPIProperty(this.HTTP_SESSION_ID_NAME, "JSESSIONID");
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public numeric function getRememberTokenDuration() {
		local.days = getESAPIProperty(this.REMEMBER_TOKEN_DURATION, 14);
		return javaCast("long", 1000 * 60 * 60 * 24 * local.days);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public numeric function getSessionIdleTimeoutLength() {
		local.minutes = getESAPIProperty(this.IDLE_TIMEOUT_DURATION, 20);
		return javaCast("long", 1000 * 60 * local.minutes);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public numeric function getSessionAbsoluteTimeoutLength() {
		local.minutes = getESAPIProperty(this.ABSOLUTE_TIMEOUT_DURATION, 20);
		return javaCast("long", 1000 * 60 * local.minutes);
	}
	
	/**
	 * getValidationPattern returns a single pattern based upon key
	 *
	 *  @param key
	 *              validation pattern name you'd like
	 *  @return
	 *              if key exists, the associated validation pattern, null otherwise
	 */
	
	public function getValidationPattern(required String key) {
		local.value = getESAPIProperty("Validator." & arguments.key, "");
		// check cache
		if(structKeyExists(instance.patternCache, local.value)) {
			local.p = instance.patternCache.get(local.value);
		}
		if(!isNull(local.p)) {
			return local.p;
		}
	
		// compile a new pattern
		if(isNull(local.value) || local.value.equals("")) {
			return "";
		}
		try {
			local.q = newJava("java.util.regex.Pattern").compile(local.value);
			instance.patternCache.put(local.value, local.q);
			return local.q;
		}
		catch(java.util.regex.PatternSyntaxException e) {
			logSpecial("SecurityConfiguration for " & arguments.key & " not a valid regex in ESAPI.properties. Returning null");
			return "";
		}
	}
	
	/**
	 * getWorkingDirectory returns the default directory where processes will be executed
	 * by the Executor.
	 */
	
	public function getWorkingDirectory() {
		local.dir = getESAPIProperty(this.WORKING_DIRECTORY, newJava("java.lang.System").getProperty("user.dir"));
		if(!isNull(local.dir)) {
			return newJava("java.io.File").init(local.dir);
		}
		return "";
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getPreferredJCEProvider() {
		return instance.properties.getProperty(this.PREFERRED_JCE_PROVIDER);// No default!
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public Array function getCombinedCipherModes() {
		local.empty = [];// Default is empty list
		return getESAPIProperty(this.COMBINED_CIPHER_MODES, local.empty);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public Array function getAdditionalAllowedCipherModes() {
		local.empty = [];// Default is empty list
		return getESAPIProperty(this.ADDITIONAL_ALLOWED_CIPHER_MODES, local.empty);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function getLenientDatesAccepted() {
		return getESAPIProperty(this.ACCEPT_LENIENT_DATES, false);
	}
	
	/**
	 * Returns a property.
	 * 
	 * @param key  The specified property name
	 * @param def  A default value for the property name to return if the property
	 *             is not set.
	 * @return A property value.
	 */
	
	private function getESAPIProperty(required String key, required def) {
		// Array
		if(isArray(arguments.def)) {
			local.property = instance.properties.getProperty(arguments.key);
			if(isNull(local.property)) {
				logSpecial("SecurityConfiguration for " & arguments.key & " not found in ESAPI.properties. Using default: " & arrayToList(arguments.def));
				return arguments.def;
			}
			local.parts = local.property.split(",");
			return local.parts;
		}
		// Boolean - numerics test true as boolean so we need to check default value as well
		else if(isBoolean(arguments.def) && listFindNoCase("true,false", arguments.def)) {
			local.property = instance.properties.getProperty(arguments.key);
			if(isNull(local.property)) {
				logSpecial("SecurityConfiguration for " & arguments.key & " not found in ESAPI.properties. Using default: " & arguments.def);
				return arguments.def;
			}
			if(local.property.equalsIgnoreCase("true") || local.property.equalsIgnoreCase("yes")) {
				return true;
			}
			if(local.property.equalsIgnoreCase("false") || local.property.equalsIgnoreCase("no")) {
				return false;
			}
			logSpecial("SecurityConfiguration for " & arguments.key & ' not either "true" or "false" in ESAPI.properties. Using default: ' & arguments.def);
			return arguments.def;
		}
		// Numeric
		else if(isNumeric(arguments.def)) {
			local.property = instance.properties.getProperty(arguments.key);
			if(isNull(local.property)) {
				logSpecial("SecurityConfiguration for " & arguments.key & " not found in ESAPI.properties. Using default: " & arguments.def);
				return arguments.def;
			}
			try {
				return int(local.property);
			}
			catch(java.lang.NumberFormatException e) {
				logSpecial("SecurityConfiguration for " & arguments.key & " not an integer in ESAPI.properties. Using default: " & arguments.def);
				return arguments.def;
			}
		}
		// String
		else if(isSimpleValue(arguments.def)) {
			local.value = instance.properties.getProperty(arguments.key);
			if(isNull(local.value)) {
				logSpecial("SecurityConfiguration for " & arguments.key & " not found in ESAPI.properties. Using default: " & arguments.def);
				return arguments.def;
			}
			return local.value;
		}
	}
	
	private binary function getESAPIPropertyEncoded(required String key, required binary def) {
		local.property = instance.properties.getProperty(arguments.key);
		if(isNull(local.property)) {
			logSpecial("SecurityConfiguration for " & arguments.key & " not found in ESAPI.properties. Using default: " & arguments.def.toString());
			return arguments.def;
		}
		try {
			return instance.ESAPI.encoder().decodeFromBase64(local.property);
		}
		catch(java.io.IOException e) {
			logSpecial("SecurityConfiguration for " & arguments.key & " not properly Base64 encoded in ESAPI.properties. Using default: " & arguments.def.toString());
			return toBinary("");
		}
	}
	
	private boolean function shouldPrintProperties() {
		return getESAPIProperty(this.PRINT_PROPERTIES_WHEN_LOADED, false);
	}
	
	public function getESAPIProperties() {
		return instance.properties;
	}
	
}