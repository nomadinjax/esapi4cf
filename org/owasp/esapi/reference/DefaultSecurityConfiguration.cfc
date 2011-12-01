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
<cfcomponent displayname="DefaultSecurityConfiguration" extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.SecurityConfiguration" output="false"
             hint="The reference {@code SecurityConfiguration} manages all the settings used by the ESAPI in a single place. In this reference implementation, resources can be put in several locations, which are searched in the following order: 1) Inside a directory set with a call to SecurityConfiguration.setResourceDirectory( 'C:\temp\resources' ). 2) Inside the {@code System.getProperty( 'user.home' ) + '/.esapi'} directory (supported for backward compatibility) or inside the {@code System.getProperty( 'user.home' ) + '/esapi'} directory. 3) The first '.esapi' or 'esapi' directory on the classpath. (The former for backward compatibility.) Once the Configuration is initialized with a resource directory, you can edit it to set things like master keys and passwords, logging locations, error thresholds, and allowed file extensions. WARNING: Do not forget to update ESAPI.properties to change the master key and other security critical settings.">

	<cfscript>
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
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.SecurityConfiguration" name="init" output="false"
	            hint="Instantiates a new configuration with the supplied properties. Warning - if the setResourceDirectory() method is invoked the properties will be re-loaded, replacing the supplied properties.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument name="properties"/>

		<cfset var local = {}/>

		<cfscript>
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
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ConfigurationException").init("Failed to load security configuration", e);
					throwError(local.exception);
				}
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="setCipherXProperties" output="false">

		<cfscript>
			// TODO: FUTURE: Replace by future CryptoControls class???
			// See SecurityConfiguration.setCipherTransformation() for
			// explanation of this.
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
		<cfset var local = {}/>

		<cfscript>
			local.key = getESAPIPropertyEncoded(this.MASTER_KEY, toBinary(""));
			if(!structKeyExists(local, "key") || !isBinary(local.key) || arrayLen(local.key) == 0) {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ConfigurationException").init("Property '" & this.MASTER_KEY & "' missing or empty in ESAPI.properties file.");
				throwError(local.exception);
			}
			return local.key;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setResourceDirectory" output="false">
		<cfargument required="true" type="String" name="dir"/>

		<cfscript>
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
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getEncryptionKeyLength" output="false">

		<cfscript>
			return getESAPIProperty(this.KEY_LENGTH, 128);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="binary" name="getMasterSalt" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.salt = getESAPIPropertyEncoded(this.MASTER_SALT, toBinary(""));
			if(!structKeyExists(local, "salt") || !isBinary(local.salt) || arrayLen(local.salt) == 0) {
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ConfigurationException").init("Property '" & this.MASTER_SALT & "' missing or empty in ESAPI.properties file.");
				throwError(local.exception);
			}
			return local.salt;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getAllowedExecutables" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.def = "";
			local.exList = listToArray(getESAPIProperty(this.APPROVED_EXECUTABLES, local.def));
			return local.exList;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getAllowedFileExtensions" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.def = ".zip,.pdf,.tar,.gz,.xls,.properties,.txt,.xml";
			local.extList = listToArray(getESAPIProperty(this.APPROVED_UPLOAD_EXTENSIONS, local.def));
			return local.extList;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getAllowedFileUploadSize" output="false">

		<cfscript>
			return getESAPIProperty(this.MAX_UPLOAD_FILE_BYTES, 5000000);
		</cfscript>

	</cffunction>

	<cffunction access="private" name="loadPropertiesFromStream" output="false">
		<cfargument required="true" name="input"/>
		<cfargument required="true" type="String" name="name"/>

		<cfset var local = {}/>

		<cfscript>
			local.config = newJava("java.util.Properties").init();
			try {
				local.config.load(arguments.input);
				logSpecial("Loaded '" & arguments.name & "' properties file");
			}
			catch(any e) {
				// ignore
			}

			if(structKeyExists(arguments, "input")) {
				try {
					arguments.input.close();
				}
				catch(java.lang.Exception e) {
				}
			}

			return local.config;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="loadConfiguration" output="false"
	            hint="Load configuration. Never prints properties.">
		<cfset var local = {}/>

		<cfscript>

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
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ConfigurationException").init(this.RESOURCE_FILE & " could not be loaded by any means. Fail.", e);
					throwError(local.exception);
				}
			}

			// if properties loaded properly above, get validation properties and merge them into the main properties
			if(structKeyExists(instance, "properties")) {

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

				if(structKeyExists(local, "validationProperties")) {
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
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getResourceStream" output="false" hint="Returns an {@code InputStream} associated with the specified file name as a resource stream.">
		<cfargument required="true" type="String" name="filename"/>

		<cfset var local = {}/>

		<cfscript>
			if(arguments.filename == "") {
				return "";
			}

			try {
				local.f = getResourceFile(arguments.filename);
				if(structKeyExists(local, "f") && local.f.exists()) {
					return newJava("java.io.FileInputStream").init(local.f);
				}
			}
			catch(java.lang.Exception e) {
			}

			throwError(newJava("java.io.FileNotFoundException").init(arguments.filename & " file was not found."));
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getResourceFile" output="false">
		<cfargument required="true" type="String" name="filename"/>

		<cfset var local = {}/>

		<cfscript>
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
			if(!structKeyExists(local, "homeDir")) {
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
					logSpecial("Not found in 'user.home' (" & local.homeDir & ") directory: " & local.f.getAbsolutePath());
				}
			}

			// third, fallback to the default configuration directory
			local.f = newJava("java.io.File").init(instance.configurationDirectory, arguments.filename);
			if(structKeyExists(instance, "configurationDirectory") && local.f.canRead()) {
				logSpecial("Found in configuration directory: " & local.f.getAbsolutePath());
				return local.f;
			}
			else {
				logSpecial("Not found in configuration directory or file not readable: " & local.f.getAbsolutePath());
			}

			// return null if not found
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="private" name="loadConfigurationFromClasspath" output="false" hint="Used to load ESAPI.properties from a variety of different classpath locations.">
		<cfargument required="true" type="String" name="fileName"/>

		<cfset var local = {}/>

		<cfscript>
			local.result = "";
			local.in = "";

			local.loaders = newJava("java.lang.ClassLoader").init(Thread.currentThread().getContextClassLoader(), newJava("java.lang.ClassLoader").getSystemClassLoader(), getClass().getClassLoader());
			local.classLoaderNames = ["current thread context class loader", "system class loader", "class loader for DefaultSecurityConfiguration class"];

			local.currentLoader = "";
			for(local.i = 0; local.i < local.loaders.length; local.i++) {
				if(structKeyExists(local.loaders, local.i)) {
					local.currentLoader = local.loaders[local.i];
					try {
						// try root
						local.currentClasspathSearchLocation = "/ (root)";
						local.in = local.loaders[i].getResourceAsStream(arguments.fileName);

						// try resourceDirectory folder
						if(!structKeyExists(local, "in")) {
							local.currentClasspathSearchLocation = instance.resourceDirectory & "/";
							local.in = local.currentLoader.getResourceAsStream(instance.resourceDirectory & "/" & arguments.fileName);
						}

						// try .esapi folder. Look here first for backward compatibility.
						if(!structKeyExists(local, "in")) {
							local.currentClasspathSearchLocation = ".esapi/";
							local.in = local.currentLoader.getResourceAsStream(".esapi/" & arguments.fileName);
						}

						// try esapi folder (new directory)
						if(!structKeyExists(local, "in")) {
							local.currentClasspathSearchLocation = "esapi/";
							local.in = local.currentLoader.getResourceAsStream("esapi/" & arguments.fileName);
						}

						// try resources folder
						if(!structKeyExists(local, "in")) {
							local.currentClasspathSearchLocation = "resources/";
							local.in = local.currentLoader.getResourceAsStream("resources/" & arguments.fileName);
						}

						// now load the properties
						if(structKeyExists(local, "in")) {
							local.result = newJava("java.util.Properties").init();
							local.result.load(local.in);// Can throw IOException
							logSpecial("SUCCESSFULLY LOADED " & arguments.fileName & " via the CLASSPATH from '" & local.currentClasspathSearchLocation & "' using " & local.classLoaderNames[i] & "!");
							break;// Outta here since we've found and loaded it.
						}
					}
					catch(java.lang.Exception e) {
						local.result = "";
					}
					try {
						local.in.close();
					}
					catch(java.lang.Exception e) {
					}
				}
			}

			if(!structKeyExists(local, "result")) {
				// CHECKME: This is odd...why not ConfigurationException?
				throwError(IllegalArgumentException.init("Failed to load " & this.RESOURCE_FILE & " as a classloader resource."));
			}

			return local.result;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="logSpecial" output="false"
	            hint="Used to log errors to the console during the loading of the properties file itself. Can't use standard logging in this case, since the Logger may not be initialized yet. Output is sent to {@code PrintStream} {@code System.out}.">
		<cfargument required="true" type="String" name="message" hint="The message to send to the console."/>
		<cfargument name="e" hint="The error that occurred. (This value printed via {@code e.toString()}.)"/>

		<cfset var local = {}/>

		<cfscript>
			local.msg = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init(arguments.message);
			if(structKeyExists(arguments, "e")) {
				local.msg.append(" Exception was: ").append(arguments.e.toString());
			}
			newJava("java.lang.System").out.println(local.msg.toStringESAPI());
			// if ( e != null) e.printStackTrace();// TODO ??? Do we want this?
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
			assert(structKeyExists(instance, "cipherXformCurrent"), "Current cipher transformation is null");
			return instance.cipherXformCurrent;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="setCipherTransformation" output="false">
		<cfargument required="true" type="String" name="cipherXform"/>

		<cfset var local = {}/>

		<cfscript>
			local.previous = getCipherTransformation();
			if(!structKeyExists(arguments, "cipherXform") || arguments.cipherXform == "") {
				// Special case... means set it to original value from ESAPI.properties
				instance.cipherXformCurrent = instance.cipherXformFromESAPIProp;
			}
			else {
				assert(!arguments.cipherXform.trim() == "", "Cipher transformation cannot be just white space or empty string");
				instance.cipherXformCurrent = arguments.cipherXform;// Note: No other sanity checks!!!
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
		<cfset var local = {}/>

		<cfscript>
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
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ConfigurationException").init("'" & this.IV_TYPE & "=specified' is not yet implemented. Use 'fixed' or 'random'");
				throwError(local.exception);
			}
			else {
				// TODO: Once 'specified' is legal, adjust exception msg, below.
				// DISCUSS: Could just log this and then silently return "random" instead.
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ConfigurationException").init(local.value & " is illegal value for " & this.IV_TYPE & ". Use 'random' (preferred) or 'fixed'.");
				throwError(local.exception);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getFixedIV" output="false">
		<cfset var local = {}/>

		<cfscript>
			if(getIVType().equalsIgnoreCase("fixed")) {
				local.ivAsHex = getESAPIProperty(this.FIXED_IV, "");// No default
				if(!structKeyExists(local, "ivAsHex") || local.ivAsHex.trim() == "") {
					local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ConfigurationException").init("Fixed IV requires property " & this.FIXED_IV & " to be set, but it is not.");
					throwError(local.exception);
				}
				return local.ivAsHex;// We do no further checks here as we have no context.
			}
			else {
				// DISCUSS: Should we just log a warning here and return null instead?
				//If so, may cause NullPointException somewhere later.
				local.exception = newComponent("cfesapi.org.owasp.esapi.errors.ConfigurationException").init("IV type not 'fixed' (set to '" & getIVType() & "'), so no fixed IV applicable.");
				throwError(local.exception);
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

	<cffunction access="public" returntype="String" name="getKDFPseudoRandomFunction" output="false">

		<cfscript>
			return getESAPIProperty(this.KDF_PRF_ALG, "HmacSHA256");// NSA recommended SHA2 or better.
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false">

		<cfscript>
			return getESAPIProperty(this.CHARACTER_ENCODING, "UTF-8");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="getAllowMultipleEncoding" output="false">

		<cfscript>
			return getESAPIProperty(this.ALLOW_MULTIPLE_ENCODING, false);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="getAllowMixedEncoding" output="false">

		<cfscript>
			return getESAPIProperty(this.ALLOW_MIXED_ENCODING, false);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getDefaultCanonicalizationCodecs" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.def = [];
			local.def.add("org.owasp.esapi.codecs.HTMLEntityCodec");
			local.def.add("org.owasp.esapi.codecs.PercentCodec");
			local.def.add("org.owasp.esapi.codecs.JavaScriptCodec");
			return getESAPIProperty(this.CANONICALIZATION_CODECS, local.def);
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

	<cffunction access="public" name="getUploadDirectory" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.dir = getESAPIProperty(this.UPLOAD_DIRECTORY, "UploadDir");
			return newJava("java.io.File").init(local.dir);
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getUploadTempDirectory" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.dir = getESAPIProperty(this.UPLOAD_TEMP_DIRECTORY, newJava("java.lang.System").getProperty("java.io.tmpdir", "UploadTempDir"));
			return newJava("java.io.File").init(local.dir);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="getDisableIntrusionDetection" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.value = instance.properties.getProperty(this.DISABLE_INTRUSION_DETECTION);
			if(structKeyExists(local, "value") && "true" == local.value) {
				return true;
			}
			return false;// Default result
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getQuota" output="false">
		<cfargument required="true" type="String" name="eventName"/>

		<cfset var local = {}/>

		<cfscript>
			local.count = getESAPIProperty("IntrusionDetector." & arguments.eventName & ".count", 0);
			local.interval = getESAPIProperty("IntrusionDetector." & arguments.eventName & ".interval", 0);
			local.actions = [];
			local.actionString = getESAPIProperty("IntrusionDetector." & arguments.eventName & ".actions", "");
			if(structKeyExists(local, "actionString")) {
				local.actions = local.actionString.split(",");
			}
			if(local.count > 0 && local.interval > 0 && arrayLen(local.actions) > 0) {
				return newComponent("cfesapi.org.owasp.esapi.SecurityConfiguration$Threshold").init(arguments.eventName, local.count, local.interval, local.actions);
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getLogLevel" output="false">
		<cfset var local = {}/>

		<cfscript>
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
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLogFileName" output="false">

		<cfscript>
			return getESAPIProperty(this.LOG_FILE_NAME, "ESAPI_logging_file");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getMaxLogFileSize" output="false">

		<cfscript>
			return getESAPIProperty(this.MAX_LOG_FILE_SIZE, this.DEFAULT_MAX_LOG_FILE_SIZE);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="getLogEncodingRequired" output="false">

		<cfscript>
			return getESAPIProperty(this.LOG_ENCODING_REQUIRED, false);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="getLogApplicationName" output="false">

		<cfscript>
			return getESAPIProperty(this.LOG_APPLICATION_NAME, true);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="getLogServerIP" output="false">

		<cfscript>
			return getESAPIProperty(this.LOG_SERVER_IP, true);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="getForceHttpOnlySession" output="false">

		<cfscript>
			return getESAPIProperty(this.FORCE_HTTPONLYSESSION, true);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="getForceSecureSession" output="false">

		<cfscript>
			return getESAPIProperty(this.FORCE_SECURESESSION, true);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="getForceHttpOnlyCookies" output="false">

		<cfscript>
			return getESAPIProperty(this.FORCE_HTTPONLYCOOKIES, true);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="getForceSecureCookies" output="false">

		<cfscript>
			return getESAPIProperty(this.FORCE_SECURECOOKIES, true);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getMaxHttpHeaderSize" output="false">

		<cfscript>
			return getESAPIProperty(this.MAX_HTTP_HEADER_SIZE, 4096);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getResponseContentType" output="false">

		<cfscript>
			return getESAPIProperty(this.RESPONSE_CONTENT_TYPE, "text/html; charset=UTF-8");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getHttpSessionIdName" output="false">

		<cfscript>
			return getESAPIProperty(this.HTTP_SESSION_ID_NAME, "JSESSIONID");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getRememberTokenDuration" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.days = getESAPIProperty(this.REMEMBER_TOKEN_DURATION, 14);
			return javaCast("long", 1000 * 60 * 60 * 24 * local.days);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getSessionIdleTimeoutLength" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.minutes = getESAPIProperty(this.IDLE_TIMEOUT_DURATION, 20);
			return javaCast("long", 1000 * 60 * local.minutes);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getSessionAbsoluteTimeoutLength" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.minutes = getESAPIProperty(this.ABSOLUTE_TIMEOUT_DURATION, 20);
			return javaCast("long", 1000 * 60 * local.minutes);
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getValidationPattern" output="false" hint="getValidationPattern returns a single pattern based upon key">
		<cfargument required="true" type="String" name="key" hint="validation pattern name you'd like"/>

		<cfset var local = {}/>

		<cfscript>
			local.value = getESAPIProperty("Validator." & arguments.key, "");
			// check cache
			if(structKeyExists(instance.patternCache, local.value)) {
				local.p = instance.patternCache.get(local.value);
			}
			if(structKeyExists(local, "p")) {
				return local.p;
			}

			// compile a new pattern
			if(!structKeyExists(local, "value") || local.value.equals("")) {
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
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getWorkingDirectory" output="false" hint="getWorkingDirectory returns the default directory where processes will be executed by the Executor.">
		<cfset var local = {}/>

		<cfscript>
			local.dir = getESAPIProperty(this.WORKING_DIRECTORY, newJava("java.lang.System").getProperty("user.dir"));
			if(structKeyExists(local, "dir")) {
				return newJava("java.io.File").init(local.dir);
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getPreferredJCEProvider" output="false">

		<cfscript>
			return instance.properties.getProperty(this.PREFERRED_JCE_PROVIDER);// No default!
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getCombinedCipherModes" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.empty = [];// Default is empty list
			return getESAPIProperty(this.COMBINED_CIPHER_MODES, local.empty);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getAdditionalAllowedCipherModes" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.empty = [];// Default is empty list
			return getESAPIProperty(this.ADDITIONAL_ALLOWED_CIPHER_MODES, local.empty);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="getLenientDatesAccepted" output="false">

		<cfscript>
			return getESAPIProperty(this.ACCEPT_LENIENT_DATES, false);
		</cfscript>

	</cffunction>

	<cffunction access="private" name="getESAPIProperty" output="false" hint="Returns a property.">
		<cfargument required="true" type="String" name="key" hint="The specified property name"/>
		<cfargument required="true" name="def" hint="A default value for the property name to return if the property is not set."/>

		<cfset var local = {}/>

		<cfscript>
			// Array
			if(isArray(arguments.def)) {
				local.property = instance.properties.getProperty(arguments.key);
				if(!structKeyExists(local, "property")) {
					logSpecial("SecurityConfiguration for " & arguments.key & " not found in ESAPI.properties. Using default: " & arrayToList(arguments.def));
					return arguments.def;
				}
				local.parts = local.property.split(",");
				return local.parts;
			}
			// Boolean - numerics test true as boolean so we need to check default value as well
			else if(isBoolean(arguments.def) && listFindNoCase("true,false", arguments.def)) {
				local.property = instance.properties.getProperty(arguments.key);
				if(!structKeyExists(local, "property")) {
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
				if(!structKeyExists(local, "property")) {
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
				if(!structKeyExists(local, "value")) {
					logSpecial("SecurityConfiguration for " & arguments.key & " not found in ESAPI.properties. Using default: " & arguments.def);
					return arguments.def;
				}
				return local.value;
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="binary" name="getESAPIPropertyEncoded" output="false">
		<cfargument required="true" type="String" name="key"/>
		<cfargument required="true" type="binary" name="def"/>

		<cfset var local = {}/>

		<cfscript>
			local.property = instance.properties.getProperty(arguments.key);
			if(!structKeyExists(local, "property")) {
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
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="shouldPrintProperties" output="false">

		<cfscript>
			return getESAPIProperty(this.PRINT_PROPERTIES_WHEN_LOADED, false);
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getESAPIProperties" output="false">

		<cfscript>
			return instance.properties;
		</cfscript>

	</cffunction>

</cfcomponent>