<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 --->
<cfcomponent implements="cfesapi.org.owasp.esapi.SecurityConfiguration" extends="cfesapi.org.owasp.esapi.util.Object" output="false" hint="The SecurityConfiguration manages all the settings used by the ESAPI in a single place. Initializing the Configuration is critically important to getting the ESAPI working properly. You must set a system property before invoking any part of the ESAPI. You may have to add this to the batch script that starts your web server. For example, in the 'catalina' script that starts Tomcat, you can set the JAVA_OPTS variable to the -D string above. Once the Configuration is initialized with a resource directory, you can edit it to set things like master keys and passwords, logging locations, error thresholds, and allowed file extensions.">

	<cfscript>
		System = getJava("java.lang.System");
	
		/** The properties. */
		instance.properties = getJava("java.util.Properties").init();
	
		/** The name of the ESAPI property file */
		this.RESOURCE_FILE = "ESAPI.properties";
	
		/** The location of the Resources directory used by ESAPI. */
		this.RESOURCE_DIRECTORY = "cfesapi.org.owasp.esapi.resources";
	
		// private
		instance.ALLOWED_LOGIN_ATTEMPTS = "AllowedLoginAttempts";
		instance.APPLICATION_NAME = "ApplicationName";
		instance.MASTER_PASSWORD = "MasterPassword";
		instance.MASTER_SALT = "MasterSalt";
		instance.VALID_EXTENSIONS = "ValidExtensions";
		instance.MAX_UPLOAD_FILE_BYTES = "MaxUploadFileBytes";
		instance.USERNAME_PARAMETER_NAME = "UsernameParameterName";
		instance.PASSWORD_PARAMETER_NAME = "PasswordParameterName";
		instance.MAX_OLD_PASSWORD_HASHES = "MaxOldPasswordHashes";
		instance.ENCRYPTION_ALGORITHM = "EncryptionAlgorithm";
		instance.HASH_ALGORITHM = "HashAlgorithm";
		instance.CHARACTER_ENCODING = "CharacterEncoding";
		instance.RANDOM_ALGORITHM = "RandomAlgorithm";
		instance.DIGITAL_SIGNATURE_ALGORITHM = "DigitalSignatureAlgorithm";
		instance.RESPONSE_CONTENT_TYPE = "ResponseContentType";
		instance.REMEMBER_TOKEN_DURATION = "RememberTokenDuration";
		instance.IDLE_TIMEOUT_DURATION = "IdleTimeoutDuration";
		instance.ABSOLUTE_TIMEOUT_DURATION = "AbsoluteTimeoutDuration";
		instance.DISABLE_INTRUSION_DETECTION = "DisableIntrusionDetection";
		instance.LOG_LEVEL = "LogLevel";
		instance.LOG_FILE_NAME = "LogFileName";
		instance.MAX_LOG_FILE_SIZE = "MaxLogFileSize";
		instance.LOG_ENCODING_REQUIRED = "LogEncodingRequired";
		instance.LOG_DEFAULT_LOG4J = "LogDefaultLog4J";
	
		//protected
		instance.MAX_REDIRECT_LOCATION = 1000;
		instance.MAX_FILE_NAME_LENGTH = 1000;
	
		/**
		 * Load properties from properties file. Set this with setResourceDirectory
		 * from your web application or ESAPI filter. For test and non-web
		 * applications, this implementation defaults to a System property defined
		 * when Java is launched. Use:
		 * <P>
		 * java -Dorg.owasp.esapi.resources="/path/resources"
		 * <P>
		 * where 'path' references the appropriate directory in your system.
		 */
		instance.resourceDirectory = System.getProperty(this.RESOURCE_DIRECTORY);
	
		/*
		 * Absolute path to the customDirectory
		 */
		instance.customDirectory = System.getProperty("cfesapi.org.owasp.esapi.resources");
	
		/*
		 * Absolute path to the userDirectory
		 */
		instance.userDirectory = System.getProperty("user.home") & getJava("java.io.File").separator & ".esapi";
	</cfscript>
	
	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.SecurityConfiguration" name="init" output="false"
	            hint="Instantiates a new configuration.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
	
		<cfscript>
			try {
				loadConfiguration();
			}
			catch(java.io.FileNotFoundException e) {
				logSpecial("Failed to load security configuration", e);
			}
		
			return this;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getApplicationName" output="false">
	
		<cfscript>
			return instance.properties.getProperty(instance.APPLICATION_NAME, "AppNameNotSpecified");
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="Array" name="getMasterPassword" output="false">
	
		<cfscript>
			return instance.properties.getProperty(instance.MASTER_PASSWORD).toCharArray();
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" name="getKeystore" output="false">
	
		<cfscript>
			return getJava("java.io.File").init(getResourceDirectory(), "keystore");
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getResourceDirectory" output="false">
	
		<cfscript>
			var local = {};
			if (!structKeyExists(instance, "resourceDirectory")) {
				instance.resourceDirectory = "";
			}
			local.fileSeparator = getJava("java.io.File").separator;
			if(trim(len(instance.resourceDirectory)) && !instance.resourceDirectory.endsWith(local.fileSeparator)) {
				instance.resourceDirectory &= local.fileSeparator;
			}
			return instance.resourceDirectory;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setResourceDirectory" output="false">
		<cfargument required="true" type="String" name="dir"/>
	
		<cfscript>
			instance.resourceDirectory = arguments.dir;
			logSpecial("Reset resource directory to: " & arguments.dir, "");
		
			// reload configuration if necessary
			try {
				loadConfiguration();
			}
			catch(java.io.IOException e) {
				logSpecial("Failed to load security configuration from " & arguments.dir, e);
			}
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="binary" name="getMasterSalt" output="false">
	
		<cfscript>
			return instance.properties.getProperty(instance.MASTER_SALT).getBytes();
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="Array" name="getAllowedFileExtensions" output="false">
	
		<cfscript>
			var local = {};
			local.def = ".zip,.pdf,.tar,.gz,.xls,.properties,.txt,.xml";
			local.extList = instance.properties.getProperty(instance.VALID_EXTENSIONS, local.def).split(",");
			return local.extList;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="numeric" name="getAllowedFileUploadSize" output="false">
	
		<cfscript>
			var local = {};
			local.bytes = instance.properties.getProperty(instance.MAX_UPLOAD_FILE_BYTES, "5000000");
			return int(local.bytes);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="private" returntype="void" name="loadConfiguration" output="false"
	            hint="Load configuration. Never prints properties.">
	
		<cfscript>
			try {
				//first attempt file IO loading of properties
				logSpecial("Attempting to load " & this.RESOURCE_FILE & " via file io.");
				instance.properties = loadPropertiesFromStream(getResourceStream(this.RESOURCE_FILE), this.RESOURCE_FILE);
			}
			catch(java.io.FileNotFoundException iae) {
				//if file io loading fails, attempt classpath based loading next
				logSpecial("Loading " & this.RESOURCE_FILE & " via file io failed.");
				logSpecial("Attempting to load " & this.RESOURCE_FILE & " via the classpath.");
				try {
					instance.properties = loadConfigurationFromClasspath(this.RESOURCE_FILE);
				}
				catch(java.lang.IllegalArgumentException e) {
					logSpecial(this.RESOURCE_FILE & " could not be loaded by any means. fail.", e);
				}
			}
		</cfscript>
		
	</cffunction>
	
	<cffunction access="private" returntype="Properties" name="loadConfigurationFromClasspath" output="false">
		<cfargument required="true" type="String" name="fileName"/>
	
		<cfscript>
			var local = {};
		
			local.result = "";
			local.input = "";
		
			local.loaders = [getJava("java.lang.Thread").currentThread().getContextClassLoader(), getJava("java.lang.ClassLoader").getSystemClassLoader(), getPageContext().getClass().getClassLoader()];
		
			local.currentLoader = "";
			for(local.i = 1; local.i <= arrayLen(local.loaders); local.i++) {
				if(isObject(local.loaders[local.i])) {
					local.currentLoader = local.loaders[local.i];
					try {
						// try root
						local.input = local.loaders[local.i].getResourceAsStream(arguments.fileName);
					
						// try .esapi folder
						if(!structKeyExists(local, "in")) {
							local.in = local.currentLoader.getResourceAsStream(".esapi/" & arguments.fileName);
						}
					
						// try resources folder
						if(!structKeyExists(local, "in")) {
							local.in = local.currentLoader.getResourceAsStream("resources/" & arguments.fileName);
						}
					
						// now load the properties
						if(structKeyExists(local, "in")) {
							local.result = getJava("java.util.Properties").init();
							local.result.load(local.in);// Can throw IOException
							logSpecial("Successfully loaded " & arguments.fileName & " via the classpath! BOO-YA!");
						}
					}
					catch(java.lang.Exception e) {
						local.result = "";
					}
					if(structKeyExists(local, "in")) {
						try {
							local.in.close();
						}
						catch(java.lang.Exception e) {
						}
					}
				}
			}
		
			if(local.result == "") {
				throwException(getJava("java.lang.IllegalArgumentException").init("[CFESAPI] Failed to load " & this.RESOURCE_FILE & " as a classloader resource."));
			}
		
			return local.result;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="private" returntype="void" name="logSpecial" output="false"
	            hint="Used to log errors to the console during the loading of the properties file itself. Can't use standard logging in this case, since the Logger is not initialized yet.">
		<cfargument required="true" type="String" name="message" hint="The message to send to the console."/>
		<cfargument required="false" name="e" hint="The error that occured (this value is currently ignored)."/>
	
		<cfscript>
			System.out.println("[CFESAPI] " & arguments.message);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getPasswordParameterName" output="false">
	
		<cfscript>
			return instance.properties.getProperty(instance.PASSWORD_PARAMETER_NAME, "password");
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getUsernameParameterName" output="false">
	
		<cfscript>
			return instance.properties.getProperty(instance.USERNAME_PARAMETER_NAME, "username");
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getEncryptionAlgorithm" output="false">
	
		<cfscript>
			return instance.properties.getProperty(instance.ENCRYPTION_ALGORITHM, "PBEWithMD5AndDES/CBC/PKCS5Padding");
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getHashAlgorithm" output="false">
	
		<cfscript>
			return instance.properties.getProperty(instance.HASH_ALGORITHM, "SHA-512");
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false">
	
		<cfscript>
			return instance.properties.getProperty(instance.CHARACTER_ENCODING, "UTF-8");
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getDigitalSignatureAlgorithm" output="false">
	
		<cfscript>
			return instance.properties.getProperty(instance.DIGITAL_SIGNATURE_ALGORITHM, "SHAwithDSA");
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getRandomAlgorithm" output="false">
	
		<cfscript>
			return instance.properties.getProperty(instance.RANDOM_ALGORITHM, "SHA1PRNG");
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="numeric" name="getAllowedLoginAttempts" output="false">
	
		<cfscript>
			var local = {};
			local.attempts = instance.properties.getProperty(instance.ALLOWED_LOGIN_ATTEMPTS, "5");
			return getJava("java.lang.Integer").parseInt(local.attempts);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="numeric" name="getMaxOldPasswordHashes" output="false">
	
		<cfscript>
			var local = {};
			local.max = instance.properties.getProperty(instance.MAX_OLD_PASSWORD_HASHES, "12");
			return getJava("java.lang.Integer").parseInt(local.max);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="boolean" name="getDisableIntrusionDetection" output="false">
	
		<cfscript>
			var local = {};
			local.value = instance.properties.getProperty(instance.DISABLE_INTRUSION_DETECTION);
			if(structKeyExists(local, "value") && local.value.equalsIgnoreCase("true"))
				return true;
			return false;// Default result
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" name="getQuota" output="false">
		<cfargument required="true" type="String" name="eventName"/>
	
		<cfscript>
			var local = {};
			local.count = 0;
			local.countString = instance.properties.getProperty(arguments.eventName & ".count");
			if(structKeyExists(local, "countString")) {
				local.count = getJava("java.lang.Integer").parseInt(local.countString);
			}
		
			local.interval = 0;
			local.intervalString = instance.properties.getProperty(arguments.eventName & ".interval");
			if(structKeyExists(local, "intervalString")) {
				local.interval = getJava("java.lang.Integer").parseInt(local.intervalString);
			}
		
			local.actions = [];
			local.actionString = instance.properties.getProperty(arguments.eventName & ".actions");
			if(structKeyExists(local, "actionString")) {
				local.actionList = local.actionString.split(",");
				local.actions = getJava("java.util.Arrays").asList(local.actionList);
			}
		
			local.q = getJava("org.owasp.esapi.SecurityConfiguration$Threshold").init(javaCast("string", arguments.eventName), javaCast("int", local.count), javaCast("long", local.interval), local.actions);
			return local.q;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="numeric" name="getLogLevel" output="false">
	
		<cfscript>
			var local = {};
			local.level = instance.properties.getProperty(instance.LOG_LEVEL);
			if(!structKeyExists(local, "level")) {
				// This error is NOT logged the normal way because the logger constructor calls getLogLevel() and if this error occurred it would cause an infinite loop.
				logSpecial("The LOG-LEVEL property in the ESAPI properties file is not defined.", "");
				return getJava("org.owasp.esapi.Logger").WARNING;
			}
			if(local.level.equalsIgnoreCase("OFF"))
				return getJava("org.owasp.esapi.Logger").OFF;
			if(local.level.equalsIgnoreCase("FATAL"))
				return getJava("org.owasp.esapi.Logger").FATAL;
			if(local.level.equalsIgnoreCase("ERROR"))
				return getJava("org.owasp.esapi.Logger").ERROR;
			if(local.level.equalsIgnoreCase("WARNING"))
				return getJava("org.owasp.esapi.Logger").WARNING;
			if(local.level.equalsIgnoreCase("INFO"))
				return getJava("org.owasp.esapi.Logger").INFO;
			if(local.level.equalsIgnoreCase("DEBUG"))
				return getJava("org.owasp.esapi.Logger").DEBUG;
			if(local.level.equalsIgnoreCase("TRACE"))
				return getJava("org.owasp.esapi.Logger").TRACE;
			if(local.level.equalsIgnoreCase("ALL"))
				return getJava("org.owasp.esapi.Logger").ALL;
		
			// This error is NOT logged the normal way because the logger constructor calls getLogLevel() and if this error occurred it would cause an infinite loop.
			logSpecial("The LOG-LEVEL property in the ESAPI properties file has the unrecognized value: " & local.level, "");
			return getJava("org.owasp.esapi.Logger").WARNING;// Note: The default logging level is WARNING.
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getLogFileName" output="false">
	
		<cfscript>
			return instance.properties.getProperty(instance.LOG_FILE_NAME, "ESAPI_logging_file");
		</cfscript>
		
	</cffunction>
	
	<cfscript>
		/**
		 * The default max log file size is set to 10,000,000 bytes (10 Meg). If the
		 * current log file exceeds the current max log file size, the logger will
		 * move the old log data into another log file. There currently is a max of
		 * 1000 log files of the same name. If that is exceeded it will presumably
		 * start discarding the oldest logs.
		 */
		this.DEFAULT_MAX_LOG_FILE_SIZE = 10000000;
	</cfscript>
	
	<cffunction access="public" returntype="numeric" name="getMaxLogFileSize" output="false">
	
		<cfscript>
			var local = {};
			// The default is 10 Meg if the property is not specified
			local.value = instance.properties.getProperty(instance.MAX_LOG_FILE_SIZE);
			if(local.value == "")
				return DEFAULT_MAX_LOG_FILE_SIZE;
		
			try {
				return Integer.parseInt(value);
			}
			catch(NumberFormatException e) {
				return DEFAULT_MAX_LOG_FILE_SIZE;
			}
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="boolean" name="getLogDefaultLog4J" output="false">
	
		<cfscript>
			var local = {};
			local.value = instance.properties.getProperty(instance.LOG_DEFAULT_LOG4J);
			if(structKeyExists(local, "value") && local.value.equalsIgnoreCase("true"))
				return true;
			return false;// Default result
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="boolean" name="getLogEncodingRequired" output="false">
	
		<cfscript>
			var local = {};
			local.value = instance.properties.getProperty(instance.LOG_ENCODING_REQUIRED);
			if(structKeyExists(local, "value") && local.value.equalsIgnoreCase("true"))
				return true;
			return false;// Default result
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getResponseContentType" output="false">
	
		<cfscript>
			return instance.properties.getProperty(instance.RESPONSE_CONTENT_TYPE, "text/html; charset=UTF-8");
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="numeric" name="getRememberTokenDuration" output="false">
	
		<cfscript>
			var local = {};
			local.value = instance.properties.getProperty(instance.REMEMBER_TOKEN_DURATION, "14");
			local.days = getJava("java.lang.Long").parseLong(local.value);
			local.duration = 1000 * 60 * 60 * 24 * local.days;
			return local.duration;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="numeric" name="getSessionIdleTimeoutLength" output="false">
	
		<cfscript>
			var local = {};
			local.value = instance.properties.getProperty(instance.IDLE_TIMEOUT_DURATION, "20");
			local.minutes = getJava("java.lang.Integer").parseInt(local.value);
			local.duration = 1000 * 60 * local.minutes;
			return local.duration;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="numeric" name="getSessionAbsoluteTimeoutLength" output="false">
	
		<cfscript>
			var local = {};
			local.value = instance.properties.getProperty(instance.ABSOLUTE_TIMEOUT_DURATION, "120");
			local.minutes = getJava("java.lang.Integer").parseInt(local.value);
			local.duration = 1000 * 60 * local.minutes;
			return local.duration;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" name="getValidationPatternNames" output="false" hint="getValidationPattern names returns validator pattern names from ESAPI's global properties">
	
		<cfscript>
			var local = {};
			local.list = [];
			local.i = instance.properties.keySet().iterator();
			while(local.i.hasNext()) {
				local.name = local.i.next();
				if(local.name.startsWith("Validator.")) {
					local.list.add(local.name.substring(local.name.indexOf('.') + 1));
				}
			}
			return local.list.iterator();
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" name="getValidationPattern" output="false" hint="getValidationPattern returns a single pattern based upon key">
		<cfargument required="true" type="String" name="key" hint="validation pattern name you'd like"/>
	
		<cfscript>
			var local = {};
			local.value = instance.properties.getProperty("Validator." & arguments.key);
			if(!structKeyExists(local, "value") || local.value == "")
				return "";
			local.pattern = getJava("java.util.regex.Pattern").compile(local.value);
			return local.pattern;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="private" name="loadPropertiesFromStream" output="false">
		<cfargument required="true" name="is"/>
		<cfargument required="true" type="String" name="name"/>
	
		<cfscript>
			var local = {};
			local.config = getJava("java.util.Properties").init();
			try {
				local.config.load(arguments.is);
				logSpecial("successfully loaded '" & arguments.name & "' via an inputStream.");
			}
			catch(any e) {
			}
			if(isObject(arguments.is))
				try {
					arguments.is.close();
				}
				catch(java.lang.Exception e) {
				}
			return local.config;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" name="getResourceStream" output="false" hint="Utility method to get a resource as an InputStream. The search looks for an 'esapi-resources' directory in the setResourceDirectory() location, then the System.getProperty( 'org.owasp.esapi.resources' ) location, then the System.getProperty( 'user.home' ) location, and then the classpath.">
		<cfargument required="true" type="String" name="filename"/>
	
		<cfscript>
			var local = {};
			local.f = "";
			if(arguments.filename == "") {
				return "";
			}
		
			try {
				local.f = getResourceFile(arguments.filename);
				if(isObject(local.f) && local.f.exists()) {
					return getJava("java.io.FileInputStream").init(local.f);
				}
			}
			catch(java.lang.Exception e) {
			}
			throwException(getJava("java.io.FileNotFoundException").init());
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" name="getResourceFile" output="false">
		<cfargument required="true" type="String" name="filename"/>
	
		<cfscript>
			var local = {};
			local.fileSeparator = getJava("java.io.File").separator;
		
			logSpecial("Attempting to load " & arguments.filename & " via file io.");
		
			if(arguments.filename == "") {
				logSpecial("Failed to load properties via FileIO. Filename is empty.");
				return "";// not found.
			}
		
			// first, allow command line overrides. -Dorg.owasp.esapi.resources
			// directory
			if(structKeyExists(instance, "customDirectory")) {
				local.f = getJava("java.io.File").init(expandPath(instance.customDirectory), arguments.filename);
				if(instance.customDirectory != "" && local.f.canRead()) {
					logSpecial("Found in 'cfesapi.org.owasp.esapi.resources' directory: " & local.f.getAbsolutePath());
					return local.f;
				}
				else {
					logSpecial("Not found in 'cfesapi.org.owasp.esapi.resources' directory or file not readable: " & local.f.getAbsolutePath());
				}
			}
		
			// if not found, then try the programatically set resource directory
			// (this defaults to SystemResource directory/RESOURCE_FILE
			if(structKeyExists(instance, "resourceDirectory")) {
				local.fileLocation = expandPath(instance.resourceDirectory & local.fileSeparator & arguments.filename);
				if(fileExists(local.fileLocation)) {
					local.f = getJava("java.io.File").init(local.fileLocation);
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
			}
		
			// if not found, then try the user's home directory
			if(structKeyExists(instance, "userDirectory")) {
				local.f = getJava("java.io.File").init(instance.userDirectory, arguments.filename);
				if(instance.userDirectory != "" && local.f.exists()) {
					logSpecial("Found in 'user.home' directory: " & local.f.getAbsolutePath());
					return local.f;
				}
				else {
					logSpecial("Not found in 'user.home' directory: " & local.f.getAbsolutePath());
				}
			}
		
			// return empty if not found
			return "";
		</cfscript>
		
	</cffunction>
	
</cfcomponent>