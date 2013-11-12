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
<cfcomponent implements="org.owasp.esapi.SecurityConfiguration" extends="org.owasp.esapi.util.Object" output="false" hint="The SecurityConfiguration manages all the settings used by the ESAPI in a single place. Initializing the Configuration is critically important to getting the ESAPI working properly. You must set a system property before invoking any part of the ESAPI. You may have to add this to the batch script that starts your web server. For example, in the 'catalina' script that starts Tomcat, you can set the JAVA_OPTS variable to the -D string above. Once the Configuration is initialized with a resource directory, you can edit it to set things like master keys and passwords, logging locations, error thresholds, and allowed file extensions.">

	<cfscript>
		/** The properties. */
		variables.properties = newJava("java.util.Properties").init();

		/** The name of the ESAPI property file */
		this.RESOURCE_FILE = "ESAPI.properties";

		/** The location of the Resources directory used by ESAPI. */
		this.RESOURCE_DIRECTORY = "org.owasp.esapi.resources";

		// private
		variables.ALLOWED_LOGIN_ATTEMPTS = "AllowedLoginAttempts";
		variables.APPLICATION_NAME = "ApplicationName";
		variables.MASTER_PASSWORD = "MasterPassword";
		variables.MASTER_SALT = "MasterSalt";
		variables.VALID_EXTENSIONS = "ValidExtensions";
		variables.MAX_UPLOAD_FILE_BYTES = "MaxUploadFileBytes";
		variables.USERNAME_PARAMETER_NAME = "UsernameParameterName";
		variables.PASSWORD_PARAMETER_NAME = "PasswordParameterName";
		variables.MAX_OLD_PASSWORD_HASHES = "MaxOldPasswordHashes";
		variables.ENCRYPTION_ALGORITHM = "EncryptionAlgorithm";
		variables.HASH_ALGORITHM = "HashAlgorithm";
		variables.CHARACTER_ENCODING = "CharacterEncoding";
		variables.RANDOM_ALGORITHM = "RandomAlgorithm";
		variables.DIGITAL_SIGNATURE_ALGORITHM = "DigitalSignatureAlgorithm";
		variables.RESPONSE_CONTENT_TYPE = "ResponseContentType";
		variables.REMEMBER_TOKEN_DURATION = "RememberTokenDuration";
		variables.IDLE_TIMEOUT_DURATION = "IdleTimeoutDuration";
		variables.ABSOLUTE_TIMEOUT_DURATION = "AbsoluteTimeoutDuration";
		variables.DISABLE_INTRUSION_DETECTION = "DisableIntrusionDetection";
		variables.LOG_LEVEL = "LogLevel";
		variables.LOG_FILE_NAME = "LogFileName";
		variables.MAX_LOG_FILE_SIZE = "MaxLogFileSize";
		variables.LOG_ENCODING_REQUIRED = "LogEncodingRequired";
		variables.LOG_DEFAULT_LOG4J = "LogDefaultLog4J";

		//protected
		variables.MAX_REDIRECT_LOCATION = 1000;
		variables.MAX_FILE_NAME_LENGTH = 1000;

		/**
		 * Load properties from properties file. Set this with setResourceDirectory
		 * from your web application or ESAPI filter.
		 */
		variables.resourceDirectory = System.getProperty(this.RESOURCE_DIRECTORY);
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.SecurityConfiguration" name="init" output="false"
	            hint="Instantiates a new configuration.">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument type="String" name="resourceDirectory">

		<cfscript>
			if (structKeyExists(arguments, "resourceDirectory")) {
				variables.resourceDirectory = arguments.resourceDirectory;
			}

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
			// prefer the CF application name
			if(structKeyExists(application, "applicationName")) {
				return application.applicationName;
			}
			// fallback on the ESAPI.properties ApplicationName
			return variables.properties.getProperty(variables.APPLICATION_NAME, "AppNameNotSpecified");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getMasterPassword" output="false">

		<cfscript>
			return variables.properties.getProperty(variables.MASTER_PASSWORD).toCharArray();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getKeystore" output="false">

		<cfscript>
			return newJava("java.io.File").init(getResourceDirectory(), "keystore");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getResourceDirectory" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var fileSeparator = "";

			if(!structKeyExists(variables, "resourceDirectory")) {
				variables.resourceDirectory = "";
			}
			fileSeparator = newJava("java.io.File").separator;
			if(trim(len(variables.resourceDirectory)) && !variables.resourceDirectory.endsWith(fileSeparator)) {
				variables.resourceDirectory &= fileSeparator;
			}
			return variables.resourceDirectory;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setResourceDirectory" output="false">
		<cfargument required="true" type="String" name="dir"/>

		<cfscript>
			variables.resourceDirectory = arguments.dir;
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
			return variables.properties.getProperty(variables.MASTER_SALT).getBytes();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getAllowedFileExtensions" output="false">

		<cfscript>
			var def = ".zip,.pdf,.tar,.gz,.xls,.properties,.txt,.xml";
			var extList = variables.properties.getProperty(variables.VALID_EXTENSIONS, def).split(",");
			return extList;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getAllowedFileUploadSize" output="false">

		<cfscript>
			var bytes = variables.properties.getProperty(variables.MAX_UPLOAD_FILE_BYTES, "5000000");
			return int(bytes);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="loadConfiguration" output="false"
	            hint="Load configuration. Never prints properties.">

		<cfscript>
			try {
				//first attempt file IO loading of properties
				logSpecial("Attempting to load " & this.RESOURCE_FILE & " via file io.");
				variables.properties = loadPropertiesFromStream(getResourceStream(this.RESOURCE_FILE), this.RESOURCE_FILE);
			}
			catch(java.io.FileNotFoundException iae) {
				//if file io loading fails, attempt classpath based loading next
				logSpecial("Loading " & this.RESOURCE_FILE & " via file io failed.");
				logSpecial("Attempting to load " & this.RESOURCE_FILE & " via the classpath.");
				try {
					variables.properties = loadConfigurationFromClasspath(this.RESOURCE_FILE);
				}
				catch(java.lang.IllegalArgumentException e) {
					logSpecial(this.RESOURCE_FILE & " could not be loaded by any means. fail.", e);
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" name="loadConfigurationFromClasspath" output="false">
		<cfargument required="true" type="String" name="fileName"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";

			var result = "";
			var ins = "";
			var loaders = [newJava("java.lang.Thread").currentThread().getContextClassLoader(), newJava("java.lang.ClassLoader").getSystemClassLoader()];

			var currentLoader = "";
			for(i = 1; i <= arrayLen(loaders); i++) {
				if(isObject(loaders[i])) {
					currentLoader = loaders[i];
					try {
						// try root
						ins = loaders[i].getResourceAsStream(arguments.fileName);

						// try .esapi folder
						if(!(isDefined("ins") && !cf8_isNull(ins))) {
							ins = currentLoader.getResourceAsStream(".esapi/" & arguments.fileName);
						}

						// try resources folder
						if(!(isDefined("ins") && !cf8_isNull(ins))) {
							ins = currentLoader.getResourceAsStream("resources/" & arguments.fileName);
						}

						// now load the properties
						if(isDefined("ins") && !cf8_isNull(ins)) {
							result = newJava("java.util.Properties").init();
							result.load(ins);// Can throw IOException
							logSpecial("Successfully loaded " & arguments.fileName & " via the classpath! BOO-YA!");
						}
					}
					catch(java.lang.Exception e) {
						result = "";
					}
					if(isDefined("ins") && !cf8_isNull(ins)) {
						try {
							ins.close();
						}
						catch(java.lang.Exception e) {
						}
					}
				}
			}

			if(!isObject(result)) {
				throwException(newJava("java.lang.IllegalArgumentException").init("[" & this.ESAPINAME & "] Failed to load " & this.RESOURCE_FILE & " as a classloader resource."));
			}

			return result;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="logSpecial" output="false"
	            hint="Used to log errors to the console during the loading of the properties file itself. Can't use standard logging in this case, since the Logger is not initialized yet.">
		<cfargument required="true" type="String" name="message" hint="The message to send to the console."/>
		<cfargument required="false" name="e" hint="The error that occured (this value is currently ignored)."/>

		<cfscript>
			System.out.println("[" & this.ESAPINAME & "] " & arguments.message);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getPasswordParameterName" output="false">

		<cfscript>
			return variables.properties.getProperty(variables.PASSWORD_PARAMETER_NAME, "password");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getUsernameParameterName" output="false">

		<cfscript>
			return variables.properties.getProperty(variables.USERNAME_PARAMETER_NAME, "username");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getEncryptionAlgorithm" output="false">

		<cfscript>
			return variables.properties.getProperty(variables.ENCRYPTION_ALGORITHM, "PBEWithMD5AndDES/CBC/PKCS5Padding");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getHashAlgorithm" output="false">

		<cfscript>
			return variables.properties.getProperty(variables.HASH_ALGORITHM, "SHA-512");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false">

		<cfscript>
			return variables.properties.getProperty(variables.CHARACTER_ENCODING, "UTF-8");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getDigitalSignatureAlgorithm" output="false">

		<cfscript>
			return variables.properties.getProperty(variables.DIGITAL_SIGNATURE_ALGORITHM, "SHAwithDSA");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRandomAlgorithm" output="false">

		<cfscript>
			return variables.properties.getProperty(variables.RANDOM_ALGORITHM, "SHA1PRNG");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getAllowedLoginAttempts" output="false">

		<cfscript>
			var attempts = variables.properties.getProperty(variables.ALLOWED_LOGIN_ATTEMPTS, "5");
			return newJava("java.lang.Integer").parseInt(attempts);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getMaxOldPasswordHashes" output="false">

		<cfscript>
			var max = variables.properties.getProperty(variables.MAX_OLD_PASSWORD_HASHES, "12");
			return newJava("java.lang.Integer").parseInt(max);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="getDisableIntrusionDetection" output="false">

		<cfscript>
			var value = variables.properties.getProperty(variables.DISABLE_INTRUSION_DETECTION);
			if(isDefined("value") && !cf8_isNull(value) && value.equalsIgnoreCase("true"))
				return true;
			return false;// Default result
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getQuota" output="false">
		<cfargument required="true" type="String" name="eventName"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var count = "";
			var countString = "";
			var interval = "";
			var intervalString = "";
			var actions = "";
			var actionString = "";
			var actionList = "";
			var q = "";

			count = 0;
			countString = variables.properties.getProperty(arguments.eventName & ".count");
			if(isDefined("countString") && !cf8_isNull(countString)) {
				count = newJava("java.lang.Integer").parseInt(countString);
			}

			interval = 0;
			intervalString = variables.properties.getProperty(arguments.eventName & ".interval");
			if(isDefined("intervalString") && !cf8_isNull(intervalString)) {
				interval = newJava("java.lang.Integer").parseInt(intervalString);
			}

			actions = [];
			actionString = variables.properties.getProperty(arguments.eventName & ".actions");
			if(isDefined("actionString") && !cf8_isNull(actionString)) {
				actionList = actionString.split(",");
				actions = newJava("java.util.Arrays").asList(actionList);
			}

			q = newJava("org.owasp.esapi.SecurityConfiguration$Threshold").init(javaCast("string", arguments.eventName), javaCast("int", count), javaCast("long", interval), actions);
			return q;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getLogLevel" output="false">

		<cfscript>
			var level = variables.properties.getProperty(variables.LOG_LEVEL);
			if(!(isDefined("level") && !cf8_isNull(level))) {
				// This error is NOT logged the normal way because the logger constructor calls getLogLevel() and if this error occurred it would cause an infinite loop.
				logSpecial("The LOG-LEVEL property in the ESAPI properties file is not defined.", "");
				return newJava("org.owasp.esapi.Logger").WARNING;
			}
			if(level.equalsIgnoreCase("OFF"))
				return newJava("org.owasp.esapi.Logger").OFF;
			if(level.equalsIgnoreCase("FATAL"))
				return newJava("org.owasp.esapi.Logger").FATAL;
			if(level.equalsIgnoreCase("ERROR"))
				return newJava("org.owasp.esapi.Logger").ERROR;
			if(level.equalsIgnoreCase("WARNING"))
				return newJava("org.owasp.esapi.Logger").WARNING;
			if(level.equalsIgnoreCase("INFO"))
				return newJava("org.owasp.esapi.Logger").INFO;
			if(level.equalsIgnoreCase("DEBUG"))
				return newJava("org.owasp.esapi.Logger").DEBUG;
			if(level.equalsIgnoreCase("TRACE"))
				return newJava("org.owasp.esapi.Logger").TRACE;
			if(level.equalsIgnoreCase("ALL"))
				return newJava("org.owasp.esapi.Logger").ALL;

			// This error is NOT logged the normal way because the logger constructor calls getLogLevel() and if this error occurred it would cause an infinite loop.
			logSpecial("The LOG-LEVEL property in the ESAPI properties file has the unrecognized value: " & level, "");
			return newJava("org.owasp.esapi.Logger").WARNING;// Note: The default logging level is WARNING.
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLogFileName" output="false">

		<cfscript>
			return variables.properties.getProperty(variables.LOG_FILE_NAME, "ESAPI_logging_file");
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
			// The default is 10 Meg if the property is not specified
			var value = variables.properties.getProperty(variables.MAX_LOG_FILE_SIZE);
			if(value == "")
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
			var value = variables.properties.getProperty(variables.LOG_DEFAULT_LOG4J);
			if(isDefined("value") && !cf8_isNull(value) && value.equalsIgnoreCase("true"))
				return true;
			return false;// Default result
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="getLogEncodingRequired" output="false">

		<cfscript>
			var value = variables.properties.getProperty(variables.LOG_ENCODING_REQUIRED);
			if(isDefined("value") && !cf8_isNull(value) && value.equalsIgnoreCase("true"))
				return true;
			return false;// Default result
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getResponseContentType" output="false">

		<cfscript>
			return variables.properties.getProperty(variables.RESPONSE_CONTENT_TYPE, "text/html; charset=UTF-8");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getRememberTokenDuration" output="false">

		<cfscript>
			var value = variables.properties.getProperty(variables.REMEMBER_TOKEN_DURATION, "14");
			var days = newJava("java.lang.Long").parseLong(value);
			var duration = 1000 * 60 * 60 * 24 * days;
			return duration;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getSessionIdleTimeoutLength" output="false">

		<cfscript>
			var value = variables.properties.getProperty(variables.IDLE_TIMEOUT_DURATION, "20");
			var minutes = newJava("java.lang.Integer").parseInt(value);
			var duration = 1000 * 60 * minutes;
			return duration;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getSessionAbsoluteTimeoutLength" output="false">

		<cfscript>
			var value = variables.properties.getProperty(variables.ABSOLUTE_TIMEOUT_DURATION, "120");
			var minutes = newJava("java.lang.Integer").parseInt(value);
			var duration = 1000 * 60 * minutes;
			return duration;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getValidationPatternNames" output="false" hint="getValidationPattern names returns validator pattern names from ESAPI's global properties">

		<cfscript>
			// CF8 requires 'var' at the top
			var name = "";

			var list = [];
			var i = variables.properties.keySet().iterator();
			while(i.hasNext()) {
				name = i.next();
				if(name.startsWith("Validator.")) {
					list.add(name.substring(name.indexOf('.') + 1));
				}
			}
			return list.iterator();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getValidationPattern" output="false" hint="getValidationPattern returns a single pattern based upon key">
		<cfargument required="true" type="String" name="key" hint="validation pattern name you'd like"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var pattern = "";

			var value = variables.properties.getProperty("Validator." & arguments.key);
			if(!(isDefined("value") && !cf8_isNull(value)) || value == "")
				return "";
			pattern = newJava("java.util.regex.Pattern").compile(value);
			return pattern;
		</cfscript>

	</cffunction>

	<cffunction access="private" name="loadPropertiesFromStream" output="false">
		<cfargument required="true" name="is"/>
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			var config = newJava("java.util.Properties").init();
			try {
				config.load(arguments.is);
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
			return config;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getResourceStream" output="false" hint="Utility method to get a resource as an InputStream. The search looks for an 'esapi-resources' directory in the setResourceDirectory() location, then the System.getProperty( 'org.owasp.esapi.resources' ) location, then the System.getProperty( 'user.home' ) location, and then the classpath.">
		<cfargument required="true" type="String" name="filename"/>

		<cfscript>
			var f = "";
			if(arguments.filename == "") {
				return "";
			}

			try {
				f = getResourceFile(arguments.filename);
				if(isObject(f) && f.exists()) {
					return newJava("java.io.FileInputStream").init(f);
				}
			}
			catch(java.lang.Exception e) {
			}
			throwException(newJava("java.io.FileNotFoundException").init());
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getResourceFile" output="false">
		<cfargument required="true" type="String" name="filename"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var fileLocation = "";

			var fileSeparator = newJava("java.io.File").separator;
			var f = "";

			logSpecial("Attempting to load " & arguments.filename & " via file io.");

			if(arguments.filename == "") {
				logSpecial("Failed to load properties via FileIO. Filename is empty.");
				return "";// not found.
			}

			// check specific setting first
			// (this defaults to SystemResource directory/RESOURCE_FILE)
			if(structKeyExists(variables, "resourceDirectory")) {
				fileLocation = expandPath(variables.resourceDirectory & fileSeparator & arguments.filename);
				if(fileExists(fileLocation)) {
					f = newJava("java.io.File").init(fileLocation);
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

			// return empty if not found
			return "";
		</cfscript>

	</cffunction>

</cfcomponent>