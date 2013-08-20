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
<cfinterface hint="The SecurityConfiguration interface stores all configuration information that directs the behavior of the ESAPI implementation. Protection of this configuration information is critical to the secure operation of the application using the ESAPI. You should use operating system access controls to limit access to wherever the configuration information is stored. Please note that adding another layer of encryption does not make the attackers job much more difficult. Somewhere there must be a master 'secret' that is stored unencrypted on the application platform. Creating another layer of indirection doesn't provide any real additional security. Its up to the reference implementation to decide whether this file should be encrypted or not. The ESAPI reference implementation (DefaultSecurityConfiguration.java) does not encrypt its properties file.">

	<cffunction access="public" returntype="String" name="getApplicationName" output="false" hint="Gets the application name, used for logging">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getMasterPassword" output="false" hint="Gets the master password. This password can be used to encrypt/decrypt other files or types of data that need to be protected by your application.">
	</cffunction>


	<cffunction access="public" name="getKeystore" output="false" hint="Gets the keystore used to hold any encryption keys used by your application.">
	</cffunction>


	<cffunction access="public" returntype="binary" name="getMasterSalt" output="false" hint="Gets the master salt that is used to salt stored password hashes and any other location where a salt is needed.">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getAllowedFileExtensions" output="false" hint="Gets the allowed file extensions for files that are uploaded to this application.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getAllowedFileUploadSize" output="false" hint="Gets the maximum allowed file upload size.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getPasswordParameterName" output="false" hint="Gets the name of the password parameter used during user authentication.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getUsernameParameterName" output="false" hint="Gets the name of the username parameter used during user authentication.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getEncryptionAlgorithm" output="false" hint="Gets the encryption algorithm used by ESAPI to protect data.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getHashAlgorithm" output="false" hint="Gets the hashing algorithm used by ESAPI to hash data.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false" hint="Gets the character encoding scheme supported by this application. This is used to set the character encoding scheme on requests and responses when setCharacterEncoding() is called on SafeRequests and SafeResponses. This scheme is also used for encoding/decoding URLs and any other place where the current encoding scheme needs to be known. Note: This does not get the configured response content type. That is accessed by calling getResponseContentType().">
	</cffunction>


	<cffunction access="public" returntype="String" name="getDigitalSignatureAlgorithm" output="false" hint="Gets the digital signature algorithm used by ESAPI to generate and verify signatures.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getRandomAlgorithm" output="false" hint="Gets the random number generation algorithm used to generate random numbers where needed.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getAllowedLoginAttempts" output="false" hint="Gets the number of login attempts allowed before the user's account is locked. If this many failures are detected within the alloted time period, the user's account will be locked.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getMaxOldPasswordHashes" output="false" hint="Gets the maximum number of old password hashes that should be retained. These hashes can be used to ensure that the user doesn't reuse the specified number of previous passwords when they change their password.">
	</cffunction>


	<cffunction access="public" name="getQuota" output="false" hint="Gets the intrusion detection quota for the specified event.">
		<cfargument required="true" type="String" name="eventName" hint="the name of the event whose quota is desired">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getDisableIntrusionDetection" output="false" hint="Allows for complete disabling of all intrusion detection mechanisms">
	</cffunction>


	<cffunction access="public" returntype="String" name="getResourceDirectory" output="false" hint="Gets the name of the ESAPI resource directory as a String.">
	</cffunction>


	<cffunction access="public" returntype="void" name="setResourceDirectory" output="false" hint="Sets the ESAPI resource directory.">
		<cfargument required="true" type="String" name="dir">
	</cffunction>


	<cffunction access="public" returntype="String" name="getResponseContentType" output="false" hint="Gets the content type for responses used when setSafeContentType() is called. Note: This does not get the configured character encoding scheme. That is accessed by calling getCharacterEncoding().">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getRememberTokenDuration" output="false" hint="Gets the length of the time to live window for remember me tokens (in milliseconds).">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getSessionIdleTimeoutLength" output="false" hint="Gets the idle timeout length for sessions (in milliseconds). This is the amount of time that a session can live before it expires due to lack of activity. Applications or frameworks could provide a reauthenticate function that enables a session to continue after reauthentication.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getSessionAbsoluteTimeoutLength" output="false" hint="Gets the absolute timeout length for sessions (in milliseconds). This is the amount of time that a session can live before it expires regardless of the amount of user activity. Applications or frameworks could provide a reauthenticate function that enables a session to continue after reauthentication.">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getLogEncodingRequired" output="false" hint="Returns whether HTML entity encoding should be applied to log entries.">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getLogDefaultLog4J" output="false" hint="As a backwards compatibility measure, the allows the default logging class to be log4j. This will eventually migrate to the ESAPI 2.0 configuration mechanism where any class with the right interface can be configured in ESAPI.properties.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getLogLevel" output="false" hint="Get the log level specified in the ESAPI configuration properties file. Return a default value if it is not specified in the properties file.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getLogFileName" output="false" hint="Get the name of the log file specified in the ESAPI configuration properties file. Return a default value if it is not specified.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getMaxLogFileSize" output="false" hint="Get the maximum size of a single log file from the ESAPI configuration properties file. Return a default value if it is not specified. Once the log hits this file size, it will roll over into a new log.">
	</cffunction>

</cfinterface>
