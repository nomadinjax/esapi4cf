<cfinterface hint="The SecurityConfiguration interface stores all configuration information that directs the behavior of the ESAPI implementation. Protection of this configuration information is critical to the secure operation of the application using the ESAPI. You should use operating system access controls to limit access to wherever the configuration information is stored. Please note that adding another layer of encryption does not make the attackers job much more difficult. Somewhere there must be a master 'secret' that is stored unencrypted on the application platform (unless you are willing to prompt for some passphrase when you application starts or insert a USB thumb drive or an HSM card, etc., in which case this master 'secret' it would only be in memory). Creating another layer of indirection provides additional obfuscation, but doesn't provide any real additional security. It's up to the reference implementation to decide whether this file should be encrypted or not. The ESAPI reference implementation (DefaultSecurityConfiguration.java) does NOT encrypt its properties file.">

	<cffunction access="public" returntype="String" name="getApplicationName" output="false" hint="Gets the application name, used for logging">
	</cffunction>


	<cffunction access="public" returntype="String" name="getLogImplementation" output="false" hint="Returns the fully qualified classname of the ESAPI Logging implementation.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getAuthenticationImplementation" output="false" hint="Returns the fully qualified classname of the ESAPI Authentication implementation.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getEncoderImplementation" output="false" hint="Returns the fully qualified classname of the ESAPI Encoder implementation.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getAccessControlImplementation" output="false" hint="Returns the fully qualified classname of the ESAPI Access Control implementation.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getIntrusionDetectionImplementation" output="false" hint="Returns the fully qualified classname of the ESAPI Intrusion Detection implementation.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getRandomizerImplementation" output="false" hint="Returns the fully qualified classname of the ESAPI Randomizer implementation.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getEncryptionImplementation" output="false" hint="Returns the fully qualified classname of the ESAPI Encryption implementation.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getValidationImplementation" output="false" hint="Returns the fully qualified classname of the ESAPI Validation implementation.">
	</cffunction>


	<cffunction access="public" returntype="any" name="getValidationPattern" output="false" hint="Returns the validation pattern for a particular type">
		<cfargument type="String" name="key" required="true">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getLenientDatesAccepted" output="false" hint="Determines whether ESAPI will accept 'lenient' dates when attempt to parse dates. Controlled by ESAPI property Validator.AcceptLenientDates, which defaults to false if unset.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getExecutorImplementation" output="false" hint="Returns the fully qualified classname of the ESAPI OS Execution implementation.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getHTTPUtilitiesImplementation" output="false" hint="Returns the fully qualified classname of the ESAPI HTTPUtilities implementation.">
	</cffunction>


	<cffunction access="public" returntype="binary" name="getMasterKey" output="false" hint="Gets the master key. This password is used to encrypt/decrypt other files or types of data that need to be protected by your application.">
	</cffunction>


	<cffunction access="public" returntype="any" name="getUploadDirectory" output="false" hint="java.io.File: Retrieves the upload directory as specified in the ESAPI.properties file.">
	</cffunction>


	<cffunction access="public" returntype="any" name="getUploadTempDirectory" output="false" hint="java.io.File: Retrieves the temp directory to use when uploading files, as specified in ESAPI.properties.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getEncryptionKeyLength" output="false" hint="Gets the key length to use in cryptographic operations declared in the ESAPI properties file.">
	</cffunction>


	<cffunction access="public" returntype="binary" name="getMasterSalt" output="false" hint="Gets the master salt that is used to salt stored password hashes and any other location where a salt is needed.">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getAllowedExecutables" output="false" hint="Gets the allowed executables to run with the Executor.">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getAllowedFileExtensions" output="false" hint="Gets the allowed file extensions for files that are uploaded to this application.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getAllowedFileUploadSize" output="false" hint="Gets the maximum allowed file upload size.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getPasswordParameterName" output="false" hint="Gets the name of the password parameter used during user authentication.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getUsernameParameterName" output="false" hint="Gets the name of the username parameter used during user authentication.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getEncryptionAlgorithm" output="false" hint="Gets the encryption algorithm used by ESAPI to protect data. This is mostly used for compatibility with ESAPI 1.4; ESAPI 2.0 prefers to use 'cipher transformation' since it supports multiple cipher modes and padding schemes.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getCipherTransformation" output="false" hint="Retrieve the cipher transformation.">
	</cffunction>

	<!--- @Deprecated --->

	<cffunction access="public" returntype="String" name="setCipherTransformation" output="false" hint="Set the cipher transformation. This allows a different cipher transformation to be used without changing the ESAPI.properties file. For instance you may normally want to use AES/CBC/PKCS5Padding, but have some legacy encryption where you have ciphertext that was encrypted using 3DES.">
		<cfargument type="String" name="cipherXform" required="true" hint="The new cipher transformation. See getCipherTransformation for format. If null is passed as the parameter, the cipher transformation will be set to the the default taken from the property Encryptor.CipherTransformation in the ESAPI.properties file. BEWARE: there is NO sanity checking here (other than the empty string, and then, only if Java assertions are enabled), so if you set this wrong, you will not get any errors until you later try to use it to encrypt or decrypt data.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getPreferredJCEProvider" output="false" hint="Retrieve the PREFERRED JCE provider for ESAPI and your application. ESAPI 2.0 now allows setting the property Encryptor.PreferredJCEProvider in the ESAPI.properties file, which will cause the specified JCE provider to be automatically and dynamically loaded (assuming that SecurityManager permissions allow) as the Ii&gt;preferred&lt;/i&gt; JCE provider. (Note this only happens if the JCE provider is not already loaded.) This method returns the property Encryptor.PreferredJCEProvider. By default, this Encryptor.PreferredJCEProvider property is set to an empty string, which means that the preferred JCE provider is not changed.">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="useMACforCipherText" output="false" hint="Determines whether the CipherText should be used with a Message Authentication Code (MAC). Generally this makes for a more robust cryptographic scheme, but there are some minor performance implications. Controlled by the ESAPI property Encryptor.CipherText.useMAC.">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="overwritePlainText" output="false" hint="Indicates whether the PlainText objects may be overwritten after they have been encrypted. Generally this is a good idea, especially if your VM is shared by multiple applications (e.g., multiple applications running in the same J2EE container) or if there is a possibility that your VM may leave a core dump (say because it is running non-native Java code. Controlled by the property Encryptor.PlainText.overwrite in the ESAPI.properties file.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getIVType" output="false" hint="Get a string indicating how to compute an Initialization Vector (IV). Currently supported modes are 'random' to generate a random IV or 'fixed' to use a fixed (static) IV. If a 'fixed' IV is chosen, then the the value of this fixed IV must be specified as the property Encryptor.fixedIV and be of the appropriate length.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getFixedIV" output="false" hint="If a 'fixed' (i.e., static) Initialization Vector (IV) is to be used, this will return the IV value as a hex-encoded string.">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getCombinedCipherModes" output="false" hint="Return a List of strings of combined cipher modes that support BOTH confidentiality and authenticity. These would be preferred cipher modes to use if your JCE provider supports them. If such a cipher mode is used, no explicit SEPARATE MAC is calculated as part of the CipherText object upon encryption nor is any attempt made to verify the same on decryption. The list is taken from the comma-separated list of cipher modes specified by the ESAPI property Encryptor.cipher_modes.combined_modes.">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getAdditionalAllowedCipherModes" output="false" hint="Return List of strings of additional cipher modes that are permitted (i.e., in ADDITION to those returned by getPreferredCipherModes()) to be used for encryption and decryption operations. The list is taken from the comma-separated list of cipher modes specified by the ESAPI property Encryptor.cipher_modes.additional_allowed.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getHashAlgorithm" output="false" hint="Gets the hashing algorithm used by ESAPI to hash data.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getHashIterations" output="false" hint="Gets the hash iterations used by ESAPI to hash data.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getKDFPseudoRandomFunction" output="false" hint="Retrieve the Pseudo Random Function (PRF) used by the ESAPI Key Derivation Function (KDF).">
	</cffunction>


	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false" hint="Gets the character encoding scheme supported by this application. This is used to set the character encoding scheme on requests and responses when setCharacterEncoding() is called on SafeRequests and SafeResponses. This scheme is also used for encoding/decoding URLs and any other place where the current encoding scheme needs to be known. Note: This does not get the configured response content type. That is accessed by calling getResponseContentType().">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getAllowMixedEncoding" output="false" hint="Return true if mixed encoding is allowed">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getAllowMultipleEncoding" output="false" hint="Return true if multiple encoding is allowed">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getDefaultCanonicalizationCodecs" output="false" hint="Returns the List of Codecs to use when canonicalizing data">
	</cffunction>


	<cffunction access="public" returntype="String" name="getDigitalSignatureAlgorithm" output="false" hint="Gets the digital signature algorithm used by ESAPI to generate and verify signatures.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getDigitalSignatureKeyLength" output="false" hint="Gets the digital signature key length used by ESAPI to generate and verify signatures.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getRandomAlgorithm" output="false" hint="Gets the random number generation algorithm used to generate random numbers where needed.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getAllowedLoginAttempts" output="false" hint="Gets the number of login attempts allowed before the user's account is locked. If this many failures are detected within the alloted time period, the user's account will be locked.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getMaxOldPasswordHashes" output="false" hint="Gets the maximum number of old password hashes that should be retained. These hashes can be used to ensure that the user doesn't reuse the specified number of previous passwords when they change their password.">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getDisableIntrusionDetection" output="false" hint="Allows for complete disabling of all intrusion detection mechanisms">
	</cffunction>


	<cffunction access="public" returntype="any" name="getQuota" output="false" hint="cfesapi.org.owasp.esapi.reference.Threshold: Gets the intrusion detection quota for the specified event.">
		<cfargument type="String" name="eventName" required="true" hint="the name of the event whose quota is desired">
	</cffunction>


	<cffunction access="public" returntype="any" name="getResourceFile" output="false" hint="java.io.File: Gets a file from the resource directory">
		<cfargument type="String" name="filename" required="true" hint="The file name resource.">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getForceHttpOnlySession" output="false" hint="Forces new cookies to have HttpOnly flag set.">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getForceSecureSession" output="false" hint="Forces session cookies to have Secure flag set.">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getForceHttpOnlyCookies" output="false" hint="Forces new cookies to have HttpOnly flag set.">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getForceSecureCookies" output="false" hint="Forces new cookies to have Secure flag set.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getMaxHttpHeaderSize" output="false" hint="Returns the maximum allowable HTTP header size.">
	</cffunction>


	<cffunction access="public" returntype="any" name="getResourceStream" output="false" hint="java.io.InputStream: Gets an InputStream to a file in the resource directory">
		<cfargument type="String" name="filename" required="true" hint="A file name in the resource directory.">
	</cffunction>


	<cffunction access="public" returntype="void" name="setResourceDirectory" output="false" hint="Sets the ESAPI resource directory.">
		<cfargument type="String" name="dir" required="true" hint="The location of the resource directory.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getResponseContentType" output="false" hint="Gets the content type for responses used when setSafeContentType() is called. Note: This does not get the configured character encoding scheme. That is accessed by calling getCharacterEncoding().">
	</cffunction>


	<cffunction access="public" returntype="String" name="getHttpSessionIdName" output="false" hint="This method returns the configured name of the session identifier, likely 'JSESSIONID' though this can be overridden.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getRememberTokenDuration" output="false" hint="Gets the length of the time to live window for remember me tokens (in milliseconds).">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getSessionIdleTimeoutLength" output="false" hint="Gets the idle timeout length for sessions (in milliseconds). This is the amount of time that a session can live before it expires due to lack of activity. Applications or frameworks could provide a reauthenticate function that enables a session to continue after reauthentication.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getSessionAbsoluteTimeoutLength" output="false" hint="Gets the absolute timeout length for sessions (in milliseconds). This is the amount of time that a session can live before it expires regardless of the amount of user activity. Applications or frameworks could provide a reauthenticate function that enables a session to continue after reauthentication.">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getLogEncodingRequired" output="false" hint="Returns whether HTML entity encoding should be applied to log entries.">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getLogApplicationName" output="false" hint="Returns whether ESAPI should log the application name. This might be clutter in some single-server/single-app environments.">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="getLogServerIP" output="false" hint="Returns whether ESAPI should log the server IP. This might be clutter in some single-server environments.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getLogLevel" output="false" hint="Returns the current log level.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getLogFileName" output="false" hint="Get the name of the log file specified in the ESAPI configuration properties file. Return a default value if it is not specified.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getMaxLogFileSize" output="false" hint="Get the maximum size of a single log file from the ESAPI configuration properties file. Return a default value if it is not specified. Once the log hits this file size, it will roll over into a new log.">
	</cffunction>


	<cffunction access="public" returntype="any" name="getWorkingDirectory" output="false" hint="java.io.File: Returns the default working directory for executing native processes with Runtime.exec().">
	</cffunction>

</cfinterface>
