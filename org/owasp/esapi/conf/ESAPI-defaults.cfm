<!---
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
--->
<cfscript>
// ESAPI Configuration Defaults
/*
# Do NOT alter this file.
# You can override these settings by passing a struct into the ESAPI.init(configuration) call.
# The struct must match the same hierarchy as this file.
*/
variables.properties = {

"ESAPI": {

	/*
	# If true, then print all the ESAPI properties set here when they are loaded.
	# If false, they are not printed. Useful to reduce output when running JUnit tests.
	# If you need to troubleshoot a properties related problem, turning this on may help,
	# but we leave it off for running JUnit tests. (It will be 'true' in the one delivered
	# as part of production ESAPI, mostly for backward compatibility.)
	*/
	"printProperties": true,

	/*
	# ESAPI is designed to be easily extensible. You can use the reference implementation
	# or implement your own providers to take advantage of your enterprise's security
	# infrastructure. The functions in ESAPI are referenced using the ESAPI locator, like:
	#
	#    String ciphertext =
	#		ESAPI.encryptor().encrypt("Secret message");   // Deprecated in 2.0
	#    CipherText cipherText =
	#		ESAPI.encryptor().encrypt(new PlainText("Secret message")); // Preferred
	#
	# Below you can specify the classname for the provider that you wish to use in your
	# application. The only requirement is that it implement the appropriate ESAPI interface.
	# This allows you to switch security implementations in the future without rewriting the
	# entire application.
	*/
	"AccessControl": "org.owasp.esapi.reference.AccessController",
	"Authenticator": "org.owasp.esapi.reference.Authenticator",
	"Encoder": "org.owasp.esapi.reference.Encoder",
	"Encryptor": "org.owasp.esapi.reference.crypto.Encryptor",
	"Executor": "org.owasp.esapi.reference.Executor",
	"HTTPUtilities": "org.owasp.esapi.reference.HTTPUtilities",
	"IntrusionDetector": "org.owasp.esapi.reference.IntrusionDetector",
	"Logger": "org.owasp.esapi.reference.LogFactory",
	"Randomizer": "org.owasp.esapi.reference.Randomizer",
	"Resource": "org.owasp.esapi.reference.ResourceFactory",
	"Validator": "org.owasp.esapi.reference.Validator"

},

/*
#===========================================================================
# ESAPI Authenticator
*/
"Authenticator": {

	/*
	#
	*/
	"AllowedLoginAttempts": 3,

	/*
	#
	*/
	"MaxOldPasswordHashes": 13,

	/*
	#
	*/
	"UsernameParameterName": "username",
	"PasswordParameterName": "password",

	/*
	# RememberTokenDuration (in days)
	*/
	"RememberTokenDuration": 14,

	/*
	# Session Timeouts (in minutes)
	*/
	"IdleTimeoutDuration": 20,
	"AbsoluteTimeoutDuration": 120,

	/*
	#
	*/
	"AccountNameLengthMax": 254,

	/*
	#
	*/
	"UserSessionKey": "ESAPIUserSessionKey"

},

/*
#===========================================================================
# ESAPI Encoder
#
# ESAPI canonicalizes input before validation to prevent bypassing filters with encoded attacks.
# Failure to canonicalize input is a very common mistake when implementing validation schemes.
# Canonicalization is automatic when using the ESAPI Validator, but you can also use the
# following code to canonicalize data.
#
#      ESAPI.Encoder().canonicalize( "%22hello world&#x22;" );
*/
"Encoder": {

	/*
	# Multiple encoding is when a single encoding format is applied multiple times. Allowing
	# multiple encoding is strongly discouraged.
	*/
	"AllowMultipleEncoding": false,

	/*
	# Mixed encoding is when multiple different encoding formats are applied, or when
	# multiple formats are nested. Allowing multiple encoding is strongly discouraged.
	*/
	"AllowMixedEncoding": false,

	/*
	# The default list of codecs to apply when canonicalizing untrusted data. The list should include the codecs
	# for all downstream interpreters or decoders. For example, if the data is likely to end up in a URL, HTML, or
	# inside JavaScript, then the list of codecs below is appropriate. The order of the list is not terribly important.
	*/
	"DefaultCodecList": "HTMLEntityCodec,PercentCodec,JavaScriptCodec",

	/*
	# Toggle between the default ESAPI encoder vs. the OWASP Java Encoder.
	# See https://www.owasp.org/index.php/OWASP_Java_Encoder_Project
	# The Java Encoder JAR is not included with ESAPI. You must add this yourself.
	*/
	"isJavaEncoderPreferred": false

},

/*
#===========================================================================
# ESAPI Encryption
#
# The ESAPI Encryptor provides basic cryptographic functions with a simplified API.
#
# WARNING: Not all combinations of algorithms and key lengths are supported.
# If you choose to use a key length greater than 128, you MUST download the
# unlimited strength policy files and install in the lib directory of your JRE/JDK.
# See http://java.sun.com/javase/downloads/index.jsp for more information.
*/
"Encryptor": {

	/*
	# ***** IMPORTANT: Do NOT forget to provide with your own values! *****
	# MasterKey and MasterSalt must be provided by the application
	# To get started, generate a new key using <localhost>/esapi4cf/utilities/secretKeyGenerator.cfm
	# There is not currently any support for key rotation, so be careful when changing your key and salt as it
	# will invalidate all signed, encrypted, and hashed data.
	*/
	//"MasterKey": "",
	//"MasterSalt": "",

	/*
	# Provides the default JCE provider that ESAPI will "prefer" for its symmetric
	# encryption and hashing. (That is it will look to this provider first, but it
	# will defer to other providers if the requested algorithm is not implemented
	# by this provider.) If left unset, ESAPI will just use your Java VM's current
	# preferred JCE provider, which is generally set in the file
	# "$JAVA_HOME/jre/lib/security/java.security".
	#
	# The main intent of this is to allow ESAPI symmetric encryption to be
	# used with a FIPS 140-2 compliant crypto-module. For details, see the section
	# "Using ESAPI Symmetric Encryption with FIPS 140-2 Cryptographic Modules" in
	# the ESAPI 2.0 Symmetric Encryption User Guide, at:
	# http://owasp-esapi-java.googlecode.com/svn/trunk/documentation/esapi4java-core-2.0-symmetric-crypto-user-guide.html
	# However, this property also allows you to easily use an alternate JCE provider
	# such as "Bouncy Castle" without having to make changes to "java.security".
	# See Javadoc for SecurityProviderLoader for further details. If you wish to use
	# a provider that is not known to SecurityProviderLoader, you may specify the
	# fully-qualified class name of the JCE provider class that implements
	# java.security.Provider. If the name contains a '.', this is interpreted as
	# a fully-qualified class name that implements java.security.Provider.
	#
	# NOTE: Setting this property has the side-effect of changing it in your application
	#       as well, so if you are using JCE in your application directly rather than
	#       through ESAPI (you wouldn't do that, would you? ;-), it will change the
	#       preferred JCE provider there as well.
	#
	# Default: Keeps the JCE provider set to whatever JVM sets it to.
	*/
	"PreferredJCEProvider": "",

	/*
	# AES is the most widely used and strongest encryption algorithm. This
	# should agree with your Encryptor.CipherTransformation property.
	# By default, ESAPI Java 1.4 uses "PBEWithMD5AndDES" and which is
	# very weak. It is essentially a password-based encryption key, hashed
	# with MD5 around 1K times and then encrypted with the weak DES algorithm
	# (56-bits) using ECB mode and an unspecified padding (it is
	# JCE provider specific, but most likely "NoPadding"). However, 2.0 uses
	# "AES/CBC/PKCSPadding". If you want to change these, change them here.
	# Warning: This property does not control the default reference implementation for
	#		   ESAPI 2.0 using JavaEncryptor. Also, this property will be dropped
	#		   in the future.
	# @deprecated
	*/
	"EncryptionAlgorithm": "AES",

	/*
	#		For ESAPI Java 2.0 - New encrypt / decrypt methods use this.
	*/
	"CipherTransformation": "AES/CBC/PKCS5Padding",

	"cipher_modes": {
		/*
		# Comma-separated list of cipher modes that provide *BOTH*
		# confidentiality *AND* message authenticity. (NIST refers to such cipher
		# modes as "combined modes" so that's what we shall call them.) If any of these
		# cipher modes are used then no MAC is calculated and stored
		# in the CipherText upon encryption. Likewise, if one of these
		# cipher modes is used with decryption, no attempt will be made
		# to validate the MAC contained in the CipherText object regardless
		# of whether it contains one or not. Since the expectation is that
		# these cipher modes support support message authenticity already,
		# injecting a MAC in the CipherText object would be at best redundant.
		#
		# Note that as of JDK 1.5, the SunJCE provider does not support *any*
		# of these cipher modes. Of these listed, only GCM and CCM are currently
		# NIST approved. YMMV for other JCE providers. E.g., Bouncy Castle supports
		# GCM and CCM with "NoPadding" mode, but not with "PKCS5Padding" or other
		# padding modes.
		*/
		"combined_modes": "GCM,CCM,IAPM,EAX,OCB,CWC",
		/*
		# Additional cipher modes allowed for ESAPI 2.0 encryption. These
		# cipher modes are in _addition_ to those specified by the property
		# 'Encryptor.cipher_modes.combined_modes'.
		# Note: We will add support for streaming modes like CFB & OFB once
		# we add support for 'specified' to the property 'Encryptor.ChooseIVMethod'
		# (probably in ESAPI 2.1).
		*/
		"additional_allowed": "CBC"
	},

	/*
	# 128-bit is almost always sufficient and appears to be more resistant to
	# related key attacks than is 256-bit AES. Use '_' to use default key size
	# for cipher algorithms (where it makes sense because the algorithm supports
	# a variable key size). Key length must agree to what's provided as the
	# cipher transformation, otherwise this will be ignored after logging a
	# warning.
	*/
	"EncryptionKeyLength": 128,

	/*
	# Because 2.0 uses CBC mode by default, it requires an initialization vector (IV).
	# (All cipher modes except ECB require an IV.) There are two choices: we can either
	# use a fixed IV known to both parties or allow ESAPI to choose a random IV. While
	# the IV does not need to be hidden from adversaries, it is important that the
	# adversary not be allowed to choose it. Also, random IVs are generally much more
	# secure than fixed IVs. (In fact, it is essential that feed-back cipher modes
	# such as CFB and OFB use a different IV for each encryption with a given key so
	# in such cases, random IVs are much preferred. By default, ESAPI 2.0 uses random
	# IVs. If you wish to use 'fixed' IVs, set 'Encryptor.ChooseIVMethod=fixed' and
	# uncomment the Encryptor.fixedIV.
	#
	# Valid values:		random|fixed|specified		'specified' not yet implemented; planned for 2.1
	*/
	"ChooseIVMethod": "random",

	/*
	# If you choose to use a fixed IV, then you must place a fixed IV here that
	# is known to all others who are sharing your secret key. The format should
	# be a hex string that is the same length as the cipher block size for the
	# cipher algorithm that you are using. The following is an example for AES
	# from an AES test vector for AES-128/CBC as described in:
	# NIST Special Publication 800-38A (2001 Edition)
	# "Recommendation for Block Cipher Modes of Operation".
	# (Note that the block size for AES is 16 bytes == 128 bits.)
	*/
	"fixedIV": "0x000102030405060708090a0b0c0d0e0f",

	/*
	# Whether or not CipherText should use a message authentication code (MAC) with it.
	# This prevents an adversary from altering the IV as well as allowing a more
	# fool-proof way of determining the decryption failed because of an incorrect
	# key being supplied. This refers to the "separate" MAC calculated and stored
	# in CipherText, not part of any MAC that is calculated as a result of a
	# "combined mode" cipher mode.
	#
	# If you are using ESAPI with a FIPS 140-2 cryptographic module, you *must* also
	# set this property to false.
	*/
	"CipherText": {
		"useMAC": true
	},

	/*
	# Whether or not the PlainText object may be overwritten and then marked
	# eligible for garbage collection. If not set, this is still treated as 'true'.
	*/
	"PlainText": {
		"overwrite": true
	},

	/*
	#
	*/
	"HashAlgorithm": "SHA-512",

	/*
	#
	*/
	"HashIterations": 1024,

	/*
	#
	*/
	"DigitalSignatureAlgorithm": "SHA1withDSA",

	/*
	#
	*/
	"DigitalSignatureKeyLength": 1024,

	/*
	#
	*/
	"RandomAlgorithm": "SHA1PRNG",

	/*
	#
	*/
	"CharacterEncoding": "UTF-8",

	/*
	# Currently supported choices for JDK 1.5 and 1.6 are:
	#	HmacSHA1 (160 bits), HmacSHA256 (256 bits), HmacSHA384 (384 bits), and
	#	HmacSHA512 (512 bits).
	# Note that HmacMD5 is *not* supported for the PRF used by the KDF even though
	# these JDKs support it.
	*/
	"KDF": {
		"PRF": "HmacSHA256"
	}

},

/*
#===========================================================================
# ESAPI HttpUtilties
#
# The HttpUtilities provide basic protections to HTTP requests and responses. Primarily these methods
# protect against malicious data from attackers, such as unprintable characters, escaped characters,
# and other simple attacks. The HttpUtilities also provides utility methods for dealing with cookies,
# headers, and CSRF tokens.
*/
"HttpUtilities": {

	/*
	# Default file upload location
	*/
	"UploadDir": getTempDirectory(),

	/*
	#
	*/
	"UploadTempDir": getTempDirectory(),

	/*
	# Force flags on cookies, if you use HttpUtilities to set cookies
	*/
	"ForceHttpOnlySession": false,
	"ForceSecureSession": false,
	"ForceHttpOnlyCookies": true,
	"ForceSecureCookies": true,

	/*
	# Maximum size of HTTP headers
	*/
	"MaxHeaderSize": 4096,

	/*
	# File upload configuration
	*/
	"ApprovedUploadExtensions": ".doc,.docx,.gif,.jpeg,.jpg,.pdf,.png,.ppt,.pptx,.rtf,.txt,.xls,.xlsx",
	"MaxUploadFileBytes": 500000000,

	/*
	# Using UTF-8 throughout your stack is highly recommended. That includes your database driver,
	# container, and any other technologies you may be using. Failure to do this may expose you
	# to Unicode transcoding injection attacks. Use of UTF-8 does not hinder internationalization.
	*/
	"ResponseContentType": "text/html; charset=UTF-8",

	/*
	# This is the name of the cookie used to represent the HTTP session
	# Typically this will be the default "JSESSIONID"
	*/
	"HttpSessionIdName": "JSESSIONID",

	/*
	# modes are "log", "skip", "sanitize", "throw"
	*/
	"UnsafeCookieMode": "log"

},

/*
#===========================================================================
# ESAPI Executor
# CHECKME - This should be made OS independent. Don't use unsafe defaults.
# # Examples only -- do NOT blindly copy!
#   For Windows:
#     Executor.WorkingDirectory=C:\Windows\Temp
#     Executor.ApprovedExecutables=C:\Windows\System32\cmd.exe,C:\Windows\System32\runas.exe
#   For *nux, MacOS:
#     Executor.WorkingDirectory=/tmp
#     Executor.ApprovedExecutables=/bin/bash
*/
"Executor": {
	"WorkingDirectory": "",
	"ApprovedExecutables": ""
},

/*
#===========================================================================
# ESAPI Logging
*/
"Logger": {

	/*
	# Set the application name if these logs are combined with other applications
	*/
	"ApplicationName": getApplicationMetaData().name,

	/*
	# If you use an HTML log viewer that does not properly HTML escape log data, you can set LogEncodingRequired to true
	*/
	"LogEncodingRequired": false,

	/*
	# Determines whether ESAPI should log the application name. This might be clutter in some single-server/single-app environments.
	*/
	"LogApplicationName": true,

	/*
	# Determines whether ESAPI should log the server IP and port. This might be clutter in some single-server environments.
	*/
	"LogServerIP": true,

	/*
	# LogFileName, the name of the logging file. Provide a full directory path (e.g., C:\\ESAPI\\ESAPI_logging_file) if you
	# want to place it in a specific directory.
	*/
	"LogFileName": "ESAPI_logging_file"

	/*
	# MaxLogFileSize, the max size (in bytes) of a single log file before it cuts over to a new one (default is 10,000,000)
	*/
	// not needed as we will allow CF to handle archiving log files when they reach a certain size
	//"MaxLogFileSize": 10000000

},

/*
#===========================================================================
# ESAPI Intrusion Detection
#
# Each event has a base to which .count, .interval, and .action are added
# The IntrusionException will fire if we receive "count" events within "interval" seconds
# The IntrusionDetector is configurable to take the following actions: log, logout, and disable
#  (multiple actions separated by commas are allowed e.g. event.test.actions=log,disable
*/
"IntrusionDetector": {

	/*
	# You can also disable intrusion detection completely by changing
	# the following parameter to true
	*/
	"Disable": false,

	/*
	# Custom Events
	# Names must start with "event." as the base
	# Use IntrusionDetector.addEvent( "test" ) in your code to trigger "event.test" here
	*/
	"event": {
		"test": {
			"count": 2,
			"interval": 10,
			"actions": "disable,log"
		}
	},

	/*
	# Exception Events
	# All EnterpriseSecurityExceptions are registered automatically
	# Call IntrusionDetector.getInstance().addException(e) for Exceptions that do not extend EnterpriseSecurityException
	# Use the fully qualified classname of the exception as the base
	*/
	"org": {
		"owasp": {
			"esapi": {
				"errors": {

					/*
					# any intrusion is an attack
					*/
					"IntrusionException": {
						"count": 1,
						"interval": 1,
						"actions": "log,disable,logout"
					},

					/*
					# for test purposes
					# CHECKME: Shouldn't there be something in the property name itself that designates
					#		   that these are for testing???
					*/
					"IntegrityException": {
						"count": 10,
						"interval": 5,
						"actions": "log,disable,logout"
					},

					/*
					# rapid validation errors indicate scans or attacks in progress
					"ValidationException": {
						"count": 10,
						"interval": 10,
						"actions": "log,logout"
					},
					*/

					/*
					# sessions jumping between hosts indicates session hijacking
					*/
					"AuthenticationHostException": {
						"count": 2,
						"interval": 10,
						"actions": "log,logout"
					}

				}
			}
		}
	}

},

/*
#===========================================================================
# ESAPI Validation
#
# The ESAPI Validator works on Java regular expressions with defined names. You can define names
# either here, or you may define application specific patterns in a separate file defined below.
# This allows enterprises to specify both organizational standards as well as application specific
# validation rules.
*/
"Validator": {

	"Patterns": {

		/*
		# Validators used by ESAPI
		*/
		"AccountName": "^[a-zA-Z0-9]{3,20}$",
		"SystemCommand": "^[a-zA-Z\-\/]{1,64}$",
		"RoleName": "^[a-z]{1,20}$",

		/*
		#the word TEST below should be changed to your application
		#name - only relative URL's are supported
		*/
		"Redirect": "^\/test.*$",

		/*
		# Global HTTP Validation Rules
		# Values with Base64 encoded data (e.g. encrypted state) will need at least [a-zA-Z0-9\/+=]
		*/
		"HTTPScheme": "^(http|https)$",
		"HTTPServerName": "^[a-zA-Z0-9_.\-]*$",
		"HTTPParameterName": "^[a-zA-Z0-9_]{1,32}$",
		"HTTPParameterValue": "^[\p{L}\p{N}.\-/+=@_ !$*?]*$",
		"HTTPCookieName": "^[a-zA-Z0-9\-_]{1,32}$",
		// added . to pass JSESSIONID under CF11
		"HTTPCookieValue": "^[a-zA-Z0-9.\-\/+=_ ]*$",
		"HTTPHeaderName": "^[a-zA-Z0-9\-_]{1,32}$",
		"HTTPHeaderValue": "^[a-zA-Z0-9()\-=\*\.\?;,+\/:&_ ]*$",
		"HTTPContextPath": "^\/?[a-zA-Z0-9.\-\/_]*$",
		"HTTPServletPath": "^[a-zA-Z0-9.\-\/_]*$",
		"HTTPPath": "^[a-zA-Z0-9.\-_]*$",
		"HTTPQueryString": "^[a-zA-Z0-9()\-=\*\.\?;,+\/:&_ %]*$",
		"HTTPURI": "^[a-zA-Z0-9()\-=\*\.\?;,+\/:&_ ]*$",
		"HTTPURL": "^.*$",
		"HTTPJSESSIONID": "^[A-Z0-9]{10,30}$",

		/*
		# Validation of file related input
		*/
		"FileName": "^[a-zA-Z0-9!@##$%^&{}\[\]()_+\-=,.~'` ]{1,255}$",
		"DirectoryName": "^[a-zA-Z0-9:/\\!@##$%^&{}\[\]()_+\-=,.~'` ]{1,255}$",

		/*
		# The ESAPI validator does many security checks on input, such as canonicalization
		# and whitelist validation. Note that all of these validation rules are applied *after*
		# canonicalization. Double-encoded characters (even with different encodings involved,
		# are never allowed.
		#
		# To use:
		#
		# First set up a pattern below. You can choose any name you want, prefixed by the word
		# "Validation." For example:
		#   Validation.Email=^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\\.[a-zA-Z]{2,4}$
		#
		# Then you can validate in your code against the pattern like this:
		#     ESAPI.validator().isValidInput("User Email", input, "Email", maxLength, allowNull);
		# Where maxLength and allowNull are set for you needs, respectively.
		#
		# But note, when you use boolean variants of validation functions, you lose critical
		# canonicalization. It is preferable to use the "get" methods (which throw exceptions) and
		# and use the returned user input which is in canonical form. Consider the following:
		#
		# try {
		#    someObject.setEmail(ESAPI.validator().getValidInput("User Email", input, "Email", maxLength, allowNull));
		*/
		"SafeString": "^[.\p{Alnum}\p{Space}]{0,1024}$",
		"Email": "^[A-Za-z0-9._%'-]+@[A-Za-z0-9.-]+\.[a-zA-Z]{2,4}$",
		"IPAddress": "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
		"URL": "^(ht|f)tp(s?)\:\/\/[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:(0-9)*)*(\/?)([a-zA-Z0-9\-\.\?\,\:\'\/\\\+=&amp;%\$##_]*)?$",
		"CreditCard": "^(\d{4}[- ]?){3}\d{4}$",
		"SSN": "^(?!000)([0-6]\d{2}|7([0-6]\d|7[012]))([ -]?)(?!00)\d\d\3(?!0000)\d{4}$"

	},

	/*
	# Validation of dates. Controls whether or not 'lenient' dates are accepted.
	# See DataFormat.setLenient(boolean flag) for further details.
	*/
	"AcceptLenientDates": false,

	/*
	# The location of the AntiSamy configuration file
	*/
	"AntiSamyPolicyFile": expandPath("/org/owasp/esapi/conf/antisamy-esapi.xml")

	/*
	TODO: need to allow use of Java HTML Sanitizer Project in place of AntiSamy
	https://www.owasp.org/index.php/OWASP_Java_HTML_Sanitizer_Project
	*/

}

};// END : ESAPI Configuration
</cfscript>