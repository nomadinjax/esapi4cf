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
<cfcomponent displayname="DefaultSecurityConfigurationTest" extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false">

	<cfscript>
		instance.ESAPI = newComponent("cfesapi.org.owasp.esapi.ESAPI").init();
	</cfscript>

	<cffunction access="private" returntype="cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration" name="createWithProperty" output="false">
		<cfargument required="true" type="String" name="key"/>
		<cfargument required="true" type="String" name="val"/>

		<cfset var local = {}/>

		<cfscript>
			local.properties = newJava("java.util.Properties").init();
			local.properties.setProperty(javaCast("string", arguments.key), javaCast("string", arguments.val));
			return newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetApplicationName" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.expected = "ESAPI_UnitTests";
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().APPLICATION_NAME, local.expected);
			assertEquals(local.expected, local.secConf.getApplicationName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetLogImplementation" output="false">
		<cfset var local = {}/>

		<cfscript>
			//test the default
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_LOG_IMPLEMENTATION, local.secConf.getLogImplementation());

			local.expected = "TestLogger";
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getLogImplementation());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testAuthenticationImplementation" output="false">
		<cfset var local = {}/>

		<cfscript>
			//test the default
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_AUTHENTICATION_IMPLEMENTATION, local.secConf.getAuthenticationImplementation());

			local.expected = "TestAuthentication";
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().AUTHENTICATION_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getAuthenticationImplementation());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncoderImplementation" output="false">

		<cfscript>
			//test the default
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_ENCODER_IMPLEMENTATION, local.secConf.getEncoderImplementation());

			local.expected = "TestEncoder";
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().ENCODER_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getEncoderImplementation());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testAccessControlImplementation" output="false">
		<cfset var local = {}/>

		<cfscript>
			//test the default
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_ACCESS_CONTROL_IMPLEMENTATION, local.secConf.getAccessControlImplementation());

			local.expected = "TestAccessControl";
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().ACCESS_CONTROL_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getAccessControlImplementation());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncryptionImplementation" output="false">
		<cfset var local = {}/>

		<cfscript>
			//test the default
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_ENCRYPTION_IMPLEMENTATION, local.secConf.getEncryptionImplementation());

			local.expected = "TestEncryption";
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().ENCRYPTION_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getEncryptionImplementation());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIntrusionDetectionImplementation" output="false">
		<cfset var local = {}/>

		<cfscript>
			//test the default
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION, local.secConf.getIntrusionDetectionImplementation());

			local.expected = "TestIntrusionDetection";
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().INTRUSION_DETECTION_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getIntrusionDetectionImplementation());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testRandomizerImplementation" output="false">
		<cfset var local = {}/>

		<cfscript>
			//test the default
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_RANDOMIZER_IMPLEMENTATION, local.secConf.getRandomizerImplementation());

			local.expected = "TestRandomizer";
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().RANDOMIZER_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getRandomizerImplementation());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testExecutorImplementation" output="false">
		<cfset var local = {}/>

		<cfscript>
			//test the default
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_EXECUTOR_IMPLEMENTATION, local.secConf.getExecutorImplementation());

			local.expected = "TestExecutor";
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().EXECUTOR_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getExecutorImplementation());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testHTTPUtilitiesImplementation" output="false">
		<cfset var local = {}/>

		<cfscript>
			//test the default
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_HTTP_UTILITIES_IMPLEMENTATION, local.secConf.getHTTPUtilitiesImplementation());

			local.expected = "TestHTTPUtilities";
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().HTTP_UTILITIES_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getHTTPUtilitiesImplementation());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testValidationImplementation" output="false">
		<cfset var local = {}/>

		<cfscript>
			//test the default
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_VALIDATOR_IMPLEMENTATION, local.secConf.getValidationImplementation());

			local.expected = "TestValidation";
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().VALIDATOR_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getValidationImplementation());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetEncryptionKeyLength" output="false">
		<cfset var local = {}/>

		<cfscript>
			// test the default
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals(128, local.secConf.getEncryptionKeyLength());

			local.expected = 256;
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().KEY_LENGTH, int(local.expected));
			assertEquals(local.expected, local.secConf.getEncryptionKeyLength());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetKDFPseudoRandomFunction" output="false">
		<cfset var local = {}/>

		<cfscript>
			// test the default
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals("HmacSHA256", local.secConf.getKDFPseudoRandomFunction());

			local.expected = "HmacSHA1";
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().KDF_PRF_ALG, local.expected);
			assertEquals(local.expected, local.secConf.getKDFPseudoRandomFunction());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetMasterSalt" output="false">
		<cfset var local = {}/>

		<cfscript>
			try {
				local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
				local.secConf.getMasterSalt();
				fail("Expected Exception not thrown");
			}
			catch(cfesapi.org.owasp.esapi.errors.ConfigurationException ce) {
				assertFalse(!structKeyExists(ce, "message"));
			}

			local.salt = "53081";
			local.property = instance.ESAPI.encoder().encodeForBase64(local.salt.getBytes(), false);
			local.properties = newJava("java.util.Properties").init();
			local.properties.setProperty(instance.ESAPI.securityConfiguration().MASTER_SALT, local.property);
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
			assertEquals(local.salt, newJava("java.lang.String").init(local.secConf.getMasterSalt()));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetAllowedExecutables" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			local.allowedExecutables = local.secConf.getAllowedExecutables();

			//is this really what should be returned? what about an empty list?
			assertEquals(1, arrayLen(local.allowedExecutables));
			assertEquals("", local.allowedExecutables[1]);

			local.properties = newJava("java.util.Properties").init();
			local.properties.setProperty(instance.ESAPI.securityConfiguration().APPROVED_EXECUTABLES, "/bin/bzip2,/bin/diff, /bin/cvs");
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
			local.allowedExecutables = local.secConf.getAllowedExecutables();
			assertEquals(3, arrayLen(local.allowedExecutables));
			assertEquals("/bin/bzip2", local.allowedExecutables[1]);
			assertEquals("/bin/diff", local.allowedExecutables[2]);

			//this seems less than optimal, maybe each value should have a trim() done to it
			//at least we know that this behavior exists, the property should'nt have spaces between values
			assertEquals(" /bin/cvs", local.allowedExecutables[3]);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetAllowedFileExtensions" output="false">
		<cfset var local = {}/>

		<cfscript>

			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			local.allowedFileExtensions = local.secConf.getAllowedFileExtensions();
			assertFalse(arrayLen(local.allowedFileExtensions) == 0);

			local.properties = newJava("java.util.Properties").init();
			local.properties.setProperty(instance.ESAPI.securityConfiguration().APPROVED_UPLOAD_EXTENSIONS, ".txt,.xml,.html,.png");
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
			local.allowedFileExtensions = local.secConf.getAllowedFileExtensions();
			assertEquals(4, arrayLen(local.allowedFileExtensions));
			assertEquals(".html", local.allowedFileExtensions[3]);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetAllowedFileUploadSize" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			//assert that the default is of some reasonable size
			assertTrue(local.secConf.getAllowedFileUploadSize() > (1024 * 100));

			local.expected = (1024 * 1000);
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().MAX_UPLOAD_FILE_BYTES, int(local.expected));
			assertEquals(local.expected, local.secConf.getAllowedFileUploadSize());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetParameterNames" output="false">
		<cfset var local = {}/>

		<cfscript>
			//test the default
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals("password", local.secConf.getPasswordParameterName());
			assertEquals("username", local.secConf.getUsernameParameterName());

			local.properties = newJava("java.util.Properties").init();
			local.properties.setProperty(instance.ESAPI.securityConfiguration().PASSWORD_PARAMETER_NAME, "j_password");
			local.properties.setProperty(instance.ESAPI.securityConfiguration().USERNAME_PARAMETER_NAME, "j_username");
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
			assertEquals("j_password", local.secConf.getPasswordParameterName());
			assertEquals("j_username", local.secConf.getUsernameParameterName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetEncryptionAlgorithm" output="false">
		<cfset var local = {}/>

		<cfscript>
			//test the default
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals("AES", local.secConf.getEncryptionAlgorithm());

			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().ENCRYPTION_ALGORITHM, "3DES");
			assertEquals("3DES", local.secConf.getEncryptionAlgorithm());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetCipherXProperties" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals("AES/CBC/PKCS5Padding", local.secConf.getCipherTransformation());
			//assertEquals("AES/CBC/PKCS5Padding", local.secConf.getC);
			local.properties = newJava("java.util.Properties").init();
			local.properties.setProperty(instance.ESAPI.securityConfiguration().CIPHER_TRANSFORMATION_IMPLEMENTATION, "Blowfish/CFB/ISO10126Padding");
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
			assertEquals("Blowfish/CFB/ISO10126Padding", local.secConf.getCipherTransformation());

			local.secConf.setCipherTransformation("DESede/PCBC/PKCS5Padding");
			assertEquals("DESede/PCBC/PKCS5Padding", local.secConf.getCipherTransformation());

			local.secConf.setCipherTransformation("");//sets it back to default
			assertEquals("Blowfish/CFB/ISO10126Padding", local.secConf.getCipherTransformation());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testIV" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals("random", local.secConf.getIVType());
			try {
				local.secConf.getFixedIV();
				fail();
			}
			catch(cfesapi.org.owasp.esapi.errors.ConfigurationException ce) {
				assertFalse(!structKeyExists(ce, "message"));
			}

			local.properties = newJava("java.util.Properties").init();
			local.properties.setProperty(instance.ESAPI.securityConfiguration().IV_TYPE, "fixed");
			local.properties.setProperty(instance.ESAPI.securityConfiguration().FIXED_IV, "ivValue");
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
			assertEquals("fixed", local.secConf.getIVType());
			assertEquals("ivValue", local.secConf.getFixedIV());

			local.properties.setProperty(instance.ESAPI.securityConfiguration().IV_TYPE, "illegal");
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
			try {
				local.secConf.getIVType();
				fail();
			}
			catch(cfesapi.org.owasp.esapi.errors.ConfigurationException ce) {
				assertTrue(len(ce.message));
			}
			try {
				local.secConf.getFixedIV();
				fail();
			}
			catch(cfesapi.org.owasp.esapi.errors.ConfigurationException ce) {
				assertTrue(len(ce.message));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetAllowMultipleEncoding" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertFalse(local.secConf.getAllowMultipleEncoding());

			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().ALLOW_MULTIPLE_ENCODING, "yes");
			assertTrue(local.secConf.getAllowMultipleEncoding());

			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().ALLOW_MULTIPLE_ENCODING, "true");
			assertTrue(local.secConf.getAllowMultipleEncoding());

			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().ALLOW_MULTIPLE_ENCODING, "no");
			assertFalse(local.secConf.getAllowMultipleEncoding());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetDefaultCanonicalizationCodecs" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertFalse(local.secConf.getDefaultCanonicalizationCodecs().isEmpty());

			local.property = "org.owasp.esapi.codecs.TestCodec1,org.owasp.esapi.codecs.TestCodec2";
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().CANONICALIZATION_CODECS, local.property);
			assertTrue(arrayFind(local.secConf.getDefaultCanonicalizationCodecs(), "org.owasp.esapi.codecs.TestCodec1"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetDisableIntrusionDetection" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertFalse(local.secConf.getDisableIntrusionDetection());

			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().DISABLE_INTRUSION_DETECTION, "TRUE");
			assertTrue(local.secConf.getDisableIntrusionDetection());

			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().DISABLE_INTRUSION_DETECTION, "true");
			assertTrue(local.secConf.getDisableIntrusionDetection());

			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().DISABLE_INTRUSION_DETECTION, "false");
			assertFalse(local.secConf.getDisableIntrusionDetection());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetLogLevel" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals(newJava("org.owasp.esapi.Logger").WARNING, local.secConf.getLogLevel());

			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_LEVEL, "trace");
			assertEquals(newJava("org.owasp.esapi.Logger").TRACE, local.secConf.getLogLevel());

			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_LEVEL, "Off");
			assertEquals(newJava("org.owasp.esapi.Logger").OFF, local.secConf.getLogLevel());

			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_LEVEL, "all");
			assertEquals(newJava("org.owasp.esapi.Logger").ALL, local.secConf.getLogLevel());

			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_LEVEL, "DEBUG");
			assertEquals(newJava("org.owasp.esapi.Logger").DEBUG, local.secConf.getLogLevel());

			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_LEVEL, "info");
			assertEquals(newJava("org.owasp.esapi.Logger").INFO, local.secConf.getLogLevel());

			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_LEVEL, "ERROR");
			assertEquals(newJava("org.owasp.esapi.Logger").ERROR, local.secConf.getLogLevel());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetLogFileName" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals("ESAPI_logging_file", local.secConf.getLogFileName());

			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_FILE_NAME, "log.txt");
			assertEquals("log.txt", local.secConf.getLogFileName());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetMaxLogFileSize" output="false">
		<cfset var local = {}/>

		<cfscript>
			local.secConf = newComponent("cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, newJava("java.util.Properties").init());
			assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_MAX_LOG_FILE_SIZE, local.secConf.getMaxLogFileSize());

			local.maxLogSize = (1024 * 1000);
			local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().MAX_LOG_FILE_SIZE, local.maxLogSize);
			assertEquals(local.maxLogSize, local.secConf.getMaxLogFileSize());
		</cfscript>

	</cffunction>

</cfcomponent>