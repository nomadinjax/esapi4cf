<cfcomponent extends="cfesapi.test.org.owasp.esapi.TestCase" output="false">

	<cfscript>
		instance.ESAPI = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			structClear(session);
			structClear(request);

			instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="tearDown" output="false">
		<cfscript>
			instance.ESAPI = "";

			structClear(session);
			structClear(request);
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration" name="createWithProperty" output="false">
		<cfargument type="String" name="key" required="true">
		<cfargument type="String" name="val" required="true">
		<cfscript>
			local.properties = createObject("java", "java.util.Properties").init();
			local.properties.setProperty(arguments.key, javaCast("string", arguments.val));
			return createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetApplicationName" output="false">
		<cfscript>
			local.expected = "ESAPI_UnitTests";
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").APPLICATION_NAME, local.expected);
			assertEquals(local.expected, local.secConf.getApplicationName());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetLogImplementation" output="false">
		<cfscript>
			//test the default
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").DEFAULT_LOG_IMPLEMENTATION, local.secConf.getLogImplementation());

			local.expected = "TestLogger";
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").LOG_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getLogImplementation());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testAuthenticationImplementation" output="false">
		<cfscript>
			//test the default
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").DEFAULT_AUTHENTICATION_IMPLEMENTATION, local.secConf.getAuthenticationImplementation());

			local.expected = "TestAuthentication";
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").AUTHENTICATION_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getAuthenticationImplementation());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncoderImplementation" output="false">
		<cfscript>
			//test the default
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").DEFAULT_ENCODER_IMPLEMENTATION, secConf.getEncoderImplementation());

			local.expected = "TestEncoder";
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").ENCODER_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getEncoderImplementation());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testAccessControlImplementation" output="false">
		<cfscript>
			//test the default
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").DEFAULT_ACCESS_CONTROL_IMPLEMENTATION, local.secConf.getAccessControlImplementation());

			local.expected = "TestAccessControl";
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").ACCESS_CONTROL_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getAccessControlImplementation());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncryptionImplementation" output="false">
		<cfscript>
			//test the default
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").DEFAULT_ENCRYPTION_IMPLEMENTATION, local.secConf.getEncryptionImplementation());

			local.expected = "TestEncryption";
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").ENCRYPTION_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getEncryptionImplementation());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIntrusionDetectionImplementation" output="false">
		<cfscript>
			//test the default
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION, local.secConf.getIntrusionDetectionImplementation());

			local.expected = "TestIntrusionDetection";
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").INTRUSION_DETECTION_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getIntrusionDetectionImplementation());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testRandomizerImplementation" output="false">
		<cfscript>
			//test the default
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").DEFAULT_RANDOMIZER_IMPLEMENTATION, local.secConf.getRandomizerImplementation());

			local.expected = "TestRandomizer";
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").RANDOMIZER_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getRandomizerImplementation());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testExecutorImplementation" output="false">
		<cfscript>
			//test the default
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").DEFAULT_EXECUTOR_IMPLEMENTATION, local.secConf.getExecutorImplementation());

			local.expected = "TestExecutor";
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").EXECUTOR_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getExecutorImplementation());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testHTTPUtilitiesImplementation" output="false">
		<cfscript>
			//test the default
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").DEFAULT_HTTP_UTILITIES_IMPLEMENTATION, local.secConf.getHTTPUtilitiesImplementation());

			local.expected = "TestHTTPUtilities";
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").HTTP_UTILITIES_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getHTTPUtilitiesImplementation());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testValidationImplementation" output="false">
		<cfscript>
			//test the default
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").DEFAULT_VALIDATOR_IMPLEMENTATION, local.secConf.getValidationImplementation());

			local.expected = "TestValidation";
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").VALIDATOR_IMPLEMENTATION, local.expected);
			assertEquals(local.expected, local.secConf.getValidationImplementation());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetEncryptionKeyLength" output="false">
		<cfscript>
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals(128, local.secConf.getEncryptionKeyLength());

			local.expected = 256;
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").KEY_LENGTH, local.expected);
			assertEquals(local.expected, local.secConf.getEncryptionKeyLength());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetMasterSalt" output="false">
		<cfscript>
			try {
				local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
				local.secConf.getMasterSalt();
				fail("Expected Exception not thrown");
			}
			catch (cfesapi.org.owasp.esapi.errors.ConfigurationException ce) {
				assertTrue(len(ce.getMessage()));
			}

			local.salt = "53081";
			local.property = instance.ESAPI.encoder().encodeForBase64(local.salt.getBytes(), false);
			local.properties = createObject("java", "java.util.Properties").init();
			local.properties.setProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").MASTER_SALT, local.property);
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
			assertEquals(local.salt, createObject("java", "java.lang.String").init(local.secConf.getMasterSalt()));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetAllowedExecutables" output="false">
		<cfscript>
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			local.allowedExecutables = local.secConf.getAllowedExecutables();

			//is this really what should be returned? what about an empty list?
			assertEquals(1, arrayLen(local.allowedExecutables));
			assertEquals("", local.allowedExecutables[1]);


			local.properties = createObject("java", "java.util.Properties").init();
			local.properties.setProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").APPROVED_EXECUTABLES, "/bin/bzip2,/bin/diff, /bin/cvs");
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
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
		<cfscript>
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			local.allowedFileExtensions = local.secConf.getAllowedFileExtensions();
			assertFalse(local.allowedFileExtensions.isEmpty());

			local.properties = createObject("java", "java.util.Properties").init();
			local.properties.setProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").APPROVED_UPLOAD_EXTENSIONS, ".txt,.xml,.html,.png");
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
			local.allowedFileExtensions = local.secConf.getAllowedFileExtensions();
			assertEquals(4, arrayLen(local.allowedFileExtensions));
			assertEquals(".html", local.allowedFileExtensions[3]);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetAllowedFileUploadSize" output="false">
		<cfscript>
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			//assert that the default is of some reasonable size
			assertTrue(local.secConf.getAllowedFileUploadSize() > (1024 * 100));

			local.expected = (1024 * 1000);
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").MAX_UPLOAD_FILE_BYTES, local.expected);
			assertEquals(local.expected, local.secConf.getAllowedFileUploadSize());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetParameterNames" output="false">
		<cfscript>
			//test the default
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals("password", local.secConf.getPasswordParameterName());
			assertEquals("username", local.secConf.getUsernameParameterName());

			local.properties = createObject("java", "java.util.Properties").init();
			local.properties.setProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").PASSWORD_PARAMETER_NAME, "j_password");
			local.properties.setProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").USERNAME_PARAMETER_NAME, "j_username");
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
			assertEquals("j_password", local.secConf.getPasswordParameterName());
			assertEquals("j_username", local.secConf.getUsernameParameterName());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetEncryptionAlgorithm" output="false">
		<cfscript>
			//test the default
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals("AES", local.secConf.getEncryptionAlgorithm());

			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").ENCRYPTION_ALGORITHM, "3DES");
			assertEquals("3DES", local.secConf.getEncryptionAlgorithm());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetCipherXProperties" output="false">
		<cfscript>
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals("AES/CBC/PKCS5Padding", local.secConf.getCipherTransformation());
			//Assert.assertEquals("AES/CBC/PKCS5Padding", secConf.getC);

			local.properties = createObject("java", "java.util.Properties").init();
			local.properties.setProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").CIPHER_TRANSFORMATION_IMPLEMENTATION, "Blowfish/CFB/ISO10126Padding");
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
			assertEquals("Blowfish/CFB/ISO10126Padding", local.secConf.getCipherTransformation());

			local.secConf.setCipherTransformation("DESede/PCBC/PKCS5Padding");
			assertEquals("DESede/PCBC/PKCS5Padding", local.secConf.getCipherTransformation());

			local.secConf.setCipherTransformation("");//sets it back to default
			assertEquals("Blowfish/CFB/ISO10126Padding", local.secConf.getCipherTransformation());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testIV" output="false">
		<cfscript>
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals("random", local.secConf.getIVType());
			try {
				local.secConf.getFixedIV();
				fail();
			}
			catch (cfesapi.org.owasp.esapi.errors.ConfigurationException ce) {
				assertTrue(len(ce.getMessage()));
			}

			local.properties = createObject("java", "java.util.Properties").init();
			local.properties.setProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").IV_TYPE, "fixed");
			local.properties.setProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").FIXED_IV, "ivValue");
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
			assertEquals("fixed", local.secConf.getIVType());
			assertEquals("ivValue", local.secConf.getFixedIV());

			local.properties.setProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").IV_TYPE, "illegal");
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, local.properties);
			try {
				local.secConf.getIVType();
				fail();
			}
			catch (cfesapi.org.owasp.esapi.errors.ConfigurationException ce) {
				assertTrue(len(ce.getMessage()));
			}
			try {
				local.secConf.getFixedIV();
				fail();
			}
			catch (cfesapi.org.owasp.esapi.errors.ConfigurationException ce) {
				assertTrue(len(ce.getMessage()));
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetAllowMultipleEncoding" output="false">
		<cfscript>
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertFalse(local.secConf.getAllowMultipleEncoding());

			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").ALLOW_MULTIPLE_ENCODING, "yes");
			assertTrue(local.secConf.getAllowMultipleEncoding());

			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").ALLOW_MULTIPLE_ENCODING, "true");
			assertTrue(local.secConf.getAllowMultipleEncoding());

			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").ALLOW_MULTIPLE_ENCODING, "no");
			assertFalse(local.secConf.getAllowMultipleEncoding());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetDefaultCanonicalizationCodecs" output="false">
		<cfscript>
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertFalse(local.secConf.getDefaultCanonicalizationCodecs().isEmpty());

			local.property = "org.owasp.esapi.codecs.TestCodec1,org.owasp.esapi.codecs.TestCodec2";
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").CANONICALIZATION_CODECS, local.property);
			assertTrue(arrayFind(local.secConf.getDefaultCanonicalizationCodecs(), "org.owasp.esapi.codecs.TestCodec1"));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetDisableIntrusionDetection" output="false">
		<cfscript>
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertFalse(local.secConf.getDisableIntrusionDetection());

			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").DISABLE_INTRUSION_DETECTION, "TRUE");
			assertTrue(local.secConf.getDisableIntrusionDetection());

			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").DISABLE_INTRUSION_DETECTION, "true");
			assertTrue(local.secConf.getDisableIntrusionDetection());

			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").DISABLE_INTRUSION_DETECTION, "false");
			assertFalse(local.secConf.getDisableIntrusionDetection());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetLogLevel" output="false">
		<cfscript>
			Logger = createObject("java", "org.owasp.esapi.Logger");

			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals(Logger.WARNING, local.secConf.getLogLevel());

			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").LOG_LEVEL, "trace");
			assertEquals(Logger.TRACE, local.secConf.getLogLevel());

			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").LOG_LEVEL, "Off");
			assertEquals(Logger.OFF, local.secConf.getLogLevel());

			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").LOG_LEVEL, "all");
			assertEquals(Logger.ALL, local.secConf.getLogLevel());

			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").LOG_LEVEL, "DEBUG");
			assertEquals(Logger.DEBUG, local.secConf.getLogLevel());

			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").LOG_LEVEL, "info");
			assertEquals(Logger.INFO, local.secConf.getLogLevel());

			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").LOG_LEVEL, "ERROR");
			assertEquals(Logger.ERROR, local.secConf.getLogLevel());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetLogFileName" output="false">
		<cfscript>
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals("ESAPI_logging_file", local.secConf.getLogFileName());

			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").LOG_FILE_NAME, "log.txt");
			assertEquals("log.txt", local.secConf.getLogFileName());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetMaxLogFileSize" output="false">
		<cfscript>
			local.secConf = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").init(instance.ESAPI, createObject("java", "java.util.Properties").init());
			assertEquals(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").DEFAULT_MAX_LOG_FILE_SIZE, local.secConf.getMaxLogFileSize());

			local.maxLogSize = (1024 * 1000);
			local.secConf = createWithProperty(createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration").MAX_LOG_FILE_SIZE, local.maxLogSize);
			assertEquals(local.maxLogSize, local.secConf.getMaxLogFileSize());
		</cfscript>
	</cffunction>


</cfcomponent>
