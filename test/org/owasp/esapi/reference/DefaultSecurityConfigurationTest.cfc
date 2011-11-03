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
component DefaultSecurityConfigurationTest extends="cfesapi.test.org.owasp.esapi.lang.TestCase" {

	instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();

	private cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration function createWithProperty(required String key, required String val) {
		local.properties = newJava("java.util.Properties").init();
		local.properties.setProperty(javaCast("string", arguments.key), javaCast("string", arguments.val));
		return new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, local.properties);
	}
	
	//@Test
	
	public void function testGetApplicationName() {
		local.expected = "ESAPI_UnitTests";
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().APPLICATION_NAME, local.expected);
		Assert.assertEquals(local.expected, local.secConf.getApplicationName());
	}
	
	//@Test
	
	public void function testGetLogImplementation() {
		//test the default
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_LOG_IMPLEMENTATION, local.secConf.getLogImplementation());
	
		local.expected = "TestLogger";
		secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_IMPLEMENTATION, local.expected);
		Assert.assertEquals(local.expected, local.secConf.getLogImplementation());
	}
	
	//@Test
	
	public void function testAuthenticationImplementation() {
		//test the default
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_AUTHENTICATION_IMPLEMENTATION, local.secConf.getAuthenticationImplementation());
	
		local.expected = "TestAuthentication";
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().AUTHENTICATION_IMPLEMENTATION, local.expected);
		Assert.assertEquals(local.expected, local.secConf.getAuthenticationImplementation());
	}
	
	//@Test
	
	public void function testEncoderImplementation() {
		//test the default
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_ENCODER_IMPLEMENTATION, local.secConf.getEncoderImplementation());
	
		local.expected = "TestEncoder";
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().ENCODER_IMPLEMENTATION, local.expected);
		Assert.assertEquals(local.expected, local.secConf.getEncoderImplementation());
	}
	
	//@Test
	
	public void function testAccessControlImplementation() {
		//test the default
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_ACCESS_CONTROL_IMPLEMENTATION, local.secConf.getAccessControlImplementation());
	
		local.expected = "TestAccessControl";
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().ACCESS_CONTROL_IMPLEMENTATION, local.expected);
		Assert.assertEquals(local.expected, local.secConf.getAccessControlImplementation());
	}
	
	//@Test
	
	public void function testEncryptionImplementation() {
		//test the default
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_ENCRYPTION_IMPLEMENTATION, local.secConf.getEncryptionImplementation());
	
		local.expected = "TestEncryption";
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().ENCRYPTION_IMPLEMENTATION, local.expected);
		Assert.assertEquals(local.expected, local.secConf.getEncryptionImplementation());
	}
	
	//@Test
	
	public void function testIntrusionDetectionImplementation() {
		//test the default
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION, local.secConf.getIntrusionDetectionImplementation());
	
		local.expected = "TestIntrusionDetection";
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().INTRUSION_DETECTION_IMPLEMENTATION, local.expected);
		Assert.assertEquals(local.expected, local.secConf.getIntrusionDetectionImplementation());
	}
	
	//@Test
	
	public void function testRandomizerImplementation() {
		//test the default
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_RANDOMIZER_IMPLEMENTATION, local.secConf.getRandomizerImplementation());
	
		local.expected = "TestRandomizer";
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().RANDOMIZER_IMPLEMENTATION, local.expected);
		Assert.assertEquals(local.expected, local.secConf.getRandomizerImplementation());
	}
	
	//@Test
	
	public void function testExecutorImplementation() {
		//test the default
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_EXECUTOR_IMPLEMENTATION, local.secConf.getExecutorImplementation());
	
		local.expected = "TestExecutor";
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().EXECUTOR_IMPLEMENTATION, local.expected);
		Assert.assertEquals(local.expected, local.secConf.getExecutorImplementation());
	}
	
	//@Test
	
	public void function testHTTPUtilitiesImplementation() {
		//test the default
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_HTTP_UTILITIES_IMPLEMENTATION, local.secConf.getHTTPUtilitiesImplementation());
	
		local.expected = "TestHTTPUtilities";
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().HTTP_UTILITIES_IMPLEMENTATION, local.expected);
		Assert.assertEquals(local.expected, local.secConf.getHTTPUtilitiesImplementation());
	}
	
	//@Test
	
	public void function testValidationImplementation() {
		//test the default
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_VALIDATOR_IMPLEMENTATION, local.secConf.getValidationImplementation());
	
		local.expected = "TestValidation";
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().VALIDATOR_IMPLEMENTATION, local.expected);
		Assert.assertEquals(local.expected, local.secConf.getValidationImplementation());
	}
	
	//@Test
	
	public void function testGetEncryptionKeyLength() {
		// test the default
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals(128, local.secConf.getEncryptionKeyLength());
	
		local.expected = 256;
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().KEY_LENGTH, int(local.expected));
		Assert.assertEquals(local.expected, local.secConf.getEncryptionKeyLength());
	}
	
	//@Test
	
	public void function testGetKDFPseudoRandomFunction() {
		// test the default
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals("HmacSHA256", local.secConf.getKDFPseudoRandomFunction());
	
		local.expected = "HmacSHA1";
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().KDF_PRF_ALG, local.expected);
		Assert.assertEquals(local.expected, local.secConf.getKDFPseudoRandomFunction());
	}
	
	//@Test
	
	public void function testGetMasterSalt() {
		try {
			local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
			local.secConf.getMasterSalt();
			Assert.fail("Expected Exception not thrown");
		}
		catch(cfesapi.org.owasp.esapi.errors.ConfigurationException ce) {
			Assert.assertFalse(isNull(ce.message));
		}
		
		local.salt = "53081";
		local.property = instance.ESAPI.encoder().encodeForBase64(local.salt.getBytes(), false);
		local.properties = newJava("java.util.Properties").init();
		local.properties.setProperty(instance.ESAPI.securityConfiguration().MASTER_SALT, local.property);
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, local.properties);
		Assert.assertEquals(local.salt, newJava("java.lang.String").init(local.secConf.getMasterSalt()));
	}
	
	//@Test
	
	public void function testGetAllowedExecutables() {
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		local.allowedExecutables = local.secConf.getAllowedExecutables();
	
		//is this really what should be returned? what about an empty list?
		Assert.assertEquals(1, arrayLen(local.allowedExecutables));
		Assert.assertEquals("", local.allowedExecutables[1]);
	
		local.properties = newJava("java.util.Properties").init();
		local.properties.setProperty(instance.ESAPI.securityConfiguration().APPROVED_EXECUTABLES, "/bin/bzip2,/bin/diff, /bin/cvs");
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, local.properties);
		local.allowedExecutables = local.secConf.getAllowedExecutables();
		Assert.assertEquals(3, arrayLen(local.allowedExecutables));
		Assert.assertEquals("/bin/bzip2", local.allowedExecutables[1]);
		Assert.assertEquals("/bin/diff", local.allowedExecutables[2]);
	
		//this seems less than optimal, maybe each value should have a trim() done to it
		//at least we know that this behavior exists, the property should'nt have spaces between values
		Assert.assertEquals(" /bin/cvs", local.allowedExecutables[3]);
	}
	
	//@Test
	
	public void function testGetAllowedFileExtensions() {
	
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		local.allowedFileExtensions = local.secConf.getAllowedFileExtensions();
		Assert.assertFalse(arrayLen(local.allowedFileExtensions) == 0);
	
		local.properties = newJava("java.util.Properties").init();
		local.properties.setProperty(instance.ESAPI.securityConfiguration().APPROVED_UPLOAD_EXTENSIONS, ".txt,.xml,.html,.png");
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, local.properties);
		local.allowedFileExtensions = local.secConf.getAllowedFileExtensions();
		Assert.assertEquals(4, arrayLen(local.allowedFileExtensions));
		Assert.assertEquals(".html", local.allowedFileExtensions[3]);
	}
	
	//@Test
	
	public void function testGetAllowedFileUploadSize() {
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		//assert that the default is of some reasonable size
		Assert.assertTrue(local.secConf.getAllowedFileUploadSize() > (1024 * 100));
	
		local.expected = (1024 * 1000);
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().MAX_UPLOAD_FILE_BYTES, int(local.expected));
		Assert.assertEquals(local.expected, local.secConf.getAllowedFileUploadSize());
	}
	
	//@Test
	
	public void function testGetParameterNames() {
		//test the default
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals("password", local.secConf.getPasswordParameterName());
		Assert.assertEquals("username", local.secConf.getUsernameParameterName());
	
		local.properties = newJava("java.util.Properties").init();
		local.properties.setProperty(instance.ESAPI.securityConfiguration().PASSWORD_PARAMETER_NAME, "j_password");
		local.properties.setProperty(instance.ESAPI.securityConfiguration().USERNAME_PARAMETER_NAME, "j_username");
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, local.properties);
		Assert.assertEquals("j_password", local.secConf.getPasswordParameterName());
		Assert.assertEquals("j_username", local.secConf.getUsernameParameterName());
	}
	
	//@Test
	
	public void function testGetEncryptionAlgorithm() {
		//test the default
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals("AES", local.secConf.getEncryptionAlgorithm());
	
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().ENCRYPTION_ALGORITHM, "3DES");
		Assert.assertEquals("3DES", local.secConf.getEncryptionAlgorithm());
	}
	
	//@Test
	
	public void function testGetCipherXProperties() {
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals("AES/CBC/PKCS5Padding", local.secConf.getCipherTransformation());
		//Assert.assertEquals("AES/CBC/PKCS5Padding", local.secConf.getC);
		local.properties = newJava("java.util.Properties").init();
		local.properties.setProperty(instance.ESAPI.securityConfiguration().CIPHER_TRANSFORMATION_IMPLEMENTATION, "Blowfish/CFB/ISO10126Padding");
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, local.properties);
		Assert.assertEquals("Blowfish/CFB/ISO10126Padding", local.secConf.getCipherTransformation());
	
		local.secConf.setCipherTransformation("DESede/PCBC/PKCS5Padding");
		Assert.assertEquals("DESede/PCBC/PKCS5Padding", local.secConf.getCipherTransformation());
	
		local.secConf.setCipherTransformation("");//sets it back to default
		Assert.assertEquals("Blowfish/CFB/ISO10126Padding", local.secConf.getCipherTransformation());
	}
	
	//@Test
	
	public void function testIV() {
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals("random", local.secConf.getIVType());
		try {
			local.secConf.getFixedIV();
			Assert.fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.ConfigurationException ce) {
			Assert.assertFalse(isNull(ce.message));
		}
		
		local.properties = newJava("java.util.Properties").init();
		local.properties.setProperty(instance.ESAPI.securityConfiguration().IV_TYPE, "fixed");
		local.properties.setProperty(instance.ESAPI.securityConfiguration().FIXED_IV, "ivValue");
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, local.properties);
		Assert.assertEquals("fixed", local.secConf.getIVType());
		Assert.assertEquals("ivValue", local.secConf.getFixedIV());
	
		local.properties.setProperty(instance.ESAPI.securityConfiguration().IV_TYPE, "illegal");
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, local.properties);
		try {
			local.secConf.getIVType();
			Assert.fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.ConfigurationException ce) {
			Assert.assertTrue(len(ce.message));
		}
		try {
			local.secConf.getFixedIV();
			Assert.fail();
		}
		catch(cfesapi.org.owasp.esapi.errors.ConfigurationException ce) {
			Assert.assertTrue(len(ce.message));
		}
	}
	
	//@Test
	
	public void function testGetAllowMultipleEncoding() {
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertFalse(local.secConf.getAllowMultipleEncoding());
	
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().ALLOW_MULTIPLE_ENCODING, "yes");
		Assert.assertTrue(local.secConf.getAllowMultipleEncoding());
	
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().ALLOW_MULTIPLE_ENCODING, "true");
		Assert.assertTrue(local.secConf.getAllowMultipleEncoding());
	
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().ALLOW_MULTIPLE_ENCODING, "no");
		Assert.assertFalse(local.secConf.getAllowMultipleEncoding());
	}
	
	//@Test
	
	public void function testGetDefaultCanonicalizationCodecs() {
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertFalse(local.secConf.getDefaultCanonicalizationCodecs().isEmpty());
	
		local.property = "org.owasp.esapi.codecs.TestCodec1,org.owasp.esapi.codecs.TestCodec2";
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().CANONICALIZATION_CODECS, local.property);
		Assert.assertTrue(arrayFind(local.secConf.getDefaultCanonicalizationCodecs(), "org.owasp.esapi.codecs.TestCodec1"));
	}
	
	//@Test
	
	public void function testGetDisableIntrusionDetection() {
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertFalse(local.secConf.getDisableIntrusionDetection());
	
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().DISABLE_INTRUSION_DETECTION, "TRUE");
		Assert.assertTrue(local.secConf.getDisableIntrusionDetection());
	
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().DISABLE_INTRUSION_DETECTION, "true");
		Assert.assertTrue(local.secConf.getDisableIntrusionDetection());
	
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().DISABLE_INTRUSION_DETECTION, "false");
		Assert.assertFalse(local.secConf.getDisableIntrusionDetection());
	}
	
	//@Test
	
	public void function testGetLogLevel() {
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals(newJava("org.owasp.esapi.Logger").WARNING, local.secConf.getLogLevel());
	
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_LEVEL, "trace");
		Assert.assertEquals(newJava("org.owasp.esapi.Logger").TRACE, local.secConf.getLogLevel());
	
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_LEVEL, "Off");
		Assert.assertEquals(newJava("org.owasp.esapi.Logger").OFF, local.secConf.getLogLevel());
	
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_LEVEL, "all");
		Assert.assertEquals(newJava("org.owasp.esapi.Logger").ALL, local.secConf.getLogLevel());
	
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_LEVEL, "DEBUG");
		Assert.assertEquals(newJava("org.owasp.esapi.Logger").DEBUG, local.secConf.getLogLevel());
	
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_LEVEL, "info");
		Assert.assertEquals(newJava("org.owasp.esapi.Logger").INFO, local.secConf.getLogLevel());
	
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_LEVEL, "ERROR");
		Assert.assertEquals(newJava("org.owasp.esapi.Logger").ERROR, local.secConf.getLogLevel());
	}
	
	//@Test
	
	public void function testGetLogFileName() {
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals("ESAPI_logging_file", local.secConf.getLogFileName());
	
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().LOG_FILE_NAME, "log.txt");
		Assert.assertEquals("log.txt", local.secConf.getLogFileName());
	}
	
	//@Test
	
	public void function testGetMaxLogFileSize() {
		local.secConf = new cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration(instance.ESAPI, newJava("java.util.Properties").init());
		Assert.assertEquals(instance.ESAPI.securityConfiguration().DEFAULT_MAX_LOG_FILE_SIZE, local.secConf.getMaxLogFileSize());
	
		local.maxLogSize = (1024 * 1000);
		local.secConf = createWithProperty(instance.ESAPI.securityConfiguration().MAX_LOG_FILE_SIZE, local.maxLogSize);
		Assert.assertEquals(local.maxLogSize, local.secConf.getMaxLogFileSize());
	}
	
}