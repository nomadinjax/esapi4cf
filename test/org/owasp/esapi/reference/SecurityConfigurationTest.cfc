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
import "org.owasp.esapi.reference.SecurityConfiguration";

component extends="test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	public void function testGetApplicationName() {
		// test default
		assertEquals(getApplicationMetaData().name, variables.ESAPI.securityConfiguration().getApplicationName());

		// test override
		var expected = "ESAPI_UnitTests";
		var secConf = new SecurityConfiguration(variables.ESAPI, {Logger.ApplicationName: expected});
		assertEquals(expected, secConf.getApplicationName());
	}

	public void function testGetLogImplementation() {
		//test the default
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("org.owasp.esapi.reference.LogFactory", secConf.getLogImplementation());

		var expected = "TestLogger";
		var secConf = new SecurityConfiguration(variables.ESAPI, {ESAPI.Logger: expected});
		assertEquals(expected, secConf.getLogImplementation());
	}

	public void function testAuthenticationImplementation() {
		//test the default
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("org.owasp.esapi.reference.Authenticator", secConf.getAuthenticationImplementation());

		var expected = "TestAuthentication";
		var secConf = new SecurityConfiguration(variables.ESAPI, {ESAPI.Authenticator: expected});
		assertEquals(expected, secConf.getAuthenticationImplementation());
	}

	public void function testEncoderImplementation() {
		//test the default
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("org.owasp.esapi.reference.Encoder", secConf.getEncoderImplementation());

		var expected = "TestEncoder";
		var secConf = new SecurityConfiguration(variables.ESAPI, {ESAPI.Encoder: expected});
		assertEquals(expected, secConf.getEncoderImplementation());
	}

	public void function testAccessControlImplementation() {
		//test the default
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("org.owasp.esapi.reference.AccessController", secConf.getAccessControlImplementation());

		var expected = "TestAccessControl";
		var secConf = new SecurityConfiguration(variables.ESAPI, {ESAPI.AccessControl: expected});
		assertEquals(expected, secConf.getAccessControlImplementation());
	}

	public void function testEncryptionImplementation() {
		//test the default
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("org.owasp.esapi.reference.crypto.Encryptor", secConf.getEncryptionImplementation());

		var expected = "TestEncryption";
		var secConf = new SecurityConfiguration(variables.ESAPI, {ESAPI.Encryptor: expected});
		assertEquals(expected, secConf.getEncryptionImplementation());
	}

	public void function testIntrusionDetectionImplementation() {
		//test the default
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("org.owasp.esapi.reference.IntrusionDetector", secConf.getIntrusionDetectionImplementation());

		var expected = "TestIntrusionDetection";
		var secConf = new SecurityConfiguration(variables.ESAPI, {ESAPI.IntrusionDetector: expected});
		assertEquals(expected, secConf.getIntrusionDetectionImplementation());
	}

	public void function testRandomizerImplementation() {
		//test the default
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("org.owasp.esapi.reference.Randomizer", secConf.getRandomizerImplementation());

		var expected = "TestRandomizer";
		var secConf = new SecurityConfiguration(variables.ESAPI, {ESAPI.Randomizer: expected});
		assertEquals(expected, secConf.getRandomizerImplementation());
	}

	public void function testExecutorImplementation() {
		//test the default
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("org.owasp.esapi.reference.Executor", secConf.getExecutorImplementation());

		var expected = "TestExecutor";
		var secConf = new SecurityConfiguration(variables.ESAPI, {ESAPI.Executor: expected});
		assertEquals(expected, secConf.getExecutorImplementation());
	}

	public void function testHTTPUtilitiesImplementation() {
		//test the default
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("org.owasp.esapi.reference.HTTPUtilities", secConf.getHTTPUtilitiesImplementation());

		var expected = "TestHTTPUtilities";
		var secConf = new SecurityConfiguration(variables.ESAPI, {ESAPI.HTTPUtilities: expected});
		assertEquals(expected, secConf.getHTTPUtilitiesImplementation());
	}

	public void function testValidationImplementation() {
		//test the default
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("org.owasp.esapi.reference.Validator", secConf.getValidationImplementation());

		var expected = "TestValidation";
		var secConf = new SecurityConfiguration(variables.ESAPI, {ESAPI.Validator: expected});
		assertEquals(expected, secConf.getValidationImplementation());
	}

	public void function testGetEncryptionKeyLength() {
		// test the default
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals(128, secConf.getEncryptionKeyLength());

		// test override
		var expected = 256;
		var secConf = new SecurityConfiguration(variables.ESAPI, {Encryptor.EncryptionKeyLength: expected});
		assertEquals(expected, secConf.getEncryptionKeyLength());
	}

	public void function testGetKDFPseudoRandomFunction() {
		// test the default
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("HmacSHA256", secConf.getKDFPseudoRandomFunction());

		var expected = "HmacSHA1";
		var secConf = new SecurityConfiguration(variables.ESAPI, {Encryptor.KDF.PRF: expected});
		assertEquals(expected, secConf.getKDFPseudoRandomFunction());
	}

	public void function testGetMasterSalt() {
		try {
			var secConf = new SecurityConfiguration(variables.ESAPI, {});
			secConf.getMasterSalt();
			fail("Expected Exception not thrown");
		}
		catch (org.owasp.esapi.errors.ConfigurationException ce) {
			assertFalse(isNull(ce.message));
		}

		var salt = "53081";
		var property = variables.ESAPI.encoder().encodeForBase64(salt.getBytes(), false);
		var secConf = new SecurityConfiguration(variables.ESAPI, {Encryptor.MasterSalt: property});
		assertEquals(salt, charsetEncode(secConf.getMasterSalt(), "utf-8"));
	}

	public void function testGetAllowedExecutables() {
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		var allowedExecutables = secConf.getAllowedExecutables();

		//is this really what should be returned? what about an empty list?
		assertEquals(0, arrayLen(allowedExecutables));
		//assertEquals("", allowedExecutables[1]);

		var secConf = new SecurityConfiguration(variables.ESAPI, {Executor.ApprovedExecutables: listToArray("/bin/bzip2,/bin/diff, /bin/cvs")});
		allowedExecutables = secConf.getAllowedExecutables();
		assertEquals(3, arrayLen(allowedExecutables));
		assertEquals("/bin/bzip2", allowedExecutables[1]);
		assertEquals("/bin/diff", allowedExecutables[2]);

		//this seems less than optimal, maybe each value should have a trim() done to it
		//at least we know that this behavior exists, the property should'nt have spaces between values
		assertEquals(" /bin/cvs", allowedExecutables[3]);
	}

	public void function testGetAllowedFileExtensions() {

		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		var allowedFileExtensions = secConf.getAllowedFileExtensions();
		assertFalse(allowedFileExtensions.isEmpty());

		var secConf = new SecurityConfiguration(variables.ESAPI, {HttpUtilities.ApprovedUploadExtensions: listToArray(".txt,.xml,.html,.png")});
		allowedFileExtensions = secConf.getAllowedFileExtensions();
		assertEquals(4, arrayLen(allowedFileExtensions));
		assertEquals(".html", allowedFileExtensions[3]);
	}

	public void function testGetAllowedFileUploadSize() {
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		//assert that the default is of some reasonable size
		assertTrue(secConf.getAllowedFileUploadSize() > (1024 * 100));

		var expected = (1024 * 1000);
		var secConf = new SecurityConfiguration(variables.ESAPI, {HttpUtilities.MaxUploadFileBytes: expected});
		assertEquals(expected, secConf.getAllowedFileUploadSize());
	}

	public void function testGetParameterNames() {
		//test the default
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("password", secConf.getPasswordParameterName());
		assertEquals("username", secConf.getUsernameParameterName());

		var secConf = new SecurityConfiguration(variables.ESAPI, {
			Authenticator.PasswordParameterName: "j_password",
			Authenticator.UsernameParameterName: "j_username"
		});
		assertEquals("j_password", secConf.getPasswordParameterName());
		assertEquals("j_username", secConf.getUsernameParameterName());
	}

	public void function testGetEncryptionAlgorithm() {
		//test the default
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("AES", secConf.getEncryptionAlgorithm());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Encryptor.EncryptionAlgorithm: "3DES"});
		assertEquals("3DES", secConf.getEncryptionAlgorithm());
	}

	public void function testGetCipherXProperties() {
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("AES/CBC/PKCS5Padding", secConf.getCipherTransformation());
		//assertEquals("AES/CBC/PKCS5Padding", secConf.getC);

		var secConf = new SecurityConfiguration(variables.ESAPI, {Encryptor.CipherTransformation: "Blowfish/CFB/ISO10126Padding"});
		assertEquals("Blowfish/CFB/ISO10126Padding", secConf.getCipherTransformation());

		secConf.setCipherTransformation("DESede/PCBC/PKCS5Padding");
		assertEquals("DESede/PCBC/PKCS5Padding", secConf.getCipherTransformation());

		secConf.setCipherTransformation("");//sets it back to default
		assertEquals("Blowfish/CFB/ISO10126Padding", secConf.getCipherTransformation());
	}

	public void function testIV() {
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("random", secConf.getIVType());
		try {
			secConf.getFixedIV();
			fail();
		}
		catch (org.owasp.esapi.errors.ConfigurationException ce) {
			assertFalse(isNull(ce.message));
		}

		var secConf = new SecurityConfiguration(variables.ESAPI, {
			Encryptor.ChooseIVMethod: "fixed",
			Encryptor.fixedIV: "ivValue"
		});
		assertEquals("fixed", secConf.getIVType());
		assertEquals("ivValue", secConf.getFixedIV());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Encryptor.ChooseIVMethod: "illegal"});
		try {
			secConf.getIVType();
			fail("");
		}
		catch (org.owasp.esapi.errors.ConfigurationException ce) {
			assertFalse(isNull(ce.message));
		}
		try {
			secConf.getFixedIV();
			fail("");
		}
		catch (org.owasp.esapi.errors.ConfigurationException ce) {
			assertFalse(isNull(ce.message));
		}
	}

	public void function testGetAllowMultipleEncoding() {
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertFalse(secConf.getAllowMultipleEncoding());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Encoder.AllowMultipleEncoding: "yes"});
		assertTrue(secConf.getAllowMultipleEncoding());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Encoder.AllowMultipleEncoding: "true"});
		assertTrue(secConf.getAllowMultipleEncoding());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Encoder.AllowMultipleEncoding: "no"});
		assertFalse(secConf.getAllowMultipleEncoding());
	}

	public void function testGetDefaultCanonicalizationCodecs() {
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals(3, arrayLen(secConf.getDefaultCanonicalizationCodecs()));

		var property = "org.owasp.esapi.codecs.TestCodec1,org.owasp.esapi.codecs.TestCodec2";
		var secConf = new SecurityConfiguration(variables.ESAPI, {Encoder.DefaultCodecList: property});
		assertTrue(arrayFind(secConf.getDefaultCanonicalizationCodecs(), "org.owasp.esapi.codecs.TestCodec1"));
	}

	public void function testGetDisableIntrusionDetection() {
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertFalse(secConf.getDisableIntrusionDetection());

		var secConf = new SecurityConfiguration(variables.ESAPI, {IntrusionDetector.Disable: "TRUE"});
		assertTrue(secConf.getDisableIntrusionDetection());

		var secConf = new SecurityConfiguration(variables.ESAPI, {IntrusionDetector.Disable: "true"});
		assertTrue(secConf.getDisableIntrusionDetection());

		var secConf = new SecurityConfiguration(variables.ESAPI, {IntrusionDetector.Disable: "false"});
		assertFalse(secConf.getDisableIntrusionDetection());
	}

	public void function testGetLogLevel() {
		var Logger = createObject("java", "org.owasp.esapi.Logger");

		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals(Logger.WARNING, secConf.getLogLevel());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Logger.LogLevel: "trace"});
		assertEquals(Logger.TRACE, secConf.getLogLevel());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Logger.LogLevel: "Off"});
		assertEquals(Logger.OFF, secConf.getLogLevel());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Logger.LogLevel: "all"});
		assertEquals(Logger.ALL, secConf.getLogLevel());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Logger.LogLevel: "DEBUG"});
		assertEquals(Logger.DEBUG, secConf.getLogLevel());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Logger.LogLevel: "info"});
		assertEquals(Logger.INFO, secConf.getLogLevel());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Logger.LogLevel: "ERROR"});
		assertEquals(Logger.ERROR, secConf.getLogLevel());
	}

	public void function testGetLogFileName() {
		var secConf = new SecurityConfiguration(variables.ESAPI, {});
		assertEquals("ESAPI_logging_file", secConf.getLogFileName());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Logger.LogFileName: "log.txt"});
		assertEquals("log.txt", secConf.getLogFileName());
	}

}
