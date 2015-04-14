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

component extends="esapi4cf.test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	public void function testGetApplicationName() {
		// test default
		assertEquals(getApplicationMetaData().name, variables.ESAPI.securityConfiguration().getApplicationName());

		// test override
		var expected = "ESAPI_UnitTests";
		var secConf = new SecurityConfiguration(variables.ESAPI, {Logger.ApplicationName: expected});
		assertEquals(expected, secConf.getApplicationName());
	}

	public void function testGetEncryptionKeyLength() {
		// test the default
		assertEquals(128, variables.ESAPI.securityConfiguration().getEncryptionKeyLength());

		// test override
		var expected = 256;
		var secConf = new SecurityConfiguration(variables.ESAPI, {Encryptor.EncryptionKeyLength: expected});
		assertEquals(expected, secConf.getEncryptionKeyLength());
	}

	public void function testGetKDFPseudoRandomFunction() {
		// test the default
		assertEquals("HmacSHA256", variables.ESAPI.securityConfiguration().getKDFPseudoRandomFunction());

		var expected = "HmacSHA1";
		var secConf = new SecurityConfiguration(variables.ESAPI, {Encryptor.KDF.PRF: expected});
		assertEquals(expected, secConf.getKDFPseudoRandomFunction());
	}

	public void function testGetMasterSalt() {
		try {
			variables.ESAPI.securityConfiguration().getMasterSalt();
			fail("Expected Exception not thrown");
		}
		catch (org.owasp.esapi.errors.ConfigurationException ce) {
			assertFalse(isNull(ce.getMessage()));
		}

		var salt = "53081";
		var property = variables.ESAPI.encoder().encodeForBase64(salt.getBytes(), false);
		var secConf = new SecurityConfiguration(variables.ESAPI, {Encryptor.MasterSalt: property});
		assertEquals(salt, charsetEncode(secConf.getMasterSalt(), "utf-8"));
	}

	public void function testGetAllowedExecutables() {
		var allowedExecutables = variables.ESAPI.securityConfiguration().getAllowedExecutables();

		//is this really what should be returned? what about an empty list?
		assertEquals(0, arrayLen(allowedExecutables));
		//assertEquals("", allowedExecutables[1]);

		secConf = new SecurityConfiguration(variables.ESAPI, {Executor.ApprovedExecutables: listToArray("/bin/bzip2,/bin/diff, /bin/cvs")});
		allowedExecutables = secConf.getAllowedExecutables();
		assertEquals(3, arrayLen(allowedExecutables));
		assertEquals("/bin/bzip2", allowedExecutables[1]);
		assertEquals("/bin/diff", allowedExecutables[2]);

		//this seems less than optimal, maybe each value should have a trim() done to it
		//at least we know that this behavior exists, the property should'nt have spaces between values
		assertEquals(" /bin/cvs", allowedExecutables[3]);
	}

	public void function testGetAllowedFileExtensions() {
		var allowedFileExtensions = variables.ESAPI.securityConfiguration().getAllowedFileExtensions();
		assertFalse(allowedFileExtensions.isEmpty());

		secConf = new SecurityConfiguration(variables.ESAPI, {HttpUtilities.ApprovedUploadExtensions: listToArray(".txt,.xml,.html,.png")});
		allowedFileExtensions = secConf.getAllowedFileExtensions();
		assertEquals(4, arrayLen(allowedFileExtensions));
		assertEquals(".html", allowedFileExtensions[3]);
	}

	public void function testGetAllowedFileUploadSize() {
		//assert that the default is of some reasonable size
		assertTrue(variables.ESAPI.securityConfiguration().getAllowedFileUploadSize() > (1024 * 100));

		var expected = (1024 * 1000);
		var secConf = new SecurityConfiguration(variables.ESAPI, {HttpUtilities.MaxUploadFileBytes: expected});
		assertEquals(expected, secConf.getAllowedFileUploadSize());
	}

	public void function testGetParameterNames() {
		//test the default
		assertEquals("password", variables.ESAPI.securityConfiguration().getPasswordParameterName());
		assertEquals("username", variables.ESAPI.securityConfiguration().getUsernameParameterName());

		secConf = new SecurityConfiguration(variables.ESAPI, {
			Authenticator.PasswordParameterName: "j_password",
			Authenticator.UsernameParameterName: "j_username"
		});
		assertEquals("j_password", secConf.getPasswordParameterName());
		assertEquals("j_username", secConf.getUsernameParameterName());
	}

	public void function testGetEncryptionAlgorithm() {
		//test the default
		assertEquals("AES", variables.ESAPI.securityConfiguration().getEncryptionAlgorithm());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Encryptor.EncryptionAlgorithm: "3DES"});
		assertEquals("3DES", secConf.getEncryptionAlgorithm());
	}

	public void function testGetCipherXProperties() {
		assertEquals("AES/CBC/PKCS5Padding", variables.ESAPI.securityConfiguration().getCipherTransformation());
		//assertEquals("AES/CBC/PKCS5Padding", variables.ESAPI.securityConfiguration().getC);

		secConf = new SecurityConfiguration(variables.ESAPI, {Encryptor.CipherTransformation: "Blowfish/CFB/ISO10126Padding"});
		assertEquals("Blowfish/CFB/ISO10126Padding", secConf.getCipherTransformation());

		secConf.setCipherTransformation("DESede/PCBC/PKCS5Padding");
		assertEquals("DESede/PCBC/PKCS5Padding", secConf.getCipherTransformation());

		secConf.setCipherTransformation("");//sets it back to default
		assertEquals("Blowfish/CFB/ISO10126Padding", secConf.getCipherTransformation());
	}

	public void function testIV() {
		assertEquals("random", variables.ESAPI.securityConfiguration().getIVType());
		try {
			variables.ESAPI.securityConfiguration().getFixedIV();
			fail();
		}
		catch (org.owasp.esapi.errors.ConfigurationException ce) {
			assertFalse(isNull(ce.getMessage()));
		}

		secConf = new SecurityConfiguration(variables.ESAPI, {
			Encryptor.ChooseIVMethod: "fixed",
			Encryptor.fixedIV: "ivValue"
		});
		assertEquals("fixed", secConf.getIVType());
		assertEquals("ivValue", secConf.getFixedIV());

		secConf = new SecurityConfiguration(variables.ESAPI, {Encryptor.ChooseIVMethod: "illegal"});
		try {
			secConf.getIVType();
			fail("");
		}
		catch (org.owasp.esapi.errors.ConfigurationException ce) {
			assertFalse(isNull(ce.getMessage()));
		}
		try {
			secConf.getFixedIV();
			fail("");
		}
		catch (org.owasp.esapi.errors.ConfigurationException ce) {
			assertFalse(isNull(ce.getMessage()));
		}
	}

	public void function testGetAllowMultipleEncoding() {
		assertFalse(variables.ESAPI.securityConfiguration().getAllowMultipleEncoding());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Encoder.AllowMultipleEncoding: "yes"});
		assertTrue(secConf.getAllowMultipleEncoding());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Encoder.AllowMultipleEncoding: "true"});
		assertTrue(secConf.getAllowMultipleEncoding());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Encoder.AllowMultipleEncoding: "no"});
		assertFalse(secConf.getAllowMultipleEncoding());
	}

	public void function testGetDefaultCanonicalizationCodecs() {
		assertEquals(3, arrayLen(variables.ESAPI.securityConfiguration().getDefaultCanonicalizationCodecs()));

		var property = "org.owasp.esapi.codecs.TestCodec1,org.owasp.esapi.codecs.TestCodec2";
		var secConf = new SecurityConfiguration(variables.ESAPI, {Encoder.DefaultCodecList: property});
		assertTrue(arrayFind(secConf.getDefaultCanonicalizationCodecs(), "org.owasp.esapi.codecs.TestCodec1"));
	}

	public void function testGetDisableIntrusionDetection() {
		assertFalse(variables.ESAPI.securityConfiguration().getDisableIntrusionDetection());

		var secConf = new SecurityConfiguration(variables.ESAPI, {IntrusionDetector.Disable: "TRUE"});
		assertTrue(secConf.getDisableIntrusionDetection());

		var secConf = new SecurityConfiguration(variables.ESAPI, {IntrusionDetector.Disable: "true"});
		assertTrue(secConf.getDisableIntrusionDetection());

		var secConf = new SecurityConfiguration(variables.ESAPI, {IntrusionDetector.Disable: "false"});
		assertFalse(secConf.getDisableIntrusionDetection());
	}

	public void function testGetLogLevel() {
		var Logger = createObject("java", "org.owasp.esapi.Logger");

		assertEquals(Logger.WARNING, variables.ESAPI.securityConfiguration().getLogLevel());

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
		assertEquals("ESAPI_logging_file", variables.ESAPI.securityConfiguration().getLogFileName());

		var secConf = new SecurityConfiguration(variables.ESAPI, {Logger.LogFileName: "log.txt"});
		assertEquals("log.txt", secConf.getLogFileName());
	}

}
