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
import "org.owasp.esapi.reference.validation.StringValidationRule";

component extends="esapi4cf.test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	public void function testWhitelistPattern() {

		var validationRule = new StringValidationRule(variables.ESAPI, "Alphabetic");

		assertEquals("Magnum44", validationRule.getValid("", "Magnum44"));
		validationRule.addWhitelistPattern("^[a-zA-Z]*");
		try {
			validationRule.getValid("", "Magnum44");
			fail("Expected Exception not thrown");
		}
		catch (org.owasp.esapi.errors.ValidationException ve) {
			assertFalse(isNull(ve.getMessage()));
		}
		assertEquals("MagnumPI", validationRule.getValid("", "MagnumPI"));
	}

	public void function testWhitelistPattern_Invalid() {

		var validationRule = new StringValidationRule(variables.ESAPI, "");

		//null white list patterns throw IllegalArgumentException
		try {
			var pattern = "";
			validationRule.addWhitelistPattern(pattern);
			fail("Expected Exception not thrown");
		}
		catch (java.lang.IllegalArgumentException ie) {
			assertFalse(isNull(ie.getMessage()));
		}

		try {
			var pattern = "";
			validationRule.addWhitelistPattern(pattern);
			fail("Expected Exception not thrown");
		}
		catch (java.lang.IllegalArgumentException ie) {
			assertFalse(isNull(ie.getMessage()));
		}

		//invalid white list patterns throw PatternSyntaxException
		try {
			var pattern = "_][0}[";
			validationRule.addWhitelistPattern(pattern);
			fail("Expected Exception not thrown");
		}
		catch (java.lang.IllegalArgumentException ie) {
			assertFalse(isNull(ie.getMessage()));
		}
	}

	public void function testWhitelist() {
		var validationRule = new StringValidationRule(variables.ESAPI, "");

		var whitelistArray = ['a', 'b', 'c'];
		assertEquals("abc", validationRule.whitelist("12345abcdef", whitelistArray));
	}

	public void function testBlacklistPattern() {

		var validationRule = new StringValidationRule(variables.ESAPI, "NoAngleBrackets");

		assertEquals("beg <script> end", validationRule.getValid("", "beg <script> end"));
		validationRule.addBlacklistPattern("^.*(<|>).*");
		try {
			validationRule.getValid("", "beg <script> end");
			fail("Expected Exception not thrown");
		}
		catch (org.owasp.esapi.errors.ValidationException ve) {
			assertFalse(isNull(ve.getMessage()));
		}
		assertEquals("beg script end", validationRule.getValid("", "beg script end"));
	}

	public void function testBlacklistPattern_Invalid() {

		var validationRule = new StringValidationRule(variables.ESAPI, "");

		//null black list patterns throw IllegalArgumentException
		try {
			var pattern = "";
			validationRule.addBlacklistPattern(pattern);
			fail("Expected Exception not thrown");
		}
		catch (java.lang.IllegalArgumentException ie) {
			assertFalse(isNull(ie.getMessage()));
		}

		try {
			var pattern = "";
			validationRule.addBlacklistPattern(pattern);
			fail("Expected Exception not thrown");
		}
		catch (java.lang.IllegalArgumentException ie) {
			assertFalse(isNull(ie.getMessage()));
		}

		//invalid black list patterns throw PatternSyntaxException
		try {
			var pattern = "_][0}[";
			validationRule.addBlacklistPattern(pattern);
			fail("Expected Exception not thrown");
		}
		catch (java.lang.IllegalArgumentException ie) {
			assertFalse(isNull(ie.getMessage()));
		}
	}

	public void function testCheckLengths() {

		var validationRule = new StringValidationRule(variables.ESAPI, "Max12_Min2");
		validationRule.setMinimumLength(2);
		validationRule.setMaximumLength(12);

		assertTrue(validationRule.isValid("", "12"));
		assertTrue(validationRule.isValid("", "123456"));
		assertTrue(validationRule.isValid("", "ABCDEFGHIJKL"));

		assertFalse(validationRule.isValid("", "1"));
		assertFalse(validationRule.isValid("", "ABCDEFGHIJKLM"));

		var errorList = {};
		assertEquals("1234567890", validationRule.getValid("", "1234567890", errorList));
		assertEquals(0, errorList.size());
		assertEquals("", validationRule.getValid("", "123456789012345", errorList));
		assertEquals(1, errorList.size());
	}

	public void function testAllowNull() {

		var validationRule = new StringValidationRule(variables.ESAPI, "");

		assertFalse(validationRule.isAllowNull());
		assertFalse(validationRule.isValid("", ""));

		validationRule.setAllowNull(true);
		assertTrue(validationRule.isAllowNull());
		assertTrue(validationRule.isValid("", ""));
	}

}
