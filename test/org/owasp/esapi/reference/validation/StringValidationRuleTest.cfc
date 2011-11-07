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
component StringValidationRuleTest extends="cfesapi.test.org.owasp.esapi.lang.TestCase" {

	instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();

	public void function testWhitelistPattern() {
	
		local.validationRule = new cfesapi.org.owasp.esapi.reference.validation.StringValidationRule(instance.ESAPI, "Alphabetic");
	
		Assert.assertEquals("Magnum44", local.validationRule.getValid("", "Magnum44"));
		local.validationRule.addWhitelistPattern("^[a-zA-Z]*");
		try {
			local.validationRule.getValid("", "Magnum44");
			Assert.fail("Expected Exception not thrown");
		}
		catch(cfesapi.org.owasp.esapi.errors.ValidationException ve) {
			Assert.assertTrue(len(ve.message));
		}
		Assert.assertEquals("MagnumPI", local.validationRule.getValid("", "MagnumPI"));
	}
	
	public void function testWhitelistPattern_Invalid() {
	
		local.validationRule = new cfesapi.org.owasp.esapi.reference.validation.StringValidationRule(instance.ESAPI, "");
	
		//null white list patterns throw IllegalArgumentException
		/* NULL test
		try {
		    local.pattern = null;
		    local.validationRule.addWhitelistPattern(local.pattern);
		    Assert.fail("Expected Exception not thrown");
		}
		catch (java.lang.IllegalArgumentException ie) {
		    Assert.assertTrue(len(ie.message));
		} */
		/* NULL test
		try {
		    local.pattern = null;
		    validationRule.addWhitelistPattern(local.pattern);
		    Assert.fail("Expected Exception not thrown");
		}
		catch (java.lang.IllegalArgumentException ie) {
		    Assert.assertTrue(len(ie.message));
		}*/
		//invalid white list patterns throw PatternSyntaxException
		try {
			local.pattern = "_][0}[";
			local.validationRule.addWhitelistPattern(local.pattern);
			Assert.fail("Expected Exception not thrown");
		}
		catch(java.lang.IllegalArgumentException ie) {
			Assert.assertTrue(len(ie.message));
		}
	}
	
	public void function testWhitelist() {
		local.validationRule = new cfesapi.org.owasp.esapi.reference.validation.StringValidationRule(instance.ESAPI, "");
	
		local.whitelistArray = ['a', 'b', 'c'];
		Assert.assertEquals("abc", local.validationRule.whitelist("12345abcdef", local.whitelistArray));
	}
	
	public void function testBlacklistPattern() {
	
		local.validationRule = new cfesapi.org.owasp.esapi.reference.validation.StringValidationRule(instance.ESAPI, "NoAngleBrackets");
	
		Assert.assertEquals("beg <script> end", validationRule.getValid("", "beg <script> end"));
		local.validationRule.addBlacklistPattern("^.*(<|>).*");
		try {
			local.validationRule.getValid("", "beg <script> end");
			Assert.fail("Expected Exception not thrown");
		}
		catch(cfesapi.org.owasp.esapi.errors.ValidationException ve) {
			Assert.assertTrue(len(ve.message));
		}
		Assert.assertEquals("beg script end", local.validationRule.getValid("", "beg script end"));
	}
	
	public void function testBlacklistPattern_Invalid() {
	
		local.validationRule = new cfesapi.org.owasp.esapi.reference.validation.StringValidationRule(instance.ESAPI, "");
	
		//null black list patterns throw IllegalArgumentException
		/* NULL test
		try {
		    local.pattern = null;
		    local.validationRule.addBlacklistPattern(local.pattern);
		    Assert.fail("Expected Exception not thrown");
		}
		catch (java.lang.IllegalArgumentException ie) {
		    Assert.assertTrue(len(ie.message));
		}*/
		/* NULL test
		try {
		    local.pattern = null;
		    local.validationRule.addBlacklistPattern(local.pattern);
		    Assert.fail("Expected Exception not thrown");
		}
		catch (java.lang.IllegalArgumentException ie) {
		    Assert.assertTrue(len(ie.message));
		}*/
		//invalid black list patterns throw PatternSyntaxException
		try {
			local.pattern = "_][0}[";
			local.validationRule.addBlacklistPattern(local.pattern);
			Assert.fail("Expected Exception not thrown");
		}
		catch(java.lang.IllegalArgumentException ie) {
			Assert.assertTrue(len(ie.message));
		}
	}
	
	public void function testCheckLengths() {
	
		local.validationRule = new cfesapi.org.owasp.esapi.reference.validation.StringValidationRule(instance.ESAPI, "Max12_Min2");
		local.validationRule.setMinimumLength(2);
		local.validationRule.setMaximumLength(12);
	
		Assert.assertTrue(local.validationRule.isValid("", "12"));
		Assert.assertTrue(local.validationRule.isValid("", "123456"));
		Assert.assertTrue(local.validationRule.isValid("", "ABCDEFGHIJKL"));
	
		Assert.assertFalse(local.validationRule.isValid("", "1"));
		Assert.assertFalse(local.validationRule.isValid("", "ABCDEFGHIJKLM"));
	
		local.errorList = new cfesapi.org.owasp.esapi.ValidationErrorList();
		Assert.assertEquals("1234567890", local.validationRule.getValid("", "1234567890", local.errorList));
		Assert.assertEquals(0, local.errorList.size());
		Assert.assertEquals("", local.validationRule.getValid("", "123456789012345", local.errorList));
		Assert.assertEquals(1, local.errorList.size());
	}
	
	public void function testAllowNull() {
	
		local.validationRule = new cfesapi.org.owasp.esapi.reference.validation.StringValidationRule(instance.ESAPI, "");
	
		Assert.assertFalse(local.validationRule.isAllowNull());
		Assert.assertFalse(local.validationRule.isValid("", ""));
	
		local.validationRule.setAllowNull(true);
		Assert.assertTrue(local.validationRule.isAllowNull());
		Assert.assertTrue(local.validationRule.isValid("", ""));
	}
	
}