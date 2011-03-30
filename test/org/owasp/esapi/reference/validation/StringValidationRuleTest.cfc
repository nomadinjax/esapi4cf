<cfcomponent extends="cfesapi.test.org.owasp.esapi.TestCase" output="false">


	<cffunction access="public" returntype="void" name="testWhitelistPattern" output="false">
		<cfscript>
			local.validationRule = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.StringValidationRule").init(instance.ESAPI, "Alphabetic");

			assertEquals("Magnum44", local.validationRule.getValid("", "Magnum44"));
			local.validationRule.addWhitelistPattern("^[a-zA-Z]*");
			try {
				local.validationRule.getValid("", "Magnum44");
				fail("Expected Exception not thrown");
			}
			catch (cfesapi.org.owasp.esapi.errors.ValidationException ve) {
				assertTrue(len(ve.getMessage()));
			}
			assertEquals("MagnumPI", local.validationRule.getValid("", "MagnumPI"));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testWhitelistPattern_Invalid" output="false">
		<cfscript>
			local.validationRule = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.StringValidationRule").init(instance.ESAPI, "");

			//null white list patterns throw IllegalArgumentException
			/* NULL test
			try {
				local.pattern = null;
				local.validationRule.addWhitelistPattern(local.pattern);
				fail("Expected Exception not thrown");
			}
			catch (java.lang.IllegalArgumentException ie) {
				assertTrue(len(ie.getMessage()));
			} */

			/* NULL test
			try {
				local.pattern = null;
				validationRule.addWhitelistPattern(local.pattern);
				fail("Expected Exception not thrown");
			}
			catch (java.lang.IllegalArgumentException ie) {
				assertTrue(len(ie.getMessage()));
			}*/

			//invalid white list patterns throw PatternSyntaxException
			try {
				local.pattern = "_][0}[";
				local.validationRule.addWhitelistPattern(local.pattern);
				fail("Expected Exception not thrown");
			}
			catch (java.lang.IllegalArgumentException ie) {
				assertTrue(len(ie.getMessage()));
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testWhitelist" output="false">
		<cfscript>
			local.validationRule = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.StringValidationRule").init(instance.ESAPI, "");

			local.whitelistArray = ['a', 'b', 'c'];
			assertEquals("abc", local.validationRule.whitelist("12345abcdef", local.whitelistArray));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testBlacklistPattern" output="false">
		<cfscript>
			local.validationRule = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.StringValidationRule").init(instance.ESAPI, "NoAngleBrackets");

			assertEquals("beg <script> end", validationRule.getValid("", "beg <script> end"));
			local.validationRule.addBlacklistPattern("^.*(<|>).*");
			try {
				local.validationRule.getValid("", "beg <script> end");
				fail("Expected Exception not thrown");
			}
			catch (cfesapi.org.owasp.esapi.errors.ValidationException ve) {
				assertTrue(len(ve.getMessage()));
			}
			assertEquals("beg script end", local.validationRule.getValid("", "beg script end"));
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testBlacklistPattern_Invalid" output="false">
		<cfscript>
			local.validationRule = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.StringValidationRule").init(instance.ESAPI, "");

			//null black list patterns throw IllegalArgumentException
			/* NULL test
			try {
				local.pattern = null;
				local.validationRule.addBlacklistPattern(local.pattern);
				fail("Expected Exception not thrown");
			}
			catch (java.lang.IllegalArgumentException ie) {
				assertTrue(len(ie.getMessage()));
			}*/

			/* NULL test
			try {
				local.pattern = null;
				local.validationRule.addBlacklistPattern(local.pattern);
				fail("Expected Exception not thrown");
			}
			catch (java.lang.IllegalArgumentException ie) {
				assertTrue(len(ie.getMessage()));
			}*/

			//invalid black list patterns throw PatternSyntaxException
			try {
				local.pattern = "_][0}[";
				local.validationRule.addBlacklistPattern(local.pattern);
				fail("Expected Exception not thrown");
			}
			catch (java.lang.IllegalArgumentException ie) {
				assertTrue(len(ie.getMessage()));
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCheckLengths" output="false">
		<cfscript>
			local.validationRule = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.StringValidationRule").init(instance.ESAPI, "Max12_Min2");
			local.validationRule.setMinimumLength(2);
			local.validationRule.setMaximumLength(12);

			assertTrue(local.validationRule.isValid("", "12"));
			assertTrue(local.validationRule.isValid("", "123456"));
			assertTrue(local.validationRule.isValid("", "ABCDEFGHIJKL"));

			assertFalse(local.validationRule.isValid("", "1"));
			assertFalse(local.validationRule.isValid("", "ABCDEFGHIJKLM"));

			local.errorList = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");
			assertEquals("1234567890", local.validationRule.getValid("", "1234567890", local.errorList));
			assertEquals(0, local.errorList.size());
			assertEquals("", local.validationRule.getValid("", "123456789012345", local.errorList));
			assertEquals(1, local.errorList.size());
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testAllowNull" output="false">
		<cfscript>
			local.validationRule = createObject("component", "cfesapi.org.owasp.esapi.reference.validation.StringValidationRule").init(instance.ESAPI, "");

			assertFalse(local.validationRule.isAllowNull());
			assertFalse(local.validationRule.isValid("", ""));

			local.validationRule.setAllowNull(true);
			assertTrue(local.validationRule.isAllowNull());
			assertTrue(local.validationRule.isValid("", ""));
		</cfscript>
	</cffunction>


</cfcomponent>
