<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfcomponent implements="org.owasp.esapi.Validator" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Validator interface. This implementation relies on the ESAPI Encoder, Java Pattern (regex), Date, and several other classes to provide basic validation functions. This library has a heavy emphasis on whitelist validation and canonicalization. All double-encoded characters, even in multiple encoding schemes, such as &amp;lt; or %26lt; or even %25%26lt; are disallowed.">

	<cfscript>
		// imports
		Utils = createObject("component", "org.owasp.esapi.util.Utils");

		variables.ESAPI = "";

		/** OWASP AntiSamy markup verification policy */
		variables.antiSamyPolicy = "";

		/** constants */
		variables.MAX_CREDIT_CARD_LENGTH = 19;
		this.MAX_PARAMETER_NAME_LENGTH = 100;
		this.MAX_PARAMETER_VALUE_LENGTH = 65536;
		this.MAX_HTTPHEADER_NAME_LENGTH = 150;
		this.MAX_HTTPHEADER_VALUE_LENGTH = 1024;
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.Validator" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidInput" output="false"
	            hint="Returns true if data received from browser is valid. Only URL encoding is supported. Double encoding is treated as an attack.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name for the field to validate. This is used for error facing validation messages and element identification."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="String" name="type" hint="The regular expression name while maps to the actual regular expression from 'ESAPI.properties'."/>
		<cfargument required="true" type="numeric" name="maxLength" hint="The maximum post-canonicalized String length allowed."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>

		<cfscript>
			try {
				getValidInput(arguments.context, arguments.input, arguments.type, arguments.maxLength, arguments.allowNull);
				return true;
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidInput" output="false"
	            hint="Validates data received from the browser and returns a safe version. Only URL encoding is supported. Double encoding is treated as an attack.">
		<cfargument required="true" type="String" name="context" hint="A descriptive name for the field to validate. This is used for error facing validation messages and element identification."/>
		<cfargument required="true" type="String" name="input" hint="The actual user input data to validate."/>
		<cfargument required="true" type="String" name="type" hint="The regular expression name while maps to the actual regular expression from 'ESAPI.properties'."/>
		<cfargument required="true" type="numeric" name="maxLength" hint="The maximum post-canonicalized String length allowed."/>
		<cfargument required="true" type="boolean" name="allowNull" hint="If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException."/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList" hint="If ValidationException is thrown, then add to error list instead of throwing out to caller"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var canonical = "";
			var p = "";
			var msgParams = [];

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidInput(arguments.context, arguments.input, arguments.type, arguments.maxLength, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				return arguments.input;
			}
			else {
				try {
					arguments.context = variables.ESAPI.encoder().canonicalize(arguments.context);
					canonical = variables.ESAPI.encoder().canonicalize(arguments.input);

					if(arguments.type == "" || arguments.type.length() == 0) {
						msgParams = [arguments.context, arguments.input, arguments.type];
						throw(object=createObject("java", "java.lang.RuntimeException").init(variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInput_typeMismatch_message", msgParams)));
					}

					if(isEmptyInput(canonical)) {
						if(arguments.allowNull)
							return "";
						msgParams = [arguments.context, arguments.input, arguments.type];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInput_valueMissing_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInput_valueMissing_logMessage", msgParams), context=arguments.context));
					}

					if(canonical.length() > arguments.maxLength) {
						msgParams = [arguments.context, arguments.input, arguments.maxLength, canonical.length() - arguments.maxLength, arguments.type];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInput_tooLong_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInput_tooLong_logMessage", msgParams), context=arguments.context));
					}

					p = variables.ESAPI.securityConfiguration().getValidationPattern(arguments.type);
					if(!isObject(p)) {
						try {
							p = createObject("java", "java.util.regex.Pattern").compile(arguments.type);
						}
						catch(java.util.regex.PatternSyntaxException e) {
							msgParams = [arguments.context, arguments.input, arguments.type];
							throw(object=createObject("java", "java.lang.RuntimeException").init(variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInput_patternMismatch_message", msgParams)));
						}
					}

					if(!p.matcher(canonical).matches()) {
						msgParams = [arguments.context, arguments.input, p.pattern(), arguments.type, arguments.maxLength];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInput_patternMismatch_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInput_patternMismatch_logMessage", msgParams), context=arguments.context));
					}

					return canonical;
				}
				catch(org.owasp.esapi.errors.EncodingException e) {
					msgParams = [arguments.context];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInput_badInput_userMessage", msgParams), variables.ESAPI.resourceBundle().getString("Validator_getValidInput_badInput_logMessage"), e, arguments.context));
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidDate" output="false"
	            hint="Returns true if input is a valid date according to the specified date format.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" name="format"/>
		<cfargument required="true" name="minValue"/>
		<cfargument required="true" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>

		<cfscript>
			try {
				getValidDate(arguments.context, arguments.input, arguments.format, arguments.minValue, arguments.maxValue, arguments.allowNull);
				return true;
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getValidDate" output="false"
	            hint="Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" name="format"/>
		<cfargument required="true" name="minValue"/>
		<cfargument required="true" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var date = "";
			var msgParams = [];

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidDate(arguments.context, arguments.input, arguments.format, arguments.minValue, arguments.maxValue, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				return "";
			}
			else {
				if(arguments.minValue > arguments.maxValue) {
					//should this be a RunTime?
					msgParams = [arguments.context, arguments.minValue, arguments.maxValue];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDate_rangeInvalid_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDate_rangeInvalid_logMessage", msgParams), arguments.context));
				}

				if(isEmptyInput(arguments.input)) {
					if(arguments.allowNull)
						return "";
					msgParams = [arguments.context, arguments.input];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDate_valueMissing_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDate_valueMissing_logMessage", msgParams), arguments.context));
				}

				date = arguments.input;
				if (!isNull(arguments.format) && isObject(arguments.format)) {
					try {
						date = arguments.format.parse(javaCast("string", date));
					}
					catch(java.text.ParseException e) {
						msgParams = [arguments.context, arguments.input, arguments.format.toLocalizedPattern()];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDate_patternMismatch_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDate_patternMismatch_logMessage", msgParams), e, arguments.context));
					}
				}

				if(date < arguments.minValue || date > arguments.maxValue) {
					msgParams = [arguments.context, arguments.input, arguments.minValue, arguments.maxValue];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDate_rangeUnderflowOverflow_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDate_rangeUnderflowOverflow_logMessage", msgParams), context=arguments.context));
				}

				if (isDate(date)) {
					return date;
				}

				msgParams = [arguments.context, arguments.input];
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDate_badInput_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDate_badInput_logMessage", msgParams), arguments.context));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidSafeHTML" output="false"
	            hint="Returns true if input is 'safe' HTML. Implementors should reference the OWASP AntiSamy project for ideas on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="maxLength"/>
		<cfargument required="true" type="boolean" name="allowNull"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var loader = "";
			var ins = "";
			var as = "";
			var test = "";

			try {
				if(!isObject(variables.antiSamyPolicy)) {
					variables.antiSamyPolicy = createObject("java", "org.owasp.validator.html.Policy").getInstance(variables.ESAPI.securityConfiguration().getResourceFile("antisamy-esapi.xml"));
				}
				as = createObject("java", "org.owasp.validator.html.AntiSamy").init();
				test = as.scan(arguments.input, variables.antiSamyPolicy);
				return (test.getErrorMessages().size() == 0);
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidSafeHTML" output="false"
	            hint="Returns canonicalized and validated 'safe' HTML. Implementors should reference the OWASP AntiSamy project for ideas  on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="maxLength"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var loader = "";
			var ins = "";
			var as = "";
			var test = "";
			var errors = "";
			var msgParams = [];

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidSafeHTML(arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				return arguments.input;
			}
			else {
				if(isEmptyInput(arguments.input)) {
					if(arguments.allowNull)
						return "";
					msgParams = [arguments.context, arguments.input];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidSafeHTML_valueMissing_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidSafeHTML_valueMissing_logMessage", msgParams), arguments.context));
				}

				if(arguments.input.length() > arguments.maxLength) {
					msgParams = [arguments.context, arguments.input.length(), arguments.maxLength, arguments.input.length() - arguments.maxLength];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidSafeHTML_tooLong_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidSafeHTML_tooLong_logMessage", msgParams), arguments.context));
				}

				try {
					if(!isObject(variables.antiSamyPolicy)) {
						variables.antiSamyPolicy = createObject("java", "org.owasp.validator.html.Policy").getInstance(variables.ESAPI.securityConfiguration().getResourceFile("antisamy-esapi.xml"));
					}
					as = createObject("java", "org.owasp.validator.html.AntiSamy").init();
					test = as.scan(arguments.input, variables.antiSamyPolicy);
					errors = test.getErrorMessages();

					if(errors.size() > 0) {
						// just create new exception to get it logged and intrusion detected
						msgParams = [arguments.context, arrayToList(errors)];
						createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidSafeHTML_badInput_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidSafeHTML_badInput_logMessage", msgParams), context=arguments.context);
					}

					return test.getCleanHTML().trim();
				}
				catch(org.owasp.validator.html.ScanException e) {
					msgParams = [arguments.context, e.getMessage()];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidSafeHTML_scanError_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidSafeHTML_scanError_logMessage", msgParams), e, arguments.context));
				}
				catch(org.owasp.validator.html.PolicyException e) {
					msgParams = [arguments.context, e.getMessage()];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidSafeHTML_policyError_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidSafeHTML_policyError_logMessage", msgParams), e, arguments.context));
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidCreditCard" output="false"
	            hint="Returns true if input is a valid credit card. Maxlength is mandated by valid credit card type.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>

		<cfscript>
			try {
				getValidCreditCard(arguments.context, arguments.input, arguments.allowNull);
				return true;
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidCreditCard" output="false"
	            hint="Returns a canonicalized and validated credit card number as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var canonical = "";
			var digitsOnly = "";
			var c = "";
			var i = "";
			var sum = "";
			var digit = "";
			var addend = "";
			var timesTwo = "";
			var modulus = "";
			var msgParams = [];

			if(structKeyExists(arguments, "errorList")) {

				try {
					return getValidCreditCard(arguments.context, arguments.input, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				return arguments.input;
			}
			else {
				if(isEmptyInput(arguments.input)) {
					if(arguments.allowNull)
						return "";
					msgParams = [arguments.context, arguments.input];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidCreditCard_valueMissing_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidCreditCard_valueMissing_logMessage", msgParams), arguments.context));
				}

				canonical = getValidInput(arguments.context, arguments.input, "CreditCard", variables.MAX_CREDIT_CARD_LENGTH, arguments.allowNull);

				// perform Luhn algorithm checking
				digitsOnly = createObject("java", "java.lang.StringBuffer").init();
				c = "";
				for(i = 0; i < canonical.length(); i++) {
					c = canonical.charAt(i);
					if(createObject("java", "java.lang.Character").isDigit(c)) {
						digitsOnly.append(c);
					}
				}

				sum = 0;
				digit = 0;
				addend = 0;
				timesTwo = false;

				for(i = digitsOnly.length() - 1; i >= 0; i--) {
					digit = int(digitsOnly.substring(i, i + 1));
					if(timesTwo) {
						addend = digit * 2;
						if(addend > 9) {
							addend -= 9;
						}
					}
					else {
						addend = digit;
					}
					sum += addend;
					timesTwo = !timesTwo;
				}

				modulus = sum % 10;
				if(modulus != 0) {
					msgParams = [arguments.context];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidCreditCard_badInput_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidCreditCard_badInput_logMessage", msgParams), arguments.context));
				}

				return canonical;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidDirectoryPath" output="false"
	            hint="Returns true if the directory path (not including a filename) is valid. Note: On platforms that support symlinks, this function will fail canonicalization if directorypath is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real path (/private/etc), not the symlink (/etc).">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>

		<cfscript>
			try {
				getValidDirectoryPath(arguments.context, arguments.input, arguments.allowNull);
				return true;
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidDirectoryPath" output="false"
	            hint="Returns a canonicalized and validated directory path as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var dir = "";
			var canonicalPath = "";
			var canonical = "";
			var msgParams = [];

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidDirectoryPath(arguments.context, arguments.input, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				return arguments.input;
			}
			else {
				try {
					if(isEmptyInput(arguments.input)) {
						if(arguments.allowNull)
							return "";
						msgParams = [arguments.context, arguments.input];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDirectoryPath_valueMissing_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDirectoryPath_valueMissing_logMessage", msgParams), context=arguments.context));
					}

					dir = createObject("java", "java.io.File").init(arguments.input);

					// check dir exists and parent exists and dir is inside parent
					if(!dir.exists()) {
						msgParams = [arguments.context, arguments.input];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDirectoryPath_badInput_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDirectoryPath_badInput_logMessage", msgParams)));
					}
					if(!dir.isDirectory()) {
						msgParams = [arguments.context, arguments.input];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDirectoryPath_typeMismatch_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDirectoryPath_typeMismatch_logMessage", msgParams)));
					}

					// check canonical form matches input
					canonicalPath = dir.getCanonicalPath();
					//canonical = getValidInput(arguments.context, canonicalPath, "DirectoryName", 255, false);
					canonical = canonicalPath;
					if(canonical != arguments.input) {
						msgParams = [arguments.context, arguments.input, canonical];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDirectoryPath_patternMismatch_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDirectoryPath_patternMismatch_logMessage", msgParams), context=arguments.context));
					}
					return canonical;
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					msgParams = [arguments.context, arguments.input];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDirectoryPath_failure_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDirectoryPath_failure_logMessage", msgParams), e, arguments.context));
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidFileName" output="false"
	            hint="Returns true if input is a valid file name.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>

		<cfscript>
			try {
				getValidFileName(arguments.context, arguments.input, arguments.allowNull);
				return true;
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidFileName" output="false"
	            hint="Returns a canonicalized and validated file name as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var canonical = "";
			var f = "";
			var c = "";
			var cpath = "";
			var extensions = "";
			var i = "";
			var ext = "";
			var msgParams = [];

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidFileName(arguments.context, arguments.input, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				return arguments.input;
			}
			else {
				canonical = "";
				// detect path manipulation
				try {
					if(isEmptyInput(arguments.input)) {
						if(arguments.allowNull)
							return "";
						msgParams = [arguments.context, arguments.input];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileName_valueMissing_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileName_valueMissing_logMessage", msgParams), context=arguments.context));
					}

					// do basic validation
					canonical = variables.ESAPI.encoder().canonicalize(arguments.input);
					getValidInput(arguments.context, arguments.input, "FileName", 255, true);

					f = createObject("java", "java.io.File").init(canonical);
					c = f.getCanonicalPath();
					cpath = c.substring(c.lastIndexOf(createObject("java", "java.io.File").separator) + 1);

					// the path is valid if the input matches the canonical path
					if(!arguments.input.equals(cpath.toLowerCase())) {
						msgParams = [arguments.context, arguments.input, canonical];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileName_patternMismatch_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileName_patternMismatch_logMessage", msgParams), context=arguments.context));
					}
				}
				catch(java.io.IOException e) {
					msgParams = [arguments.context, canonical];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileName_badInput_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileName_badInput_logMessage", msgParams), e, arguments.context));
				}
				catch(org.owasp.esapi.errors.EncodingException ee) {
					msgParams = [arguments.context, canonical];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.IntrusionException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileName_failure_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileName_failure_logMessage", msgParams), ee));
				}

				// verify extensions
				extensions = variables.ESAPI.securityConfiguration().getAllowedFileExtensions();
				for(i = 1; i <= arrayLen(extensions); i++) {
					ext = extensions[i];
					if(arguments.input.toLowerCase().endsWith(ext.toLowerCase())) {
						return canonical;
					}
				}
				msgParams = [arguments.context, variables.ESAPI.securityConfiguration().getAllowedFileExtensions(), arguments.input];
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileName_typeMismatch_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileName_typeMismatch_logMessage", msgParams), arguments.context));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidNumber" output="false"
	            hint="Returns true if input is a valid number.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" name="format"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>

		<cfscript>
			try {
				getValidNumber(arguments.context, arguments.input, arguments.format, arguments.minValue, arguments.maxValue, arguments.allowNull);
				return true;
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getValidNumber" output="false"
	            hint="Returns a validated number as a double. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" name="format"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var number = "";
			var minDoubleValue = "";
			var maxDoubleValue = "";
			var msgParams = [];

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidNumber(arguments.context, arguments.input, arguments.format, arguments.minValue, arguments.maxValue, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				//not sure what to return on error
				return createObject("java", "java.lang.Double").init(0);
			}
			else {
				if(isEmptyInput(arguments.input)) {
					if(arguments.allowNull)
						return "";
					msgParams = [arguments.context, arguments.input];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidNumber_valueMissing_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidNumber_valueMissing_logMessage", msgParams), context=arguments.context));
				}

				number = arguments.input;
				if (!isNull(arguments.format) && isObject(arguments.format)) {
					try {
						number = arguments.format.parse(javaCast("string", number));
					}
					catch(java.text.ParseException e) {
						msgParams = [arguments.context, arguments.input, arguments.format.toLocalizedPattern()];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidNumber_patternMismatch_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidNumber_patternMismatch_logMessage", msgParams), e, arguments.context));
					}
				}

				if (isNumeric(number)) {
					minDoubleValue = createObject("java", "java.lang.Double").init(arguments.minValue);
					maxDoubleValue = createObject("java", "java.lang.Double").init(arguments.maxValue);
					return getValidDouble(arguments.context, number, minDoubleValue.doubleValue(), maxDoubleValue.doubleValue(), arguments.allowNull);
				}

				msgParams = [arguments.context, arguments.input];
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidNumber_badInput_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidNumber_badInput_logMessage", msgParams), arguments.context));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidDouble" output="false"
	            hint="Returns true if input is a valid number.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>

		<cfscript>
			try {
				getValidDouble(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				return true;
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getValidDouble" output="false"
	            hint="Returns a validated number as a double. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var d = "";
			var msgParams = [];

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidDouble(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				//not sure what to return on error
				return createObject("java", "java.lang.Double").init(0);
			}
			else {
				if(arguments.minValue > arguments.maxValue) {
					//should this be a RunTime?
					msgParams = [arguments.context, arguments.minValue, arguments.maxValue];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDouble_rangeInvalid_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDouble_rangeInvalid_logMessage", msgParams), arguments.context));
				}

				if(isEmptyInput(arguments.input)) {
					if(arguments.allowNull)
						return "";
					msgParams = [arguments.context, arguments.input];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDouble_valueMissing_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDouble_valueMissing_logMessage", msgParams), context=arguments.context));
				}

				try {
					d = createObject("java", "java.lang.Double").init(createObject("java", "java.lang.Double").parseDouble(javaCast("string", arguments.input)));
					if(d.isInfinite()) {
						msgParams = [arguments.context, arguments.input];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDouble_isInfinite_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDouble_isInfinite_logMessage", msgParams), context=arguments.context));
					}
					if(d.isNaN()) {
						msgParams = [arguments.context, arguments.input];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDouble_isNaN_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDouble_isNaN_logMessage", msgParams), context=arguments.context));
					}
					if(d.doubleValue() < arguments.minValue || d.doubleValue() > arguments.maxValue) {
						msgParams = [arguments.context, arguments.input, arguments.minValue, arguments.maxValue];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDouble_rangeUnderflowOverflow_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDouble_rangeUnderflowOverflow_logMessage", msgParams), context=arguments.context));
					}
					return d;
				}
				catch(java.lang.NumberFormatException e) {
					msgParams = [arguments.context, arguments.input];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDouble_patternMismatch_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidDouble_patternMismatch_logMessage", msgParams), e, arguments.context));
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidInteger" output="false"
	            hint="Returns true if input is a valid number.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>

		<cfscript>
			try {
				getValidInteger(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				return true;
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getValidInteger" output="false"
	            hint="Returns a validated number as a double. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var msgParams = [];

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidInteger(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				//not sure what to return on error
				return createObject("java", "java.lang.Integer").init(0);
			}
			else {
				if(arguments.minValue > arguments.maxValue) {
					//should this be a RunTime?
					msgParams = [arguments.context, arguments.minValue, arguments.maxValue];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInteger_rangeInvalid_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInteger_rangeInvalid_logMessage", msgParams), arguments.context));
				}

				if(isEmptyInput(arguments.input)) {
					if(arguments.allowNull)
						return "";
					msgParams = [arguments.context, arguments.input];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInteger_valueMissing_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInteger_valueMissing_logMessage", msgParams), context=arguments.context));
				}

				try {
					i = createObject("java", "java.lang.Integer").parseInt(javaCast("string", arguments.input));
					if(i < arguments.minValue || i > arguments.maxValue) {
						msgParams = [arguments.context, arguments.input, arguments.minValue, arguments.maxValue];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInteger_rangeUnderflowOverflow_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInteger_rangeUnderflowOverflow_logMessage", msgParams), context=arguments.context));
					}
					return i;
				}
				catch(java.lang.NumberFormatException e) {
					msgParams = [arguments.context, arguments.input];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInteger_patternMismatch_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidInteger_patternMismatch_logMessage", msgParams), e, arguments.context));
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidFileContent" output="false"
	            hint="Returns true if input is valid file content.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="binary" name="input"/>
		<cfargument required="true" type="numeric" name="maxBytes"/>
		<cfargument required="true" type="boolean" name="allowNull"/>

		<cfscript>
			try {
				getValidFileContent(arguments.context, arguments.input, arguments.maxBytes, arguments.allowNull);
				return true;
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="binary" name="getValidFileContent" output="false"
	            hint="Returns validated file content as a byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="binary" name="input"/>
		<cfargument required="true" type="numeric" name="maxBytes"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var esapiMaxBytes = "";
			var msgParams = [];

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidFileContent(arguments.context, arguments.input, arguments.maxBytes, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				//not sure what to return on error
				return arguments.input;
			}
			else {
				if(isEmptyInput(arguments.input)) {
					if(arguments.allowNull)
						return "";
					msgParams = [arguments.context, toString(arguments.input)];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileContent_valueMissing_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileContent_valueMissing_logMessage", msgParams), context=arguments.context));
				}

				esapiMaxBytes = variables.ESAPI.securityConfiguration().getAllowedFileUploadSize();
				if(arrayLen(arguments.input) > esapiMaxBytes) {
					msgParams = [arguments.context, esapiMaxBytes];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileContent_tooLong_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileContent_ESAPItooLong_logMessage", msgParams), context=arguments.context));
				}
				if(arrayLen(arguments.input) > arguments.maxBytes) {
					msgParams = [arguments.context, arguments.maxBytes];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileContent_tooLong_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidFileContent_tooLong_logMessage", msgParams), context=arguments.context));
				}

				return arguments.input;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidFileUpload" output="false"
	            hint="Returns true if a file upload has a valid name, path, and content. Note: On platforms that support symlinks, this function will fail canonicalization if directorypath is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real path (/private/etc), not the symlink (/etc).">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="filepath"/>
		<cfargument required="true" type="String" name="filename"/>
		<cfargument required="true" type="binary" name="content"/>
		<cfargument required="true" type="numeric" name="maxBytes"/>
		<cfargument required="true" type="boolean" name="allowNull"/>

		<cfscript>
			var validFile = isValidFileName(arguments.context, arguments.filename, arguments.allowNull);
			var validDir = isValidDirectoryPath(arguments.context, arguments.filepath, arguments.allowNull);
			var validContent = isValidFileContent(arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull);

			//System.out.println("isValidFileUpload: validFile="&validFile&" validDir="&validFile& " validContent="&validContent);
			return (validFile && validDir && validContent);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertValidFileUpload" output="false"
	            hint="Validates the filepath, filename, and content of a file. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="filepath"/>
		<cfargument required="true" type="String" name="filename"/>
		<cfargument required="true" type="binary" name="content"/>
		<cfargument required="true" type="numeric" name="maxBytes"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					assertValidFileUpload(arguments.context, arguments.filepath, arguments.filename, arguments.content, arguments.maxBytes, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
			}
			else {
				getValidFileName(arguments.context, arguments.filename, arguments.allowNull);
				getValidDirectoryPath(arguments.context, arguments.filepath, arguments.allowNull);
				getValidFileContent(arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidHTTPRequest" output="false"
	            hint="Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument name="httpRequest" default="#variables.ESAPI.httpUtilities().getCurrentRequest()#" hint="Defaults the current HTTPRequest saved in EASPI Authenticator"/>

		<cfscript>
			try {
				assertIsValidHTTPRequest(arguments.httpRequest);
				return true;
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
			catch(org.owasp.esapi.errors.IntrusionException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertIsValidHTTPRequest" output="false"
	            hint="Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument name="httpRequest" default="#variables.ESAPI.httpUtilities().getCurrentRequest()#" hint="Defaults the current HTTPRequest saved in EASPI Authenticator"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var parameters = "";
			var name = "";
			var values = "";
			var i3 = "";
			var cookies = "";
			var i2 = "";
			var httpCookie = "";
			var value = "";
			var headers = "";
			var i = "";
			var e2 = "";
			var msgParams = [];

			if(!isObject(arguments.httpRequest)) {
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Validator_assertIsValidHTTPRequest_valueMissing_userMessage"), variables.ESAPI.resourceBundle().getString("Validator_assertIsValidHTTPRequest_valueMissing_logMessage")));
			}
			if(arguments.httpRequest.getMethod() != "GET" && arguments.httpRequest.getMethod() != "POST") {
				msgParams = [arguments.httpRequest.getMethod()];
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.IntrusionException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Validator_assertIsValidHTTPRequest_typeMismatch_userMessage"), variables.ESAPI.resourceBundle().messageFormat("Validator_assertIsValidHTTPRequest_typeMismatch_logMessage", msgParams)));
			}

			parameters = arguments.httpRequest.getParameterMap();
			for(name in parameters) {
				getValidInput("HTTP request parameter: " & name, name, "HTTPParameterName", this.MAX_PARAMETER_NAME_LENGTH, false);
				values = parameters[name];
				for(i3 = 1; i3 <= arrayLen(values); i3++) {
					value = values[i3];
					getValidInput("HTTP request parameter: " & name, value, "HTTPParameterValue", this.MAX_PARAMETER_VALUE_LENGTH, true);
				}
			}

			cookies = arguments.httpRequest.getCookies();
			for(i2 = 1; i2 <= arrayLen(cookies); i2++) {
				httpCookie = cookies[i2];
				name = httpCookie.getName();
				getValidInput("HTTP request cookie: " & name, name, "HTTPCookieName", this.MAX_PARAMETER_NAME_LENGTH, true);
				value = httpCookie.getValue();
				getValidInput("HTTP request cookie: " & name, value, "HTTPCookieValue", this.MAX_PARAMETER_VALUE_LENGTH, true);
			}

			headers = arguments.httpRequest.getHeaderNames();
			for(i = 1; i <= arrayLen(headers); i++) {
				name = headers[i];
				if(name != "" && !name.equalsIgnoreCase("Cookie")) {
					getValidInput("HTTP request header: " & name, name, "HTTPHeaderName", this.MAX_PARAMETER_NAME_LENGTH, true);
					e2 = arguments.httpRequest.getHeaders(name);
					for(i2 = 1; i2 <= arrayLen(e2); i2++) {
						value = e2[i2];
						getValidInput("HTTP request header: " & name, value, "HTTPHeaderValue", this.MAX_PARAMETER_VALUE_LENGTH, true);
					}
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidListItem" output="false"
	            hint="Returns true if input is a valid list item.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="Array" name="list"/>

		<cfscript>
			try {
				getValidListItem(arguments.context, arguments.input, arguments.list);
				return true;
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getValidListItem" output="false"
	            hint="Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="Array" name="list"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var msgParams = [];

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidListItem(arguments.context, arguments.input, arguments.list);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				return arguments.input;
			}
			else {
				if(arguments.list.contains(arguments.input))
					return arguments.input;
				msgParams = [arguments.context, arguments.input];
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidListItem_valueMissing_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidListItem_valueMissing_logMessage", msgParams), context=arguments.context));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidHTTPRequestParameterSet" output="false"
	            hint="Returns true if the parameters in the current request contain all required parameters and only optional ones in addition.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="Array" name="requiredNames"/>
		<cfargument required="true" type="Array" name="optionalNames"/>

		<cfscript>
			try {
				assertIsValidHTTPRequestParameterSet(arguments.context, arguments.requiredNames, arguments.optionalNames);
				return true;
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertIsValidHTTPRequestParameterSet" output="false"
	            hint="Validates that the parameters in the current request contain all required parameters and only optional ones in addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="Array" name="requiredNames"/>
		<cfargument required="true" type="Array" name="optionalNames"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var httpRequest = "";
			var actualNames = "";
			var missing = "";
			var extra = "";
			var msgParams = [];

			if(structKeyExists(arguments, "errorList")) {
				try {
					assertIsValidHTTPRequestParameterSet(arguments.context, arguments.requiredNames, arguments.optionalNames);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
			}
			else {
				httpRequest = variables.ESAPI.httpUtilities().getCurrentRequest();
				actualNames = httpRequest.getParameterMap().keySet();

				// verify ALL required parameters are present
				missing = duplicate(arguments.requiredNames);
				missing.removeAll(actualNames);
				if(missing.size() > 0) {
					msgParams = [arguments.context, arrayToList(missing)];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_assertIsValidHTTPRequestParameterSet_valueMissing_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_assertIsValidHTTPRequestParameterSet_valueMissing_logMessage", msgParams), context=arguments.context));
				}

				// verify ONLY optional & required parameters are present
				extra = duplicate(actualNames);
				extra.removeAll(arguments.requiredNames);
				extra.removeAll(arguments.optionalNames);
				if(extra.size() > 0) {
					msgParams = [arguments.context, extra];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_assertIsValidHTTPRequestParameterSet_badInput_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_assertIsValidHTTPRequestParameterSet_badInput_logMessage", msgParams), context=arguments.context));
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidPrintable" output="false"
	            hint="Checks that all bytes are valid ASCII characters (between 33 and 126 inclusive). This implementation does no decoding. http://en.wikipedia.org/wiki/ASCII.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" name="input"/>
		<cfargument required="true" type="numeric" name="maxLength"/>
		<cfargument required="true" type="boolean" name="allowNull"/>

		<cfscript>
			if(isBinary(arguments.input)) {
				try {
					getValidPrintable(arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
					return true;
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					return false;
				}
			}
			else {
				try {
					getValidPrintable(arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
					return true;
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					return false;
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getValidPrintable" output="false" hint="Returns canonicalized and validated printable characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" name="input"/>
		<cfargument required="true" type="numeric" name="maxLength"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var canonical = "";
			var msgParams = [];

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidPrintable(arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				return arguments.input;
			}

			if(isArray(arguments.input)) {
				if(isEmptyInput(arguments.input)) {
					if(arguments.allowNull)
						return "";
					msgParams = [arguments.context, arguments.input];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidPrintable_valueMissing_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidPrintable_valueMissing_logMessage", msgParams), context=arguments.context));
				}

				if(arrayLen(arguments.input) > arguments.maxLength) {
					msgParams = [arguments.context, arrayToList(arguments.input), arguments.maxLength, arrayLen(arguments.input) - arguments.maxLength];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidPrintable_tooLong_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidPrintable_tooLong_logMessage", msgParams), context=arguments.context));
				}

				for(i = 1; i <= arrayLen(arguments.input); i++) {
					if(arguments.input[i] < 33 || arguments.input[i] > 126) {
						msgParams = [arguments.context, arrayToList(arguments.input)];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidPrintable_patternMismatch_userMessage", msgParams), logMessage=variables.ESAPI.resourceBundle().messageFormat("Validator_getValidPrintable_patternMismatch_logMessage", msgParams), context=arguments.context));
					}
				}
				return arguments.input;
			}
			else {
				canonical = "";
				try {
					canonical = variables.ESAPI.encoder().canonicalize(arguments.input);
					return createObject("java", "java.lang.String").init(getValidPrintable(arguments.context, canonical.getBytes(), arguments.maxLength, arguments.allowNull));
				}
				catch(org.owasp.esapi.errors.EncodingException e) {
					msgParams = [arguments.context, arrayToList(arguments.input)];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidPrintable_failure_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidPrintable_failure_logMessage", msgParams), e, arguments.context));
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidRedirectLocation" output="false"
	            hint="Returns true if input is a valid redirect location.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>

		<cfscript>
			return variables.ESAPI.validator().isValidInput(arguments.context, arguments.input, "Redirect", 512, arguments.allowNull);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidRedirectLocation" output="false"
	            hint="Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidRedirectLocation(arguments.context, arguments.input, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				return arguments.input;
			}
			else {
				return variables.ESAPI.validator().getValidInput(arguments.context, arguments.input, "Redirect", 512, arguments.allowNull);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="safeReadLine" output="false"
	            hint="This implementation reads until a newline or the specified number of characters.">
		<cfargument required="true" name="inputStream"/>
		<cfargument required="true" type="numeric" name="maxLength"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var sb = "";
			var count = "";
			var c = "";
			var msgParams = [];

			if(arguments.maxLength <= 0) {
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationAvailabilityException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Validator_safeReadLine_badInput_userMessage"), variables.ESAPI.resourceBundle().getString("Validator_safeReadLine_badInput_logMessage")));
			}

			sb = createObject("java", "java.lang.StringBuffer").init();
			count = 0;
			c = "";

			try {
				while(true) {
					c = arguments.inputStream.read();
					if(c == -1) {
						if(sb.length() == 0)
							return;
						break;
					}
					if(c == 13 || c == 10)
						break;
					count++;
					if(count > arguments.maxLength) {
						msgParams = [arguments.maxLength];
						Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationAvailabilityException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_safeReadLine_tooLong_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_safeReadLine_tooLong_logMessage", msgParams)));
					}
					sb.append(chr(c));
				}
				return sb.toString();
			}
			catch(java.io.IOException e) {
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationAvailabilityException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("Validator_safeReadLine_failure_userMessage"), variables.ESAPI.resourceBundle().getString("Validator_safeReadLine_failure_logMessage"), e));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidBoolean" output="false"
				hint="Returns true if input is a valid boolean.">
		<cfargument required="true" type="String" name="context">
		<cfargument required="true" type="String" name="input">
		<cfargument required="true" type="boolean" name="allowNull">
		<cfscript>
			try {
				getValidBoolean(arguments.context, arguments.input, arguments.allowNull);
				return true;
			}
			catch(org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>
	</cffunction>

	<cffunction access="public" name="getValidBoolean" output="false"
				hint="Returns a valid Boolean. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context">
		<cfargument required="true" type="String" name="input">
		<cfargument required="true" type="boolean" name="allowNull">
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList">
		<cfscript>
			var exception = {};
			var msgParams = [];

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidBoolean(arguments.context, arguments.input, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				return "";
			}
			else {
				if(isEmptyInput(arguments.input)) {
					if(arguments.allowNull)
						return "";
					msgParams = [arguments.context, arguments.input];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidBoolean_valueMissing_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidBoolean_valueMissing_logMessage", msgParams)));
				}

				if (!isBoolean(arguments.input)) {
					msgParams = [arguments.context, arguments.input];
					Utils.throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, variables.ESAPI.resourceBundle().messageFormat("Validator_getValidBoolean_badInput_userMessage", msgParams), variables.ESAPI.resourceBundle().messageFormat("Validator_getValidBoolean_badInput_logMessage", msgParams)));
				}

				return Utils.getBoolean(arguments.input);
			}
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="boolean" name="isEmptyInput" output="false"
	            hint="Helper function to check if a value is empty">
		<cfargument required="true" name="input" hint="input value"/>

		<cfscript>
			if (isNull(arguments.input)) {
				return true;
			}
			if(isSimpleValue(arguments.input)) {
				return (len(trim(arguments.input)) == 0);
			}
			else if(isBinary(arguments.input)) {
				return (arrayLen(arguments.input) == 0);
			}
			else if(isArray(arguments.input)) {
				return (arrayLen(arguments.input) == 0);
			}
		</cfscript>

	</cffunction>

</cfcomponent>