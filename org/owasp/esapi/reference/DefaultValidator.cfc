<!---
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
--->
<cfcomponent implements="org.owasp.esapi.Validator" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Validator interface. This implementation relies on the ESAPI Encoder, Java Pattern (regex), Date, and several other classes to provide basic validation functions. This library has a heavy emphasis on whitelist validation and canonicalization. All double-encoded characters, even in multiple encoding schemes, such as &amp;lt; or %26lt; or even %25%26lt; are disallowed.">

	<cfscript>
		variables.ESAPI = "";

		/** OWASP AntiSamy markup verification policy */
		variables.antiSamyPolicy = "";

		/** constants */
		variables.MAX_CREDIT_CARD_LENGTH = 19;
		this.MAX_PARAMETER_NAME_LENGTH = 100;
		this.MAX_PARAMETER_VALUE_LENGTH = 65535;
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
						throwException(newJava("java.lang.RuntimeException").init("Validation misconfiguration, specified type to validate against was null: context=" & arguments.context & ", type=" & arguments.type & "), input=" & arguments.input));
					}

					if(isEmptyInput(canonical)) {
						if(arguments.allowNull)
							return "";
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Input required.", logMessage="Input required: context=" & arguments.context & ", type=" & arguments.type & "), input=" & arguments.input, context=arguments.context));
					}

					if(canonical.length() > arguments.maxLength) {
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Invalid input. The maximum length of " & arguments.maxLength & " characters was exceeded.", logMessage="Input exceeds maximum allowed length of " & arguments.maxLength & " by " & (canonical.length() - arguments.maxLength) & " characters: context=" & arguments.context & ", type=" & arguments.type & "), input=" & arguments.input, context=arguments.context));
					}

					p = variables.ESAPI.securityConfiguration().getValidationPattern(arguments.type);
					if(!isObject(p)) {
						try {
							p = newJava("java.util.regex.Pattern").compile(arguments.type);
						}
						catch(java.util.regex.PatternSyntaxException e) {
							throwException(newJava("java.lang.RuntimeException").init("Validation misconfiguration, specified type to validate against was null: context=" & arguments.context & ", type=" & arguments.type & "), input=" & arguments.input));
						}
					}

					if(!p.matcher(canonical).matches()) {
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Invalid input. Please conform to: " & p.pattern() & " with a maximum length of " & arguments.maxLength, logMessage="Invalid input: context=" & arguments.context & ", type=" & arguments.type & "(" & p.pattern() & "), input=" & arguments.input, context=arguments.context));
					}

					return canonical;
				}
				catch(org.owasp.esapi.errors.EncodingException e) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid input. An encoding error occurred.", "Error canonicalizing user input", e, arguments.context));
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidDate" output="false"
	            hint="Returns true if input is a valid date according to the specified date format.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" name="format"/>
		<cfargument required="true" type="boolean" name="allowNull"/>

		<cfscript>
			try {
				getValidDate(arguments.context, arguments.input, arguments.format, arguments.allowNull);
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
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var date = "";

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidDate(arguments.context, arguments.input, arguments.format, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}
				return "";
			}
			else {
				try {
					if(isEmptyInput(arguments.input)) {
						if(arguments.allowNull)
							return "";
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Input date required", "Input date required: context=" & arguments.context & ", input=" & arguments.input, arguments.context));
					}

					date = arguments.format.parse(arguments.input);
					return createDateTime(year(date), month(date), day(date), hour(date), minute(date), second(date));
				}
				catch(java.lang.Exception e) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid date must follow " & arguments.format & " format", "Invalid date: context=" & arguments.context & ", format=" & arguments.format & ", input=" & arguments.input, e, arguments.context));
				}
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
					if(variables.ESAPI.securityConfiguration().getResourceDirectory() == "") {

						//load via classpath
						loader = getClass().getClassLoader();

						ins = "";
						try {
							ins = loader.getResourceAsStream("antisamy-esapi.xml");
							if(ins != "") {
								variables.antiSamyPolicy = newJava("org.owasp.validator.html.Policy").getInstance(ins);
							}
						}
						catch(org.owasp.esapi.errors.ValidationException e) {
							variables.antiSamyPolicy = "";
						}
						if(ins != "")
							try {
								ins.close();
							}
							catch(java.lang.Throwable ignore) {
							}

						if(variables.antiSamyPolicy == "") {
							throwException(newJava("java.lang.IllegalArgumentException").init("Can't load antisamy-esapi.xml as a classloader resource"));
						}
					}
					else {
						//load via fileio
						variables.antiSamyPolicy = newJava("org.owasp.validator.html.Policy").getInstance(expandPath(variables.ESAPI.securityConfiguration().getResourceDirectory() & "antisamy-esapi.xml"));
					}
				}
				as = newJava("org.owasp.validator.html.AntiSamy").init();
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
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Input HTML required", "Input HTML required: context=" & arguments.context & ", input=" & arguments.input, arguments.context));
				}

				if(arguments.input.length() > arguments.maxLength) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid HTML. You enterted " & arguments.input.length() & " characters. Input can not exceed " & arguments.maxLength & " characters.", arguments.context & " arguments.input exceedes maxLength by " & (arguments.input.length() - arguments.maxLength) & " characters", arguments.context));
				}

				try {
					if(!isObject(variables.antiSamyPolicy)) {
						if(variables.ESAPI.securityConfiguration().getResourceDirectory() == "") {

							//load via classpath
							loader = getClass().getClassLoader();

							ins = "";
							try {
								ins = loader.getResourceAsStream("antisamy-esapi.xml");
								if(ins != "") {
									variables.antiSamyPolicy = newJava("org.owasp.validator.html.Policy").getInstance(ins);
								}
							}
							catch(org.owasp.esapi.errors.ValidationException e) {
								variables.antiSamyPolicy = "";
							}
							if(ins != "") {
								try {
									ins.close();
								}
								catch(java.lang.Throwable ignore) {
								}
							}
							if(variables.antiSamyPolicy == "") {
								throwException(newJava("java.lang.IllegalArgumentException").init("Can't load antisamy-esapi.xml as a classloader resource"));
							}
						}
						else {
							//load via fileio
							variables.antiSamyPolicy = newJava("org.owasp.validator.html.Policy").getInstance(expandPath(variables.ESAPI.securityConfiguration().getResourceDirectory() & "antisamy-esapi.xml"));
						}
					}
					as = newJava("org.owasp.validator.html.AntiSamy").init();
					test = as.scan(arguments.input, variables.antiSamyPolicy);
					errors = test.getErrorMessages();

					if(errors.size() > 0) {
						// just create new exception to get it logged and intrusion detected
						createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage="Invalid HTML input: context=" & arguments.context, logMessage="Invalid HTML input: context=" & arguments.context & ", errors=" & arrayToList(errors), context=arguments.context);
					}

					return (test.getCleanHTML().trim());
				}
				catch(org.owasp.validator.html.ScanException e) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid HTML input", "Invalid HTML input: context=" & arguments.context & " error=" & e.getMessage(), e, arguments.context));
				}
				catch(org.owasp.validator.html.PolicyException e) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid HTML input", "Invalid HTML input does not follow rules in antisamy-esapi.xml: context=" & arguments.context & " error=" & e.getMessage(), e, arguments.context));
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
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Input credit card required", "Input credit card required: context=" & arguments.context & ", input=" & arguments.input, arguments.context));
				}

				canonical = getValidInput(arguments.context, arguments.input, "CreditCard", variables.MAX_CREDIT_CARD_LENGTH, arguments.allowNull);

				// perform Luhn algorithm checking
					digitsOnly = newJava("java.lang.StringBuffer").init();
					c = "";
					for(i = 0; i < canonical.length(); i++) {
						c = canonical.charAt(i);
						if(newJava("java.lang.Character").isDigit(c)) {
							digitsOnly.append(c);
						}
					}

					sum = 0;
					digit = 0;
					addend = 0;
					timesTwo = false;

					for(i = digitsOnly.length() - 1; i >= 0; i--) {
						digit = newJava("java.lang.Integer").parseInt(digitsOnly.substring(i, i + 1));
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
					if(modulus != 0)
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid credit card input", "Invalid credit card input: context=" & arguments.context, arguments.context));

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
			var canonical = "";

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
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Input directory path required", logMessage="Input directory path required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));
					}

					dir = newJava("java.io.File").init(arguments.input);

					// check dir exists and parent exists and dir is inside parent
					if(!dir.exists()) {
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, does not exist: context=" & arguments.context & ", input=" & arguments.input));
					}
					if(!dir.isDirectory()) {
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, not a directory: context=" & arguments.context & ", input=" & arguments.input));
					}

					// check canonical form matches input
					canonical = dir.getCanonicalPath();
					//String canonical = getValidInput( arguments.context, canonicalPath, "DirectoryName", 255, false);
					if(canonical != arguments.input) {
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Invalid directory name", logMessage="Invalid directory name does not match the canonical path: context=" & arguments.context & ", input=" & arguments.input & ", canonical=" & canonical, context=arguments.context));
					}
					return canonical;
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid directory name", "Failure to validate directory path: context=" & arguments.context & ", input=" & arguments.input, e, arguments.context));
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
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Input file name required", logMessage="Input required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));
					}

					// do basic validation
					canonical = variables.ESAPI.encoder().canonicalize(arguments.input);
					getValidInput(arguments.context, arguments.input, "FileName", 255, true);

					f = newJava("java.io.File").init(canonical);
					c = f.getCanonicalPath();
					cpath = c.substring(c.lastIndexOf(newJava("java.io.File").separator) + 1);

					// the path is valid if the input matches the canonical path
					if(!arguments.input.equals(cpath.toLowerCase())) {
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Invalid file name", logMessage="Invalid directory name does not match the canonical path: context=" & arguments.context & ", input=" & arguments.input & ", canonical=" & canonical, context=arguments.context));
					}
				}
				catch(java.io.IOException e) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid file name", "Invalid file name does not exist: context=" & arguments.context & ", canonical=" & canonical, e, arguments.context));
				}
				catch(org.owasp.esapi.errors.EncodingException ee) {
					throwException(createObject("component", "org.owasp.esapi.errors.IntrusionException").init(variables.ESAPI, arguments.context & ": Invalid file name", "Invalid file name: context=" & arguments.context & ", canonical=" & canonical, ee));
				}

				// verify extensions
				extensions = variables.ESAPI.securityConfiguration().getAllowedFileExtensions();
				for(i = 1; i <= arrayLen(extensions); i++) {
					ext = extensions[i];
					if(arguments.input.toLowerCase().endsWith(ext.toLowerCase())) {
						return canonical;
					}
				}
				throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid file name does not have valid extension ( " & variables.ESAPI.securityConfiguration().getAllowedFileExtensions() & ")", "Invalid file name does not have valid extension ( " & variables.ESAPI.securityConfiguration().getAllowedFileExtensions() & "): context=" & arguments.context & ", input=" & arguments.input, arguments.context));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidNumber" output="false"
	            hint="Returns true if input is a valid number.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>

		<cfscript>
			try {
				getValidNumber(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
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
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var minDoubleValue = "";
			var maxDoubleValue = "";

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidNumber(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				//not sure what to return on error
				return newJava("java.lang.Double").init(0);
			}
			else {
				minDoubleValue = newJava("java.lang.Double").init(arguments.minValue);
				maxDoubleValue = newJava("java.lang.Double").init(arguments.maxValue);
				return getValidDouble(arguments.context, arguments.input, minDoubleValue.doubleValue(), maxDoubleValue.doubleValue(), arguments.allowNull);
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

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidDouble(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				//not sure what to return on error
				return newJava("java.lang.Double").init(0);
			}
			else {
				if(arguments.minValue > arguments.maxValue) {
					//should this be a RunTime?
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid double input: context", "Validation parameter error for double: maxValue ( " & arguments.maxValue & ") must be greater than minValue ( " & arguments.minValue & ") for " & arguments.context, arguments.context));
				}

				if(isEmptyInput(arguments.input)) {
					if(arguments.allowNull)
						return "";
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Input required: context", logMessage="Input required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));
				}

				try {
					d = newJava("java.lang.Double").init(newJava("java.lang.Double").parseDouble(arguments.input));
					if(d.isInfinite())
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage="Invalid double input: context=" & arguments.context, logMessage="Invalid double input is infinite: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));
					if(d.isNaN())
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage="Invalid double input: context=" & arguments.context, logMessage="Invalid double input is infinite: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));
					if(d.doubleValue() < arguments.minValue)
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage="Invalid double input must be between " & arguments.minValue & " and " & arguments.maxValue & ": context=" & arguments.context, logMessage="Invalid double input must be between " & arguments.minValue & " and " & arguments.maxValue & ": context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));
					if(d.doubleValue() > arguments.maxValue)
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage="Invalid double input must be between " & arguments.minValue & " and " & arguments.maxValue & ": context=" & arguments.context, logMessage="Invalid double input must be between " & arguments.minValue & " and " & arguments.maxValue & ": context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));

					return d;
				}
				catch(java.lang.NumberFormatException e) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid double input", "Invalid double input format: context=" & arguments.context & ", input=" & arguments.input, e, arguments.context));
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

			if(structKeyExists(arguments, "errorList")) {
				try {
					return getValidInteger(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError(arguments.context, e);
				}

				//not sure what to return on error
				return newJava("java.lang.Integer").init(0);
			}
			else {
				if(arguments.minValue > arguments.maxValue) {
					//should this be a RunTime?
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid Integer", "Validation parameter error for double: maxValue ( " & arguments.maxValue & ") must be greater than minValue ( " & arguments.minValue & ") for " & arguments.context, arguments.context));
				}

				if(isEmptyInput(arguments.input)) {
					if(arguments.allowNull)
						return "";
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Input required", logMessage="Input required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));
				}

				try {
					i = newJava("java.lang.Integer").parseInt(javaCast('string', arguments.input));
					if(i < arguments.minValue || i > arguments.maxValue)
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Invalid Integer. Value must be between " & arguments.minValue & " and " & arguments.maxValue, logMessage="Invalid int input must be between " & arguments.minValue & " and " & arguments.maxValue & ": context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));
					return newJava("java.lang.Integer").init(i);
				}
				catch(java.lang.NumberFormatException e) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid integer input", "Invalid int input: context=" & arguments.context & ", input=" & arguments.input, e, arguments.context));
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
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Input required", logMessage="Input required: context=" & arguments.context & ", input=" & toString(arguments.input), context=arguments.context));
				}

				esapiMaxBytes = variables.ESAPI.securityConfiguration().getAllowedFileUploadSize();
				if(arrayLen(arguments.input) > esapiMaxBytes)
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Invalid file content can not exceed " & esapiMaxBytes & " bytes", logMessage="Exceeded ESAPI max length", context=arguments.context));
				if(arrayLen(arguments.input) > arguments.maxBytes)
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Invalid file content can not exceed " & arguments.maxBytes & " bytes", logMessage="Exceeded maxBytes ( " & arguments.input.length & ")", context=arguments.context));

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

			if(!isObject(arguments.httpRequest)) {
				throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, "Input required: HTTP request is null", "Input required: HTTP request is null"));
			}
			if(arguments.httpRequest.getMethod() != "GET" && arguments.httpRequest.getMethod() != "POST") {
				throwException(createObject("component", "org.owasp.esapi.errors.IntrusionException").init(variables.ESAPI, "Bad HTTP method received", "Bad HTTP method received: " & arguments.httpRequest.getMethod()));
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
				throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Invalid list item", logMessage="Invalid list item: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context));
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
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Invalid HTTP request missing parameters", logMessage="Invalid HTTP request missing parameters " & arrayToList(missing) & ": context=" & arguments.context, context=arguments.context));
				}

				// verify ONLY optional & required parameters are present
				extra = duplicate(actualNames);
				extra.removeAll(arguments.requiredNames);
				extra.removeAll(arguments.optionalNames);
				if(extra.size() > 0) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Invalid HTTP request extra parameters " & extra, logMessage="Invalid HTTP request extra parameters " & extra & ": context=" & arguments.context, context=arguments.context));
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
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Input bytes required", logMessage="Input bytes required: HTTP request is null", context=arguments.context));
				}

				if(arrayLen(arguments.input) > arguments.maxLength) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Input bytes can not exceed " & arguments.maxLength & " bytes", logMessage="Input exceeds maximum allowed length of " & arguments.maxLength & " by " & (arrayLen(arguments.input) - arguments.maxLength) & " bytes: context=" & arguments.context & ", input=" & arrayToList(arguments.input), context=arguments.context));
				}

				for(i = 1; i <= arrayLen(arguments.input); i++) {
					if(arguments.input[i] < 33 || arguments.input[i] > 126) {
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(ESAPI=variables.ESAPI, userMessage=arguments.context & ": Invalid input bytes: context=" & arguments.context, logMessage="Invalid non-ASCII input bytes, context=" & arguments.context & ", input=" & arrayToList(arguments.input), context=arguments.context));
					}
				}
				return arguments.input;
			}
			else {
				canonical = "";
				try {
					canonical = variables.ESAPI.encoder().canonicalize(arguments.input);
					return newJava("java.lang.String").init(getValidPrintable(arguments.context, canonical.getBytes(), arguments.maxLength, arguments.allowNull));
				}
				catch(org.owasp.esapi.errors.EncodingException e) {
					throwException(createObject("component", "org.owasp.esapi.errors.ValidationException").init(variables.ESAPI, arguments.context & ": Invalid printable input", "Invalid encoding of printable input, context=" & arguments.context & ", input=" & arguments.input, e, arguments.context));
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

			if(arguments.maxLength <= 0)
				throwException(createObject("component", "org.owasp.esapi.errors.ValidationAvailabilityException").init(variables.ESAPI, "Invalid input", "Invalid readline. Must read a positive number of bytes from the stream"));

			sb = newJava("java.lang.StringBuffer").init();
			count = 0;
			c = "";

			try {
				while(true) {
					c = arguments.inputStream.read();
					if(c == -1) {
						if(sb.length() == 0)
							return -1;
						break;
					}
					if(c == 13 || c == 10)
						break;
					count++;
					if(count > arguments.maxLength) {
						throwException(createObject("component", "org.owasp.esapi.errors.ValidationAvailabilityException").init(variables.ESAPI, "Invalid input", "Invalid readLine. Read more than maximum characters allowed (" & arguments.maxLength & ")"));
					}
					sb.append(chr(c));
				}
				return sb.toString();
			}
			catch(java.io.IOException e) {
				throwException(createObject("component", "org.owasp.esapi.errors.ValidationAvailabilityException").init(variables.ESAPI, "Invalid input", "Invalid readLine. Problem reading from input stream", e));
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="isEmptyInput" output="false"
	            hint="Helper function to check if a value is empty">
		<cfargument required="true" name="input" hint="input value"/>

		<cfscript>
			if(isSimpleValue(arguments.input)) {
				return (arguments.input == "" || len(trim(arguments.input)) == 0);
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