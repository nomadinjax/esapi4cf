<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 --->
<cfcomponent implements="cfesapi.org.owasp.esapi.Validator" extends="cfesapi.org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Validator interface. This implementation relies on the ESAPI Encoder, Java Pattern (regex), Date, and several other classes to provide basic validation functions. This library has a heavy emphasis on whitelist validation and canonicalization. All double-encoded characters, even in multiple encoding schemes, such as &amp;lt; or %26lt; or even %25%26lt; are disallowed.">

	<cfscript>
		instance.ESAPI = "";

		/** OWASP AntiSamy markup verification policy */
		instance.antiSamyPolicy = "";

		/** constants */
		instance.MAX_CREDIT_CARD_LENGTH = 19;
		this.MAX_PARAMETER_NAME_LENGTH = 100;
		this.MAX_PARAMETER_VALUE_LENGTH = 65535;
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Validator" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
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
				getValidInput( arguments.context, arguments.input, arguments.type, arguments.maxLength, arguments.allowNull );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
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
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" hint="If ValidationException is thrown, then add to error list instead of throwing out to caller"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "errorList" )) {
				try {
					return getValidInput( arguments.context, arguments.input, arguments.type, arguments.maxLength, arguments.allowNull );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}
				return arguments.input;
			}
			else {
				try {
					arguments.context = instance.ESAPI.encoder().canonicalize( arguments.context );
					local.canonical = instance.ESAPI.encoder().canonicalize( arguments.input );

					if(arguments.type == "" || arguments.type.length() == 0) {
						throwException( newJava( "java.lang.RuntimeException" ).init( "Validation misconfiguration, specified type to validate against was null: context=" & arguments.context & ", type=" & arguments.type & "), input=" & arguments.input ) );
					}

					if(isEmpty( local.canonical )) {
						if(arguments.allowNull)
							return "";
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input required.", logMessage="Input required: context=" & arguments.context & ", type=" & arguments.type & "), input=" & arguments.input, context=arguments.context ) );
					}

					if(local.canonical.length() > arguments.maxLength) {
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid input. The maximum length of " & arguments.maxLength & " characters was exceeded.", logMessage="Input exceeds maximum allowed length of " & arguments.maxLength & " by " & (local.canonical.length() - arguments.maxLength) & " characters: context=" & arguments.context & ", type=" & arguments.type & "), input=" & arguments.input, context=arguments.context ) );
					}

					local.p = instance.ESAPI.securityConfiguration().getValidationPattern( arguments.type );
					if(!isObject( local.p )) {
						try {
							local.p = getJava( "java.util.regex.Pattern" ).compile( arguments.type );
						}
						catch(java.util.regex.PatternSyntaxException e) {
							throwException( newJava( "java.lang.RuntimeException" ).init( "Validation misconfiguration, specified type to validate against was null: context=" & arguments.context & ", type=" & arguments.type & "), input=" & arguments.input ) );
						}
					}

					if(!local.p.matcher( local.canonical ).matches()) {
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid input. Please conform to: " & local.p.pattern() & " with a maximum length of " & arguments.maxLength, logMessage="Invalid input: context=" & arguments.context & ", type=" & arguments.type & "(" & local.p.pattern() & "), input=" & arguments.input, context=arguments.context ) );
					}

					return local.canonical;
				}
				catch(cfesapi.org.owasp.esapi.errors.EncodingException e) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid input. An encoding error occurred.", "Error canonicalizing user input", e, arguments.context ) );
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
				getValidDate( arguments.context, arguments.input, arguments.format, arguments.allowNull );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Date" name="getValidDate" output="false"
	            hint="Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" name="format"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "errorList" )) {
				try {
					return getValidDate( arguments.context, arguments.input, arguments.format, arguments.allowNull );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}
				return "";
			}
			else {
				try {
					if(isEmpty( arguments.input )) {
						if(arguments.allowNull)
							return "";
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Input date required", "Input date required: context=" & arguments.context & ", input=" & arguments.input, arguments.context ) );
					}

					local.date = arguments.format.parse( arguments.input );
					return local.date;
				}
				catch(java.lang.Exception e) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid date must follow " & arguments.format & " format", "Invalid date: context=" & arguments.context & ", format=" & arguments.format & ", input=" & arguments.input, e, arguments.context ) );
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
			var local = {};

			try {
				if(!isObject( instance.antiSamyPolicy )) {
					if(instance.ESAPI.securityConfiguration().getResourceDirectory() == "") {

						//load via classpath
						local.loader = getClass().getClassLoader();

						local.in = "";
						try {
							local.in = local.loader.getResourceAsStream( "antisamy-esapi.xml" );
							if(local.in != "") {
								instance.antiSamyPolicy = getJava( "org.owasp.validator.html.Policy" ).getInstance( local.in );
							}
						}
						catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
							instance.antiSamyPolicy = "";
						}
						if(local.in != "")
							try {
								local.in.close();
							}
							catch(java.lang.Throwable ignore) {
							}

						if(instance.antiSamyPolicy == "") {
							throwException( newJava( "java.lang.IllegalArgumentException" ).init( "Can't load antisamy-esapi.xml as a classloader resource" ) );
						}
					}
					else {
						//load via fileio
						instance.antiSamyPolicy = getJava( "org.owasp.validator.html.Policy" ).getInstance( expandPath( instance.ESAPI.securityConfiguration().getResourceDirectory() & "antisamy-esapi.xml" ) );
					}
				}
				local.as = getJava( "org.owasp.validator.html.AntiSamy" ).init();
				local.test = local.as.scan( arguments.input, instance.antiSamyPolicy );
				return (local.test.getErrorMessages().size() == 0);
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
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
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "errorList" )) {
				try {
					return getValidSafeHTML( arguments.context, arguments.input, arguments.maxLength, arguments.allowNull );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}
				return arguments.input;
			}
			else {
				if(isEmpty( arguments.input )) {
					if(arguments.allowNull)
						return "";
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Input HTML required", "Input HTML required: context=" & arguments.context & ", input=" & arguments.input, arguments.context ) );
				}

				if(arguments.input.length() > arguments.maxLength) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid HTML. You enterted " & arguments.input.length() & " characters. Input can not exceed " & arguments.maxLength & " characters.", arguments.context & " arguments.input exceedes maxLength by " & (arguments.input.length() - arguments.maxLength) & " characters", arguments.context ) );
				}

				try {
					if(!isObject( instance.antiSamyPolicy )) {
						if(instance.ESAPI.securityConfiguration().getResourceDirectory() == "") {

							//load via classpath
							local.loader = getClass().getClassLoader();

							local.in = "";
							try {
								local.in = loader.getResourceAsStream( "antisamy-esapi.xml" );
								if(local.in != "") {
									instance.antiSamyPolicy = getJava( "org.owasp.validator.html.Policy" ).getInstance( local.in );
								}
							}
							catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
								instance.antiSamyPolicy = "";
							}
							if(local.in != "") {
								try {
									local.in.close();
								}
								catch(java.lang.Throwable ignore) {
								}
							}
							if(instance.antiSamyPolicy == "") {
								throwException( newJava( "java.lang.IllegalArgumentException" ).init( "Can't load antisamy-esapi.xml as a classloader resource" ) );
							}
						}
						else {
							//load via fileio
							instance.antiSamyPolicy = getJava( "org.owasp.validator.html.Policy" ).getInstance( expandPath( instance.ESAPI.securityConfiguration().getResourceDirectory() & "antisamy-esapi.xml" ) );
						}
					}
					local.as = getJava( "org.owasp.validator.html.AntiSamy" ).init();
					local.test = local.as.scan( arguments.input, instance.antiSamyPolicy );
					local.errors = local.test.getErrorMessages();

					if(local.errors.size() > 0) {
						// just create new exception to get it logged and intrusion detected
						createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage="Invalid HTML input: context=" & arguments.context, logMessage="Invalid HTML input: context=" & arguments.context & ", errors=" & arrayToList( local.errors ), context=arguments.context );
					}

					return (local.test.getCleanHTML().trim());
				}
				catch(org.owasp.validator.html.ScanException e) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid HTML input", "Invalid HTML input: context=" & arguments.context & " error=" & e.getMessage(), e, arguments.context ) );
				}
				catch(org.owasp.validator.html.PolicyException e) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid HTML input", "Invalid HTML input does not follow rules in antisamy-esapi.xml: context=" & arguments.context & " error=" & e.getMessage(), e, arguments.context ) );
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
				getValidCreditCard( arguments.context, arguments.input, arguments.allowNull );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidCreditCard" output="false"
	            hint="Returns a canonicalized and validated credit card number as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "errorList" )) {

				try {
					return getValidCreditCard( arguments.context, arguments.input, arguments.allowNull );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}
				return arguments.input;
			}
			else {
				if(isEmpty( arguments.input )) {
					if(arguments.allowNull)
						return "";
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Input credit card required", "Input credit card required: context=" & arguments.context & ", input=" & arguments.input, arguments.context ) );
				}

				local.canonical = getValidInput( arguments.context, arguments.input, "CreditCard", instance.MAX_CREDIT_CARD_LENGTH, arguments.allowNull );

				// perform Luhn algorithm checking
					local.digitsOnly = getJava( "java.lang.StringBuffer" ).init();
					local.c = "";
					for(local.i = 0; local.i < local.canonical.length(); local.i++) {
						local.c = local.canonical.charAt( local.i );
						if(getJava( "java.lang.Character" ).isDigit( local.c )) {
							local.digitsOnly.append( local.c );
						}
					}

					local.sum = 0;
					local.digit = 0;
					local.addend = 0;
					local.timesTwo = false;

					for(local.i = local.digitsOnly.length() - 1; local.i >= 0; local.i--) {
						local.digit = getJava( "java.lang.Integer" ).parseInt( local.digitsOnly.substring( local.i, local.i + 1 ) );
						if(local.timesTwo) {
							local.addend = local.digit * 2;
							if(local.addend > 9) {
								local.addend -= 9;
							}
						}
						else {
							local.addend = local.digit;
						}
						local.sum += local.addend;
						local.timesTwo = !local.timesTwo;
					}

					local.modulus = local.sum % 10;
					if(local.modulus != 0)
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid credit card input", "Invalid credit card input: context=" & arguments.context, arguments.context ) );

					return local.canonical;
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
				getValidDirectoryPath( arguments.context, arguments.input, arguments.allowNull );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidDirectoryPath" output="false"
	            hint="Returns a canonicalized and validated directory path as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "errorList" )) {
				try {
					return getValidDirectoryPath( arguments.context, arguments.input, arguments.allowNull );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}
				return arguments.input;
			}
			else {
				try {
					if(isEmpty( arguments.input )) {
						if(arguments.allowNull)
							return "";
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input directory path required", logMessage="Input directory path required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ) );
					}

					local.dir = getJava( "java.io.File" ).init( arguments.input );

					// check dir exists and parent exists and dir is inside parent
					if(!local.dir.exists()) {
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, does not exist: context=" & arguments.context & ", input=" & arguments.input ) );
					}
					if(!local.dir.isDirectory()) {
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, not a directory: context=" & arguments.context & ", input=" & arguments.input ) );
					}

					// check canonical form matches input
					local.canonical = local.dir.getCanonicalPath();
					//String canonical = getValidInput( arguments.context, canonicalPath, "DirectoryName", 255, false);
					if(local.canonical != arguments.input) {
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid directory name", logMessage="Invalid directory name does not match the canonical path: context=" & arguments.context & ", input=" & arguments.input & ", canonical=" & local.canonical, context=arguments.context ) );
					}
					return local.canonical;
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid directory name", "Failure to validate directory path: context=" & arguments.context & ", input=" & arguments.input, e, arguments.context ) );
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
				getValidFileName( arguments.context, arguments.input, arguments.allowNull );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidFileName" output="false"
	            hint="Returns a canonicalized and validated file name as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "errorList" )) {
				try {
					return getValidFileName( arguments.context, arguments.input, arguments.allowNull );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}
				return arguments.input;
			}
			else {
				local.canonical = "";
				// detect path manipulation
				try {
					if(isEmpty( arguments.input )) {
						if(arguments.allowNull)
							return "";
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input file name required", logMessage="Input required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ) );
					}

					// do basic validation
					local.canonical = instance.ESAPI.encoder().canonicalize( arguments.input );
					getValidInput( arguments.context, arguments.input, "FileName", 255, true );

					local.f = getJava( "java.io.File" ).init( local.canonical );
					local.c = local.f.getCanonicalPath();
					local.cpath = local.c.substring( local.c.lastIndexOf( getJava( "java.io.File" ).separator ) + 1 );

					// the path is valid if the input matches the canonical path
					if(!arguments.input.equals( local.cpath.toLowerCase() )) {
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file name", logMessage="Invalid directory name does not match the canonical path: context=" & arguments.context & ", input=" & arguments.input & ", canonical=" & local.canonical, context=arguments.context ) );
					}
				}
				catch(java.io.IOException e) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid file name", "Invalid file name does not exist: context=" & arguments.context & ", canonical=" & local.canonical, e, arguments.context ) );
				}
				catch(cfesapi.org.owasp.esapi.errors.EncodingException ee) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.IntrusionException" ).init( instance.ESAPI, arguments.context & ": Invalid file name", "Invalid file name: context=" & arguments.context & ", canonical=" & local.canonical, ee ) );
				}

				// verify extensions
				local.extensions = instance.ESAPI.securityConfiguration().getAllowedFileExtensions();
				for(local.i = 1; local.i <= arrayLen( local.extensions ); local.i++) {
					local.ext = local.extensions[local.i];
					if(arguments.input.toLowerCase().endsWith( local.ext.toLowerCase() )) {
						return local.canonical;
					}
				}
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid file name does not have valid extension ( " & instance.ESAPI.securityConfiguration().getAllowedFileExtensions() & ")", "Invalid file name does not have valid extension ( " & instance.ESAPI.securityConfiguration().getAllowedFileExtensions() & "): context=" & arguments.context & ", input=" & arguments.input, arguments.context ) );
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
				getValidNumber( arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidNumber" output="false"
	            hint="Returns a validated number as a double. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "errorList" )) {
				try {
					return getValidNumber( arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}

				//not sure what to return on error
				return getJava( "java.lang.Double" ).init( 0 );
			}
			else {
				local.minDoubleValue = getJava( "java.lang.Double" ).init( arguments.minValue );
				local.maxDoubleValue = getJava( "java.lang.Double" ).init( arguments.maxValue );
				return getValidDouble( arguments.context, arguments.input, local.minDoubleValue.doubleValue(), local.maxDoubleValue.doubleValue(), arguments.allowNull );
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
				getValidDouble( arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidDouble" output="false"
	            hint="Returns a validated number as a double. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "errorList" )) {
				try {
					return getValidDouble( arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}

				//not sure what to return on error
				return getJava( "java.lang.Double" ).init( 0 );
			}
			else {
				if(arguments.minValue > arguments.maxValue) {
					//should this be a RunTime?
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid double input: context", "Validation parameter error for double: maxValue ( " & arguments.maxValue & ") must be greater than minValue ( " & arguments.minValue & ") for " & arguments.context, arguments.context ) );
				}

				if(isEmpty( arguments.input )) {
					if(arguments.allowNull)
						return "";
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input required: context", logMessage="Input required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ) );
				}

				try {
					local.d = getJava( "java.lang.Double" ).init( getJava( "java.lang.Double" ).parseDouble( arguments.input ) );
					if(local.d.isInfinite())
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage="Invalid double input: context=" & arguments.context, logMessage="Invalid double input is infinite: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ) );
					if(local.d.isNaN())
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage="Invalid double input: context=" & arguments.context, logMessage="Invalid double input is infinite: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ) );
					if(local.d.doubleValue() < arguments.minValue)
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage="Invalid double input must be between " & arguments.minValue & " and " & arguments.maxValue & ": context=" & arguments.context, logMessage="Invalid double input must be between " & arguments.minValue & " and " & arguments.maxValue & ": context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ) );
					if(local.d.doubleValue() > arguments.maxValue)
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage="Invalid double input must be between " & arguments.minValue & " and " & arguments.maxValue & ": context=" & arguments.context, logMessage="Invalid double input must be between " & arguments.minValue & " and " & arguments.maxValue & ": context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ) );

					return local.d;
				}
				catch(java.lang.NumberFormatException e) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid double input", "Invalid double input format: context=" & arguments.context & ", input=" & arguments.input, e, arguments.context ) );
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
				getValidInteger( arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidInteger" output="false"
	            hint="Returns a validated number as a double. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="numeric" name="minValue"/>
		<cfargument required="true" type="numeric" name="maxValue"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "errorList" )) {
				try {
					return getValidInteger( arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}

				//not sure what to return on error
				return getJava( "java.lang.Integer" ).init( 0 );
			}
			else {
				if(arguments.minValue > arguments.maxValue) {
					//should this be a RunTime?
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid Integer", "Validation parameter error for double: maxValue ( " & arguments.maxValue & ") must be greater than minValue ( " & arguments.minValue & ") for " & arguments.context, arguments.context ) );
				}

				if(isEmpty( arguments.input )) {
					if(arguments.allowNull)
						return "";
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input required", logMessage="Input required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ) );
				}

				try {
					local.i = getJava( "java.lang.Integer" ).parseInt( arguments.input );
					if(local.i < arguments.minValue || local.i > arguments.maxValue)
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid Integer. Value must be between " & arguments.minValue & " and " & arguments.maxValue, logMessage="Invalid int input must be between " & arguments.minValue & " and " & arguments.maxValue & ": context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ) );
					return getJava( "java.lang.Integer" ).init( local.i );
				}
				catch(java.lang.NumberFormatException e) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid integer input", "Invalid int input: context=" & arguments.context & ", input=" & arguments.input, e, arguments.context ) );
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
				getValidFileContent( arguments.context, arguments.input, arguments.maxBytes, arguments.allowNull );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
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
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "errorList" )) {
				try {
					return getValidFileContent( arguments.context, arguments.input, arguments.maxBytes, arguments.allowNull );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}

				//not sure what to return on error
				return arguments.input;
			}
			else {
				if(isEmpty( arguments.input )) {
					if(arguments.allowNull)
						return "";
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input required", logMessage="Input required: context=" & arguments.context & ", input=" & toString( arguments.input ), context=arguments.context ) );
				}

				local.esapiMaxBytes = instance.ESAPI.securityConfiguration().getAllowedFileUploadSize();
				if(arrayLen( arguments.input ) > local.esapiMaxBytes)
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file content can not exceed " & local.esapiMaxBytes & " bytes", logMessage="Exceeded ESAPI max length", context=arguments.context ) );
				if(arrayLen( arguments.input ) > arguments.maxBytes)
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file content can not exceed " & arguments.maxBytes & " bytes", logMessage="Exceeded maxBytes ( " & arguments.input.length & ")", context=arguments.context ) );

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
			var local = {};

			local.validFile = isValidFileName( arguments.context, arguments.filename, arguments.allowNull );
			local.validDir = isValidDirectoryPath( arguments.context, arguments.filepath, arguments.allowNull );
			local.validContent = isValidFileContent( arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull );

			//System.out.println("isValidFileUpload: validFile="&local.validFile&" validDir="&local.validFile& " validContent="&local.validContent);
			return (local.validFile && local.validDir && local.validContent);
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
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			if(structKeyExists( arguments, "errorList" )) {
				try {
					assertValidFileUpload( arguments.context, arguments.filepath, arguments.filename, arguments.content, arguments.maxBytes, arguments.allowNull );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}
			}
			else {
				getValidFileName( arguments.context, arguments.filename, arguments.allowNull );
				getValidDirectoryPath( arguments.context, arguments.filepath, arguments.allowNull );
				getValidFileContent( arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidHTTPRequest" output="false"
	            hint="Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument name="request" default="#instance.ESAPI.httpUtilities().getCurrentRequest()#" hint="Defaults the current HTTPRequest saved in EASPI Authenticator"/>

		<cfscript>
			try {
				assertIsValidHTTPRequest( arguments.request );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
			catch(cfesapi.org.owasp.esapi.errors.IntrusionException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertIsValidHTTPRequest" output="false"
	            hint="Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument name="request" default="#instance.ESAPI.httpUtilities().getCurrentRequest()#" hint="Defaults the current HTTPRequest saved in EASPI Authenticator"/>

		<cfscript>
			var local = {};

			if(!isObject( arguments.request )) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, "Input required: HTTP request is null", "Input required: HTTP request is null" ) );
			}
			if(arguments.request.getMethod() != "GET" && arguments.request.getMethod() != "POST") {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.IntrusionException" ).init( instance.ESAPI, "Bad HTTP method received", "Bad HTTP method received: " & arguments.request.getMethod() ) );
			}

			local.parameters = arguments.request.getParameterMap();
			for (local.name in local.parameters) {
				getValidInput( "HTTP request parameter: " & local.name, local.name, "HTTPParameterName", this.MAX_PARAMETER_NAME_LENGTH, false );
				local.values = local.parameters[local.name];
				for (local.i3 = 1; local.i3 <= arrayLen(local.values); local.i3++) {
					local.value = local.values[local.i3];
					getValidInput( "HTTP request parameter: " & local.name, local.value, "HTTPParameterValue", this.MAX_PARAMETER_VALUE_LENGTH, true );
				}
			}

			local.cookies = arguments.request.getCookies();
			for (local.i2 = 1; local.i2 <= arrayLen(local.cookies); local.i2++) {
				local.cookie = local.cookies[local.i2];
				local.name = local.cookie.getName();
				getValidInput( "HTTP request cookie: " & local.name, local.name, "HTTPCookieName", this.MAX_PARAMETER_NAME_LENGTH, true );
				local.value = local.cookie.getValue();
				getValidInput( "HTTP request cookie: " & local.name, local.value, "HTTPCookieValue", this.MAX_PARAMETER_VALUE_LENGTH, true );
			}

			local.e = arguments.request.getHeaderNames();
			for(local.i = 1; local.i <= arrayLen( local.e ); local.i++) {
				local.name = local.e[local.i];
				if(local.name != "" && !local.name.equalsIgnoreCase( "Cookie" )) {
					getValidInput( "HTTP request header: " & local.name, local.name, "HTTPHeaderName", this.MAX_PARAMETER_NAME_LENGTH, true );
					local.e2 = arguments.request.getHeaders( local.name );
					for(local.i2 = 1; local.i2 <= arrayLen( local.e2 ); local.i2++) {
						local.value = local.e2[local.i2];
						getValidInput( "HTTP request header: " & local.name, local.value, "HTTPHeaderValue", this.MAX_PARAMETER_VALUE_LENGTH, true );
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
				getValidListItem( arguments.context, arguments.input, arguments.list );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidListItem" output="false"
	            hint="Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="Array" name="list"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			if(structKeyExists( arguments, "errorList" )) {
				try {
					return getValidListItem( arguments.context, arguments.input, arguments.list );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}
				return arguments.input;
			}
			else {
				if(arguments.list.contains( arguments.input ))
					return arguments.input;
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid list item", logMessage="Invalid list item: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ) );
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
				assertIsValidHTTPRequestParameterSet( arguments.context, arguments.requiredNames, arguments.optionalNames );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertIsValidHTTPRequestParameterSet" output="false"
	            hint="Validates that the parameters in the current request contain all required parameters and only optional ones in addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="Array" name="requiredNames"/>
		<cfargument required="true" type="Array" name="optionalNames"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "errorList" )) {
				try {
					assertIsValidHTTPRequestParameterSet( arguments.context, arguments.requiredNames, arguments.optionalNames );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}
			}
			else {
				local.request = instance.ESAPI.httpUtilities().getCurrentRequest();
				local.actualNames = local.request.getParameterMap().keySet();

				// verify ALL required parameters are present
				local.missing = duplicate( arguments.requiredNames );
				local.missing.removeAll( local.actualNames );
				if(local.missing.size() > 0) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid HTTP request missing parameters", logMessage="Invalid HTTP request missing parameters " & arrayToList( local.missing ) & ": context=" & arguments.context, context=arguments.context ) );
				}

				// verify ONLY optional & required parameters are present
				local.extra = duplicate( local.actualNames );
				local.extra.removeAll( arguments.requiredNames );
				local.extra.removeAll( arguments.optionalNames );
				if(local.extra.size() > 0) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid HTTP request extra parameters " & local.extra, logMessage="Invalid HTTP request extra parameters " & local.extra & ": context=" & arguments.context, context=arguments.context ) );
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
			if(isBinary( arguments.input )) {
				try {
					getValidPrintable( arguments.context, arguments.input, arguments.maxLength, arguments.allowNull );
					return true;
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					return false;
				}
			}
			else {
				try {
					getValidPrintable( arguments.context, arguments.input, arguments.maxLength, arguments.allowNull );
					return true;
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
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
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "errorList" )) {
				try {
					return getValidPrintable( arguments.context, arguments.input, arguments.maxLength, arguments.allowNull );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}
				return arguments.input;
			}

			if(isArray( arguments.input )) {
				if(isEmpty( arguments.input )) {
					if(arguments.allowNull)
						return "";
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input bytes required", logMessage="Input bytes required: HTTP request is null", context=arguments.context ) );
				}

				if(arrayLen( arguments.input ) > arguments.maxLength) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input bytes can not exceed " & arguments.maxLength & " bytes", logMessage="Input exceeds maximum allowed length of " & arguments.maxLength & " by " & (arrayLen( arguments.input ) - arguments.maxLength) & " bytes: context=" & arguments.context & ", input=" & arrayToList( arguments.input ), context=arguments.context ) );
				}

				for(local.i = 1; local.i <= arrayLen( arguments.input ); local.i++) {
					if(arguments.input[local.i] < 33 || arguments.input[local.i] > 126) {
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid input bytes: context=" & arguments.context, logMessage="Invalid non-ASCII input bytes, context=" & arguments.context & ", input=" & arrayToList( arguments.input ), context=arguments.context ) );
					}
				}
				return arguments.input;
			}
			else {
				local.canonical = "";
				try {
					local.canonical = instance.ESAPI.encoder().canonicalize( arguments.input );
					return getJava( "java.lang.String" ).init( getValidPrintable( arguments.context, local.canonical.getBytes(), arguments.maxLength, arguments.allowNull ) );
				}
				catch(cfesapi.org.owasp.esapi.errors.EncodingException e) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationException" ).init( instance.ESAPI, arguments.context & ": Invalid printable input", "Invalid encoding of printable input, context=" & arguments.context & ", input=" & arguments.input, e, arguments.context ) );
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
			return instance.ESAPI.validator().isValidInput( arguments.context, arguments.input, "Redirect", 512, arguments.allowNull );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getValidRedirectLocation" output="false"
	            hint="Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack will generate a descriptive IntrusionException.">
		<cfargument required="true" type="String" name="context"/>
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="true" type="boolean" name="allowNull"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList"/>

		<cfscript>
			if(structKeyExists( arguments, "errorList" )) {
				try {
					return getValidRedirectLocation( arguments.context, arguments.input, arguments.allowNull );
				}
				catch(cfesapi.org.owasp.esapi.errors.ValidationException e) {
					arguments.errorList.addError( arguments.context, e );
				}
				return arguments.input;
			}
			else {
				return instance.ESAPI.validator().getValidInput( arguments.context, arguments.input, "Redirect", 512, arguments.allowNull );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="safeReadLine" output="false"
	            hint="This implementation reads until a newline or the specified number of characters.">
		<cfargument required="true" name="inputStream"/>
		<cfargument required="true" type="numeric" name="maxLength"/>

		<cfscript>
			var local = {};

			if(arguments.maxLength <= 0)
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException" ).init( instance.ESAPI, "Invalid input", "Invalid readline. Must read a positive number of bytes from the stream" ) );

			local.sb = getJava( "java.lang.StringBuffer" ).init();
			local.count = 0;
			local.c = "";

			try {
				while(true) {
					local.c = arguments.inputStream.read();
					if(local.c == -1) {
						if(local.sb.length() == 0)
							return -1;
						break;
					}
					if(local.c == 13 || local.c == 10)
						break;
					local.count++;
					if(local.count > arguments.maxLength) {
						throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException" ).init( instance.ESAPI, "Invalid input", "Invalid readLine. Read more than maximum characters allowed (" & arguments.maxLength & ")" ) );
					}
					local.sb.append( chr( local.c ) );
				}
				return local.sb.toString();
			}
			catch(java.io.IOException e) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException" ).init( instance.ESAPI, "Invalid input", "Invalid readLine. Problem reading from input stream", e ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="isEmpty" output="false"
	            hint="Helper function to check if a value is empty">
		<cfargument required="true" name="input" hint="input value"/>

		<cfscript>
			if(isSimpleValue( arguments.input )) {
				return (arguments.input == "" || arguments.input.trim().length() == 0);
			}
			else if(isBinary( arguments.input )) {
				return (arrayLen( arguments.input ) == 0);
			}
			else if(isArray( arguments.input )) {
				return (arrayLen( arguments.input ) == 0);
			}
		</cfscript>

	</cffunction>

</cfcomponent>