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
<cfcomponent extends="BaseValidationRule" output="false">

	<cfscript>
		instance.whitelistPatterns = [];
		instance.blacklistPatterns = [];

		instance.minLength = 0;
		instance.maxLength = createObject("java", "java.lang.Integer").MAX_VALUE;
		instance.validateInputAndCanonical = true;
	</cfscript>
 
	<cffunction access="public" returntype="StringValidationRule" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="String" name="typeName" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.Encoder" name="encoder" required="false">
		<cfargument type="String" name="whitelistPattern" required="false">
		<cfscript>
			super.init( argumentCollection=arguments );

			if (structKeyExists(arguments, "whitelistPattern")) {
				addWhitelistPattern( arguments.whitelistPattern );
			}

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="addWhitelistPattern" output="false">
		<cfargument type="any" name="pattern" required="true">
		<cfscript>
			if (isInstanceOf(arguments.pattern, "java.util.regex.Pattern")) {
				if (isNull(arguments.pattern)) {
					throw(object=createObject("java", "java.lang.IllegalArgumentException").init("Pattern cannot be null"));
				}
				instance.whitelistPatterns.add( arguments.pattern );
			}
			else {
				if (isNull(arguments.pattern)) {
					throw(object=createObject("java", "java.lang.IllegalArgumentException").init("Pattern cannot be null"));
				}
				try {
					instance.whitelistPatterns.add( createObject("java", "java.util.regex.Pattern").compile( arguments.pattern ) );
				} catch( java.util.regex.PatternSyntaxException e ) {
					throw(object=createObject("java", "java.lang.IllegalArgumentException").init( "Validation misconfiguration, problem with specified pattern: " & arguments.pattern, e ));
				}
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="addBlacklistPattern" output="false">
		<cfargument type="any" name="pattern" required="true">
		<cfscript>
			if (isInstanceOf(arguments.pattern, "java.util.regex.Pattern")) {
				if (isNull(arguments.pattern)) {
					throw(object=createObject("java", "java.lang.IllegalArgumentException").init("Pattern cannot be null"));
				}
				instance.blacklistPatterns.add( arguments.pattern );
			}
			else {
				if (isNull(arguments.pattern)) {
					throw(object=createObject("java", "java.lang.IllegalArgumentException").init("Pattern cannot be null"));
				}
				try {
					instance.blacklistPatterns.add( createObject("java", "java.util.regex.Pattern").compile( arguments.pattern ) );
				} catch( java.util.regex.PatternSyntaxException e ) {
					throw(object=createObject("java", "java.lang.IllegalArgumentException").init( "Validation misconfiguration, problem with specified pattern: " & arguments.pattern, e ));
				}
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setMinimumLength" output="false">
		<cfargument type="numeric" name="length" required="true">
		<cfscript>
			instance.minLength = arguments.length;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setMaximumLength" output="false">
		<cfargument type="numeric" name="length" required="true">
		<cfscript>
			instance.maxLength = arguments.length;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setValidateInputAndCanonical" output="false" hint="Set the flag which determines whether the in input itself is checked as well as the canonical form of the input.">
		<cfargument type="boolean" name="flag" required="true">
		<cfscript>
			instance.validateInputAndCanonical = arguments.flag;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="checkWhitelist" output="false" hint="checks input against whitelists.">
		<cfargument type="String" name="context" required="true" hint="The context to include in exception messages">
		<cfargument type="String" name="input" required="true" hint="the input to check">
		<cfargument type="String" name="orig" required="false" default="#arguments.input#" hint="A origional input to include in exception messages. This is not included if it is the same as input.">
		<cfscript>
			// check whitelist patterns
			for (local.i = 1; local.i <= arrayLen(instance.whitelistPatterns); local.i++) {
				local.p = instance.whitelistPatterns[local.i];
				if ( !local.p.matcher(arguments.input).matches() ) {
					NullSafe = createObject("java", "org.owasp.esapi.util.NullSafe");
					cfex = createObject('component', 'cfesapi.org.owasp.esapi.errors.ValidationException').init(
						ESAPI = instance.ESAPI,
						userMessage = arguments.context & ": Invalid input. Please conform to regex " & local.p.pattern() & ( instance.maxLength == createObject("java", "java.lang.Integer").MAX_VALUE ? "" : " with a maximum length of " & instance.maxLength ),
						logMessage = "Invalid input: context=" & arguments.context & ", type(" & getTypeName() & ")=" & local.p.pattern() & ", input=" & arguments.input & (NullSafe.equals(arguments.orig,arguments.input) ? "" : ", orig=" & arguments.orig),
						context = arguments.context
					);
					throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
				}
			}

			return arguments.input;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="checkBlacklist" output="false" hint="checks input against blacklists.">
		<cfargument type="String" name="context" required="true" hint="The context to include in exception messages">
		<cfargument type="String" name="input" required="true" hint="the input to check">
		<cfargument type="String" name="orig" required="false" default="#arguments.input#" hint="A origional input to include in exception messages. This is not included if it is the same as input.">
		<cfscript>
			// check blacklist patterns
			for (local.p in instance.blacklistPatterns) {
				if ( local.p.matcher(arguments.input).matches() ) {
					NullSafe = createObject("java", "org.owasp.esapi.util.NullSafe");
					cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid input. Dangerous input matching " & local.p.pattern() & " detected.", logMessage="Dangerous input: context=" & arguments.context & ", type(" & getTypeName() & ")=" & local.p.pattern() & ", input=" & arguments.input & (NullSafe.equals(arguments.orig,arguments.input) ? "" : ", orig=" & arguments.orig), context=arguments.context );
					throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
				}
			}

			return arguments.input;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="checkLength" output="false" hint="checks input lengths">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="String" name="orig" required="false" default="#arguments.input#">
		<cfscript>
			if (len(arguments.input) < instance.minLength) {
				NullSafe = createObject("java", "org.owasp.esapi.util.NullSafe");
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid input. The minimum length of " & instance.minLength & " characters was not met.", logMessage="Input does not meet the minimum length of " & instance.minLength & " by " & (instance.minLength - arguments.input.length()) & " characters: context=" & arguments.context & ", type=" & getTypeName() & "), input=" & arguments.input & (NullSafe.equals(arguments.input,arguments.orig) ? "" : ", orig=" & arguments.orig), context=arguments.context );
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}

			if (len(arguments.input) > instance.maxLength) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid input. The maximum length of " & instance.maxLength & " characters was exceeded.", logMessage="Input exceeds maximum allowed length of " & instance.maxLength & " by " & (arguments.input.length()-instance.maxLength) & " characters: context=" & arguments.context & ", type=" & getTypeName() & ", orig=" & arguments.orig &", input=" & arguments.input, context=arguments.context );
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}

			return arguments.input;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="checkEmpty" output="false" hint="checks input emptiness">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="String" name="orig" required="false" default="#arguments.input#">
		<cfscript>
			if(!createObject("java", "org.owasp.esapi.StringUtilities").isEmpty(javaCast("string", arguments.input))) {
				return arguments.input;
			}
			if (instance.allowNull) {
				return "";
			}
			NullSafe = createObject("java", "org.owasp.esapi.util.NullSafe");
			cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.ValidationException").init( ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input required.", logMessage="Input required: context=" & arguments.context & "), input=" & arguments.input & (NullSafe.equals(arguments.input,arguments.orig) ? "" : ", orig=" & arguments.orig), context=arguments.context );
			throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getValid" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false">
		<cfscript>
			if (structKeyExists(arguments, "errorList")) {
				return super.getValid(argumentCollection=arguments);
			}

			local.data = "";

			// checks on input itself
			try {
				// check for empty/null
				if(checkEmpty(arguments.context, arguments.input) == "") {
					return "";
				}
				if (instance.validateInputAndCanonical) {
					//first validate pre-canonicalized data

					// check length
					checkLength(arguments.context, arguments.input);

					// check whitelist patterns
					checkWhitelist(arguments.context, arguments.input);

					// check blacklist patterns
					checkBlacklist(arguments.context, arguments.input);

					// canonicalize
					local.data = getEncoder().canonicalize( arguments.input );
				}
				else {
					//skip canonicalization
					local.data = arguments.input;
				}

				// check for empty/null
				if(checkEmpty(arguments.context, local.data, arguments.input) == "") {
					return "";
				}
				// check length
				checkLength(arguments.context, local.data, arguments.input);

				// check whitelist patterns
				checkWhitelist(arguments.context, local.data, arguments.input);

				// check blacklist patterns
				checkBlacklist(arguments.context, local.data, arguments.input);
			}
			catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				throw(type=e.type, message=e.message);
			}

			// validation passed
			return local.data;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="sanitize" output="false">
		<cfargument type="String" name="context" required="true">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			return whitelist( arguments.input, createObject("java", "org.owasp.esapi.EncoderConstants").CHAR_ALPHANUMERICS );
		</cfscript> 
	</cffunction>


</cfcomponent>
