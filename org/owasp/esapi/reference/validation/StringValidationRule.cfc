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
import "org.owasp.esapi.errors.ValidationException";

/**
 * A validator performs syntax and possibly semantic validation of a single
 * piece of data from an untrusted source.
 */
component extends="BaseValidationRule" {

	variables.whitelistPatterns = [];
	variables.blacklistPatterns = [];
	variables.minLength = 0;
	variables.maxLength = createObject("java", "java.lang.Integer").MAX_VALUE;
	variables.validateInputAndCanonical = true;

	public StringValidationRule function init(required org.owasp.esapi.ESAPI ESAPI, required string typeName, org.owasp.esapi.Encoder encoder, string whitelistPattern) {
		if (structKeyExists(arguments, "encoder")) {
			super.init(arguments.ESAPI, arguments.typeName, arguments.encoder);
		}
		else {
			super.init(arguments.ESAPI, arguments.typeName);
		}
		if (structKeyExists(arguments, "whitelistPattern")) {
			addWhitelistPattern(arguments.whitelistPattern);
		}

		return this;
	}

	public void function addWhitelistPattern(required pattern) {
		if (isNull(arguments.pattern)) {
			throws(createObject("java", "java.lang.IllegalArgumentException").init("Pattern cannot be null"));
		}

		if (isSimpleValue(arguments.pattern)) {
			try {
				variables.whitelistPatterns.add(createObject("java", "java.util.regex.Pattern").compile(arguments.pattern));
			}
			catch (java.util.regex.PatternSyntaxException e) {
				throws(createObject("java", "java.lang.IllegalArgumentException").init("Validation misconfiguration, problem with specified pattern: " & arguments.pattern, e));
			}
		}
		else {
			variables.whitelistPatterns.add(arguments.pattern);
		}
	}

	public void function addBlacklistPattern( required pattern ) {
		if (isNull(arguments.pattern)) {
			throws(createObject("java", "java.lang.IllegalArgumentException").init("Pattern cannot be null"));
		}
		if (isSimpleValue(arguments.pattern)) {
			try {
				variables.blacklistPatterns.add( createObject("java", "java.util.regex.Pattern").compile( arguments.pattern ) );
			}
			catch( java.util.regex.PatternSyntaxException e ) {
				throws(createObject("java", "java.lang.IllegalArgumentException").init( "Validation misconfiguration, problem with specified pattern: " & arguments.pattern, e ));
			}
		}
		else {
			variables.blacklistPatterns.add( arguments.pattern );
		}
	}

	public void function setMinimumLength(required numeric length) {
		variables.minLength = arguments.length;
	}


	public void function setMaximumLength(required numeric length) {
		variables.maxLength = arguments.length;
	}

	/**
	 * Set the flag which determines whether the in input itself is
	 * checked as well as the canonical form of the input.
	 * @param flag The value to set
	 */
	public void function setValidateInputAndCanonical(required boolean flag) {
		variables.validateInputAndCanonical = arguments.flag;
	}

	/**
	 * checks input against whitelists.
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private string function checkWhitelist(required string context, required input, string orig=arguments.input) {
		// check whitelist patterns
		for (var p in variables.whitelistPatterns) {
			if (!p.matcher(javaCast("string", arguments.input)).matches()) {
				throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid input. Please conform to regex " & p.pattern() & (variables.maxLength == createObject("java", "java.lang.Integer").MAX_VALUE ? "" : " with a maximum length of " & variables.maxLength), "Invalid input: context=" & arguments.context & ", type(" & getTypeName() & ")=" & p.pattern() & ", input=" & arguments.input & (arguments.orig == arguments.input ? "" : ", orig=" & arguments.orig), arguments.context));
			}
		}
		return arguments.input;
	}

	/**
	 * checks input against blacklists.
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private string function checkBlacklist(required string context, required input, string orig=arguments.input) {
		// check blacklist patterns
		for (var p in variables.blacklistPatterns) {
			if ( p.matcher(javaCast("string", arguments.input)).matches() ) {
				throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid input. Dangerous input matching " & p.pattern() & " detected.", "Dangerous input: context=" & arguments.context & ", type(" & getTypeName() & ")=" & p.pattern() & ", input=" & arguments.input & (arguments.orig == arguments.input ? "" : ", orig=" & arguments.orig), arguments.context));
			}
		}
		return arguments.input;
	}

	/**
	 * checks input lengths
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private string function checkLength(required string context, required input, string orig=arguments.input) {
		if (len(arguments.input) < variables.minLength) {
			throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid input. The minimum length of " & variables.minLength & " characters was not met.", "Input does not meet the minimum length of " & variables.minLength & " by " & (variables.minLength - len(arguments.input)) & " characters: context=" & arguments.context & ", type=" & getTypeName() & "), input=" & arguments.input & (arguments.input == arguments.orig ? "" : ", orig=" & arguments.orig), arguments.context));
		}

		if (len(arguments.input) > variables.maxLength) {
			throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid input. The maximum length of " & variables.maxLength & " characters was exceeded.", "Input exceeds maximum allowed length of " & variables.maxLength & " by " & (len(arguments.input) - variables.maxLength) & " characters: context=" & arguments.context & ", type=" & getTypeName() & ", orig=" & arguments.orig & ", input=" & arguments.input, arguments.context));
		}

		return arguments.input;
	}

	/**
	 * checks input emptiness
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private string function checkEmpty(required string context, required input, orig=arguments.input) {
		var StringUtilities = createObject("java", "org.owasp.esapi.StringUtilities");
		if(!StringUtilities.isEmpty(javaCast("string", arguments.input))) {
			return arguments.input;
		}
		if(variables.allowNull) {
			return;
		}
		throws(new ValidationException(variables.ESAPI, arguments.context & ": Input required.", "Input required: context=" & arguments.context & ", input=" & arguments.input & (arguments.input == arguments.orig ? "" : ", orig=" & arguments.orig), arguments.context));
	}

	public function getValid(required string context, required input, struct errorList) {
		if (structKeyExists(arguments, "errorList")) {
			return super.getValid(arguments.context, arguments.input, arguments.errorList);
		}

		var data = "";

		// checks on input itself

		// check for empty/null
		if(isNull(checkEmpty(arguments.context, arguments.input))) {
			return;
		}

		if (variables.validateInputAndCanonical) {
			//first validate pre-canonicalized data

			// check length
			checkLength(arguments.context, arguments.input);

			// check whitelist patterns
			checkWhitelist(arguments.context, arguments.input);

			// check blacklist patterns
			checkBlacklist(arguments.context, arguments.input);

			// canonicalize
			data = variables.encoder.canonicalize( arguments.input );
		}
		else {
			//skip canonicalization
			data = arguments.input;
		}

		// check for empty/null
		if(isNull(checkEmpty(arguments.context, data, arguments.input))) {
			return;
		}

		// check length
		checkLength(arguments.context, data, arguments.input);

		// check whitelist patterns
		checkWhitelist(arguments.context, data, arguments.input);

		// check blacklist patterns
		checkBlacklist(arguments.context, data, arguments.input);

		// validation passed
		return data;
	}


	public string function sanitize( required string context, required input ) {
		return whitelist( arguments.input, variables.encoder.CHAR_ALPHANUMERICS );
	}

}

