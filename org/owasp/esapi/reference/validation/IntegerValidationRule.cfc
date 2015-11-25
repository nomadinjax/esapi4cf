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

	variables.minValue = createObject("java", "java.lang.Integer").MIN_VALUE;
	variables.maxValue = createObject("java", "java.lang.Integer").MAX_VALUE;

	public IntegerValidationRule function init( required org.owasp.esapi.ESAPI ESAPI, required string typeName, required org.owasp.esapi.Encoder encoder, numeric minValue, numeric maxValue ) {
		super.init( arguments.ESAPI, arguments.typeName, arguments.encoder );
		if (structKeyExists(arguments, "minValue")) {
			variables.minValue = arguments.minValue;
		}
		if (structKeyExists(arguments, "maxValue")) {
			variables.maxValue = arguments.maxValue;
		}
		return this;
	}

	public function getValid(required string context, required input, struct errorList) {
		if (structKeyExists(arguments, "errorList")) {
			return super.getValid(arguments.context, arguments.input, arguments.errorList);
		}
		return safelyParse(arguments.context, arguments.input);
	}

	private function safelyParse(required string context, required input) {
		// do not allow empty Strings such as "   " - so trim to ensure
		// isEmpty catches "    "
		if (!isNull(arguments.input)) arguments.input = trim(arguments.input);

		var StringUtilities = createObject("java", "org.owasp.esapi.StringUtilities");

	    if (isNull(arguments.input) || StringUtilities.isEmpty(javaCast("string", arguments.input)) ) {
			if (variables.allowNull) {
				return "";
			}
			raiseException(new ValidationException( variables.ESAPI, arguments.context & ": Input number required", "Input number required: context=" & arguments.context & ", input=" & arguments.input, arguments.context ));
	    }

	    // canonicalize
	    var canonical = variables.encoder.canonicalize( arguments.input );

		if (variables.minValue > variables.maxValue) {
			raiseException(new ValidationException( variables.ESAPI, arguments.context & ": Invalid number input: context", "Validation parameter error for number: maxValue ( " & variables.maxValue & ") must be greater than minValue ( " & variables.minValue & ") for " & arguments.context, arguments.context ));
		}

		// validate min and max
		try {
			var i = createObject("java", "java.lang.Integer").valueOf(canonical);
			if (i < variables.minValue) {
				raiseException(new ValidationException( variables.ESAPI, "Invalid number input must be between " & variables.minValue & " and " & variables.maxValue & ": context=" & arguments.context, "Invalid number input must be between " & variables.minValue & " and " & variables.maxValue & ": context=" & arguments.context & ", input=" & arguments.input, arguments.context ));
			}
			if (i > variables.maxValue) {
				raiseException(new ValidationException( variables.ESAPI, "Invalid number input must be between " & variables.minValue & " and " & variables.maxValue & ": context=" & arguments.context, "Invalid number input must be between " & variables.minValue & " and " & variables.maxValue & ": context=" & arguments.context & ", input=" & arguments.input, arguments.context ));
			}
			return i;
		} catch (java.lang.NumberFormatException e) {
			raiseException(new ValidationException( variables.ESAPI, arguments.context & ": Invalid number input", "Invalid number input format: context=" & arguments.context & ", input=" & arguments.input, arguments.context, e));
		}
	}

	public numeric function sanitize( required string context, required input ) {
		var toReturn = createObject("java", "java.lang.Integer").valueOf( 0 );
		try {
			toReturn = safelyParse(arguments.context, arguments.input);
		} catch (ValidationException e ) {
			// do nothing
		}
		return toReturn;
	}
}