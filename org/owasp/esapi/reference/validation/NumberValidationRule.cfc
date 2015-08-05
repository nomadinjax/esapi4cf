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

	variables.minValue = createObject("java", "java.lang.Double").NEGATIVE_INFINITY;
	variables.maxValue = createObject("java", "java.lang.Double").POSITIVE_INFINITY;

	public NumberValidationRule function init( required org.owasp.esapi.ESAPI ESAPI, required string typeName, required org.owasp.esapi.Encoder encoder, numeric minValue, numeric maxValue ) {
		super.init( arguments.ESAPI, arguments.typeName, arguments.encoder );
		if (structKeyExists(arguments, "minValue")) {
			variables.minValue = arguments.minValue;
		}
		if (structKeyExists(arguments, "maxValue")) {
			variables.maxValue = arguments.maxValue;
		}
		return this;
	}

	public function getValid( required string context, required input, struct errorList ) {
		if (structKeyExists(arguments, "errorList")) {
			return super.getValid(arguments.context, arguments.input, arguments.errorList);
		}
		return safelyParse(arguments.context, arguments.input);
	}

	public numeric function sanitize( required string context, required input ) {
		var toReturn = createObject("java", "java.lang.Double").valueOf(0);
		try {
			toReturn = safelyParse(arguments.context, arguments.input);
		} catch (ValidationException e) {
			// do nothing
		}
		return toReturn;
	}
	//
	// These statics needed to detect double parsing DOS bug in Java
	//
	variables.bigBad = "";
	variables.smallBad = "";

	variables.one = createObject("java", "java.math.BigDecimal").init(1);
	variables.two = createObject("java", "java.math.BigDecimal").init(2);

	variables.tiny = variables.one.divide(variables.two.pow(1022));

	// 2^(-1022) ­ 2^(-1076)
	variables.bigBad = variables.tiny.subtract(variables.one.divide(variables.two.pow(1076)));
	//2^(-1022) ­ 2^(-1075)
	variables.smallBad = variables.tiny.subtract(variables.one.divide(variables.two.pow(1075)));

	private function safelyParse(required string context, required input) {
		var Double = createObject("java", "java.lang.Double");
		var StringUtilities = createObject("java", "org.owasp.esapi.StringUtilities");

		// CHECKME should this allow empty Strings? "   " us IsBlank instead?
	    if ( StringUtilities.isEmpty(javaCast("string", arguments.input)) ) {
			if (variables.allowNull) {
				return "";
			}
			raiseException(new ValidationException( variables.ESAPI, arguments.context & ": Input number required", "Input number required: context=" & arguments.context & ", input=" & arguments.input, arguments.context ));
	    }

	    // canonicalize
	    var canonical = variables.encoder.canonicalize( arguments.input );

	    //if MinValue is greater than maxValue then programmer is likely calling this wrong
		if (variables.minValue > variables.maxValue) {
			raiseException(new ValidationException( variables.ESAPI, arguments.context & ": Invalid number input: context", "Validation parameter error for number: maxValue ( " & variables.maxValue & ") must be greater than minValue ( " & variables.minValue & ") for " & arguments.context, arguments.context ));
		}

		//convert to BigDecimal so we can safely parse dangerous numbers to
		//check if the number may DOS the double parser
		var bd = "";
		try {
			bd = createObject("java", "java.math.BigDecimal").init(javaCast("string", canonical));
		}
		// Railo (preferred)
		catch (java.lang.NumberFormatException e) {
			raiseException(new ValidationException( variables.ESAPI, arguments.context & ": Invalid number input", "Invalid number input format: context=" & arguments.context & ", input=" & arguments.input, arguments.context, e));
		}
		// CF (why does CF not pick up on the java.lang.NumberFormatException type?)
		catch (Object e) {
			raiseException(new ValidationException( variables.ESAPI, arguments.context & ": Invalid number input", "Invalid number input format: context=" & arguments.context & ", input=" & arguments.input, arguments.context, e));
		}

		// Thanks to Brian Chess for this suggestion
		// Check if string input is in the "dangerous" double parsing range
		if (bd.compareTo(variables.smallBad) >= 0 && bd.compareTo(variables.bigBad) <= 0) {
			// if you get here you know you're looking at a bad value. The final
			// value for any double in this range is supposed to be the following safe #
			return Double.init("2.2250738585072014E-308");
		}

		// the number is safe to parseDouble
		var d = "";
		// validate min and max
		try {
			d = Double.valueOf(Double.parseDouble( canonical ));
		} catch (NumberFormatException e) {
			raiseException(new ValidationException( variables.ESAPI, arguments.context & ": Invalid number input", "Invalid number input format: context=" & arguments.context & ", input=" & arguments.input, arguments.context, e));
		}

		if (d.isInfinite()) {
			raiseException(new ValidationException( variables.ESAPI, "Invalid number input: context=" & arguments.context, "Invalid double input is infinite: context=" & arguments.context & ", input=" & arguments.input, arguments.context ));
		}
		if (d.isNaN()) {
			raiseException(new ValidationException( variables.ESAPI, "Invalid number input: context=" & arguments.context, "Invalid double input is not a number: context=" & arguments.context & ", input=" & arguments.input, arguments.context ));
		}
		if (d.doubleValue() < variables.minValue) {
			raiseException(new ValidationException( variables.ESAPI, "Invalid number input must be between " & variables.minValue & " and " & variables.maxValue & ": context=" & arguments.context, "Invalid number input must be between " & variables.minValue & " and " & variables.maxValue & ": context=" & arguments.context & ", input=" & arguments.input, arguments.context ));
		}
		if (d.doubleValue() > variables.maxValue) {
			raiseException(new ValidationException( variables.ESAPI, "Invalid number input must be between " & variables.minValue & " and " & variables.maxValue & ": context=" & arguments.context, "Invalid number input must be between " & variables.minValue & " and " & variables.maxValue & ": context=" & arguments.context & ", input=" & arguments.input, arguments.context ));
		}
		return d;
	}
}
