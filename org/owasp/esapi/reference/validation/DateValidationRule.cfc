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
	variables.format = createObject("java", "java.text.DateFormat").getDateInstance();

	public DateValidationRule function init( required org.owasp.esapi.ESAPI ESAPI, required string typeName, required org.owasp.esapi.Encoder encoder, required newFormat ) {
		super.init( arguments.ESAPI, arguments.typeName, arguments.encoder );
		if (!isNull(arguments.newFormat) && isObject(arguments.newFormat)) {
			setDateFormat( arguments.newFormat );
		}
		return this;
	}

    public void function setDateFormat( required newFormat ) {
        if (isNull(arguments.newFormat) || !isObject(arguments.newFormat)) {
			raiseException(createObject("java", "java.lang.IllegalArgumentException").init("DateValidationRule.setDateFormat requires a non-null DateFormat"));
		}
    	// CHECKME fail fast?
/*
  		try {
			newFormat.parse(new Date());
		} catch (ParseException e) {
			throw new IllegalArgumentException(e);
		}
*/
        variables.format = arguments.newFormat;
        variables.format.setLenient( variables.ESAPI.securityConfiguration().getLenientDatesAccepted() );
    }

	public function getValid(required string context, required input, struct errorList) {
		if (structKeyExists(arguments, "errorList")) {
			return super.getValid(arguments.context, arguments.input, arguments.errorList);
		}
		return safelyParse(arguments.context, arguments.input);
	}

    /**
     * Calls sanitize(String, String, DateFormat) with DateFormat.getInstance()
     */
	public date function sanitize( required string context, required input )  {
		var date = createObject("java", "java.lang.Date").init(0);
		try {
			date = safelyParse(arguments.context, arguments.input);
		} catch (org.owasp.esapi.errors.ValidationException e) {
			// do nothing
	    }
		return date;
	}

	private function safelyParse(required string context, required input) {
		var StringUtilities = createObject("java", "org.owasp.esapi.StringUtilities");
		// CHECKME should this allow empty Strings? "   " use IsBlank instead?
		if (StringUtilities.isEmpty(javaCast("string", arguments.input))) {
			if (variables.allowNull) {
				return;
			}
			raiseException(new ValidationException(variables.ESAPI,
				arguments.context & ": Input date required",
				"Input date required: context=" & arguments.context & ", input=" & arguments.input,
				arguments.context
			));
		}

		if (isDate(arguments.input)) return arguments.input;

	    var canonical = variables.encoder.canonicalize(arguments.input);

		try {
			return variables.format.parse(javaCast("string", canonical));
		} catch (any e) {
			raiseException(new ValidationException(variables.ESAPI,
				arguments.context & ": Invalid date must follow the " & variables.format.toPattern() & " format",
				"Invalid date: context=" & arguments.context & ", format=" & variables.format.toPattern() & ", input=" & arguments.input,
				arguments.context,
				e
			));
		}
	}
}
