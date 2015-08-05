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
import "org.owasp.esapi.errors.ConfigurationException";
import "org.owasp.esapi.errors.ValidationException";

/**
 * A validator performs syntax and possibly semantic validation of a single
 * piece of data from an untrusted source.
 */
component extends="StringValidationRule" {

	/** OWASP AntiSamy markup verification policy */
	variables.antiSamyPolicy = "";
	variables.logger = "";

    variables.resourceStream = "";

	public HTMLValidationRule function init( required org.owasp.esapi.ESAPI ESAPI, required string typeName, org.owasp.esapi.Encoder encoder, string whitelistPattern ) {
		if (structKeyExists(arguments, "whitelistPattern") && structKeyExists(arguments, "encoder")) {
			super.init( arguments.ESAPI, arguments.typeName, arguments.encoder, arguments.whitelistPattern );
		}
		else if (structKeyExists(arguments, "encoder")) {
			super.init( arguments.ESAPI, arguments.typeName, arguments.encoder );
		}
		else {
			super.init( arguments.ESAPI, arguments.typeName );
		}

		variables.logger = variables.ESAPI.getLogger(getMetaData(this).fullName);

		variables.resourceStream = variables.ESAPI.securityConfiguration().getAntiSamyPolicyFile();
		try {
			// attempt read to ensure file exists
			fileRead(variables.resourceStream);
		} catch (expression e) {
			raiseException(new ConfigurationException("Couldn't find antisamy-esapi.xml", e));
		}
	    if (isSimpleValue(variables.resourceStream)) {
	    	try {
				variables.antiSamyPolicy = createObject("java", "org.owasp.validator.html.Policy").getInstance(variables.resourceStream);
			} catch (org.owasp.validator.html.PolicyException e) {
				raiseException(new ConfigurationException("Couldn't parse antisamy policy", e));
		    }
		}

		return this;
	}

	public function getValid(required string context, required input, struct errorList) {
		if (structKeyExists(arguments, "errorList")) {
			return super.getValid(arguments.context, arguments.input, arguments.errorList);
		}
		return invokeAntiSamy( arguments.context, arguments.input );
	}

	public string function sanitize( required string context, required input ) {
		var safe = "";
		try {
			safe = invokeAntiSamy( arguments.context, arguments.input );
		} catch( org.owasp.esapi.errors.ValidationException e ) {
			// just return safe
		}
		return safe;
	}

	private string function invokeAntiSamy( required string context, required input ) {
		var StringUtilities = createObject("java", "org.owasp.esapi.StringUtilities");
		// CHECKME should this allow empty Strings? "   " us IsBlank instead?
	    if ( StringUtilities.isEmpty(javaCast("string", arguments.input)) ) {
			if (variables.allowNull) {
				return null;
			}
			raiseException(new ValidationException(variables.ESAPI, arguments.context & " is required", "AntiSamy validation error: context=" & arguments.context & ", input=" & arguments.input, arguments.context ));
	    }

		var canonical = super.getValid( arguments.context, arguments.input );

		try {
			var as = createObject("java", "org.owasp.validator.html.AntiSamy").init();
			var test = as.scan(canonical, variables.antiSamyPolicy);

			var errors = test.getErrorMessages();
			if ( !errors.isEmpty() ) {
				variables.logger.info( variables.logger.SECURITY_FAILURE, "Cleaned up invalid HTML input: " & arrayToList(errors) );
			}

			return test.getCleanHTML().trim();

		} catch (org.owasp.validator.html.ScanException e) {
			raiseException(new ValidationException(variables.ESAPI, arguments.context & ": Invalid HTML input", "Invalid HTML input: context=" & arguments.context & " error=" & e.getMessage(), arguments.context, e ));
		} catch (org.owasp.validator.html.PolicyException e) {
			raiseException(new ValidationException(variables.ESAPI, arguments.context & ": Invalid HTML input", "Invalid HTML input does not follow rules in antisamy-esapi.xml: context=" & arguments.context & " error=" & e.getMessage(), arguments.context, e ));
		}
	}
}

