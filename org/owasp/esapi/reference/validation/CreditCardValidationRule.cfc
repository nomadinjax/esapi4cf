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
import "org.owasp.esapi.validation.StringValidationRule";
import "org.owasp.esapi.errors.ValidationException";

/**
 * A validator performs syntax and possibly semantic validation of Credit Card
 * String from an untrusted source.
 */
component extends="BaseValidationRule" {
	variables.maxCardLength = 19;

	/**
	 * Key used to pull out encoder in configuration.  Prefixed with "Validator."
	 */
	variables.CREDIT_CARD_VALIDATOR_KEY = "CreditCard";

	variables.ccrule = "";

	/**
	 * Creates a CreditCardValidator using the rule found in security configuration
	 * @param typeName a description of the type of card being validated
	 * @param encoder
	 */
	public CreditCardValidationRule function init( required org.owasp.esapi.ESAPI ESAPI, required string typeName, required org.owasp.esapi.Encoder encoder, StringValidationRule validationRule ) {
		super.init( arguments.ESAPI, arguments.typeName, arguments.encoder );
		if (structKeyExists(arguments, "validationRule")) {
			variables.ccrule = arguments.validationRule;
		}
		else {
			variables.ccrule = readDefaultCreditCardRule();
		}
		return this;
	}

	private StringValidationRule function readDefaultCreditCardRule() {
		var p = variables.ESAPI.securityConfiguration().getValidationPattern( variables.CREDIT_CARD_VALIDATOR_KEY );
		var ccr = new StringValidationRule( variables.ESAPI, "ccrule", variables.encoder, p.pattern() );
		ccr.setMaximumLength(getMaxCardLength());
		ccr.setAllowNull( false );
		return ccr;
	}

	public function getValid(required string context, required input, struct errorList) {
		if (structKeyExists(arguments, "errorList")) {
			return super.getValid(arguments.context, arguments.input, arguments.errorList);
		}

		var StringUtilities = createObject("java", "org.owasp.esapi.StringUtilities");

		// CHECKME should this allow empty Strings? "   " us IsBlank instead?
	    if ( StringUtilities.isEmpty(javaCast("string", arguments.input)) ) {
			if (variables.allowNull) {
				return "";
			}
			raiseException(new ValidationException( variables.ESAPI, arguments.context & ": Input credit card required", "Input credit card required: context=" & arguments.context & ", input=" & arguments.input, arguments.context ));
	    }

	    var canonical = variables.ccrule.getValid( arguments.context, arguments.input );

		if( !validCreditCardFormat(canonical)) {
			raiseException(new ValidationException( variables.ESAPI, arguments.context & ": Invalid credit card input", "Invalid credit card input: context=" & arguments.context, arguments.context ));
		}

		return canonical;
	}

	/**
	 * Performs additional validation on the card nummber.
	 * This implementation performs Luhn algorithm checking
	 * @param ccNum number to be validated
	 * @return true if the ccNum passes the Luhn Algorithm
	 */
	private boolean function validCreditCardFormat(required string ccNum) {

	    var digitsOnly = reReplace(arguments.ccNum, "[^0-9]", "", "all");

		var sum = 0;
		var digit = 0;
		var addend = 0;
		var timesTwo = false;

		for (var i = len(digitsOnly); i > 0; i--) {
			// guaranteed to be an int
			digit = mid(digitsOnly, i, 1);
			if (timesTwo) {
				addend = digit * 2;
				if (addend > 9) {
					addend -= 9;
				}
			} else {
				addend = digit;
			}
			sum += addend;
			timesTwo = !timesTwo;
		}

		return sum % 10 == 0;
	}

	public string function sanitize( required string context, required input ) {
		return whitelist( arguments.input, variables.encoder.CHAR_DIGITS );
	}

	/**
	 * @param ccrule the ccrule to set
	 */
	public void function setStringValidatorRule(required StringValidationRule ccrule) {
		variables.ccrule = arguments.ccrule;
	}

	/**
	 * @return the ccrule
	 */
	public StringValidationRule function getStringValidatorRule() {
		return variables.ccrule;
	}

	/**
	 * @param maxCardLength the maxCardLength to set
	 */
	public void function setMaxCardLength(required numeric maxCardLength) {
		this.maxCardLength = arguments.maxCardLength;
	}

	/**
	 * @return the maxCardLength
	 */
	public numeric function getMaxCardLength() {
		return variables.maxCardLength;
	}

}
