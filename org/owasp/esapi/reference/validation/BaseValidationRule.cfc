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

/**
 * A ValidationRule performs syntax and possibly semantic validation of a single
 * piece of data from an untrusted source.
 */
component implements="org.owasp.esapi.ValidationRule" extends="org.owasp.esapi.util.Object" {

	variables.typeName = "";
	variables.allowNull = false;
	variables.encoder = "";

	public BaseValidationRule function init(required org.owasp.esapi.ESAPI ESAPI, required string typeName, org.owasp.esapi.Encoder encoder) {
		variables.ESAPI = arguments.ESAPI;

		if (!structKeyExists(arguments, "encoder")) {
			arguments.encoder = variables.ESAPI.encoder();
		}

		setEncoder(arguments.encoder);
		setTypeName(arguments.typeName);

		return this;
	}

	public void function setAllowNull(required boolean flag) {
		variables.allowNull = arguments.flag;
	}

	public string function getTypeName() {
		return variables.typeName;
	}

	public void function setTypeName(required string typeName) {
		variables.typeName = arguments.typeName;
	}

	public void function setEncoder(required encoder) {
		variables.encoder = arguments.encoder;
	}

	public void function assertValid(required string context, required string input) {
		getValid( arguments.context, arguments.input );
	}

	public function getValid(required string context, required string input, struct errorList) {
		var valid = "";
		try {
			valid = getValid(arguments.context, arguments.input);
		} catch (org.owasp.esapi.errors.ValidationException e) {
			arguments.errorList[arguments.context] = e;
		}
		return valid;
	}

	public function getSafe(required string context, required string input) {
		var valid = "";
		try {
			valid = getValid( arguments.context, arguments.input );
		} catch ( org.owasp.esapi.errors.ValidationException e ) {
			return sanitize( arguments.context, arguments.input );
		}
		return valid;
	}

	/**
	 * The method is similar to ValidationRuile.getSafe except that it returns a
	 * harmless object that <b>may or may not have any similarity to the original
	 * input (in some cases you may not care)</b>. In most cases this should be the
	 * same as the getSafe method only instead of throwing an exception, return
	 * some default value.
	 *
	 * @param context
	 * @param input
	 * @return a parsed version of the input or a default value.
	 */
//	protected abstract Object sanitize( String context, String input );

	public boolean function isValid(required string context, required string input) {
		var valid = false;
		try {
			getValid( arguments.context, arguments.input );
			valid = true;
		} catch( org.owasp.esapi.errors.ValidationException e ) {
			valid = false;
		}

		return valid;
	}

	/**
	 * Removes characters that aren't in the whitelist from the input String.
	 * O(input.length) whitelist performance
	 * @param input String to be sanitized
	 * @param whitelist allowed characters
	 * @return input stripped of all chars that aren't in the whitelist
	 */
	public string function whitelist(required string input, required array whitelist) {
		var stripped = createObject("java", "java.lang.StringBuilder").init();
		for (var i = 1; i <= len(arguments.input); i++) {
			var c = mid(arguments.input, i, 1);
			if (arrayFind(arguments.whitelist, c)) {
				stripped.append(c);
			}
		}
		return stripped.toString();
	}

	public boolean function isAllowNull() {
		return variables.allowNull;
	}

	public org.owasp.esapi.Encoder function getEncoder() {
		return variables.encoder;
	}
}
