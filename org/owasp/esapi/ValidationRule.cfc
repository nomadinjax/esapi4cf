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

interface {

	/**
	 * Whether or not a valid valid can be null. getValid will throw an
	 * Exception and getSafe will return the default value if flag is set to
	 * true
	 *
	 * @param flag
	 *            whether or not null values are valid/safe
	 */
	public void function setAllowNull(required boolean flag);

	/**
	 * Programmatically supplied name for the validator
	 * @return a name, describing the validator
	 */
	public string function getTypeName();

	/**
	 * @param typeName a name, describing the validator
	 */
	public void function setTypeName(required string typeName);

	/**
	 * @param encoder the encoder to use
	 */
	public void function setEncoder(required encoder);

	/**
	 * Check if the input is valid, throw an Exception otherwise
	 */
	public void function assertValid(required string context, required string input);

	/**
	 * Get a validated value, add the errors to an existing error list
	 *
	 * @param context
	 *            for logging
	 * @param input
	 *            the value to be parsed
	 * @return a validated value
	 * @throws ValidationException
	 *             if any validation rules fail
	 */
	public function getValid(required string context, required string input, struct errorList);

	/**
	 * Try to call get valid, then call sanitize, finally return a default value
	 */
	public function getSafe(required string context, required string input);

	/**
	 * @return true if the input passes validation
	 */
	public boolean function isValid(required string context, required string input);

	/**
	 * String the input of all chars contained in the list
	 */
	public string function whitelist(required string input, required array whitelist);

}