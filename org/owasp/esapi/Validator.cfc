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
 * The Validator interface defines a set of methods for canonicalizing and
 * validating untrusted input. Implementors should feel free to extend this
 * interface to accommodate their own data formats. Rather than throw exceptions,
 * this interface returns boolean results because not all validation problems
 * are security issues. Boolean returns allow developers to handle both valid
 * and invalid results more cleanly than exceptions.
 * <P>
 * Implementations must adopt a "whitelist" approach to validation where a
 * specific pattern or character set is matched. "Blacklist" approaches that
 * attempt to identify the invalid or disallowed characters are much more likely
 * to allow a bypass with encoding or other tricks.
 */
interface {

	public void function addRule(required org.owasp.esapi.ValidationRule rule);

	public function getRule(required string name);

	/**
	 * Calls isValidInput and returns true if no exceptions are thrown.
	 */
	public boolean function isValidInput(required string context, required input, required string type, required numeric maxLength, required boolean allowNull, boolean canonicalize, struct errors);

	/**
	 * Returns validated input as a String with optional canonicalization. Invalid input will generate a descriptive ValidationException,
	 * and input that is clearly an attack will generate a descriptive IntrusionException.
	 *
	 * @param context
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input
	 * 		The actual user input data to validate.
	 * @param type
	 * 		The regular expression name that maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength
	 * 		The maximum post-canonicalized String length allowed.
	 * @param allowNull
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param canonicalize
	 *      If canonicalize is true then input will be canonicalized before validation
	 *
	 * @return The canonicalized user input.
	 *
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	public function getValidInput(required string context, required input, required string type, required numeric maxLength, required boolean allowNull, boolean canonicalize, struct errors);

	/**
	 * Calls isValidDate and returns true if no exceptions are thrown.
	 */
	public boolean function isValidDate(required string context, required input, required format, required boolean allowNull, struct errors);

	/**
	 * Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 * @param context
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input
	 * 		The actual user input data to validate.
	 * @param format
	 * 		Required formatting of date inputted.
	 * @param allowNull
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 *
	 * @return A valid date as a Date
	 *
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	public function getValidDate(required string context, required input, required format, required boolean allowNull, struct errors);

	/**
	 * Calls getValidSafeHTML and returns true if no exceptions are thrown.
	 */
	public boolean function isValidSafeHTML(required string context, required input, required numeric maxLength, required boolean allowNull, struct errors);

	/**
	 * Returns canonicalized and validated "safe" HTML that does not contain unwanted scripts in the body, attributes, CSS, URLs, or anywhere else.
	 * Implementors should reference the OWASP AntiSamy project for ideas
	 * on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.
	 *
	 * @param context
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input
	 * 		The actual user input data to validate.
	 * @param maxLength
	 * 		The maximum String length allowed.
	 * @param allowNull
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 *
	 * @return Valid safe HTML
	 *
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	public function getValidSafeHTML(required string context, required input, required numeric maxLength, required boolean allowNull, struct errors);

	/**
	 * Calls getValidCreditCard and returns true if no exceptions are thrown.
	 */
	public boolean function isValidCreditCard(required string context, required input, required boolean allowNull, struct errors);

	/**
	 * Returns a canonicalized and validated credit card number as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 * @param context
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input
	 * 		The actual user input data to validate.
	 * @param allowNull
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 *
	 * @return A valid credit card number
	 *
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	public string function getValidCreditCard(required string context, required input, required boolean allowNull, struct errors);

	/**
	 * Calls getValidDirectoryPath and returns true if no exceptions are thrown.
	 */
	public boolean function isValidDirectoryPath(required string context, required input, required parent, required boolean allowNull, struct errors);

	/**
	 * Returns a canonicalized and validated directory path as a String, provided that the input
	 * maps to an existing directory that is an existing subdirectory (at any level) of the specified parent. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 *
	 * @param context
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input
	 * 		The actual input data to validate.
	 * @param allowNull
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 *
	 * @return A valid directory path
	 *
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	public string function getValidDirectoryPath(required string context, required input, required parent, required boolean allowNull, struct errors);

	/**
	 * Calls getValidFileName with the default list of allowedExtensions
	 */
	public boolean function isValidFileName(required string context, required input, required array allowedExtensions, required boolean allowNull, struct errors);

	/**
	 * Returns a canonicalized and validated file name as a String. Implementors should check for allowed file extensions here, as well as allowed file name characters, as declared in "ESAPI.properties". Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 * @param context
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     * 		The actual input data to validate.
     * @param allowNull
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     *
     * @return A valid file name
     *
     * @throws ValidationException
     * @throws IntrusionException
	 */
	public string function getValidFileName(required string context, required input, required array allowedExtensions, required boolean allowNull, struct errors);

	/**
	 * Calls getValidNumber and returns true if no exceptions are thrown.
	 */
	public boolean function isValidNumber(required string context, required input, required numeric minValue, required numeric maxValue, required boolean allowNull, struct errors);

	/**
	 * Returns a validated number as a double within the range of minValue to maxValue. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 * @param context
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     * 		The actual input data to validate.
     * @param allowNull
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * @param minValue
     * 		Lowest legal value for input.
     * @param maxValue
     * 		Highest legal value for input.
     *
     * @return A validated number as a double.
     *
     * @throws ValidationException
     * @throws IntrusionException
	 */
	public function getValidNumber(required string context, required input, required numeric minValue, required numeric maxValue, required boolean allowNull, struct errors);

	/**
	 * Calls getValidInteger and returns true if no exceptions are thrown.
	 */
	public boolean function isValidInteger(required string context, required input, required numeric minValue, required numeric maxValue, required boolean allowNull, struct errors);

	/**
	 * Returns a validated integer. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 * @param context
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     * 		The actual input data to validate.
     * @param allowNull
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * @param minValue
     * 		Lowest legal value for input.
     * @param maxValue
     * 		Highest legal value for input.
     *
     * @return A validated number as an integer.
     *
     * @throws ValidationException
     * @throws IntrusionException
	 */
	public function getValidInteger(required string context, required input, required numeric minValue, required numeric maxValue, required boolean allowNull, struct errors);

	/**
	 * Calls getValidDouble and returns true if no exceptions are thrown.
	 */
	public boolean function isValidDouble(required string context, required input, required numeric minValue, required numeric maxValue, required boolean allowNull, struct errors);

	/**
	 * Returns a validated real number as a double. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 * @param context
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     * 		The actual input data to validate.
     * @param allowNull
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * @param minValue
     * 		Lowest legal value for input.
     * @param maxValue
     * 		Highest legal value for input.
     *
     * @return A validated real number as a double.
     *
     * @throws ValidationException
     * @throws IntrusionException
	 */
	public function getValidDouble(required string context, required input, required numeric minValue, required numeric maxValue, required boolean allowNull, struct errors);

	/**
	 * Calls getValidFileContent and returns true if no exceptions are thrown.
	 */
	public boolean function isValidFileContent(required string context, required binary input, required numeric maxBytes, required boolean allowNull, struct errors);

	/**
	 * Returns validated file content as a byte array. This is a good place to check for max file size, allowed character sets, and do virus scans.  Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 * @param context
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input
	 * 		The actual input data to validate.
	 * @param maxBytes
	 * 		The maximum number of bytes allowed in a legal file.
	 * @param allowNull
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 *
	 * @return A byte array containing valid file content.
	 *
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	public binary function getValidFileContent(required string context, required binary input, required numeric maxBytes, required boolean allowNull, struct errors);

	/**
	 * Calls getValidFileUpload and returns true if no exceptions are thrown.
	 */
	public boolean function isValidFileUpload(required string context, required string directorypath, required string filename, required parent, required binary content, required numeric maxBytes, required array allowedExtensions, required boolean allowNull, struct errors);

	/**
	 * Validates the filepath, filename, and content of a file. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 * @param context
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param directorypath
	 * 		The directory path of the uploaded file.
	 * @param filename
	 * 		The filename of the uploaded file
	 * @param content
	 * 		A byte array containing the content of the uploaded file.
	 * @param maxBytes
	 * 		The max number of bytes allowed for a legal file upload.
	 * @param allowNull
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 *
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	public void function assertValidFileUpload(required string context, required string directorypath, required string filename, required parent, required binary content, required numeric maxBytes, required array allowedExtensions, required boolean allowNull, struct errors);

	/**
	 * Calls getValidListItem and returns true if no exceptions are thrown.
	 */
	public boolean function isValidListItem(required string context, required input, required array list, struct errors);

	/**
	 * Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 * @param context
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input
	 * 		The value to search 'list' for.
	 * @param list
	 * 		The list to search for 'input'.
	 *
	 * @return The list item that exactly matches the canonicalized input.
	 *
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	public string function getValidListItem(required string context, required input, required array list, struct errors);

	/**
	 * Calls assertValidHTTPRequestParameterSet and returns true if no exceptions are thrown.
	 */
	public boolean function isValidHTTPRequestParameterSet(required string context, required array requiredNames, required array optionalNames, struct errors, httpRequest);

	/**
	 * Validates that the parameters in the current request contain all required parameters and only optional ones in
	 * addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 * @param context
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param required
	 * 		parameters that are required to be in HTTP request
	 * @param optional
	 * 		additional parameters that may be in HTTP request
	 *
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	public void function assertValidHTTPRequestParameterSet(required string context, required array requiredNames, required array optionalNames, struct errors, httpRequest);

	/**
	 * Calls getValidPrintable and returns true if no exceptions are thrown.
	 */
	public boolean function isValidPrintable(required string context, required input, required numeric maxLength, required boolean allowNull, struct errors);

	/**
	 * Returns canonicalized and validated printable characters as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 *  @param context
	 *  		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 *  @param input
	 *  		data to be returned as valid and printable
	 *  @param maxLength
	 *  		Maximum number of bytes stored in 'input'
	 *  @param allowNull
	 *  		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 *
	 *  @return a byte array containing only printable characters, made up of data from 'input'
	 *
	 *  @throws ValidationException
	 */
	public string function getValidPrintable(required string context, required input, required numeric maxLength, required boolean allowNull, struct errors);

	/**
	 * Calls getValidRedirectLocation and returns true if no exceptions are thrown.
	 */
	public boolean function isValidRedirectLocation(required string context, required input, required boolean allowNull, struct errors);

	/**
	 * Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 *  @param context
	 *  		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 *  @param input
	 *  		redirect location to be returned as valid, according to encoding rules set in "ESAPI.properties"
	 *  @param allowNull
	 *  		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 *
	 *  @return A canonicalized and validated redirect location, as defined in "ESAPI.properties"
	 *
	 *  @throws ValidationException
	 *  @throws IntrusionException
	 */
	public string function getValidRedirectLocation(required string context, required input, required boolean allowNull, struct errors);

	/**
	 * Reads from an input stream until end-of-line or a maximum number of
	 * characters. This method protects against the inherent denial of service
	 * attack in reading until the end of a line. If an attacker doesn't ever
	 * send a newline character, then a normal input stream reader will read
	 * until all memory is exhausted and the platform throws an OutOfMemoryError
	 * and probably terminates.
	 *
	 * @param inputStream
	 * 		The InputStream from which to read data
	 * @param maxLength
	 * 		Maximum characters allowed to be read in per line
	 *
	 * @return a String containing the current line of inputStream
	 *
	 * @throws ValidationException
	 */
	public string function safeReadLine(required input, required numeric max);

}
