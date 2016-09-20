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
import "org.owasp.esapi.errors.ValidationAvailabilityException";
import "org.owasp.esapi.reference.validation.DateValidationRule";
import "org.owasp.esapi.reference.validation.CreditCardValidationRule";
import "org.owasp.esapi.reference.validation.HTMLValidationRule";
import "org.owasp.esapi.reference.validation.IntegerValidationRule";
import "org.owasp.esapi.reference.validation.NumberValidationRule";
import "org.owasp.esapi.reference.validation.StringValidationRule";

/**
 * Reference implementation of the Validator interface. This implementation
 * relies on the ESAPI Encoder, Java Pattern (regex), Date,
 * and several other classes to provide basic validation functions. This library
 * has a heavy emphasis on whitelist validation and canonicalization.
 */
component implements="org.owasp.esapi.Validator" extends="org.owasp.esapi.util.Object" {

	variables.ESAPI = "";

	/** A map of validation rules */
	variables.rules = {};

	/** The encoder to use for canonicalization */
	variables.encoder = "";

	/** The encoder to use for file system */
	variables.fileValidator = "";

	private org.owasp.esapi.Validator function getFileValidator() {
		if (!isInstanceOf(variables.fileValidator, "org.owasp.esapi.Validator")) {
			/** Initialize file validator with an appropriate set of codecs */
			var list = [];
			arrayAppend(list, "HTMLEntityCodec");
			arrayAppend(list, "PercentCodec");
			var fileEncoder = new Encoder(variables.ESAPI, list);
			variables.fileValidator = new Validator(variables.ESAPI, fileEncoder);
		}
		return variables.fileValidator;
	}

	/**
	 * Construct a new DefaultValidator that will use the specified
	 * Encoder for canonicalization.
     *
     * @param encoder
     */
	public org.owasp.esapi.Validator function init(required org.owasp.esapi.ESAPI ESAPI, org.owasp.esapi.Encoder encoder=arguments.ESAPI.encoder()) {
		variables.ESAPI = arguments.ESAPI;
	    variables.encoder = arguments.encoder;

	    return this;
	}

	/**
	 * Add a validation rule to the registry using the "type name" of the rule as the key.
	 */
	public void function addRule(required org.owasp.esapi.ValidationRule rule) {
		variables.rules[arguments.rule.getTypeName()] = arguments.rule;
	}

	/**
	 * Get a validation rule from the registry with the "type name" of the rule as the key.
	 */
	public function getRule(required string name) {
		if (structKeyExists(variables.rules, arguments.name)) {
			return variables.rules[arguments.name];
		}
		return "";
	}


	/**
	 * Returns true if data received from browser is valid. Double encoding is treated as an attack. The
	 * default encoder supports html encoding, URL encoding, and javascript escaping. Input is canonicalized
	 * by default before validation.
	 *
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name while maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized string length allowed.
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty string will throw a ValidationException.
	 * @return The canonicalized user input.
	 * @throws IntrusionException
	 */
    public boolean function isValidInput(required string context, required input, required string type, required numeric maxLength, required boolean allowNull, boolean canonicalize=true, struct errors) {
		try {
			getValidInput( arguments.context, arguments.input, arguments.type, arguments.maxLength, arguments.allowNull, arguments.canonicalize);
			return true;
		}
		catch(org.owasp.esapi.errors.ValidationException e) {
			if (structKeyExists(arguments, "errors")) {
				arguments.errors[arguments.context] = e;
			}
			return false;
		}
	}

	/**
	 * Validates data received from the browser and returns a safe version. Only
	 * URL encoding is supported. Double encoding is treated as an attack.
	 *
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name while maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized string length allowed
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty string will throw a ValidationException.
	 * @param canonicalize If canonicalize is true then input will be canonicalized before validation
	 * @param errors If ValidationException is thrown, then add to error list instead of throwing out to caller
	 * @return The user input, may be canonicalized if canonicalize argument is true
	 * @throws IntrusionException
	 */
	public function getValidInput(required string context, required input, required string type, required numeric maxLength, required boolean allowNull, boolean canonicalize=true, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			try {
				return getValidInput(arguments.context, arguments.input, arguments.type, arguments.maxLength, arguments.allowNull, arguments.canonicalize);
			} catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
			if (isNull(arguments.input)) return;
			return arguments.input;
		}
		else {
			var rvr = new StringValidationRule( variables.ESAPI, arguments.type, variables.encoder );
			var p = variables.ESAPI.securityConfiguration().getValidationPattern( arguments.type );
			if ( !isNull(p) ) {
				rvr.addWhitelistPattern( p );
			} else {
	            // Issue 232 - Specify requested type in exception message - CS
				throws(createObject("java", "java.lang.IllegalArgumentException").init("The selected type [" & arguments.type & "] was not set via the ESAPI validation configuration"));
			}
			rvr.setMaximumLength(arguments.maxLength);
			rvr.setAllowNull(arguments.allowNull);
			rvr.setValidateInputAndCanonical(arguments.canonicalize);
			return rvr.getValid(arguments.context, arguments.input);
		}
	}

	public boolean function isValidDate(required string context, required input, required format, required boolean allowNull, struct errors) {
		try {
			getValidDate( arguments.context, arguments.input, arguments.format, arguments.allowNull);
			return true;
		} catch(org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errors")) {
            	arguments.errors[arguments.context] = e;
            }
			return false;
		}
	}

	public function getValidDate(required string context, required input, required format, required boolean allowNull, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			try {
				return getValidDate(arguments.context, arguments.input, arguments.format, arguments.allowNull);
			} catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
			// error has been added to list, so return input
			if (isNull(arguments.input)) return;
			return arguments.input;
		}
		else {
			var dvr = new DateValidationRule( variables.ESAPI, "SimpleDate", variables.encoder, arguments.format);
			dvr.setAllowNull(arguments.allowNull);
			return dvr.getValid(arguments.context, arguments.input);
		}
	}

	public boolean function isValidSafeHTML(required string context, required input, required numeric maxLength, required boolean allowNull, struct errors) {
		try {
			getValidSafeHTML( arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
			return true;
		} catch(org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errors")) {
            	arguments.errors[arguments.context] = e;
            }
			return false;
		}
	}

	/**
	 * This implementation relies on the OWASP AntiSamy project.
	 */
	public function getValidSafeHTML(required string context, required input, required numeric maxLength, required boolean allowNull, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			try {
				return getValidSafeHTML(arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
			} catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
			if (isNull(arguments.input)) return;
			return arguments.input;
		}
		else {
			var hvr = new HTMLValidationRule( variables.ESAPI, "safehtml", variables.encoder );
			hvr.setMaximumLength(arguments.maxLength);
			hvr.setAllowNull(arguments.allowNull);
			hvr.setValidateInputAndCanonical(false);
			return hvr.getValid(arguments.context, arguments.input);
		}
	}

	public boolean function isValidCreditCard(required string context, required input, required boolean allowNull, struct errors) {
		try {
			getValidCreditCard( arguments.context, arguments.input, arguments.allowNull);
			return true;
		} catch(org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errors")) {
            	arguments.errors[arguments.context] = e;
            }
			return false;
		}
	}

	public string function getValidCreditCard(required string context, required input, required boolean allowNull, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			try {
				return getValidCreditCard(arguments.context, arguments.input, arguments.allowNull);
			} catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
			if (isNull(arguments.input)) return;
			return arguments.input;
		}
		else {
			var ccvr = new CreditCardValidationRule( variables.ESAPI, "creditcard", variables.encoder );
			ccvr.setAllowNull(arguments.allowNull);
			return ccvr.getValid(arguments.context, arguments.input);
		}
	}

    /**
	 * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	 * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	 * path (/private/etc), not the symlink (/etc).</p>
	 */
	public boolean function isValidDirectoryPath(required string context, required input, required parent, required boolean allowNull, struct errors) {
		try {
			getValidDirectoryPath( arguments.context, arguments.input, arguments.parent, arguments.allowNull);
			return true;
		} catch(org.owasp.esapi.errors.ValidationException e ) {
            if (structKeyExists(arguments, "errors")) {
            	arguments.errors[arguments.context] = e;
            }
			return false;
		}
	}

	public string function getValidDirectoryPath(required string context, required input, required parent, required boolean allowNull, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			try {
				return getValidDirectoryPath(arguments.context, arguments.input, arguments.parent, arguments.allowNull);
			} catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
			if (isNull(arguments.input)) return;
			return arguments.input;
		}
		else {
			try {
				if (isEmpty(arguments.input)) {
					if (arguments.allowNull) return;
	       			throws(new ValidationException(variables.ESAPI, arguments.context & ": Input directory path required", "Input directory path required: context=" & arguments.context & ", input=" & arguments.input, arguments.context ));
				}

				// canonicalPath never has trailing slash so remove it from input if it is not root so the paths will match
				if (listLen(arguments.input, "\") > 1 && right(arguments.input, 1) == "\") {
					arguments.input = left(arguments.input, len(arguments.input)-1);
				}

				var dir = createObject("java", "java.io.File").init( arguments.input );

				// check dir exists and parent exists and dir is inside parent
				if ( !dir.exists() ) {
					throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, does not exist: context=" & arguments.context & ", input=" & arguments.input ));
				}
				if ( !dir.isDirectory() ) {
					throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, not a directory: context=" & arguments.context & ", input=" & arguments.input ));
				}
				if ( !arguments.parent.exists() ) {
					throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, specified parent does not exist: context=" & arguments.context & ", input=" & arguments.input & ", parent=" & arguments.parent ));
				}
				if ( !arguments.parent.isDirectory() ) {
					throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, specified parent is not a directory: context=" & arguments.context & ", input=" & arguments.input & ", parent=" & arguments.parent ));
				}
				if ( !dir.getCanonicalPath().startsWith(arguments.parent.getCanonicalPath() ) ) {
					throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, not inside specified parent: context=" & arguments.context & ", input=" & arguments.input & ", parent=" & arguments.parent ));
				}

				// check canonical form matches input
				var canonicalPath = dir.getCanonicalPath();
				var canonical = getFileValidator().getValidInput( arguments.context, canonicalPath, "DirectoryName", 255, false);
				if ( !canonical.equals( arguments.input ) ) {
					throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory name does not match the canonical path: context=" & arguments.context & ", input=" & arguments.input & ", canonical=" & canonical, arguments.context ));
				}
				return canonical;
			} catch (any e) {
				throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid directory name", "Failure to validate directory path: context=" & arguments.context & ", input=" & arguments.input, arguments.context, e ));
			}
		}
	}

	public boolean function isValidFileName(required string context, required input, required array allowedExtensions, required boolean allowNull, struct errors) {
		try {
			getValidFileName( arguments.context, arguments.input, arguments.allowedExtensions, arguments.allowNull);
			return true;
		} catch(org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errors")) {
            	arguments.errors[arguments.context] = e;
            }
			return false;
		}
	}

	public string function getValidFileName(required string context, required input, required array allowedExtensions, required boolean allowNull, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			try {
				return getValidFileName(arguments.context, arguments.input, arguments.allowedExtensions, arguments.allowNull);
			} catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
			if (isNull(arguments.input)) return;
			return arguments.input;
		}
		else {
			if ((!structKeyExists(arguments, "allowedExtensions") || arrayLen(arguments.allowedExtensions) == 0)) {
				throws(new ValidationException(variables.ESAPI, "Internal Error", "getValidFileName called with an empty or null list of allowed Extensions, therefore no files can be uploaded" ));
			}

			var File = createObject("java", "java.io.File");
			var canonical = "";
			// detect path manipulation
			try {
				if (isEmpty(arguments.input)) {
					if (arguments.allowNull) return;
		   			throws(new ValidationException(variables.ESAPI, arguments.context & ": Input file name required", "Input required: context=" & arguments.context & ", input=" & arguments.input, arguments.context ));
				}

				// do basic validation
		        canonical = File.init(arguments.input).getCanonicalFile().getName();
		        getValidInput( arguments.context, arguments.input, "FileName", 255, true );

				var f = File.init(canonical);
				var c = f.getCanonicalPath();
				var cpath = c.substring(c.lastIndexOf(File.separator) + 1);

				// the path is valid if the input matches the canonical path
				if (!arguments.input.equals(cpath)) {
					throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid file name", "Invalid directory name does not match the canonical path: context=" & arguments.context & ", input=" & arguments.input & ", canonical=" & canonical, arguments.context ));
				}

			} catch (java.io.IOException e) {
				throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid file name", "Invalid file name does not exist: context=" & arguments.context & ", canonical=" & canonical, arguments.context, e ));
			}

			// verify extensions
			var i = arguments.allowedExtensions.iterator();
			while (i.hasNext()) {
				var ext = i.next();
				if (arguments.input.toLowerCase().endsWith(ext.toLowerCase())) {
					return canonical;
				}
			}
			throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid file name does not have valid extension ("&arrayToList(arguments.allowedExtensions)&")", "Invalid file name does not have valid extension ("&arrayToList(arguments.allowedExtensions)&"): context=" & arguments.context&", input=" & arguments.input, arguments.context ));
		}
	}

	public boolean function isValidNumber(required string context, required input, required numeric minValue, required numeric maxValue, required boolean allowNull, struct errors) {
		try {
			getValidNumber(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
			return true;
		} catch(org.owasp.esapi.errors.ValidationException e ) {
            if (structKeyExists(arguments, "errors")) {
            	arguments.errors[arguments.context] = e;
            }
			return false;
		}
	}

	public function getValidNumber(required string context, required input, required numeric minValue, required numeric maxValue, required boolean allowNull, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			try {
				return getValidNumber(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
			} catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
			if (isNull(arguments.input)) return;
			return arguments.input;
		}
		else {
			var Double = createObject("java", "java.lang.Double");
			var minDoubleValue = Double.init(arguments.minValue);
			var maxDoubleValue = Double.init(arguments.maxValue);
			return getValidDouble(arguments.context, arguments.input, minDoubleValue.doubleValue(), maxDoubleValue.doubleValue(), arguments.allowNull);
		}
	}

	public boolean function isValidDouble(required string context, required input, required numeric minValue, required numeric maxValue, required boolean allowNull, struct errors) {
        try {
            getValidDouble( arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull );
            return true;
        } catch(org.owasp.esapi.errors.ValidationException e ) {
            if (structKeyExists(arguments, "errors")) {
            	arguments.errors[arguments.context] = e;
            }
            return false;
        }
	}

	public function getValidDouble(required string context, required input, required numeric minValue, required numeric maxValue, required boolean allowNull, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			try {
				return getValidDouble(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
			} catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
			return arguments.input;
		}
		else {
			var nvr = new NumberValidationRule( variables.ESAPI, "number", variables.encoder, arguments.minValue, arguments.maxValue );
			nvr.setAllowNull(arguments.allowNull);
			return nvr.getValid(arguments.context, arguments.input);
		}
	}

	public boolean function isValidInteger(required string context, required input, required numeric minValue, required numeric maxValue, required boolean allowNull, struct errors) {
		try {
			getValidInteger( arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
			return true;
		} catch(org.owasp.esapi.errors.ValidationException e ) {
            if (structKeyExists(arguments, "errors")) {
            	arguments.errors[arguments.context] = e;
            }
			return false;
		}
	}

	public function getValidInteger(required string context, required input, required numeric minValue, required numeric maxValue, required boolean allowNull, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			try {
				return getValidInteger(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
			} catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
			// error has been added to list, so return original input
			if (isNull(arguments.input)) return;
			return arguments.input;
		}
		else {
			var ivr = new IntegerValidationRule( variables.ESAPI, "number", variables.encoder, arguments.minValue, arguments.maxValue );
			ivr.setAllowNull(arguments.allowNull);
			return ivr.getValid(arguments.context, arguments.input);
		}
	}

	public boolean function isValidFileContent(required string context, required binary input, required numeric maxBytes, required boolean allowNull, struct errors) {
		try {
			getValidFileContent( arguments.context, arguments.input, arguments.maxBytes, arguments.allowNull);
			return true;
		} catch(org.owasp.esapi.errors.ValidationException e ) {
            if (structKeyExists(arguments, "errors")) {
            	arguments.errors[arguments.context] = e;
            }
			return false;
		}
	}

	public binary function getValidFileContent(required string context, required binary input, required numeric maxBytes, required boolean allowNull, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			try {
				return getValidFileContent(arguments.context, arguments.input, arguments.maxBytes, arguments.allowNull);
			} catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
			// return empty byte array on error
			if (isNull(arguments.input)) return;
			return arguments.input;
		}
		else {
			if (isEmpty(arguments.input)) {
				if (arguments.allowNull) return toBinary("");
	   			throws(new ValidationException(variables.ESAPI, arguments.context & ": Input required", "Input required: context=" & arguments.context & ", input=" & arguments.input, arguments.context ));
			}

			var esapiMaxBytes = variables.ESAPI.securityConfiguration().getAllowedFileUploadSize();
			if (arrayLen(arguments.input) > esapiMaxBytes ) throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid file content can not exceed " & esapiMaxBytes & " bytes", "Exceeded ESAPI max length", arguments.context ));
			if (arrayLen(arguments.input) > arguments.maxBytes ) throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid file content can not exceed " & arguments.maxBytes & " bytes", "Exceeded maxBytes ( " & arrayLen(arguments.input) & ")", arguments.context ));

			if (isNull(arguments.input)) return;
			return arguments.input;
		}
	}

    /**
	 * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	 * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	 * path (/private/etc), not the symlink (/etc).</p>
     */
	public boolean function isValidFileUpload(required string context, required string directorypath, required string filename, required parent, required binary content, required numeric maxBytes, required array allowedExtensions, required boolean allowNull, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			return( isValidFileName( arguments.context, arguments.filename, arguments.allowedExtensions, arguments.allowNull, arguments.errors ) &&
					isValidDirectoryPath( arguments.context, arguments.directorypath, arguments.parent, arguments.allowNull, arguments.errors ) &&
					isValidFileContent( arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull, arguments.errors ) );
		}
		else {
			return( isValidFileName( arguments.context, arguments.filename, arguments.allowedExtensions, arguments.allowNull ) &&
				isValidDirectoryPath( arguments.context, arguments.directorypath, arguments.parent, arguments.allowNull ) &&
				isValidFileContent( arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull ) );
		}
	}

	public void function assertValidFileUpload(required string context, required string directorypath, required string filename, required parent, required binary content, required numeric maxBytes, required array allowedExtensions, required boolean allowNull, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			try {
				assertValidFileUpload(arguments.context, arguments.directorypath, arguments.filename, arguments.parent, arguments.content, arguments.maxBytes, arguments.allowedExtensions, arguments.allowNull);
			} catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
		}
		else {
			getValidFileName( arguments.context, arguments.filename, arguments.allowedExtensions, arguments.allowNull );
			getValidDirectoryPath( arguments.context, arguments.directorypath, arguments.parent, arguments.allowNull );
			getValidFileContent( arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull );
		}
	}

    /**
	 * Returns true if input is a valid list item.
	 */
	public boolean function isValidListItem(required string context, required input, required array list, struct errors) {
		try {
			getValidListItem( arguments.context, arguments.input, arguments.list);
			return true;
		} catch(org.owasp.esapi.errors.ValidationException e ) {
            if (structKeyExists(arguments, "errors")) {
            	arguments.errors[arguments.context] = e;
            }
			return false;
		}
	}

	/**
	 * Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
     *
     * @param errors
     */
	public string function getValidListItem(required string context, required input, required array list, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			try {
				return getValidListItem(arguments.context, arguments.input, arguments.list);
			} catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
			// error has been added to list, so return original input
			if (isNull(arguments.input)) return;
			return arguments.input;
		}
		else {
			if (arguments.list.contains(arguments.input)) return arguments.input;
			throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid list item", "Invalid list item: context=" & arguments.context & ", input=" & arguments.input, arguments.context ));
		}
	}

	public boolean function isValidHTTPRequestParameterSet(required string context, required array requiredNames, required array optionalNames, struct errors, httpRequest=variables.ESAPI.httpUtilities().getCurrentRequest()) {
		try {
			assertValidHTTPRequestParameterSet( context=arguments.context, requiredNames=arguments.requiredNames, optionalNames=arguments.optionalNames, httpRequest=arguments.httpRequest);
			return true;
		} catch(org.owasp.esapi.errors.ValidationException e ) {
            if (structKeyExists(arguments, "errors")) {
            	arguments.errors[arguments.context] = e;
            }
			return false;
		}
	}

	/**
	 * Validates that the parameters in the current request contain all required parameters and only optional ones in
	 * addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
     * @param errors
     */
	public void function assertValidHTTPRequestParameterSet(required string context, required array requiredNames, required array optionalNames, struct errors, httpRequest=variables.ESAPI.httpUtilities().getCurrentRequest()) {
		if (structKeyExists(arguments, "errors")) {
			try {
				assertValidHTTPRequestParameterSet(context=arguments.context, requiredNames=arguments.requiredNames, optionalNames=arguments.optionalNames, httpRequest=arguments.httpRequest);
			} catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
		}
		else {
			var actualNames = arguments.httpRequest.getParameterMap().keySet();

			// verify ALL required parameters are present
			var missing = duplicate(arguments.requiredNames);
			missing.removeAll(actualNames);
			if (missing.size() > 0) {
				throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid HTTP request missing parameters", "Invalid HTTP request missing parameters " & arrayToList(missing) & ": context=" & arguments.context, arguments.context ));
			}

			// verify ONLY optional & required parameters are present
			var extra = duplicate(actualNames);
			extra.removeAll(arguments.requiredNames);
			extra.removeAll(arguments.optionalNames);
			if (extra.size() > 0) {
				throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid HTTP request extra parameters " & extra, "Invalid HTTP request extra parameters " & extra & ": context=" & arguments.context, arguments.context ));
			}
		}
	}

    /**
	 * Returns true if input is valid printable ASCII characters (32-126).
	 */
	public boolean function isValidPrintable(required string context, required input, required numeric maxLength, required boolean allowNull, struct errors) {
		try {
			getValidPrintable( arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
			return true;
		} catch(org.owasp.esapi.errors.ValidationException e ) {
            if (structKeyExists(arguments, "errors")) {
            	arguments.errors[arguments.context] = e;
            }
			return false;
		}
	}

	/**
	 * Returns canonicalized and validated printable characters as a string. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
     *
     * @param errors
     * @throws IntrusionException
     */
	public string function getValidPrintable(required string context, required input, required numeric maxLength, required boolean allowNull, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			try {
				return getValidPrintable(arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
			}
			catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
			// error has been added to list, so return original input
			if (isNull(arguments.input)) return;
			return arguments.input;
		}
		else {
			var canonical = variables.encoder.canonicalize(arguments.input);

			if (isEmpty(canonical)) {
				if (arguments.allowNull) return;
	   			throws(new ValidationException(variables.ESAPI, arguments.context & ": Input bytes required", "Input bytes required: HTTP request is null", arguments.context));
			}

			if (len(canonical) > arguments.maxLength) {
				throws(new ValidationException(variables.ESAPI, arguments.context & ": Input bytes can not exceed " & arguments.maxLength & " bytes", "Input exceeds maximum allowed length of " & arguments.maxLength & " by " & (len(canonical)-arguments.maxLength) & " bytes: context=" & arguments.context & ", input=" & canonical, arguments.context));
			}

			for (var i = 1; i <= len(canonical); i++) {
				if (asc(mid(canonical, i, 1)) <= 32 || asc(mid(canonical, i, 1)) >= 126 ) {
					throws(new ValidationException(variables.ESAPI, arguments.context & ": Invalid input bytes: context=" & arguments.context, "Invalid non-ASCII input bytes, context=" & arguments.context & ", input=" & canonical, arguments.context));
				}
			}
			return canonical;
		}
	}

    /**
	 * Returns true if input is a valid redirect location.
	 */
	public boolean function isValidRedirectLocation(required string context, required input, required boolean allowNull, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			return variables.ESAPI.validator().isValidInput( arguments.context, arguments.input, "Redirect", 512, arguments.allowNull, errors);
		}
		else {
			return variables.ESAPI.validator().isValidInput( arguments.context, arguments.input, "Redirect", 512, arguments.allowNull);
		}
	}


	/**
	 * Returns a canonicalized and validated redirect location as a string. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
     *
     * @param errors
     */
	public string function getValidRedirectLocation(required string context, required input, required boolean allowNull, struct errors) {
		if (structKeyExists(arguments, "errors")) {
			try {
				return getValidRedirectLocation(arguments.context, arguments.input, arguments.allowNull);
			} catch (org.owasp.esapi.errors.ValidationException e) {
				arguments.errors[arguments.context] = e;
			}
			// error has been added to list, so return original input
			if (isNull(arguments.input)) return;
			return arguments.input;
		}
		else {
			return variables.ESAPI.validator().getValidInput(arguments.context, arguments.input, "Redirect", 512, arguments.allowNull);
		}
	}

	/**
	 * This implementation reads until a newline or the specified number of
	 * characters.
     *
     * @param in
     * @param max
     */
	public string function safeReadLine(required input, required numeric max) {
		if (arguments.max <= 0) {
			throws(new ValidationAvailabilityException(variables.ESAPI, "Invalid input", "Invalid readline. Must read a positive number of bytes from the stream"));
		}

		var sb = createObject("java", "java.lang.StringBuilder").init();
		var count = 0;

		try {
			if ( fileIsEOF(arguments.input) ) {
				if (sb.length() == 0) {
					return;
				}
				break;
			}
			var line = fileReadLine(arguments.input);
			for (var i=1; i<=len(line); i++) {
				var c = mid(line, i, 1);
				if (asc(c) == 13 || asc(c) == 10) {
					break;
				}
				count++;
				if (count > arguments.max) {
					throws(new ValidationAvailabilityException(variables.ESAPI, "Invalid input", "Invalid readLine. Read more than maximum characters allowed (" & arguments.max & ")"));
				}
				sb.append(c);
			}
			return sb.tostring();
		} catch (java.io.IOException e) {
			throws(new ValidationAvailabilityException(variables.ESAPI, "Invalid input", "Invalid readLine. Problem reading from input stream", e));
		}
	}

	/**
	 * Helper function to check if a string, byte array, or char array is empty
	 *
	 * @param input string input value
	 * @return boolean response if input is empty or not
	 */
	private boolean function isEmpty(required input) {
		if (structKeyExists(arguments, "input") && !isNull(arguments.input)) {
			if (isBinary(arguments.input)) {
				return (arrayLen(arguments.input) == 0);
			}
			else if (isArray(arguments.input)) {
				return (arrayLen(arguments.input) == 0);
			}
			else if (isSimpleValue(arguments.input)) {
				return (len(trim(arguments.input)) == 0);
			}
		}
		else {
			return true;
		}
	}

}