/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Damon Miller
 * @created 2011
 */
/**
 * Reference implementation of the Validator interface. This implementation
 * relies on the ESAPI Encoder, Java Pattern (regex), Date,
 * and several other classes to provide basic validation functions. This library
 * has a heavy emphasis on whitelist validation and canonicalization.
 */
component DefaultValidator extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.Validator" {

	instance.ESAPI = "";

	/* A map of validation rules */
	instance.rules = {};

	/* The encoder to use for canonicalization */
	instance.encoder = "";

	/* The encoder to use for file system */
	instance.fileValidator = "";
 
	/**
	 * Construct a new DefaultValidator that will use the specified
	 * Encoder for canonicalization.
     *
     * @param encoder
     */
     
	public cfesapi.org.owasp.esapi.Validator function init(required cfesapi.org.owasp.esapi.ESAPI ESAPI, cfesapi.org.owasp.esapi.Encoder encoder, boolean nested=false) {
		instance.ESAPI = arguments.ESAPI;

		if (structKeyExists(arguments, "encoder")) {
			instance.encoder = arguments.encoder;
		}
		else {
			instance.encoder = instance.ESAPI.encoder();
		}

		// FIXME: are we able to identify the caller to determine whether this is nested rather than passing a stupid argument ???
		if (!arguments.nested) {
			/* Initialize file validator with an appropriate set of codecs */
			local.list = [];
			local.list.add( "HTMLEntityCodec" );
			local.list.add( "PercentCodec" );
			local.fileEncoder = new DefaultEncoder( instance.ESAPI, local.list );
			instance.fileValidator = new DefaultValidator( instance.ESAPI, local.fileEncoder, true );	// this is only call where nested arg will be true
		}

    	return this;
	}

	/**
	 * Add a validation rule to the registry using the "type name" of the rule as the key.
	 */
	 
	public void function addRule(required cfesapi.org.owasp.esapi.ValidationRule rule) {
		instance.rules[arguments.rule.getTypeName()] = arguments.rule;
	}

	/**
	 * Get a validation rule from the registry with the "type name" of the rule as the key.
	 */
	 
	public cfesapi.org.owasp.esapi.ValidationRule function getRule(required String name) {
		if (structKeyExists(instance.rules, arguments.name)) {
			return instance.rules[arguments.name];
		}
		return new cfesapi.org.owasp.esapi.reference.validation.StringValidationRule(instance.ESAPI, "");
	}

	/**
	 * Returns true if data received from browser is valid. Double encoding is treated as an attack. The
	 * default encoder supports html encoding, URL encoding, and javascript escaping. Input is canonicalized
	 * by default before validation.
	 *
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name while maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized String length allowed.
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @return The canonicalized user input.
	 * @throws IntrusionException
	 */
	 
	public boolean function isValidInput(required String context, required String input, required String type, required numeric maxLength, required boolean allowNull, boolean canonicalize=true, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		try {
			getValidInput( arguments.context, arguments.input, arguments.type, arguments.maxLength, arguments.allowNull, arguments.canonicalize);
			return true;
		} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errorList")) {
				arguments.errorList.addError( arguments.context, e );
			}
			return false;
		}
	}

	/**
	 * Validates data received from the browser and returns a safe version.
	 * Double encoding is treated as an attack. The default encoder supports
	 * html encoding, URL encoding, and javascript escaping. Input is
	 * canonicalized by default before validation.
	 *
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name which maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized String length allowed.
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @return The canonicalized user input.
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	 
	public String function getValidInput(required String context, required String input, required String type, required numeric maxLength, required boolean allowNull, boolean canonicalize=true, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			try {
				return getValidInput(arguments.context, arguments.input, arguments.type, arguments.maxLength, arguments.allowNull, arguments.canonicalize);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}
			return "";
		}

		local.rvr = new cfesapi.org.owasp.esapi.reference.validation.StringValidationRule( instance.ESAPI, arguments.type, instance.encoder );
		local.p = instance.ESAPI.securityConfiguration().getValidationPattern( arguments.type );
		if ( !isNull(local.p) ) {
			local.rvr.addWhitelistPattern( local.p );
		} else {
            // Issue 232 - Specify requested type in exception message - CS
			throwError(newJava("java.lang.IllegalArgumentException").init("The selected type [" & arguments.type & "] was not set via the ESAPI validation configuration"));
		}
		local.rvr.setMaximumLength(arguments.maxLength);
		local.rvr.setAllowNull(arguments.allowNull);
		local.rvr.setValidateInputAndCanonical(arguments.canonicalize);
		return local.rvr.getValid(arguments.context, arguments.input);
	}

	/**
	 * {@inheritDoc}
	 */
	 
	public boolean function isValidDate(required String context, required String input, required format, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		try {
			getValidDate( arguments.context, arguments.input, arguments.format, arguments.allowNull);
			return true;
		} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errorList")) {
				arguments.errorList.addError( arguments.context, e );
			}
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	 
	public String function getValidDate(required String context, required String input, required format, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			try {
				return getValidDate(arguments.context, arguments.input, arguments.format, arguments.allowNull);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}
			// error has been added to list, so return null
			return "";
		}

		local.dvr = new cfesapi.org.owasp.esapi.reference.validation.DateValidationRule( instance.ESAPI, "SimpleDate", instance.encoder, arguments.format);
		local.dvr.setAllowNull(arguments.allowNull);
		return local.dvr.getValid(arguments.context, arguments.input);
	}

	/**
	 * {@inheritDoc}
	 */
	 
	public boolean function isValidSafeHTML(required String context, required String input, required numeric maxLength, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		try {
			getValidSafeHTML( arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
			return true;
		} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errorList")) {
				arguments.errorList.addError( arguments.context, e );
			}
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	 
	public String function getValidSafeHTML(required String context, required String input, required numeric maxLength, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			try {
				return getValidSafeHTML(arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}

			return "";
		}

		local.hvr = new cfesapi.org.owasp.esapi.reference.validation.HTMLValidationRule( instance.ESAPI, "safehtml", instance.encoder );
		local.hvr.setMaximumLength(arguments.maxLength);
		local.hvr.setAllowNull(arguments.allowNull);
		local.hvr.setValidateInputAndCanonical(false);
		return local.hvr.getValid(arguments.context, arguments.input);
	}

	/**
	 * {@inheritDoc}
	 */
	 
	public boolean function isValidCreditCard(required String context, required String input, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		try {
			getValidCreditCard( arguments.context, arguments.input, arguments.allowNull);
			return true;
		} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errorList")) {
				arguments.errorList.addError( arguments.context, e );
			}
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	 
	public String function getValidCreditCard(required String context, required String input, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			try {
				return getValidCreditCard(arguments.context, arguments.input, arguments.allowNull);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}

			return "";
		}

		local.ccvr = new cfesapi.org.owasp.esapi.reference.validation.CreditCardValidationRule( instance.ESAPI, "creditcard", instance.encoder );
		local.ccvr.setAllowNull(arguments.allowNull);
		return local.ccvr.getValid(arguments.context, arguments.input);
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	 * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	 * path (/private/etc), not the symlink (/etc).</p>
	 */
	 
	public boolean function isValidDirectoryPath(required String context, required String input, required parent, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		try {
			getValidDirectoryPath( arguments.context, arguments.input, arguments.parent, arguments.allowNull);
			return true;
		} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errorList")) {
				arguments.errorList.addError( arguments.context, e );
			}
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	 
	public String function getValidDirectoryPath(required String context, required String input, required parent, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			try {
				return getValidDirectoryPath(arguments.context, arguments.input, arguments.parent, arguments.allowNull);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}

			return "";
		}

		try {
			if (isEmpty(arguments.input)) {
				if (arguments.allowNull) return "";
       			throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input directory path required", logMessage="Input directory path required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ));
			}

			local.dir = newJava("java.io.File").init( arguments.input );

			// check dir exists and parent exists and dir is inside parent
			if ( !local.dir.exists() ) {
				throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, does not exist: context=" & arguments.context & ", input=" & arguments.input ));
			}
			if ( !local.dir.isDirectory() ) {
				throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, not a directory: context=" & arguments.context & ", input=" & arguments.input ));
			}
			if ( !arguments.parent.exists() ) {
				throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, specified parent does not exist: context=" & arguments.context & ", input=" & arguments.input & ", parent=" & arguments.parent ));
			}
			if ( !arguments.parent.isDirectory() ) {
				throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, specified parent is not a directory: context=" & arguments.context & ", input=" & arguments.input & ", parent=" & arguments.parent ));
			}
			if ( !local.dir.getCanonicalPath().startsWith(arguments.parent.getCanonicalPath() ) ) {
				throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, arguments.context & ": Invalid directory name", "Invalid directory, not inside specified parent: context=" & arguments.context & ", input=" & arguments.input & ", parent=" & arguments.parent ));
			}

			// check canonical form matches input
			local.canonicalPath = local.dir.getCanonicalPath();
			local.canonical = instance.fileValidator.getValidInput( arguments.context, local.canonicalPath, "DirectoryName", 255, false);
			if ( !local.canonical.equals( arguments.input ) ) {
				throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid directory name", logMessage="Invalid directory name does not match the canonical path: context=" & arguments.context & ", input=" & arguments.input & ", canonical=" & local.canonical, context=arguments.context ));
			}
			return local.canonical;
		} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
			throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, arguments.context & ": Invalid directory name", "Failure to validate directory path: context=" & arguments.context & ", input=" & arguments.input, e, arguments.context ));
		}
	}

	/**
	 * {@inheritDoc}
	 */
	 
	public boolean function isValidFileName(required String context, required String input, Array allowedExtensions=instance.ESAPI.securityConfiguration().getAllowedFileExtensions(), required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		try {
			getValidFileName( arguments.context, arguments.input, arguments.allowedExtensions, arguments.allowNull);
			return true;
		} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errorList")) {
				arguments.errorList.addError( arguments.context, e );
			}
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	 
	public String function getValidFileName(required String context, required String input, required Array allowedExtensions, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			try {
				return getValidFileName(arguments.context, arguments.input, arguments.allowedExtensions, arguments.allowNull);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}

			return "";
		}

		if (arguments.allowedExtensions.isEmpty()) {
			throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, "Internal Error", "getValidFileName called with an empty or null list of allowed Extensions, therefore no files can be uploaded" ));
		}

		local.canonical = "";
		// detect path manipulation
		try {
			if (isEmpty(arguments.input)) {
				if (arguments.allowNull) return "";
	   			throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input file name required", logMessage="Input required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ));
			}

			// do basic validation
	        local.canonical = newJava("java.io.File").init(arguments.input).getCanonicalFile().getName();
	        getValidInput( arguments.context, arguments.input, "FileName", 255, true );

			local.f = newJava("java.io.File").init(local.canonical);
			local.c = local.f.getCanonicalPath();
			local.cpath = local.c.substring(local.c.lastIndexOf(newJava("java.io.File").separator) + 1);

			// the path is valid if the input matches the canonical path
			if (arguments.input != local.cpath) {
				throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file name", logMessage="Invalid directory name does not match the canonical path: context=" & arguments.context & ", input=" & arguments.input & ", canonical=" & local.canonical, context=arguments.context ));
			}

		} catch (java.io.IOException e) {
			throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, arguments.context & ": Invalid file name", "Invalid file name does not exist: context=" & arguments.context & ", canonical=" & local.canonical, e, arguments.context ));
		}

		// verify extensions
		local.i = arguments.allowedExtensions.iterator();
		while (local.i.hasNext()) {
			local.ext = local.i.next();
			if (arguments.input.toLowerCase().endsWith(local.ext.toLowerCase())) {
				return local.canonical;
			}
		}
		throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file name does not have valid extension (" & arrayToList(arguments.allowedExtensions) & ")", logMessage="Invalid file name does not have valid extension (" & arrayToList(arguments.allowedExtensions) & "): context=" & arguments.context&", input=" & arguments.input, context=arguments.context ));
	}

	/**
	 * {@inheritDoc}
	 */
	 
	public boolean function isValidNumber(required String context, required String input, required numeric minValue, required numeric maxValue, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		try {
			getValidNumber(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
			return true;
		} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errorList")) {
				arguments.errorList.addError( arguments.context, e );
			}
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	 
	public String function getValidNumber(required String context, required String input, required numeric minValue, required numeric maxValue, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			try {
				return getValidNumber(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}

			return "";
		}

		local.minDoubleValue = newJava("java.lang.Double").init(arguments.minValue);
		local.maxDoubleValue = newJava("java.lang.Double").init(arguments.maxValue);
		return getValidDouble(arguments.context, arguments.input, local.minDoubleValue.doubleValue(), local.maxDoubleValue.doubleValue(), arguments.allowNull);
	}

	/**
	 * {@inheritDoc}
	 */
	 
	public boolean function isValidDouble(required String context, required String input, required numeric minValue, required numeric maxValue, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
        try {
            getValidDouble( arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull );
            return true;
        } catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errorList")) {
				arguments.errorList.addError( arguments.context, e );
			}
            return false;
        }
	}

	/**
	 * {@inheritDoc}
	 */
	 
	public String function getValidDouble(required String context, required String input, required numeric minValue, required numeric maxValue, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			try {
				return getValidDouble(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}

			return newJava("java.lang.Double").init(newJava("java.lang.Double").NaN);
		}

		local.nvr = new cfesapi.org.owasp.esapi.reference.validation.NumberValidationRule( instance.ESAPI, "number", instance.encoder, arguments.minValue, arguments.maxValue );
		local.nvr.setAllowNull(arguments.allowNull);
		return local.nvr.getValid(arguments.context, arguments.input);
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean function isValidInteger(required String context, required String input, required numeric minValue, required numeric maxValue, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		try {
			getValidInteger( arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
			return true;
		} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errorList")) {
				arguments.errorList.addError( arguments.context, e );
			}
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public String function getValidInteger(required String context, required String input, required numeric minValue, required numeric maxValue, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			try {
				return getValidInteger(arguments.context, arguments.input, arguments.minValue, arguments.maxValue, arguments.allowNull);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}
			// error has been added to list, so return original input
			return "";
		}

		local.ivr = new cfesapi.org.owasp.esapi.reference.validation.IntegerValidationRule( instance.ESAPI, "number", instance.encoder, arguments.minValue, arguments.maxValue );
		local.ivr.setAllowNull(arguments.allowNull);
		return local.ivr.getValid(arguments.context, arguments.input);
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean function isValidFileContent(required String context, required binary input, required numeric maxBytes, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		try {
			getValidFileContent( arguments.context, arguments.input, arguments.maxBytes, arguments.allowNull);
			return true;
		} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errorList")) {
				arguments.errorList.addError( arguments.context, e );
			}
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public binary function getValidFileContent(required String context, required binary input, required numeric maxBytes, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			try {
				return getValidFileContent(arguments.context, arguments.input, arguments.maxBytes, arguments.allowNull);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}
			// return empty byte array on error
			return newJava("java.lang.String").init("").getBytes();
		}

		if (isEmpty(arguments.input)) {
			if (arguments.allowNull) return "";
   			throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input required", logMessage="Input required: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ));
		}

		local.esapiMaxBytes = instance.ESAPI.securityConfiguration().getAllowedFileUploadSize();
		if (len(arguments.input) > local.esapiMaxBytes ) {
			throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file content can not exceed " & local.esapiMaxBytes & " bytes", logMessage="Exceeded ESAPI max length", context=arguments.context ));
		}
		if (len(arguments.input) > arguments.maxBytes ) {
			throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid file content can not exceed " & arguments.maxBytes & " bytes", logMessage="Exceeded maxBytes ( " & len(arguments.input) & ")", context=arguments.context ));
		}

		return arguments.input;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean function isValidFileUpload(required String context, required String filepath, required String filename, required parent, required binary content, required numeric maxBytes, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			return( isValidFileName( context=arguments.context, input=arguments.filename, allowNull=arguments.allowNull, errorList=arguments.errorList ) &&
					isValidDirectoryPath( arguments.context, arguments.filepath, arguments.parent, arguments.allowNull, arguments.errorList ) &&
					isValidFileContent( arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull, arguments.errorList ) );
		}
		else {
			return( isValidFileName( context=arguments.context, input=arguments.filename, allowNull=arguments.allowNull ) &&
					isValidDirectoryPath( arguments.context, arguments.filepath, arguments.parent, arguments.allowNull ) &&
					isValidFileContent( arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull ) );
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void function assertValidFileUpload(required String context, required String filepath, required String filename, required parent, required binary content, required numeric maxBytes, required Array allowedExtensions, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			try {
				assertValidFileUpload(arguments.context, arguments.filepath, arguments.filename, arguments.parent, arguments.content, arguments.maxBytes, arguments.allowedExtensions, arguments.allowNull);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}
		}
		else {
			getValidFileName( arguments.context, arguments.filename, arguments.allowedExtensions, arguments.allowNull );
			getValidDirectoryPath( arguments.context, arguments.filepath, arguments.parent, arguments.allowNull );
			getValidFileContent( arguments.context, arguments.content, arguments.maxBytes, arguments.allowNull );
		}
	}


	 /**
	 * {@inheritDoc}
	 *
	 * Returns true if input is a valid list item.
	 */
	public boolean function isValidListItem(required String context, required String input, required Array list, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		try {
			getValidListItem( arguments.context, arguments.input, arguments.list);
			return true;
		} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errorList")) {
				arguments.errorList.addError( arguments.context, e );
			}
			return false;
		}
	}

	/**
	 * Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 */
	public String function getValidListItem(required String context, required String input, required Array list, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			try {
				return getValidListItem(arguments.context, arguments.input, arguments.list);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}
			// error has been added to list, so return original input
			return arguments.input;
		}

		if (arguments.list.contains(arguments.input)) return arguments.input;
		throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid list item", logMessage="Invalid list item: context=" & arguments.context & ", input=" & arguments.input, context=arguments.context ));
	}

	 /**
	 * {@inheritDoc}
     */
	public boolean function isValidHTTPRequestParameterSet(required String context, required cfesapi.org.owasp.esapi.HttpServletRequest request, required Array requiredNames, required Array optionalNames, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		try {
			assertValidHTTPRequestParameterSet( arguments.context, arguments.request, arguments.requiredNames, arguments.optionalNames);
			return true;
		} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errorList")) {
				arguments.errorList.addError( arguments.context, e );
			}
			return false;
		}
	}

	/**
	 * Validates that the parameters in the current request contain all required parameters and only optional ones in
	 * addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 * Uses current HTTPRequest
	 */
	public void function assertValidHTTPRequestParameterSet(required String context, required cfesapi.org.owasp.esapi.HttpServletRequest request, required Array requiredNames, required Array optionalNames, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			try {
				assertValidHTTPRequestParameterSet(arguments.context, arguments.request, arguments.requiredNames, arguments.optionalNames);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}
		}
		
		local.actualNames = arguments.request.getParameterMap().keySet();
		
		// verify ALL required parameters are present
		local.missing = duplicate(arguments.requiredNames);
		local.missing.removeAll(local.actualNames);
		if (local.missing.size() > 0) {
			throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid HTTP request missing parameters", logMessage="Invalid HTTP request missing parameters " & arrayToList(local.missing) & ": context=" & arguments.context, context=arguments.context ));
		}
		
		// verify ONLY optional + required parameters are present
		local.extra = duplicate(local.actualNames);
		local.extra.removeAll(arguments.requiredNames);
		local.extra.removeAll(arguments.optionalNames);
		if (local.extra.size() > 0) {
			throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid HTTP request extra parameters " & local.extra, logMessage="Invalid HTTP request extra parameters " & local.extra & ": context=" & arguments.context, context=arguments.context ));
		}
	}

	/**
     * {@inheritDoc}
     *
	 * Checks that all bytes are valid ASCII characters (between 33 and 126
	 * inclusive). This implementation does no decoding. http://en.wikipedia.org/wiki/ASCII.
	 */
	public boolean function isValidPrintable(required String context, required input, required numeric maxLength, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		try {
			getValidPrintable( arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
			return true;
		} catch( cfesapi.org.owasp.esapi.errors.ValidationException e ) {
			if (structKeyExists(arguments, "errorList")) {
				arguments.errorList.addError( arguments.context, e );
			}
			return false;
		}
	}

	/**
	 * Returns canonicalized and validated printable characters as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
     *
     * @throws IntrusionException
     */
	public String function getValidPrintable(required String context, required input, required numeric maxLength, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			try {
				return getValidPrintable(arguments.context, arguments.input, arguments.maxLength, arguments.allowNull);
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
				arguments.errorList.addError(arguments.context, e);
			}
			// error has been added to list, so return original input
			return arguments.input;
		}

		if (isSimpleValue(arguments.input)) {
			try {
	    		local.canonical = instance.encoder.canonicalize(arguments.input);
	    		return newJava("java.lang.String").init( getValidPrintable( arguments.context, local.canonical.toCharArray(), arguments.maxLength, arguments.allowNull) );
			    //TODO - changed this to base Exception since we no longer need EncodingException
		    	//TODO - this is a bit lame: we need to re-think this function.
			} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
		        throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(instance.ESAPI, arguments.context & ": Invalid printable input", "Invalid encoding of printable input, context=" & arguments.context & ", input=" & arguments.input, e, arguments.context));
		    }
		}
		else if (isArray(arguments.input)) {
			if (isEmpty(arguments.input)) {
				if (arguments.allowNull) return "";
	   			throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input bytes required", logMessage="Input bytes required: HTTP request is null", context=arguments.context ));
			}

			if (arrayLen(arguments.input) > arguments.maxLength) {
				throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Input bytes can not exceed " & arguments.maxLength & " bytes", logMessage="Input exceeds maximum allowed length of " & arguments.maxLength & " by " & (arguments.input.length-arguments.maxLength) & " bytes: context=" & arguments.context & ", input=" & arrayToList(arguments.input, ""), context=arguments.context));
			}

			for (local.i = 1; local.i <= arrayLen(arguments.input); local.i++) {
				local.input = arguments.input[local.i];
				if (!isNumeric(local.input)) {
					local.input = asc(local.input);
				}
				if (local.input <= inputBaseN("20", 16) || local.input >= inputBaseN("7E", 16) ) {
					throwError(new cfesapi.org.owasp.esapi.errors.ValidationException(ESAPI=instance.ESAPI, userMessage=arguments.context & ": Invalid input bytes: context=" & arguments.context, logMessage="Invalid non-ASCII input bytes, context=" & arguments.context & ", input=" & arrayToList(arguments.input, ""), context=arguments.context));
				}
			}
			return arguments.input;
		}
	}

	/**
	 * Returns true if input is a valid redirect location.
	 */
	public boolean function isValidRedirectLocation(required String context, required String input, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		if (structKeyExists(arguments, "errorList")) {
			return instance.ESAPI.validator().isValidInput( arguments.context, arguments.input, "Redirect", 512, arguments.allowNull, arguments.errorList);
		}
		else {
			return instance.ESAPI.validator().isValidInput( arguments.context, arguments.input, "Redirect", 512, arguments.allowNull);
		}
	}

	/**
	 * Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 */
	public String function getValidRedirectLocation(required String context, required String input, required boolean allowNull, cfesapi.org.owasp.esapi.ValidationErrorList errorList) {
		try {
			return instance.ESAPI.validator().getValidInput( arguments.context, arguments.input, "Redirect", 512, arguments.allowNull);
		} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
			arguments.errorList.addError(arguments.context, e);
		}
		// error has been added to list, so return original input
		return arguments.input;
	}

	/**
     * {@inheritDoc}
     *
	 * This implementation reads until a newline or the specified number of
	 * characters.
     *
     * @param in
     * @param max
     */
	public String function safeReadLine(required inputStream, required numeric maxLength) {
		if (arguments.maxLength <= 0) {
			throwError(new cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException(instance.ESAPI, "Invalid input", "Invalid readline. Must read a positive number of bytes from the stream"));
		}

		local.sb = newJava("java.lang.StringBuilder").init();
		local.count = 0;

		try {
			while (true) {
				local.c = arguments.inputStream.read();
				if ( local.c == -1 ) {
					if (local.sb.length() == 0) {
						return;
					}
					break;
				}
				if (local.c == 13 || local.c == 10) {
					break;
				}
				local.count++;
				if (local.count > arguments.maxLength) {
					throwError(new cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException(instance.ESAPI, "Invalid input", "Invalid readLine. Read more than maximum characters allowed (" & arguments.maxLength & ")"));
				}
				local.sb.append(chr(local.c));
			}
			return local.sb.toString();
		} catch (java.lang.IOException e) {
			throwError(new cfesapi.org.owasp.esapi.errors.ValidationAvailabilityException(instance.ESAPI, "Invalid input", "Invalid readLine. Problem reading from input stream", e));
		}
	}

	/**
	 * Helper function to check if a String is empty
	 * Helper function to check if a byte array is empty
	 * Helper function to check if a char array is empty
	 *
	 * @param input string input value
	 * @return boolean response if input is empty or not
	 */
	private boolean function isEmpty(required input) {
		if (isSimpleValue(arguments.input)) {
			return (arguments.input=="" || arguments.input.trim().length() == 0);
		}
		else if (isBinary(arguments.input)) {
			return (arrayLen(arguments.input) == 0);
		}
		else if (isArray(arguments.input)) {
			return (arrayLen(arguments.input) == 0);
		}
	}

}
