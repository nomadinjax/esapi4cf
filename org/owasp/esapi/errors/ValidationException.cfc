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
 * A ValidationException should be thrown to indicate that the data provided by
 * the user or from some other external source does not match the validation
 * rules that have been specified for that data.
 */
component extends="EnterpriseSecurityException" {

	property type="string" name="context";

	/** The UI reference that caused this ValidationException */
	variables.context = "";

    /**
     * Instantiates a new ValidationException.
     *
     * @param userMessage
     *            the message to display to users
     * @param logMessage
	 * 			  the message logged
     * @param cause
     *            the cause
     * @param context
     *            the source that caused this exception
     */
    public ValidationException function init(required org.owasp.esapi.ESAPI ESAPI, required string userMessage, required string logMessage, string context, cause) {
        if (structKeyExists(arguments, "cause")) {
        	super.init(arguments.ESAPI, arguments.userMessage, arguments.logMessage, arguments.cause);
        }
        else {
        	super.init(arguments.ESAPI, arguments.userMessage, arguments.logMessage);
        }

        if (structKeyExists(arguments, "context")) {
    		setContext(arguments.context);
    	}

    	return this;
    }

	/**
	 * Returns the UI reference that caused this ValidationException
	 *
	 * @return context, the source that caused the exception, stored as a string
	 */
	public string function getContext() {
		return variables.context;
	}

	/**
	 * Set's the UI reference that caused this ValidationException
	 *
	 * @param context
	 * 			the context to set, passed as a String
	 */
	public void function setContext(required string context) {
		variables.context = arguments.context;
	}

}
