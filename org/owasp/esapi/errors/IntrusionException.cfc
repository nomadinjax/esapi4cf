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
 * An IntrusionException should be thrown anytime an error condition arises that is likely to be the result of an attack
 * in progress. IntrusionExceptions are handled specially by the IntrusionDetector, which is equipped to respond by
 * either specially logging the event, logging out the current user, or invalidating the current user's account.
 * <P>
 * Unlike other exceptions in the ESAPI, the IntrusionException is a RuntimeException so that it can be thrown from
 * anywhere and will not require a lot of special exception handling.
 */
component extends="org.owasp.esapi.util.RuntimeException" {

	property type="string" name="logMessage";

	variables.ESAPI = "";

    /** The logger. */
    variables.logger = "";

    variables.logMessage = "";

    /**
     * Creates a new instance of IntrusionException.
     *
     * @param userMessage
     *            the message to display to users
     * @param logMessage
	 * 			  the message logged
     * @param cause
     *			  the cause
     */
    public IntrusionException function init(required org.owasp.esapi.ESAPI ESAPI, required string userMessage, required string logMessage, cause) {
    	variables.ESAPI = arguments.ESAPI;
    	variables.logger = variables.ESAPI.getLogger("IntrusionException");

        variables.logMessage = arguments.logMessage;

    	if (structKeyExists(arguments, "cause")) {
    		super.init(arguments.userMessage, arguments.cause);
	        variables.logger.error(variables.Logger.SECURITY_FAILURE, "INTRUSION - " & variables.logMessage, arguments.cause);
    	}
    	else {
       		super.init(arguments.userMessage);
	        variables.logger.error(variables.Logger.SECURITY_FAILURE, "INTRUSION - " & variables.logMessage);
       	}

       	return this;
    }

    /**
     * Returns a String containing a message that is safe to display to users
     *
     * @return a String containing a message that is safe to display to users
     */
    public string function getUserMessage() {
        return getMessage();
    }

    /**
     * Returns a String that is safe to display in logs, but probably not to users
     *
     * @return a String containing a message that is safe to display in logs, but probably not to users
     */
    public string function getLogMessage() {
        return variables.logMessage;
    }

}
