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
 * A ValidationException should be thrown to indicate that the data provided by
 * the user or from some other external source does not match the validation
 * rules that have been specified for that data.
 */
component ValidationException extends="EnterpriseSecurityException" {

	/** The UI reference that caused this ValidationException */
	instance.context = "";

	/**
	 * Instantiates a new ValidationException.
	 * 
	 * @param userMessage
	 *            the message to display to users
	 * @param logMessage
	 *               the message logged
	 * @param cause
	 *            the cause
	 * @param context
	 *            the source that caused this exception
	 */
	
	public ValidationException function init(required cfesapi.org.owasp.esapi.ESAPI ESAPI, String userMessage, String logMessage, cause, String context) {
		if(structKeyExists(arguments, "cause")) {
			super.init(arguments.ESAPI, arguments.userMessage, arguments.logMessage, arguments.cause);
		}
		else if(structKeyExists(arguments, "userMessage") && structKeyExists(arguments, "logMessage")) {
			super.init(arguments.ESAPI, arguments.userMessage, arguments.logMessage);
		}
		else {
			super.init(arguments.ESAPI);
		}
		if(structKeyExists(arguments, "context")) {
			setContext(arguments.context);
		}
	
		return this;
	}
	
	/**
	 * Returns the UI reference that caused this ValidationException
	 *  
	 * @return context, the source that caused the exception, stored as a string
	 */
	
	public String function getContext() {
		return instance.context;
	}
	
	/**
	 * Set's the UI reference that caused this ValidationException
	 *  
	 * @param context
	 *             the context to set, passed as a String
	 */
	
	public void function setContext(required String context) {
		instance.context = arguments.context;
	}
	
}