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
 * An IntegrityException should be thrown when a problem with the integrity of data
 * has been detected. For example, if a financial account cannot be reconciled after
 * a transaction has been performed, an integrity exception should be thrown.
 */
component IntegrityException extends="EnterpriseSecurityException" {

	/**
	 * Instantiates a new IntegrityException.
	 * 
	 * @param userMessage
	 *            the message to display to users
	 * @param logMessage
	 *               the message logged
	 * @param cause
	 *            the cause
	 */
	
	public IntegrityException function init(required cfesapi.org.owasp.esapi.ESAPI ESAPI, 
	                                        String userMessage,String logMessage, 
	                                        cause) {
		super.init(argumentCollection=arguments);
		return this;
	}
	
}