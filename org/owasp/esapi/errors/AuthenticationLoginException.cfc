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
 * An AuthenticationException should be thrown when anything goes wrong during
 * login or logout. They are also appropriate for any problems related to
 * identity management.
 */
component AuthenticationLoginException extends="AuthenticationException" {

	/**
	 * Instantiates a new authentication exception.
	 * 
	 * @param userMessage the message displayed to the user
	 * @param logMessage the message logged
	 * @param cause the cause
	 */
	
	public AuthenticationLoginException function init(required cfesapi.org.owasp.esapi.ESAPI ESAPI, 
	                                                  String userMessage,
	                                                  String logMessage,cause) {
		super.init(argumentCollection=arguments);
		return this;
	}
	
}