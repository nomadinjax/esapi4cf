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
 * RuntimeException is the superclass of those exceptions that can be thrown during the normal operation of the Java Virtual Machine.
 * A method is not required to declare in its throws clause any subclasses of RuntimeException that might be thrown during the execution of the method but not caught.
 */
component extends="Exception" {

	/**
	 * Constructs a new runtime exception with the specified detail message and cause.
	 * Note that the detail message associated with cause is not automatically incorporated in this runtime exception's detail message.
	 *
	 * @param message the detail message (which is saved for later retrieval by the Throwable.getMessage() method).
	 * @param cause the cause (which is saved for later retrieval by the Throwable.getCause() method). (A null value is permitted, and indicates that the cause is nonexistent or unknown.)
	 */
	
	public RuntimeException function init(String message, cause) {
		return super.init(argumentCollection=arguments);
	}
	
}