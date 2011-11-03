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
component  {

	/* default init */
	
	public Object function init() {
		return this;
	}
	
	/* private methods */
	instance.javaCache = {};

	/**
	 * Returns a reference to the specified Java class.
	 * Internally, this stores the reference for reuse to save on the number of classes created per request.
	 */
	
	private function newJava(required classpath) {
		if(!structKeyExists(instance.javaCache, arguments.classpath)) {
			instance.javaCache[arguments.classpath] = createObject("java", arguments.classpath);
		}
		return instance.javaCache[arguments.classpath];
	}
	
	private void function assert(required boolean boolean_expression, String string_expression) {
		if(!arguments.boolean_expression) {
			throw(object=newJava("java.lang.AssertionError").init(arguments.string_expression));
		}
	}
	
	private void function throwError(required exception) {
		// CFESAPI RuntimeExceptions
		if(isInstanceOf(arguments.exception, "cfesapi.org.owasp.esapi.lang.RuntimeException")) {
			throw(type=arguments.exception.getType(), message=arguments.exception.getMessage(), extendedInfo=arguments.exception.getCause());
		}
		// CFESAPI Exceptions
		else if(isInstanceOf(arguments.exception, "cfesapi.org.owasp.esapi.lang.Exception")) {
			throw(type=arguments.exception.getType(), message=arguments.exception.getUserMessage(), detail=arguments.exception.getLogMessage(), extendedInfo=arguments.exception.getCause());
		}
		// Java Exceptions
		else if(isInstanceOf(arguments.exception, "java.lang.Throwable")) {
			throw(object=arguments.exception);
		}
	}
	
}