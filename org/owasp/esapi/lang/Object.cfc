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

	/* private methods */
	
	private void function assert(required boolean boolean_expression, 
	                             String string_expression) {
		if(!arguments.boolean_expression) {
			throw(object=createObject("java", "java.lang.AssertionError").init(arguments.string_expression));
		}
	}
	
	private void function throwError(required cfesapi.org.owasp.esapi.lang.Exception exception) {
		throw(type=arguments.exception.getType(), message=arguments.exception.getUserMessage(), detail=arguments.exception.getLogMessage(), extendedInfo=arguments.exception.getCause());
	}
	
}