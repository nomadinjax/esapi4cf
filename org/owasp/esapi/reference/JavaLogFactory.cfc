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
 * Reference implementation of the LogFactory and Logger interfaces. This implementation uses the Java logging package, and marks each
 * log message with the currently logged in user and the word "SECURITY" for security related events. See the 
 * <a href="JavaLogFactory.JavaLogger.html">JavaLogFactory.JavaLogger</a> Javadocs for the details on the JavaLogger reference implementation.
 */
component JavaLogFactory extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.LogFactory" {
	instance.ESAPI = "";
	instance.loggersMap = {};

	/**
	* Null argument constructor for this implementation of the LogFactory interface
	* needed for dynamic configuration.
	*/
	
	public JavaLogFactory function init(required cfesapi.org.owasp.esapi.ESAPI ESAPI) {
		instance.ESAPI = arguments.ESAPI;
	
		return this;
	}
	
	/**
	* {@inheritDoc}
	*/
	
	public cfesapi.org.owasp.esapi.Logger function getLogger(required String moduleName) {
		// If a logger for this module already exists, we return the same one, otherwise we create a new one.
		if(structKeyExists(instance.loggersMap, arguments.moduleName)) {
			local.moduleLogger = instance.loggersMap.get(arguments.moduleName);
		}
		if(isNull(local.moduleLogger)) {
			local.moduleLogger = new cfesapi.org.owasp.esapi.reference.JavaLogger(instance.ESAPI, arguments.moduleName);
			instance.loggersMap.put(arguments.moduleName, local.moduleLogger);
		}
		return local.moduleLogger;
	}
	
}