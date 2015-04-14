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
import "org.owasp.esapi.util.Utils";

component extends="Object" {

	property type="string" name="type";
	property type="string" name="message";
	property type="array" name="stackTrace";
	property name="cause";

	variables.exception = "";

	public Exception function init(required string message, cause) {
       	variables.type = "org.owasp.esapi.errors." & listLast(getMetaData().name, ".");
       	variables.message = arguments.message;

        if (!isNull(arguments.cause)) {
        	// TODO: Railo sees 'cause' as a struct instead of a Java object - how can we fix that?
        	//variables.exception = createObject("java", "java.lang.Exception").init(arguments.message, arguments.cause);
        	variables.exception = createObject("java", "java.lang.Exception").init(arguments.message);
        	variables.cause = arguments.cause;
        }
        else {
			variables.exception = createObject("java", "java.lang.Exception").init(arguments.message);
       	}

		variables.stackTrace = new Utils().parseStackTrace(variables.exception.getStackTrace());

        return this;
    }

    public string function getType() {
    	return variables.type;
    }

    public string function getMessage() {
    	return variables.message;
    }

    public array function getStackTrace() {
    	return variables.stackTrace;
    }

    public function getCause() {
    	if (!isNull(variables.cause)) {
    		return variables.cause;
    	}
    }

}