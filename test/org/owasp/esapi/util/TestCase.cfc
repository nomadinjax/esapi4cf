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
component extends="mxunit.framework.TestCase" asyncAll=true {

	/**
	 * Executes once before all tests for the entire test bundle CFC
	 */
	public void function beforeTests() {
		variables.System = createObject("java", "java.lang.System");
		variables.ESAPI = new org.owasp.esapi.ESAPI({
			"ESAPI": {
				"printProperties": false
			},
			"Encryptor": {
				"MasterKey": "a6H9is3hEVGKB4Jut+lOVA==",
    			"MasterSalt": "SbftnvmEWD5ZHHP+pX3fqugNysc=",
    			"cipher_modes": {
    				// NOTE: ECB added only for testing purposes. Don't try this at home!
    				"additional_allowed": "CBC,ECB"
    			}
    		}
    	});
	}

	/**
	 * Executes once after all tests complete in the test bundle CFC
	 */
	public void function afterTests() {
		structDelete(variables, "ESAPI");
		structDelete(variables, "System");
	}

	/**
	 * Executes before every single test case and receives the name of the actual testing method
	 */
	public void function setup(required currentMethod) {}

	/**
	 * Executes after every single test case and receives the name of the actual testing method
	 */
	public void function teardown(required currentMethod) {}


	/* PRIVATE METHODS */

	private void function raiseException(required exception) {
		if (isInstanceOf(arguments.exception, "java.lang.Throwable")) {
			throw(object=arguments.exception);
		}
		else if (isInstanceOf(arguments.exception, "org.owasp.esapi.errors.EnterpriseSecurityException")) {
			throw(type=arguments.exception.getType(), message=arguments.exception.getUserMessage(), detail=arguments.exception.getLogMessage());
		}
		else if (isInstanceOf(arguments.exception, "org.owasp.esapi.util.Exception")) {
			throw(type=arguments.exception.getType(), message=arguments.exception.getMessage());
		}
		else if (isStruct(arguments.exception)) {
			throw(type=arguments.exception.type, message=arguments.exception.message, detail=arguments.exception.detail);
		}
	}

	/**
	 * blanks out the users.txt file
	 */
	private void function clearUserFile() {
		fileWrite(expandPath("/org/owasp/esapi/conf/users.txt"), "");
	}

}