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
import "org.owasp.esapi.reference.accesscontrol.policyloader.ACRPolicyFileLoader";

component implements="org.owasp.esapi.AccessController" extends="org.owasp.esapi.util.Object" {
	variables.ruleMap = {};

	variables.ESAPI = "";
	variables.logger = "";

	public AccessController function init(required org.owasp.esapi.ESAPI ESAPI) {
		variables.ESAPI = arguments.ESAPI;
		variables.logger = variables.ESAPI.getLogger(getMetaData(this).fullName);

		var policyDescriptor = new ACRPolicyFileLoader(variables.ESAPI);
		var policyDTO = policyDescriptor.load();
		variables.ruleMap = policyDTO.getAccessControlRules();

		return this;
	}

	public boolean function isAuthorized(required key, required runtimeParameter) {
		try {
			var rule = variables.ruleMap.get(arguments.key);
			if(isNull(rule)) {
				raiseException(new AccessControlException("Access Denied", "AccessControlRule was not found for key: " & arguments.key));
			}
			if(variables.logger.isDebugEnabled()){
				variables.logger.debug(Logger.EVENT_SUCCESS, 'Evaluating Authorization Rule "' & arguments.key & '" Using class: ' & rule.getClass().getCanonicalName());
			}
			return rule.isAuthorized(arguments.runtimeParameter);
		} catch(Exception e) {
			try {
				//Log the exception by throwing and then catching it.
				//TODO figure out what which string goes where.
				raiseException(new AccessControlException("Access Denied", "An unhandled Exception was caught, so access is denied.", e));
			} catch(org.owasp.esapi.errors.AccessControlException ace) {
				//the exception was just logged. There's nothing left to do.
			}
			return false; //fail closed
		}
	}

	public void function assertAuthorized(required key, required runtimeParameter) {
		var isAuthorized = false;
		try {
			var rule = variables.ruleMap.get(arguments.key);
			if(isNull(rule)) {
				raiseException(new AccessControlException("Access Denied", "AccessControlRule was not found for key: " & arguments.key));
			}
			if(variables.logger.isDebugEnabled()) {
				variables.logger.debug(Logger.EVENT_SUCCESS, 'Asserting Authorization Rule "' & arguments.key & '" Using class: ' & rule.getClass().getCanonicalName());
			}
			isAuthorized = rule.isAuthorized(arguments.runtimeParameter);
		} catch(Exception e) {
			//TODO figure out what which string goes where.
			raiseException(new AccessControlException("Access Denied", "An unhandled Exception was caught, so access is denied.", e));
		}
		if(!isAuthorized) {
			raiseException(new AccessControlException("Access Denied", "Access Denied for key: " & arguments.key & " runtimeParameter: " & arguments.runtimeParameter));
		}
	}

	public void function assertAuthorizedForData(required string action, required data) {
		assertAuthorized("AC 1.0 Data", [arguments.action, arguments.data]);
	}

	public void function assertAuthorizedForFile(required string filepath) {
		assertAuthorized("AC 1.0 File", [arguments.filepath]);
	}

	public void function assertAuthorizedForFunction(required string functionName) {
		assertAuthorized("AC 1.0 Function", [arguments.functionName]);
	}

	public void function assertAuthorizedForService(required string serviceName) {
		assertAuthorized("AC 1.0 Service", [arguments.serviceName]);
	}

	public void function assertAuthorizedForURL(required string url) {
		assertAuthorized("AC 1.0 URL", [arguments.url]);
	}

	public boolean function isAuthorizedForData(required string action, required data) {
		return isAuthorized("AC 1.0 Data", [arguments.action, arguments.data]);
	}

	public boolean function isAuthorizedForFile(required string filepath) {
		return isAuthorized("AC 1.0 File", [arguments.filepath]);
	}

	public boolean function isAuthorizedForFunction(required string functionName) {
		return isAuthorized("AC 1.0 Function", [arguments.functionName]);
	}

	public boolean function isAuthorizedForService(required string serviceName) {
		return isAuthorized("AC 1.0 Service", [arguments.serviceName]);
	}

	public boolean function isAuthorizedForURL(required string url) {
		return isAuthorized("AC 1.0 URL", [arguments.url]);
	}

}
