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
component extends="org.owasp.esapi.util.Object" {
	variables.ESAPI = "";
	variables.logger = "";

	public ACRPolicyFileLoader function init(required org.owasp.esapi.ESAPI ESAPI) {
		variables.ESAPI = arguments.ESAPI;
		variables.logger = variables.ESAPI.getLogger("ACRPolicyFileLoader");

		return this;
	}

	public PolicyDTO function load() {
		var policyDTO = new PolicyDTO(variables.ESAPI);
		var config = "";
		var file = variables.ESAPI.securityConfiguration().getResourceFile("ESAPI-AccessControlPolicy.xml");
		try
		{
		    config = new XMLConfiguration(file);
		}
		catch(ConfigurationException cex)
		{
			if(file == null) {
				raiseException(new AccessControlException(variables.ESAPI, "Unable to load configuration file for the following: " & "ESAPI-AccessControlPolicy.xml", "", cex));
			}
		    raiseException(new AccessControlException(variables.ESAPI, "Unable to load configuration file from the following location: " & file.getAbsolutePath(), "", cex));
		}

		var property = config.getProperty("AccessControlRules.AccessControlRule[@name]");
		logger.info(Logger.EVENT_SUCCESS, "Loading Property: " & property);
		var numberOfRules = 0;
		if(isInstanceOf(property, "Collection")) {
			numberOfRules = property.size();
		} //implied else property == null -> return new PolicyDTO

		var ruleName = "";
		var ruleClass = "";
		var rulePolicyParameter = null;
		var currentRule = 0;
	    try {
	    	logger.info(Logger.EVENT_SUCCESS, "Number of rules: " & numberOfRules);
			for(currentRule = 0; currentRule < numberOfRules; currentRule++) {
				logger.trace(Logger.EVENT_SUCCESS, "----");
				ruleName = config.getString("AccessControlRules.AccessControlRule(" & currentRule & ")[@name]");
				logger.trace(Logger.EVENT_SUCCESS, "Rule name: " & ruleName);
				ruleClass = config.getString("AccessControlRules.AccessControlRule(" & currentRule & ")[@class]");
				logger.trace(Logger.EVENT_SUCCESS, "Rule Class: " & ruleClass);
				rulePolicyParameter = getPolicyParameter(config, currentRule);
				logger.trace(Logger.EVENT_SUCCESS, "rulePolicyParameters: " & rulePolicyParameter);
				policyDTO.addAccessControlRule(
						ruleName,
						ruleClass,
						rulePolicyParameter);
			}
			logger.info(Logger.EVENT_SUCCESS, "policyDTO loaded: " & policyDTO);
		} catch (Exception e) {
			raiseException(new AccessControlException(variables.ESAPI, "Unable to load AccessControlRule parameter. " &
					" Rule number: " & currentRule &
					" Probably: Rule.name: " & ruleName &
					" Probably: Rule.class: " & ruleClass &
					e.getMessage(), "", e));
		}
		return policyDTO;
	}

	private function getPolicyParameter(required config, required numeric currentRule) {
		//If there aren't any properties: short circuit and return null.
//		Properties tempParameters = config.getProperties("AccessControlRules.AccessControlRule(" & currentRule & ").Parameters.Parameter[@name]");
		var property = config.getProperty("AccessControlRules.AccessControlRule(" & currentRule & ").Parameters.Parameter[@name]");
		if(property == null) {
			return null;
		}

		var numberOfProperties = 0;
		if(isInstanceOf(property, "Collection")) {
			numberOfProperties = property.size();
		} else {
			numberOfProperties = 1;
		}
		logger.info(Logger.EVENT_SUCCESS, "Number of properties: " & numberOfProperties);

		if(numberOfProperties < 1) {
			return null;
		}
		var parametersLoaderClassName = config.getString("AccessControlRules.AccessControlRule(" & currentRule & ").Parameters[@parametersLoader]");
		if("" == parametersLoaderClassName || isNull(parametersLoaderClassName)) {
			//this default should have a properties file override option
			parametersLoaderClassName = "org.owasp.esapi.reference.accesscontrol.policyloader.DynaBeanACRParameterLoader";
		}
		logger.info(Logger.EVENT_SUCCESS, "Parameters Loader:" & parametersLoaderClassName);
		var acrParamaterLoader = Class.forName(parametersLoaderClassName).newInstance();
		return acrParamaterLoader.getParameters(config, currentRule);
	}

}