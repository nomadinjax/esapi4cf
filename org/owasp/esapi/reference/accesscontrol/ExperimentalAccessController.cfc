<!---
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
    --->
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.logger = "";
		instance.ruleMap = {};
	</cfscript>

	<cffunction access="public" returntype="ExperimentalAccessController" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true"/>
		<cfargument type="Struct" name="ruleMap" required="false"/>

		<cfset var local = {}/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("DefaultAccessController");

			if(structKeyExists(arguments, "ruleMap")) {
				instance.ruleMap = arguments.ruleMap;
			}
			else {
				local.policyDescriptor = newComponent("cfesapi.org.owasp.esapi.reference.accesscontrol.policyloader.ACRPolicyFileLoader").init(instance.ESAPI);
				local.policyDTO = local.policyDescriptor.load();
				instance.ruleMap = local.policyDTO.getAccessControlRules();
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorized" output="false">
		<cfargument type="any" name="key" required="true"/>
		<cfargument type="any" name="runtimeParameter" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			try {
				if(structKeyExists(instance.ruleMap, arguments.key)) {
					local.rule = instance.ruleMap.get(arguments.key);
				}
				if(!structKeyExists(local, "rule")) {
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Access Denied", "AccessControlRule was not found for key: " & arguments.key));
				}
				if(instance.logger.isDebugEnabled()) {
					instance.logger.debug(Logger.EVENT_SUCCESS, 'Evaluating Authorization Rule "' & arguments.key & '" Using class: ' & rule.getClass().getCanonicalName());
				}
				return local.rule.isAuthorized(arguments.runtimeParameter);
			}
			catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				try {
					//Log the exception by throwing and then catching it.
					//TODO figure out what which string goes where.
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Access Denied", "An unhandled Exception was caught, so access is denied.", e));
				}
				catch(cfesapi.org.owasp.esapi.errors.AccessControlException ace) {
					//the exception was just logged. There's nothing left to do.
				}
				return false;//fail closed
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorized" output="false">
		<cfargument type="any" name="key" required="true"/>
		<cfargument type="any" name="runtimeParameter" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			local.isAuthorized = false;
			try {
				if(structKeyExists(instance.ruleMap, arguments.key)) {
					local.rule = instance.ruleMap.get(arguments.key);
				}
				if(!structKeyExists(local, "rule")) {
					throwError(newComponent("cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Access Denied", "AccessControlRule was not found for key: " & arguments.key));
				}
				if(instance.logger.isDebugEnabled()) {
					instance.logger.debug(Logger.EVENT_SUCCESS, 'Asserting Authorization Rule "' & arguments.key & '" Using class: ' & rule.getClass().getCanonicalName());
				}
				local.isAuthorized = local.rule.isAuthorized(arguments.runtimeParameter);
			}
			catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				//TODO figure out what which string goes where.
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Access Denied", "An unhandled Exception was caught, so access is denied. AccessControlException.", e));
			}
			if(!local.isAuthorized) {
				throwError(newComponent("cfesapi.org.owasp.esapi.errors.AccessControlException").init(instance.ESAPI, "Access Denied", "Access Denied for key: " & arguments.key & " runtimeParameter: " & arguments.runtimeParameter.toString()));
			}
		</cfscript>

	</cffunction>

</cfcomponent>