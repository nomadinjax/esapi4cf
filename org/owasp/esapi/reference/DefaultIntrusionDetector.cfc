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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.IntrusionDetector" output="false" hint="Reference implementation of the IntrusionDetector interface. This implementation monitors EnterpriseSecurityExceptions to see if any user exceeds a configurable threshold in a configurable time period.">

	<cfscript>
		instance.ESAPI = "";
		instance.logger = "";
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.IntrusionDetector" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("IntrusionDetector");

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addException" output="false">
		<cfargument type="any" name="exception" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			if(instance.ESAPI.securityConfiguration().getDisableIntrusionDetection())
				return;

			if(isInstanceOf(arguments.exception, "cfesapi.org.owasp.esapi.errors.EnterpriseSecurityException")) {
				instance.logger.warning(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, arguments.exception.getLogMessage(), arguments.exception);
			}
			else {
				instance.logger.warning(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, arguments.exception.getMessage(), arguments.exception);
			}

			// add the exception to the current user, which may trigger a detector
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			local.eventName = getMetaData(arguments.exception).name;

			if(isInstanceOf(arguments.exception, "cfesapi.org.owasp.esapi.errors.IntrusionException")) {
				return;
			}

			// add the exception to the user's store, handle IntrusionException if thrown
			try {
				addSecurityEvent(local.user, local.eventName);
			}
			catch(cfesapi.org.owasp.esapi.errors.IntrusionException ex) {
				local.quota = instance.ESAPI.securityConfiguration().getQuota(local.eventName);
				for(local.i = 1; local.i <= arrayLen(local.quota.actions); local.i++) {
					local.action = local.quota.actions[local.i];
					local.message = "User exceeded quota of " & local.quota.count & " per " & local.quota.interval & " seconds for event " & local.eventName & ". Taking actions " & local.quota.actions;
					takeSecurityAction(local.action, local.message);
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addEvent" output="false">
		<cfargument type="String" name="eventName" required="true"/>
		<cfargument type="String" name="logMessage" required="true"/>

		<cfset var local = {}/>

		<cfscript>
			if(instance.ESAPI.securityConfiguration().getDisableIntrusionDetection())
				return;

			instance.logger.warning(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "Security event " & arguments.eventName & " received : " & arguments.logMessage);

			// add the event to the current user, which may trigger a detector
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			try {
				addSecurityEvent(local.user, "event." & arguments.eventName);
			}
			catch(cfesapi.org.owasp.esapi.errors.IntrusionException ex) {
				local.quota = instance.ESAPI.securityConfiguration().getQuota("event." & arguments.eventName);
				for(local.i = 1; local.i <= arrayLen(local.quota.actions); local.i++) {
					local.action = local.quota.actions[local.i];
					local.message = "User exceeded quota of " & local.quota.count & " per " & local.quota.interval & " seconds for event " & arguments.eventName & ". Taking actions " & arrayToList(local.quota.actions);
					takeSecurityAction(local.action, local.message);
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="takeSecurityAction" output="false"
	            hint="Take a specified security action.  In this implementation, acceptable actions are: log, disable, logout.">
		<cfargument type="String" name="action" required="true" hint="the action to take (log, disable, logout)"/>
		<cfargument type="String" name="message" required="true" hint="the message to log if the action is 'log'"/>

		<cfset var local = {}/>

		<cfscript>
			if(instance.ESAPI.securityConfiguration().getDisableIntrusionDetection())
				return;

			if(arguments.action.equals("log")) {
				instance.logger.fatal(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "INTRUSION - " & arguments.message);
			}
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			if(isInstanceOf(local.user, "cfesapi.org.owasp.esapi.User$ANONYMOUS")) {
				return;
			}
			if(arguments.action.equals("disable")) {
				local.user.disable();
			}
			if(arguments.action.equals("logout")) {
				local.user.logout();
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="addSecurityEvent" output="false"
	            hint="Adds a security event to the user.  These events are used to check that the user has not reached the security thresholds set in the properties file.">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="user" required="true" hint="The user that caused the event."/>
		<cfargument type="String" name="eventName" required="true" hint="The name of the event that occurred."/>

		<cfset var local = {}/>

		<cfscript>
			if(instance.ESAPI.securityConfiguration().getDisableIntrusionDetection())
				return;

			if(arguments.user.isAnonymous())
				return;

			local.eventMap = arguments.user.getEventMap();

			// if there is a threshold, then track this event
			local.threshold = instance.ESAPI.securityConfiguration().getQuota(arguments.eventName);
			if(isObject(local.threshold)) {
				if(structKeyExists(local.eventMap, arguments.eventName)) {
					local.event = local.eventMap.get(arguments.eventName);
				}
				if(!structKeyExists(local, "event")) {
					local.event = newComponent("cfesapi.org.owasp.esapi.reference.Event").init(instance.ESAPI, arguments.eventName);
					local.eventMap.put(arguments.eventName, local.event);
				}
				// increment
				local.event.increment(local.threshold.count, local.threshold.interval);
			}
		</cfscript>

	</cffunction>

</cfcomponent>