<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfcomponent implements="org.owasp.esapi.IntrusionDetector" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the IntrusionDetector interface. This implementation monitors EnterpriseSecurityExceptions to see if any user exceeds a configurable threshold in a configurable time period. For example, it can monitor to see if a user exceeds 10 input validation issues in a 1 minute period. Or if there are more than 3 authentication problems in a 10 second period. More complex implementations are certainly possible, such as one that establishes a baseline of expected behavior, and then detects deviations from that baseline.">

	<cfscript>
		// imports
		Utils = createObject("component", "org.owasp.esapi.util.Utils");

		variables.ESAPI = "";
		/** The logger. */
		variables.logger = "";

		variables.userEvents = {};
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.IntrusionDetector" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.logger = variables.ESAPI.getLogger("IntrusionDetector");

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addException" output="false">
		<cfargument required="true" type="org.owasp.esapi.util.Exception" name="exception"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var eventName = "";
			var quota = "";
			var i = "";
			var action = "";
			var message = "";
			var msgParams = [];

			if(variables.ESAPI.securityConfiguration().getDisableIntrusionDetection())
				return;

			if(isInstanceOf(arguments.exception, "org.owasp.esapi.errors.EnterpriseSecurityException")) {
				variables.logger.warning(Utils.getSecurityType("SECURITY_FAILURE"), false, arguments.exception.getLogMessage(), arguments.exception);
			}
			else {
				variables.logger.warning(Utils.getSecurityType("SECURITY_FAILURE"), false, arguments.exception.getMessage(), arguments.exception);
			}

			// add the exception to the current user, which may trigger a detector
			user = variables.ESAPI.authenticator().getCurrentUser();
			eventName = getMetaData(arguments.exception).name;

			if(isInstanceOf(arguments.exception, "org.owasp.esapi.errors.IntrusionException")) {
				return;
			}

			// add the exception to the user's store, handle IntrusionException if thrown
			try {
				variables.addSecurityEvent(user, eventName);
			}
			catch(org.owasp.esapi.errors.IntrusionException ex) {
				quota = variables.ESAPI.securityConfiguration().getQuota(eventName);
				for(i = 1; i <= arrayLen(quota.actions); i++) {
					action = quota.actions[i];
					msgParams = [quota.count, quota.interval, eventName, arrayToList(quota.actions)];
					message = variables.ESAPI.resourceBundle().messageFormat("IntrusionDetector_addException_quotaExceeded_message", msgParams);
					variables.takeSecurityAction(action, message);
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addEvent" output="false">
		<cfargument required="true" type="String" name="eventName"/>
		<cfargument required="true" type="String" name="logMessage"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var quota = "";
			var i = 0;
			var action = "";
			var message = "";
			var msgParams = [];

			if(variables.ESAPI.securityConfiguration().getDisableIntrusionDetection())
				return;

			msgParams = [arguments.eventName, arguments.logMessage];
			variables.logger.warning(Utils.getSecurityType("SECURITY_FAILURE"), false, variables.ESAPI.resourceBundle().messageFormat("IntrusionDetector_addEvent_securityEvent_message", msgParams));

			// add the event to the current user, which may trigger a detector
			user = variables.ESAPI.authenticator().getCurrentUser();
			try {
				variables.addSecurityEvent(user, "event." & arguments.eventName);
			}
			catch(org.owasp.esapi.errors.IntrusionException ex) {
				quota = variables.ESAPI.securityConfiguration().getQuota("event." & arguments.eventName);
				for(i = 1; i <= arrayLen(quota.actions); i++) {
					action = quota.actions[i];
					msgParams = [quota.count, quota.interval, arguments.eventName, arrayToList(quota.actions)];
					message = variables.ESAPI.resourceBundle().messageFormat("IntrusionDetector_addEvent_quotaExceeded_message", msgParams);
					variables.takeSecurityAction(action, message);
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="takeSecurityAction" output="false"
	            hint="Take a specified security action.  In this implementation, acceptable actions are: log, disable, logout.">
		<cfargument required="true" type="String" name="action" hint="the action to take (log, disable, logout)"/>
		<cfargument required="true" type="String" name="message" hint="the message to log if the action is 'log'"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var msgParams = [];

			if(variables.ESAPI.securityConfiguration().getDisableIntrusionDetection())
				return;

			if(arguments.action.equals("log")) {
				msgParams = [arguments.message];
				variables.logger.fatal(Utils.getSecurityType("SECURITY_FAILURE"), false, variables.ESAPI.resourceBundle().messageFormat("IntrusionException_intrusion_message", msgParams));
			}
			user = variables.ESAPI.authenticator().getCurrentUser();
			if(isInstanceOf(user, "org.owasp.esapi.reference.AnonymousUser"))
				return;
			if(arguments.action.equals("disable")) {
				user.disable();
			}
			if(arguments.action.equals("logout")) {
				user.logout();
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="addSecurityEvent" output="false"
	            hint="Adds a security event to the user.  These events are used to check that the user has not reached the security thresholds set in the properties file.">
		<cfargument required="true" type="org.owasp.esapi.User" name="user" hint="The user that caused the event."/>
		<cfargument required="true" type="String" name="eventName" hint="The name of the event that occurred."/>

		<cfscript>
			// CF8 requires 'var' at the top
			var events = "";
			var event = "";
			var q = "";

			if(variables.ESAPI.securityConfiguration().getDisableIntrusionDetection())
				return;

			events = "";
			if(structKeyExists(variables.userEvents, arguments.user.getAccountName())) {
				events = variables.userEvents[arguments.user.getAccountName()];
			}
			if(!isStruct(events)) {
				events = {};
				variables.userEvents[arguments.user.getAccountName()] = events;
			}

			event = "";
			if(structKeyExists(events, arguments.eventName)) {
				event = events[arguments.eventName];
			}
			if(!isObject(event)) {
				event = createObject("component", "DefaultIntrusionDetector$Event").init(variables.ESAPI, arguments.eventName);
				events[arguments.eventName] = event;
			}
			q = variables.ESAPI.securityConfiguration().getQuota(arguments.eventName);
			if(q.count > 0) {
				event.increment(q.count, q.interval);
			}
		</cfscript>

	</cffunction>

</cfcomponent>