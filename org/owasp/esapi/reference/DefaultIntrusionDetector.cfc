<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 --->
<cfcomponent implements="cfesapi.org.owasp.esapi.IntrusionDetector" extends="cfesapi.org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the IntrusionDetector interface. This implementation monitors EnterpriseSecurityExceptions to see if any user exceeds a configurable threshold in a configurable time period. For example, it can monitor to see if a user exceeds 10 input validation issues in a 1 minute period. Or if there are more than 3 authentication problems in a 10 second period. More complex implementations are certainly possible, such as one that establishes a baseline of expected behavior, and then detects deviations from that baseline.">

	<cfscript>
		instance.ESAPI = "";
		/** The logger. */
		instance.logger = "";

		instance.userEvents = {};
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.IntrusionDetector" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger( "IntrusionDetector" );

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addException" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.util.Exception" name="exception"/>

		<cfscript>
			var local = {};
			if(instance.ESAPI.securityConfiguration().getDisableIntrusionDetection())
				return;

			if(isInstanceOf( arguments.exception, "cfesapi.org.owasp.esapi.errors.EnterpriseSecurityException" )) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, arguments.exception.getLogMessage(), arguments.exception );
			}
			else {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, arguments.exception.getMessage(), arguments.exception );
			}

			// add the exception to the current user, which may trigger a detector
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			local.eventName = getMetaData( arguments.exception ).name;

			if(isInstanceOf( arguments.exception, "cfesapi.org.owasp.esapi.errors.IntrusionException" )) {
				return;
			}

			// add the exception to the user's store, handle IntrusionException if thrown
			try {
				addSecurityEvent( local.user, local.eventName );
			}
			catch(cfesapi.org.owasp.esapi.errors.IntrusionException ex) {
				local.quota = instance.ESAPI.securityConfiguration().getQuota( local.eventName );
				for(local.i = 1; local.i <= arrayLen( local.quota.actions ); local.i++) {
					local.action = local.quota.actions[local.i];
					local.message = "User exceeded quota of " & local.quota.count & " per " & local.quota.interval & " seconds for event " & local.eventName & ". Taking actions " & arrayToList( local.quota.actions );
					takeSecurityAction( local.action, local.message );
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addEvent" output="false">
		<cfargument required="true" type="String" name="eventName"/>
		<cfargument required="true" type="String" name="logMessage"/>

		<cfscript>
			var local = {};
			if(instance.ESAPI.securityConfiguration().getDisableIntrusionDetection())
				return;

			instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Security event " & arguments.eventName & " received : " & arguments.logMessage );

			// add the event to the current user, which may trigger a detector
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			try {
				addSecurityEvent( local.user, "event." & arguments.eventName );
			}
			catch(cfesapi.org.owasp.esapi.errors.IntrusionException ex) {
				local.quota = instance.ESAPI.securityConfiguration().getQuota( "event." & arguments.eventName );
				for(local.i = 1; local.i <= arrayLen( local.quota.actions ); local.i++) {
					local.action = local.quota.actions[local.i];
					local.message = "User exceeded quota of " & local.quota.count & " per " & local.quota.interval & " seconds for event " & arguments.eventName & ". Taking actions " & arrayToList( local.quota.actions );
					takeSecurityAction( local.action, local.message );
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="takeSecurityAction" output="false"
	            hint="Take a specified security action.  In this implementation, acceptable actions are: log, disable, logout.">
		<cfargument required="true" type="String" name="action" hint="the action to take (log, disable, logout)"/>
		<cfargument required="true" type="String" name="message" hint="the message to log if the action is 'log'"/>

		<cfscript>
			var local = {};
			if(instance.ESAPI.securityConfiguration().getDisableIntrusionDetection())
				return;

			if(arguments.action.equals( "log" )) {
				instance.logger.fatal( getSecurity("SECURITY_FAILURE"), false, "INTRUSION - " & arguments.message );
			}
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			if(isInstanceOf( local.user, "cfesapi.org.owasp.esapi.User$ANONYMOUS" ))
				return;
			if(arguments.action.equals( "disable" )) {
				local.user.disable();
			}
			if(arguments.action.equals( "logout" )) {
				local.user.logout();
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="addSecurityEvent" output="false"
	            hint="Adds a security event to the user.  These events are used to check that the user has not reached the security thresholds set in the properties file.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.User" name="user" hint="The user that caused the event."/>
		<cfargument required="true" type="String" name="eventName" hint="The name of the event that occurred."/>

		<cfscript>
			var local = {};

			if(instance.ESAPI.securityConfiguration().getDisableIntrusionDetection())
				return;

			if(structKeyExists( instance.userEvents, arguments.user.getAccountName() )) {
				local.events = instance.userEvents.get( arguments.user.getAccountName() );
			}
			if(!structKeyExists( local, "events" )) {
				local.events = {};
				instance.userEvents.put( arguments.user.getAccountName(), local.events );
			}
			if(structKeyExists( local.events, arguments.eventName )) {
				local.event = local.events.get( arguments.eventName );
			}
			if(!structKeyExists( local, "event" )) {
				local.event = createObject( "component", "DefaultIntrusionDetector$Event" ).init( instance.ESAPI, arguments.eventName );
				local.events.put( arguments.eventName, local.event );
			}

			local.q = instance.ESAPI.securityConfiguration().getQuota( arguments.eventName );
			if(local.q.count > 0) {
				local.event.increment( local.q.count, local.q.interval );
			}
		</cfscript>

	</cffunction>

</cfcomponent>