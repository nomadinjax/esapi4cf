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
<cfinterface hint="The IntrusionDetector interface is intended to track security relevant events and identify attack behavior. The implementation can use as much state as necessary to detect attacks, but note that storing too much state will burden your system. The interface is currently designed to accept exceptions as well as custom events. Implementations can use this stream of information to detect both normal and abnormal behavior.">

	<cffunction access="public" returntype="void" name="addException" output="false" hint="Adds the exception to the IntrusionDetector.  This method should immediately log the exception so that developers throwing an IntrusionException do not have to remember to log every error.  The implementation should store the exception somewhere for the current user in order to check if the User has reached the threshold for any Enterprise Security Exceptions.  The User object is the recommended location for storing the current user's security exceptions.  If the User has reached any security thresholds, the appropriate security action can be taken and logged.">
		<cfargument type="any" name="exception" required="true" hint="the exception thrown">
	</cffunction>


	<cffunction access="public" returntype="void" name="addEvent" output="false" hint="Adds the event to the IntrusionDetector.  This method should immediately log the event.  The implementation should store the event somewhere for the current user in order to check if the User has reached the threshold for any Enterprise Security Exceptions.  The User object is the recommended location for storing the current user's security event.  If the User has reached any security thresholds, the appropriate security action can be taken and logged.">
		<cfargument type="String" name="eventName" required="true" hint="the event to add">
		<cfargument type="String" name="logMessage" required="true" hint="the message to log with the event">
	</cffunction>

</cfinterface>
