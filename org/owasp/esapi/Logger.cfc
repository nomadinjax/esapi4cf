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
<cfinterface>

	<cffunction access="public" returntype="void" name="setLevel" output="false" hint="Dynamically set the ESAPI logging severity level. All events of this level and higher will be logged from this point forward for all logs. All events below this level will be discarded.">
		<cfargument type="numeric" name="level" required="true" hint="The level to set the logging level to.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getESAPILevel" output="false" hint="Retrieve the current ESAPI logging level for this logger. See {@link org.owasp.esapi.reference.Log4JLogger} for an explanation of why this method is not simply called {@code getLevel()}.">
	</cffunction>


	<cffunction access="public" returntype="void" name="fatal" output="false" hint="Log a fatal level security event if 'fatal' level logging is enabled and also record the stack trace associated with the event.">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType: the type of event">
		<cfargument type="String" name="message" required="true" hint="the message to log">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable: the exception to be logged">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isFatalEnabled" output="false" hint="Allows the caller to determine if messages logged at this level will be discarded, to avoid performing expensive processing.">
	</cffunction>


	<cffunction access="public" returntype="void" name="error" output="false" hint="Log an error level security event if 'error' level logging is enabled and also record the stack trace associated with the event.">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType: the type of event">
		<cfargument type="String" name="message" required="true" hint="the message to log">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable: the exception to be logged">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isErrorEnabled" output="false" hint="Allows the caller to determine if messages logged at this level will be discarded, to avoid performing expensive processing.">
	</cffunction>


	<cffunction access="public" returntype="void" name="warning" output="false" hint="Log a warning level security event if 'warning' level logging is enabled and also record the stack trace associated with the event.">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType: the type of event">
		<cfargument type="String" name="message" required="true" hint="the message to log">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable: the exception to be logged">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isWarningEnabled" output="false" hint="Allows the caller to determine if messages logged at this level will be discarded, to avoid performing expensive processing.">
	</cffunction>


	<cffunction access="public" returntype="void" name="info" output="false" hint="Log an info level security event if 'info' level logging is enabled and also record the stack trace associated with the event.">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType: the type of event">
		<cfargument type="String" name="message" required="true" hint="the message to log">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable: the exception to be logged">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isInfoEnabled" output="false" hint="Allows the caller to determine if messages logged at this level will be discarded, to avoid performing expensive processing.">
	</cffunction>


	<cffunction access="public" returntype="void" name="debug" output="false" hint="Log a debug level security event if 'debug' level logging is enabled and also record the stack trace associated with the event.">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType: the type of event">
		<cfargument type="String" name="message" required="true" hint="the message to log">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable: the exception to be logged">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isDebugEnabled" output="false" hint="Allows the caller to determine if messages logged at this level will be discarded, to avoid performing expensive processing.">
	</cffunction>


	<cffunction access="public" returntype="void" name="trace" output="false" hint="Log a trace level security event if 'trace' level logging is enabled and also record the stack trace associated with the event.">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType: the type of event">
		<cfargument type="String" name="message" required="true" hint="the message to log">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable: the exception to be logged">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isTraceEnabled" output="false" hint="Allows the caller to determine if messages logged at this level will be discarded, to avoid performing expensive processing.">
	</cffunction>


	<cffunction access="public" returntype="void" name="always" output="false" hint="Log an event regardless of what logging level is enabled and also record the stack trace associated with the event.">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType: the type of event">
		<cfargument type="String" name="message" required="true" hint="the message to log">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable: the exception to be logged">
	</cffunction>

</cfinterface>
