<!--- /**
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
 */ --->
<cfinterface hint="The Logger interface defines a set of methods that can be used to log security events. It supports a hierarchy of logging levels which can be configured at runtime to determine the severity of events that are logged, and those below the current threshold that are discarded. Implementors should use a well established logging library as it is quite difficult to create a high-performance logger. The logging levels defined by this interface (in descending order) are: fatal (highest value), error, warning, info, debug, trace (lowest value). There are also several variations of {@code always()} methods that will always log a message regardless of the log level. ESAPI also allows for the definition of the type of log event that is being generated. The Logger interface predefines 6 types of Log events: SECURITY_SUCCESS, SECURITY_FAILURE, SECURITY_AUDIT, EVENT_SUCCESS, EVENT_FAILURE, EVENT_UNSPECIFIED. Your implementation can extend or change this list if desired. This Logger allows callers to determine which logging levels are enabled, and to submit events at different severity levels. Implementors of this interface should: 1) provide a mechanism for setting the logging level threshold that is currently enabled. This usually works by logging all events at and above that severity level, and discarding all events below that level. This is usually done via configuration, but can also be made accessible programmatically. 2) ensure that dangerous HTML characters are encoded before they are logged to defend against malicious injection into logs that might be viewed in an HTML based log viewer. 3) encode any CRLF characters included in log data in order to prevent log injection attacks. 4) avoid logging the user's session ID. Rather, they should log something equivalent like a generated logging session ID, or a hashed value of the session ID so they can track session specific events without risking the exposure of a live session's ID. 5) record the following information with each event: a) identity of the user that caused the event, b) a description of the event (supplied by the caller), c) whether the event succeeded or failed (indicated by the caller), d) severity level of the event (indicated by the caller), e) that this is a security relevant event (indicated by the caller), f) hostname or IP where the event occurred (and ideally the user's source IP as well), g) a time stamp. Custom logger implementations might also: filter out any sensitive data specific to the current application or organization, such as credit cards, social security numbers, etc. There is a native Java Logging default implementation. JavaLogger uses the java.util.logging package as the basis for its logging implementation. The default implementation implements requirements ##1 thru ##5 above. Customization: It is expected that most organizations will implement their own custom Logger class in order to integrate ESAPI logging with their logging infrastructure. The ESAPI Reference Implementation is intended to provide a simple functional example of an implementation.">

	<cffunction access="public" returntype="void" name="setLevel" output="false"
	            hint="Dynamically set the ESAPI logging severity level. All events of this level and higher will be logged from this point forward for all logs. All events below this level will be discarded.">
		<cfargument required="true" type="numeric" name="level" hint="The level to set the logging level to. "/>
	
	</cffunction>
	
	<cffunction access="public" returntype="numeric" name="getESAPILevel" output="false"
	            hint="Retrieve the current ESAPI logging level for this logger. See {@link org.owasp.esapi.reference.Log4JLogger} for an explanation of why this method is not simply called {@code getLevel()}."/>

	<cffunction access="public" returntype="void" name="fatal" output="false"
	            hint="Log a fatal level security event if 'fatal' level logging is enabled and also record the stack trace associated with the event.">
		<cfargument required="true" name="type" hint="the type of event"/>
		<cfargument required="true" type="String" name="message" hint="the message to log"/>
		<cfargument name="throwable" hint="the exception to be logged"/>
	
	</cffunction>
	
	<cffunction access="public" returntype="boolean" name="isFatalEnabled" output="false"
	            hint="Allows the caller to determine if messages logged at this level will be discarded, to avoid performing expensive processing."/>

	<cffunction access="public" returntype="void" name="error" output="false"
	            hint="Log an error level security event if 'error' level logging is enabled and also record the stack trace associated with the event.">
		<cfargument required="true" name="type" hint="the type of event"/>
		<cfargument required="true" type="String" name="message" hint="the message to log"/>
		<cfargument name="throwable" hint="the exception to be logged"/>
	
	</cffunction>
	
	<cffunction access="public" returntype="boolean" name="isErrorEnabled" output="false"
	            hint="Allows the caller to determine if messages logged at this level will be discarded, to avoid performing expensive processing."/>

	<cffunction access="public" returntype="void" name="warning" output="false"
	            hint="Log a warning level security event if 'warning' level logging is enabled and also record the stack trace associated with the event.">
		<cfargument required="true" name="type" hint="the type of event"/>
		<cfargument required="true" type="String" name="message" hint="the message to log"/>
		<cfargument name="throwable" hint="the exception to be logged"/>
	
	</cffunction>
	
	<cffunction access="public" returntype="boolean" name="isWarningEnabled" output="false"
	            hint="Allows the caller to determine if messages logged at this level will be discarded, to avoid performing expensive processing."/>

	<cffunction access="public" returntype="void" name="info" output="false"
	            hint="Log an info level security event if 'info' level logging is enabled and also record the stack trace associated with the event.">
		<cfargument required="true" name="type" hint="the type of event"/>
		<cfargument required="true" type="String" name="message" hint="the message to log"/>
		<cfargument name="throwable" hint="the exception to be logged"/>
	
	</cffunction>
	
	<cffunction access="public" returntype="boolean" name="isInfoEnabled" output="false"
	            hint="Allows the caller to determine if messages logged at this level will be discarded, to avoid performing expensive processing."/>

	<cffunction access="public" returntype="void" name="debug" output="false"
	            hint="Log a debug level security event if 'debug' level logging is enabled and also record the stack trace associated with the event.">
		<cfargument required="true" name="type" hint="the type of event"/>
		<cfargument required="true" type="String" name="message" hint="the message to log"/>
		<cfargument name="throwable" hint="the exception to be logged"/>
	
	</cffunction>
	
	<cffunction access="public" returntype="boolean" name="isDebugEnabled" output="false"
	            hint="Allows the caller to determine if messages logged at this level will be discarded, to avoid performing expensive processing."/>

	<cffunction access="public" returntype="void" name="trace" output="false"
	            hint="Log a trace level security event if 'trace' level logging is enabled and also record the stack trace associated with the event.">
		<cfargument required="true" name="type" hint="the type of event"/>
		<cfargument required="true" type="String" name="message" hint="the message to log"/>
		<cfargument name="throwable" hint="the exception to be logged"/>
	
	</cffunction>
	
	<cffunction access="public" returntype="boolean" name="isTraceEnabled" output="false"
	            hint="Allows the caller to determine if messages logged at this level will be discarded, to avoid performing expensive processing."/>

	<cffunction access="public" returntype="void" name="always" output="false"
	            hint="Log an event regardless of what logging level is enabled and also record the stack trace associated with the event.">
		<cfargument required="true" name="type" hint="the type of event"/>
		<cfargument required="true" type="String" name="message" hint="the message to log"/>
		<cfargument name="throwable" hint="the exception to be logged"/>
	
	</cffunction>
	
</cfinterface>