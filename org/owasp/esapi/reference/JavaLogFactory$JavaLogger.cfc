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
<cfcomponent implements="org.owasp.esapi.Logger" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Logger interface. It implements most of the recommendations defined in the Logger interface description. It does not filter out any sensitive data specific to the current application or organization, such as credit cards, social security numbers, etc.  ">

	<cfscript>
		variables.ESAPI = "";

		/** The jlogger object used by this class to log everything. */
		variables.jlogger = "";

		/** The application name using this log. */
		variables.applicationName = "";

		/** The module name using this log. */
		variables.moduleName = "";

		// Initialize the current logging level to the value defined in the configuration properties file
		/** The current level that logging is set to. */
		variables.currentLevel = "";
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.Logger" name="init" output="false"
	            hint="Public constructor should only ever be called via the appropriate LogFactory">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" type="String" name="applicationName" hint="the application name"/>
		<cfargument required="true" type="String" name="moduleName" hint="the module name"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.currentLevel = convertESAPILeveltoLoggerLevel(variables.ESAPI.securityConfiguration().getLogLevel());

			variables.applicationName = arguments.applicationName;
			variables.moduleName = arguments.moduleName;
			variables.jlogger = createObject("java", "java.util.logging.Logger").getLogger(arguments.applicationName & ":" & arguments.moduleName);

			// Set the logging level defined in the config file.
			// Beware getting info from SecurityConfiguration, since it logs. We made sure it doesn't log in
			// the constructor and the getLogLevel() method, so this should work.
			variables.jlogger.setLevel(variables.currentLevel);

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLevel" output="false"
	            hint="Note: In this implementation, this change is not persistent, meaning that if the application is restarted, the log level will revert to the level defined in the SAPI SecurityConfiguration properties file.">
		<cfargument required="true" type="numeric" name="level"/>

		<cfscript>
			try {
				variables.currentLevel = convertESAPILeveltoLoggerLevel(arguments.level);
			}
			catch(java.lang.IllegalArgumentException e) {
				this.error(Logger.SECURITY, false, "", e);
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" name="convertESAPILeveltoLoggerLevel" output="false" hint="Converts the ESAPI logging level (a number) into the levels used by Java's logger.">
		<cfargument required="true" type="numeric" name="level" hint="The ESAPI to convert."/>

		<cfscript>
			// NOTE: CF-all does not allow this reference in the case statements - Railo works fine
			//var Logger = createObject("java", "org.owasp.esapi.Logger");
			var jLevel = createObject("java", "java.util.logging.Level");
			switch(arguments.level) {
				case 2147483647://Logger.OFF:
					return jLevel.OFF;
				case 1000://Logger.FATAL:
					return jLevel.SEVERE;
				case 800://Logger.ERROR:
					// This is a custom level.
					return createObject("java", "org.owasp.esapi.reference.JavaLogFactory$JavaLoggerLevel").ERROR_LEVEL;
				case 600://Logger.WARNING:
					return jLevel.WARNING;
				case 400://Logger.INFO:
					return jLevel.INFO;
				case 200://Logger.DEBUG:
					return jLevel.FINE;
				case 100://Logger.TRACE:
					return jLevel.FINEST;
				case -2147483648://Logger.ALL:
					return jLevel.ALL;
				default: {
					throw(object=createObject("java", "java.lang.IllegalArgumentException").init("Invalid logging level. Value was: " & arguments.level));
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="trace" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="boolean" name="success"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = createObject("java", "java.util.logging.Level").FINEST;
			logMessage(argumentCollection=arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="debug" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="boolean" name="success"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = createObject("java", "java.util.logging.Level").FINE;
			logMessage(argumentCollection=arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="info" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="boolean" name="success"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = createObject("java", "java.util.logging.Level").INFO;
			logMessage(argumentCollection=arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="warning" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="boolean" name="success"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = createObject("java", "java.util.logging.Level").WARNING;
			logMessage(argumentCollection=arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="error" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="boolean" name="success"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = createObject("java", "java.util.logging.Level").SEVERE;
			logMessage(argumentCollection=arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="fatal" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="boolean" name="success"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = createObject("java", "java.util.logging.Level").SEVERE;
			logMessage(argumentCollection=arguments);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="logMessage" output="false"
	            hint="Log the message after optionally encoding any special characters that might be dangerous when viewed by an HTML based log viewer. Also encode any carriage returns and line feeds to prevent log injection attacks. This logs all the supplied parameters plus the user ID, user's source IP, a logging specific session ID, and the current date/time. It will only log the message if the current logging level is enabled, otherwise it will discard the message.">
		<cfargument required="true" name="level" hint="the severity level of the security event"/>
		<cfargument required="true" name="type" hint="the type of the event (SECURITY, FUNCTIONALITY, etc.)"/>
		<cfargument required="true" type="boolean" name="success" hint="whether this was a failed or successful event"/>
		<cfargument required="true" type="String" name="message" hint="the message"/>
		<cfargument name="throwable" hint="the throwable"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var user = "";
			var userSessionIDforLogging = "";
			var httpSession = "";
			var clean = "";
			var fqn = "";
			var index = "";
			var ste = "";
			var msg = "";

			// Set the current logging level to the current value since it 'might' have been changed for some other log.
			variables.jlogger.setLevel(variables.currentLevel);

			// Before we waste all kinds of time preparing this event for the log, let check to see if its loggable
			if (!variables.jlogger.isLoggable(arguments.level))
				return;

			user = variables.ESAPI.authenticator().getCurrentUser();

			// create a random session number for the user to represent the user's 'session', if it doesn't exist already
			userSessionIDforLogging = "unknown";

			try {
				httpSession = variables.ESAPI.httpUtilities().getCurrentRequest().getSession(false);
				if(isDefined("httpSession") && !isNull(httpSession) && isObject(httpSession)) {
					userSessionIDforLogging = httpSession.getAttribute("ESAPI_SESSION");
					// if there is no session ID for the user yet, we create one and store it in the user's session
					if(!(isDefined("userSessionIDforLogging") && !isNull(userSessionIDforLogging))) {
						userSessionIDforLogging = "" & variables.ESAPI.randomizer().getRandomInteger(0, 1000000);
						httpSession.setAttribute("ESAPI_SESSION", userSessionIDforLogging);
					}
				}
			}
			catch(java.lang.NullPointerException e) {
				// continue
			}

			// ensure there's something to log
			if (isNull(arguments.message)) {
				arguments.message = "";
			}

			// ensure no CRLF injection into logs for forging records
			clean = arguments.message.replace("\n", "_").replace("\r", "_");
			if(variables.ESAPI.securityConfiguration().getLogEncodingRequired()) {
				clean = variables.ESAPI.encoder().encodeForHTML(arguments.message);
				if(!arguments.message.equals(clean)) {
					clean &= " (Encoded)";
				}
			}

			// convert the stack trace into something that can be logged
			if(structKeyExists(arguments, "throwable") && !isNull(arguments.throwable) && isObject(arguments.throwable)) {
				fqn = getMetaData(arguments.throwable).name;
				index = fqn.lastIndexOf(".");
				if(index > 0)
					fqn = fqn.substring(index + 1);
				ste = arguments.throwable.getStackTrace();
				if(arrayLen(ste)) {
					ste = ste[1];
					//clean &= "\n    " & fqn & " @ " & getMetaData( ste ).name & "." & ste.getMethodName() & "(" & ste.getFileName() & ":" & ste.getLineNumber() & ")";
					clean &= "\n    " & fqn & " @ " & replace(listLast(ste.getFileName(), "\"), ".cfc", "") & "(" & ste.getFileName() & ":" & ste.getLineNumber() & ")";
				}
				// NullPointerException falls into this
				else {
					clean &= "\n    " & fqn & " @ unknownClassName(unknownFileName:-1)";
				}
			}

			// create the message to log
			msg = "";
			if(isObject(user)) {
				msg = arguments.type & "-" & iif(arguments.success, de("SUCCESS"), de("FAILURE")) & " " & user.getAccountName() & "@" & user.getLastHostAddress() & ":" & userSessionIDforLogging & " -- " & clean;
			}

			variables.jlogger.logp(arguments.level, variables.applicationName, variables.moduleName, "[" & this.ESAPINAME & "] " & msg);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isDebugEnabled" output="false">

		<cfscript>
			variables.jlogger.setLevel(variables.currentLevel);
			return variables.jlogger.isLoggable(createObject("java", "java.util.logging.Level").FINE);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isErrorEnabled" output="false">

		<cfscript>
			variables.jlogger.setLevel(variables.currentLevel);
			return variables.jlogger.isLoggable(createObject("java", "org.owasp.esapi.reference.JavaLogFactory$JavaLoggerLevel").ERROR_LEVEL);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isFatalEnabled" output="false">

		<cfscript>
			variables.jlogger.setLevel(variables.currentLevel);
			return variables.jlogger.isLoggable(createObject("java", "java.util.logging.Level").SEVERE);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isInfoEnabled" output="false">

		<cfscript>
			variables.jlogger.setLevel(variables.currentLevel);
			return variables.jlogger.isLoggable(createObject("java", "java.util.logging.Level").INFO);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isTraceEnabled" output="false">

		<cfscript>
			variables.jlogger.setLevel(variables.currentLevel);
			return variables.jlogger.isLoggable(createObject("java", "java.util.logging.Level").FINEST);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isWarningEnabled" output="false">

		<cfscript>
			variables.jlogger.setLevel(variables.currentLevel);
			return variables.jlogger.isLoggable(createObject("java", "java.util.logging.Level").WARNING);
		</cfscript>

	</cffunction>

</cfcomponent>