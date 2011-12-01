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
<cfcomponent displayname="JavaLogger" extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.Logger" output="false"
             hint="Reference implementation of the Logger interface. It implements most of the recommendations defined in the Logger interface description. It does not filter out any sensitive data specific to the current application or organization, such as credit cards, social security numbers, etc.">

	<cfscript>
		instance.ESAPI = "";

		/** The jlogger object used by this class to log everything. */
		instance.jlogger = "";

		/** The module name using this log. */
		instance.moduleName = "";

		/** The application name defined in ESAPI.properties */
		instance.applicationName = "";

		/** Log the application name? */
		instance.logAppName = "";

		/** Log the server ip? */
		instance.logServerIP = "";
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Logger" name="init" output="false"
	            hint="Public constructor should only ever be called via the appropriate LogFactory">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" type="String" name="moduleName" hint="the module name"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.applicationName = instance.ESAPI.securityConfiguration().getApplicationName();
			instance.logAppName = instance.ESAPI.securityConfiguration().getLogApplicationName();
			instance.logServerIP = instance.ESAPI.securityConfiguration().getLogServerIP();

			instance.moduleName = arguments.moduleName;
			instance.jlogger = newJava("java.util.logging.Logger").getLogger(instance.applicationName & ":" & arguments.moduleName);

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLevel" output="false"
	            hint="Note: In this implementation, this change is not persistent, meaning that if the application is restarted, the log level will revert to the level defined in the ESAPI SecurityConfiguration properties file.">
		<cfargument required="true" type="numeric" name="level"/>

		<cfscript>
			try {
				instance.jlogger.setLevel(convertESAPILeveltoLoggerLevel(arguments.level));
			}
			catch(java.lang.IllegalArgumentException e) {
				this.error(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "", e);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getESAPILevel" output="false">

		<cfscript>
			return instance.jlogger.getLevel().intValue();
		</cfscript>

	</cffunction>

	<cffunction access="private" name="convertESAPILeveltoLoggerLevel" output="false" hint="Converts the ESAPI logging level (a number) into the levels used by Java's logger.">
		<cfargument required="true" type="numeric" name="level" hint="The ESAPI to convert."/>

		<cfscript>

			// ACF: use of Logger constants in case statements causes "This expression must have a constant value. " error

			switch(arguments.level) {
				case 2147483647://Logger.OFF:
					return newJava("java.util.logging.Level").OFF;
				case 1000://Logger.FATAL:
					return newJava("java.util.logging.Level").SEVERE;
				case 800://Logger.ERROR:
					return newJava("org.owasp.esapi.reference.JavaLogFactory$JavaLoggerLevel").ERROR_LEVEL;// This is a custom level.
				case 600://Logger.WARNING:
					return newJava("java.util.logging.Level").WARNING;
				case 400://Logger.INFO:
					return newJava("java.util.logging.Level").INFO;
				case 200://Logger.DEBUG:
					return newJava("java.util.logging.Level").FINE;
				case 100://Logger.TRACE:
					return newJava("java.util.logging.Level").FINEST;
				case -2147483648://Logger.ALL:
					return newJava("java.util.logging.Level").ALL;
				default: {
					throwError(newJava("java.lang.IllegalArgumentException").init("Invalid logging level. Value was: " & arguments.level));
				}
			}

		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="trace" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = newJava("java.util.logging.Level").FINEST;
			logMessage(argumentCollection=arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="debug" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = newJava("java.util.logging.Level").FINE;
			logMessage(argumentCollection=arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="info" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = newJava("java.util.logging.Level").INFO;
			logMessage(argumentCollection=arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="warning" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = newJava("java.util.logging.Level").WARNING;
			logMessage(argumentCollection=arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="error" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = newJava("java.util.logging.Level").SEVERE;
			logMessage(argumentCollection=arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="fatal" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = newJava("java.util.logging.Level").SEVERE;
			logMessage(argumentCollection=arguments);
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="logMessage" output="false"
	            hint="Log the message after optionally encoding any special characters that might be dangerous when viewed by an HTML based log viewer. Also encode any carriage returns and line feeds to prevent log injection attacks. This logs all the supplied parameters plus the user ID, user's source IP, a logging specific session ID, and the current date/time. It will only log the message if the current logging level is enabled, otherwise it will discard the message.">
		<cfargument required="true" name="level" hint="defines the set of recognized logging levels (TRACE, INFO, DEBUG, WARNING, ERROR, FATAL)"/>
		<cfargument required="true" name="type" hint="the type of the event (SECURITY SUCCESS, SECURITY FAILURE, EVENT SUCCESS, EVENT FAILURE)"/>
		<cfargument required="true" type="String" name="message" hint="the message"/>
		<cfargument name="throwable" hint="the throwable"/>

		<cfset var local = {}/>

		<cfscript>

			// Check to see if we need to log
			if(!instance.jlogger.isLoggable(arguments.level))
				return;

			// ensure there's something to log
			if(!structKeyExists(arguments, "message")) {
				arguments.message = "";
			}

			// ensure no CRLF injection into logs for forging records
			local.clean = arguments.message.replace('\n', '_').replace('\r', '_');
			if(instance.ESAPI.securityConfiguration().getLogEncodingRequired()) {
				local.clean = instance.ESAPI.encoder().encodeForHTML(arguments.message);
				if(!arguments.message.equals(local.clean)) {
					local.clean &= " (Encoded)";
				}
			}

			// log server, port, app name, module name -- server:80/app/module
			local.appInfo = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init();
			if(isObject(instance.ESAPI.currentRequest()) && instance.logServerIP) {
				local.appInfo.append(instance.ESAPI.currentRequest().getLocalAddr() & ":" & instance.ESAPI.currentRequest().getLocalPort());
			}
			if(instance.logAppName) {
				local.appInfo.append("/" & instance.applicationName);
			}
			local.appInfo.append("/" & instance.moduleName);

			//get the type text if it exists
			local.typeInfo = "";
			if(structKeyExists(arguments, "type")) {
				local.typeInfo &= arguments.type & " ";
			}

			// log the message
			if(structKeyExists(arguments, "throwable") && isInstanceOf(arguments.throwable, "java.lang.Exception")) {
				instance.jlogger.log(arguments.level, "[" & local.typeInfo & getUserInfo() & " -> " & local.appInfo.toStringESAPI() & "] " & local.clean, arguments.throwable);
			}
			else {
				instance.jlogger.log(arguments.level, "[" & local.typeInfo & getUserInfo() & " -> " & local.appInfo.toStringESAPI() & "] " & local.clean);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isDebugEnabled" output="false">

		<cfscript>
			return instance.jlogger.isLoggable(newJava("java.util.logging.Level").FINE);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isErrorEnabled" output="false">

		<cfscript>
			return instance.jlogger.isLoggable(newJava("org.owasp.esapi.reference.JavaLogFactory$JavaLoggerLevel").ERROR_LEVEL);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isFatalEnabled" output="false">

		<cfscript>
			return instance.jlogger.isLoggable(newJava("java.util.logging.Level").SEVERE);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isInfoEnabled" output="false">

		<cfscript>
			return instance.jlogger.isLoggable(newJava("java.util.logging.Level").INFO);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isTraceEnabled" output="false">

		<cfscript>
			return instance.jlogger.isLoggable(newJava("java.util.logging.Level").FINEST);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isWarningEnabled" output="false">

		<cfscript>
			return instance.jlogger.isLoggable(newJava("java.util.logging.Level").WARNING);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getUserInfo" output="false">
		<cfset var local = {}/>

		<cfscript>
			// create a random session number for the user to represent the user's 'session', if it doesn't exist already
			local.sid = "";
			local.request = instance.ESAPI.httpUtilities().getCurrentRequest();
			if(isObject(local.request)) {
				local.session = local.request.getSession(false);
				if(structKeyExists(local, "session") && isObject(local.session)) {
					local.sid = local.session.getAttribute("ESAPI_SESSION");
					// if there is no session ID for the user yet, we create one and store it in the user's session
					if(!structKeyExists(local, "sid") || local.sid == "") {
						local.sid = instance.ESAPI.randomizer().getRandomInteger(0, 1000000);
						local.session.setAttribute("ESAPI_SESSION", local.sid);
					}
				}
			}

			// log user information - username:session@ipaddr
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			local.userInfo = "";
			//TODO - Make Type Logging configurable
			if(structKeyExists(local, "user")) {
				local.userInfo &= local.user.getAccountName() & ":" & local.sid & "@" & local.user.getLastHostAddress();
			}

			return local.userInfo;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="always" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = newJava("java.util.logging.Level").OFF;// Seems backward, but this is what works, not Level.ALL
			logMessage(argumentCollection=arguments);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="toStringESAPI" output="false">

		<cfscript>
			return getMetaData().fullName;
		</cfscript>

	</cffunction>

</cfcomponent>