<!---
 * Reference implementation of the Logger interface.
 *
 * It implements most of the recommendations defined in the Logger interface description. It does not
 * filter out any sensitive data specific to the current application or organization, such as credit
 * cards, social security numbers, etc.
 *
 * @author Damon Miller
 * @created 2011
 * @see org.owasp.esapi.LogFactory
 --->
<cfcomponent implements="esapi4cf.org.owasp.esapi.Logger" extends="esapi4cf.org.owasp.esapi.util.Object" output="false">

	<cfscript>
		instance.ESAPI = "";

		/** The jlogger object used by this class to log everything. */
		instance.jlogger = "";

		/** The application name using this log. */
		instance.applicationName = "";

		/** The module name using this log. */
		instance.moduleName = "";

		// Initialize the current logging level to the value defined in the configuration properties file
		/** The current level that logging is set to. */
		instance.currentLevel = "";
	</cfscript>

	<cffunction access="public" returntype="JavaLogger" name="init" output="false"
	            hint="Public constructor should only ever be called via the appropriate LogFactory">
		<cfargument required="true" type="esapi4cf.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" type="String" name="applicationName" hint="the application name"/>
		<cfargument required="true" type="String" name="moduleName" hint="the module name"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.currentLevel = convertESAPILeveltoLoggerLevel( ESAPI.securityConfiguration().getLogLevel() );

			instance.applicationName = arguments.applicationName;
			instance.moduleName = arguments.moduleName;
			instance.jlogger = getJava( "java.util.logging.Logger" ).getLogger( arguments.applicationName & ":" & arguments.moduleName );

			// Set the logging level defined in the config file.
			// Beware getting info from SecurityConfiguration, since it logs. We made sure it doesn't log in
			// the constructor and the getLogLevel() method, so this should work.
			instance.jlogger.setLevel( instance.currentLevel );

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLevel" output="false"
	            hint="Note: In this implementation, this change is not persistent, meaning that if the application is restarted, the log level will revert to the level defined in the SAPI SecurityConfiguration properties file.">
		<cfargument required="true" type="numeric" name="level"/>

		<cfscript>
			try {
				instance.currentLevel = convertESAPILeveltoLoggerLevel( arguments.level );
			}
			catch(java.lang.IllegalArgumentException e) {
				this.error( Logger.SECURITY, false, "", e );
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" name="convertESAPILeveltoLoggerLevel" output="false" hint="Converts the ESAPI logging level (a number) into the levels used by Java's logger.">
		<cfargument required="true" type="numeric" name="level" hint="The ESAPI to convert."/>

		<cfscript>

			switch(arguments.level) {
				case 2147483647://Logger.OFF:
					return getJava( "java.util.logging.Level" ).OFF;
				case 1000://Logger.FATAL:
					return getJava( "java.util.logging.Level" ).SEVERE;
				case 800://Logger.ERROR:
					// This is a custom level.
					return getJava( "org.owasp.esapi.reference.JavaLogFactory$JavaLoggerLevel" ).ERROR_LEVEL;
				case 600://Logger.WARNING:
					return getJava( "java.util.logging.Level" ).WARNING;
				case 400://Logger.INFO:
					return getJava( "java.util.logging.Level" ).INFO;
				case 200://Logger.DEBUG:
					return getJava( "java.util.logging.Level" ).FINE;
				case 100://Logger.TRACE:
					return getJava( "java.util.logging.Level" ).FINEST;
				case -2147483648://Logger.ALL:
					return getJava( "java.util.logging.Level" ).ALL;
				default: {
					throwException( getJava( "java.lang.IllegalArgumentException" ).init( "Invalid logging level. Value was: " & arguments.level ) );
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
			arguments.level = getJava( "java.util.logging.Level" ).FINEST;
			logMessage( argumentCollection=arguments );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="debug" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="boolean" name="success"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = getJava( "java.util.logging.Level" ).FINE;
			logMessage( argumentCollection=arguments );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="info" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="boolean" name="success"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = getJava( "java.util.logging.Level" ).INFO;
			logMessage( argumentCollection=arguments );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="warning" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="boolean" name="success"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = getJava( "java.util.logging.Level" ).WARNING;
			logMessage( argumentCollection=arguments );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="error" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="boolean" name="success"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = getJava( "java.util.logging.Level" ).SEVERE;
			logMessage( argumentCollection=arguments );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="fatal" output="false">
		<cfargument required="true" name="type"/>
		<cfargument required="true" type="boolean" name="success"/>
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="throwable"/>

		<cfscript>
			arguments.level = getJava( "java.util.logging.Level" ).SEVERE;
			logMessage( argumentCollection=arguments );
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
			var local = {};

			// Set the current logging level to the current value since it 'might' have been changed for some
			// other log.
			instance.jlogger.setLevel( instance.currentLevel );

			// Before we waste all kinds of time preparing this event for the log, let check to see if its
			//loggable
			if(!instance.jlogger.isLoggable( arguments.level ))
				return;

			local.user = instance.ESAPI.authenticator().getCurrentUser();

			// create a random session number for the user to represent the user's 'session', if it doesn't
			//exist already
			local.userSessionIDforLogging = "unknown";

			try {
				local.session = instance.ESAPI.httpUtilities().getCurrentRequest().getSession( false );
				if(structKeyExists( local, "session" ) && isObject( local.session )) {
					local.userSessionIDforLogging = local.session.getAttribute( "ESAPI_SESSION" );
					// if there is no session ID for the user yet, we create one and store it in the user's session
					if(!structKeyExists( local, "userSessionIDforLogging" )) {
						local.userSessionIDforLogging = "" & instance.ESAPI.randomizer().getRandomInteger( 0, 1000000 );
						local.session.setAttribute( "ESAPI_SESSION", local.userSessionIDforLogging );
					}
				}
			}
			catch(java.lang.NullPointerException e) {
				// continue
			}

			// ensure no CRLF injection into logs for forging records
			local.clean = arguments.message.replace( '\n', '_' ).replace( '\r', '_' );
			if(instance.ESAPI.securityConfiguration().getLogEncodingRequired()) {
				local.clean = instance.ESAPI.encoder().encodeForHTML( arguments.message );
				if(!arguments.message.equals( local.clean )) {
					local.clean &= " (Encoded)";
				}
			}

			// convert the stack trace into something that can be logged
			if(structKeyExists( arguments, "throwable" ) && isObject( arguments.throwable )) {
				local.fqn = getMetaData( arguments.throwable ).name;
				local.index = local.fqn.lastIndexOf( '.' );
				if(local.index > 0)
					local.fqn = local.fqn.substring( local.index + 1 );
				local.ste = arguments.throwable.getStackTrace();
				if (arrayLen(local.ste)) {
					local.ste = local.ste[1];
					//local.clean &= "\n    " & local.fqn & " @ " & getMetaData( local.ste ).name & "." & local.ste.getMethodName() & "(" & local.ste.getFileName() & ":" & local.ste.getLineNumber() & ")";
					local.clean &= "\n    " & local.fqn & " @ " & "(" & local.ste.getFileName() & ":" & local.ste.getLineNumber() & ")";
				}
				// NullPointerException falls into this
				else {
					local.clean &= "\n    " & local.fqn & " @ " & "(unknownFileName:-1)";
				}
			}

			// create the message to log
			local.msg = "";
			if(isObject( local.user )) {
				local.msg = arguments.type & "-" & iif( arguments.success, de( "SUCCESS" ), de( "FAILURE" ) ) & " " & local.user.getAccountName() & "@" & local.user.getLastHostAddress() & ":" & local.userSessionIDforLogging & " -- " & local.clean;
			}

			instance.jlogger.logp( arguments.level, instance.applicationName, instance.moduleName, "[ESAPI4CF] " & local.msg );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isDebugEnabled" output="false">

		<cfscript>
			instance.jlogger.setLevel( instance.currentLevel );
			return instance.jlogger.isLoggable( getJava( "java.util.logging.Level" ).FINE );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isErrorEnabled" output="false">

		<cfscript>
			instance.jlogger.setLevel( instance.currentLevel );
			return instance.jlogger.isLoggable( getJava( "org.owasp.esapi.reference.JavaLogFactory$JavaLoggerLevel" ).ERROR_LEVEL );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isFatalEnabled" output="false">

		<cfscript>
			instance.jlogger.setLevel( instance.currentLevel );
			return instance.jlogger.isLoggable( getJava( "java.util.logging.Level" ).SEVERE );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isInfoEnabled" output="false">

		<cfscript>
			instance.jlogger.setLevel( instance.currentLevel );
			return instance.jlogger.isLoggable( getJava( "java.util.logging.Level" ).INFO );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isTraceEnabled" output="false">

		<cfscript>
			instance.jlogger.setLevel( instance.currentLevel );
			return instance.jlogger.isLoggable( getJava( "java.util.logging.Level" ).FINEST );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isWarningEnabled" output="false">

		<cfscript>
			instance.jlogger.setLevel( instance.currentLevel );
			return instance.jlogger.isLoggable( getJava( "java.util.logging.Level" ).WARNING );
		</cfscript>

	</cffunction>

</cfcomponent>