<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.Logger" output="false">

	<cfscript>
		instance.ESAPI = "";

		/* The jlogger object used by this class to log everything. */
		instance.jlogger = "";

		/* The module name using this log. */
		instance.moduleName = "";

		/* The application name defined in ESAPI.properties */
	   	instance.applicationName = "";

	   	/* Log the application name? */
    	instance.logAppName = "";

	   	/* Log the server ip? */
    	instance.logServerIP = "";
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Logger" name="init" output="false" hint="Public constructor should only ever be called via the appropriate LogFactory">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="String" name="moduleName" required="true" hint="the module name">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.applicationName = instance.ESAPI.securityConfiguration().getApplicationName();
    		instance.logAppName = instance.ESAPI.securityConfiguration().getLogApplicationName();
    		instance.logServerIP = instance.ESAPI.securityConfiguration().getLogServerIP();

			instance.moduleName = arguments.moduleName;
			instance.jlogger = createObject("java", "java.util.logging.Logger").getLogger(instance.applicationName & ":" & arguments.moduleName);

			return this;
		</cfscript>
	</cffunction>

	<!--- {@inheritDoc} --->

	<cffunction access="public" returntype="void" name="setLevel" output="false" hint="Note: In this implementation, this change is not persistent, meaning that if the application is restarted, the log level will revert to the level defined in the ESAPI SecurityConfiguration properties file.">
		<cfargument type="numeric" name="level" required="true">
		<cfscript>
			try {
				instance.jlogger.setLevel(convertESAPILeveltoLoggerLevel( arguments.level ));
			}
			catch (java.lang.IllegalArgumentException e) {
				error(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "", e);
			}
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="any" name="convertESAPILeveltoLoggerLevel" output="false" hint="java.util.logging.Level: Converts the ESAPI logging level (a number) into the levels used by Java's logger.">
		<cfargument type="numeric" name="level" required="true" hint="The ESAPI to convert.">
		<cfscript>
			jLevel = createObject("java", "java.util.logging.Level");

        	switch (arguments.level) {
        		case /*Logger.OFF*/		2147483647:	return jLevel.OFF;
        		case /*Logger.FATAL*/	1000:		return jLevel.SEVERE;
        		case /*Logger.ERROR*/	800:		return javaLoader().create("org.owasp.esapi.reference.JavaLoggerLevel").ERROR_LEVEL; // This is a custom level.
        		case /*Logger.WARNING*/	600:		return jLevel.WARNING;
        		case /*Logger.INFO*/	400:		return jLevel.INFO;
        		case /*Logger.DEBUG*/	200:		return jLevel.FINE;
        		case /*Logger.TRACE*/	100:		return jLevel.FINEST;
        		case /*Logger.ALL*/		-2147483648:return jLevel.ALL;
        		default: {
        			throw(object=createObject("java", "java.lang.IllegalArgumentException").init("Invalid logging level. Value was: " & arguments.level));
        		}
        	}
        </cfscript>
	</cffunction>

	<!--- {@inheritDoc} --->

	<cffunction access="public" returntype="void" name="trace" output="false">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType">
		<cfargument type="String" name="message" required="true">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable">
		<cfscript>
			arguments.level = createObject("java", "java.util.logging.Level").FINEST;
            logMessage(argumentCollection=arguments);
        </cfscript>
	</cffunction>

	<!--- {@inheritDoc} --->

	<cffunction access="public" returntype="void" name="debug" output="false">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType">
		<cfargument type="String" name="message" required="true">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable">
		<cfscript>
			arguments.level = createObject("java", "java.util.logging.Level").FINE;
            logMessage(argumentCollection=arguments);
        </cfscript>
	</cffunction>

	<!--- {@inheritDoc} --->

	<cffunction access="public" returntype="void" name="info" output="false">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType">
		<cfargument type="String" name="message" required="true">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable">
		<cfscript>
			arguments.level = createObject("java", "java.util.logging.Level").INFO;
			logMessage(argumentCollection=arguments);
		</cfscript>
	</cffunction>

	<!--- {@inheritDoc} --->

	<cffunction access="public" returntype="void" name="warning" output="false">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType">
		<cfargument type="String" name="message" required="true">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable">
		<cfscript>
			arguments.level = createObject("java", "java.util.logging.Level").WARNING;
            logMessage(argumentCollection=arguments);
        </cfscript>
	</cffunction>

	<!--- {@inheritDoc} --->

	<cffunction access="public" returntype="void" name="error" output="false">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType">
		<cfargument type="String" name="message" required="true">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable">
		<cfscript>
			arguments.level = javaLoader().create("org.owasp.esapi.reference.JavaLoggerLevel").ERROR_LEVEL;
			logMessage(argumentCollection=arguments);
		</cfscript>
	</cffunction>

	<!--- {@inheritDoc} --->

	<cffunction access="public" returntype="void" name="fatal" output="false">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType">
		<cfargument type="String" name="message" required="true">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable">
		<cfscript>
			arguments.level = createObject("java", "java.util.logging.Level").SEVERE;
            logMessage(argumentCollection=arguments);
        </cfscript>
	</cffunction>


	<cffunction access="private" returntype="void" name="logMessage" output="false" hint="Log the message after optionally encoding any special characters that might be dangerous when viewed by an HTML based log viewer. Also encode any carriage returns and line feeds to prevent log injection attacks. This logs all the supplied parameters plus the user ID, user's source IP, a logging specific session ID, and the current date/time. It will only log the message if the current logging level is enabled, otherwise it will discard the message.">
		<cfargument type="any" name="level" required="true" hint="org.apache.log4j.Level: defines the set of recognized logging levels (TRACE, INFO, DEBUG, WARNING, ERROR, FATAL)">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType: the type of the event (SECURITY SUCCESS, SECURITY FAILURE, EVENT SUCCESS, EVENT FAILURE)">
		<cfargument type="String" name="message" required="true" hint="the message">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable: the throwable">
		<cfscript>
        	// Check to see if we need to log
        	if (!instance.jlogger.isLoggable( arguments.level )) return;

            // ensure there's something to log
            if ( isNull(arguments.message) ) {
            	arguments.message = "";
            }

            // ensure no CRLF injection into logs for forging records
            local.clean = arguments.message.replace( '\n', '_' ).replace( '\r', '_' );
            if ( instance.ESAPI.securityConfiguration().getLogEncodingRequired() ) {
            	local.clean = instance.ESAPI.encoder().encodeForHTML(arguments.message);
                if (!arguments.message.equals(local.clean)) {
                    local.clean &= " (Encoded)";
                }
            }

			// log server, port, app name, module name -- server:80/app/module
			local.appInfo = createObject("java", "java.lang.StringBuilder").init();
			if ( !isNull(instance.ESAPI.currentRequest()) && instance.logServerIP ) {
				local.appInfo.append( instance.ESAPI.currentRequest().getLocalAddr() & ":" & instance.ESAPI.currentRequest().getLocalPort() );
			}
			if ( instance.logAppName ) {
				local.appInfo.append( "/" & instance.applicationName );
			}
			local.appInfo.append( "/" & instance.moduleName );

			//get the type text if it exists
			local.typeInfo = "";
			if (!isNull(arguments.type)) {
				local.typeInfo &= arguments.type & " ";
			}

			// log the message
			if (!isNull(arguments.throwable) && isInstanceOf(arguments.throwable, "java.lang.Exception")) {
				instance.jlogger.log(arguments.level, "[" & local.typeInfo & getUserInfo() & " -> " & local.appInfo & "] " & local.clean, arguments.throwable);
			}
			else {
				instance.jlogger.log(arguments.level, "[" & local.typeInfo & getUserInfo() & " -> " & local.appInfo & "] " & local.clean);
			}
		</cfscript>
	</cffunction>

	<!--- {@inheritDoc} --->

	<cffunction access="public" returntype="boolean" name="isDebugEnabled" output="false">
		<cfscript>
    	    return instance.jlogger.isLoggable(createObject("java", "java.util.logging.Level").FINE);
        </cfscript>
	</cffunction>

	<!--- {@inheritDoc} --->

	<cffunction access="public" returntype="boolean" name="isErrorEnabled" output="false">
		<cfscript>
    	    return instance.jlogger.isLoggable(javaLoader().create("org.owasp.esapi.reference.JavaLoggerLevel").ERROR_LEVEL);
    	</cfscript>
	</cffunction>

	<!--- {@inheritDoc} --->

	<cffunction access="public" returntype="boolean" name="isFatalEnabled" output="false">
		<cfscript>
    	    return instance.jlogger.isLoggable(createObject("java", "java.util.logging.Level").SEVERE);
    	</cfscript>
	</cffunction>

	<!--- {@inheritDoc} --->

	<cffunction access="public" returntype="boolean" name="isInfoEnabled" output="false">
		<cfscript>
    	    return instance.jlogger.isLoggable(createObject("java", "java.util.logging.Level").INFO);
        </cfscript>
	</cffunction>

	<!--- {@inheritDoc} --->

	<cffunction access="public" returntype="boolean" name="isTraceEnabled" output="false">
		<cfscript>
            return instance.jlogger.isLoggable(createObject("java", "java.util.logging.Level").FINEST);
        </cfscript>
	</cffunction>

	<!--- {@inheritDoc} --->

	<cffunction access="public" returntype="boolean" name="isWarningEnabled" output="false">
		<cfscript>
    	    return instance.jlogger.isLoggable(createObject("java", "java.util.logging.Level").WARNING);
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getUserInfo" output="false">
		<cfscript>
            // create a random session number for the user to represent the user's 'session', if it doesn't exist already
            local.sid = "";
            local.request = instance.ESAPI.httpUtilities().getCurrentRequest();
            if ( isObject(local.request) ) {
                local.session = local.request.getSession( false );
                if ( !isNull(local.session) && isObject(local.session) ) {
	                local.sid = local.session.getAttribute("ESAPI_SESSION");
	                // if there is no session ID for the user yet, we create one and store it in the user's session
		            if ( isNull(local.sid) ) {
		            	local.sid = ""& instance.ESAPI.randomizer().getRandomInteger(0, 1000000);
		            	local.session.setAttribute("ESAPI_SESSION", local.sid);
		            }
                }
            }

			// log user information - username:session@ipaddr
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			local.userInfo = "";
			//TODO - Make Type Logging configurable
			if ( !isNull(local.user)) {
				local.userInfo &= local.user.getAccountName()& ":" & local.sid & "@"& local.user.getLastHostAddress();
			}

			return local.userInfo;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="toString" output="false">
		<cfscript>
			return getMetaData().fullName;
		</cfscript>
	</cffunction>


</cfcomponent>
