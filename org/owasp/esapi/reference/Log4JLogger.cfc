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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.Logger" output="false">

	<cfscript>
		jLevel = createObject("java", "org.apache.log4j.Level");

		instance.ESAPI = "";

		/* The log4j object used by this class to log everything. */
		instance.log4jlogger = "";

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
            instance.log4jlogger = createObject("java", "org.apache.log4j.Logger").getLogger(instance.applicationName & ":" & arguments.moduleName);

            return this;
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setLevel" output="false" hint="Note: In this implementation, this change is not persistent, meaning that if the application is restarted, the log level will revert to the level defined in the ESAPI SecurityConfiguration properties file.">
		<cfargument type="numeric" name="level" required="true">
		<cfscript>
			try {
				instance.log4jlogger.setLevel(convertESAPILeveltoLoggerLevel( arguments.level ));
			}
			catch (java.lang.IllegalArgumentException e) {
				error(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "", e);
			}
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="any" name="convertESAPILeveltoLoggerLevel" output="false" hint="org.apache.log4j.Level: Converts the ESAPI logging level (a number) into the levels used by Java's logger.">
		<cfargument type="numeric" name="level" required="true" hint="The ESAPI to convert.">
		<cfscript>
			switch (arguments.level) {
				case /*Logger.OFF*/		2147483647:	return jLevel.OFF;
				case /*Logger.FATAL*/	1000:		return jLevel.FATAL;
				case /*Logger.ERROR*/	800:		return jLevel.ERROR;
				case /*Logger.WARNING*/	600:		return jLevel.WARN;
				case /*Logger.INFO*/	400:		return jLevel.INFO;
				case /*Logger.DEBUG*/	200:		return jLevel.DEBUG; //fine
				case /*Logger.TRACE*/	100:		return jLevel.TRACE; //finest
				case /*Logger.ALL*/		-2147483648:return jLevel.ALL;
				default: {
					throw(object=createObject("java", "java.lang.IllegalArgumentException").init("Invalid logging level. Value was: " & arguments.level));
				}
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="trace" output="false">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType">
		<cfargument type="String" name="message" required="true">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable">
		<cfscript>
			arguments.level = jLevel.TRACE;
            logMessage(argumentCollection=arguments);
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="debug" output="false">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType">
		<cfargument type="String" name="message" required="true">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable">
		<cfscript>
			arguments.level = jLevel.DEBUG;
            logMessage(argumentCollection=arguments);
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="info" output="false">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType">
		<cfargument type="String" name="message" required="true">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable">
		<cfscript>
			arguments.level = jLevel.INFO;
			logMessage(argumentCollection=arguments);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="warning" output="false">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType">
		<cfargument type="String" name="message" required="true">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable">
		<cfscript>
			arguments.level = jLevel.WARN;
            logMessage(argumentCollection=arguments);
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="error" output="false">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType">
		<cfargument type="String" name="message" required="true">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable">
		<cfscript>
			arguments.level = jLevel.ERROR;
			logMessage(argumentCollection=arguments);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="fatal" output="false">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType">
		<cfargument type="String" name="message" required="true">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable">
		<cfscript>
			arguments.level = jLevel.FATAL;
            logMessage(argumentCollection=arguments);
        </cfscript> 
	</cffunction>


	<cffunction access="private" returntype="void" name="logMessage" output="false" hint="Log the message after optionally encoding any special characters that might be dangerous when viewed by an HTML based log viewer. Also encode any carriage returns and line feeds to prevent log injection attacks. This logs all the supplied parameters plus the user ID, user's source IP, a logging specific session ID, and the current date/time.">
		<cfargument type="any" name="level" required="true" hint="org.apache.log4j.Level: defines the set of recognized logging levels (TRACE, INFO, DEBUG, WARNING, ERROR, FATAL)">
		<cfargument type="any" name="type" required="true" hint="org.owasp.esapi.Logger$EventType: the type of the event (SECURITY SUCCESS, SECURITY FAILURE, EVENT SUCCESS, EVENT FAILURE)">
		<cfargument type="String" name="message" required="true" hint="the message">
		<cfargument type="any" name="throwable" required="false" hint="java.lang.Throwable: the throwable">
		<cfscript>
        	// Check to see if we need to log
        	if (!instance.log4jlogger.isEnabledFor( arguments.level )) return;

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
			local.appInfo.append( "/"  & instance.moduleName );

			//get the type text if it exists
			local.typeInfo = "";
			if (!isNull(arguments.type)) {
				local.typeInfo &= arguments.type.toString() & " ";
			}

			// log the message
			if (!isNull(arguments.throwable) && isInstanceOf(arguments.throwable, "java.lang.Exception")) {
				instance.log4jlogger.log(arguments.level, "[" & local.typeInfo & getUserInfo() & " -> " & local.appInfo & "] " & local.clean, arguments.throwable);
			}
			else {
				instance.log4jlogger.log(arguments.level, "[" & local.typeInfo & getUserInfo() & " -> " & local.appInfo & "] " & local.clean);
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isDebugEnabled" output="false">
		<cfscript>
    	    return instance.log4jlogger.isEnabledFor(jLevel.DEBUG);
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isErrorEnabled" output="false">
		<cfscript>
    	    return instance.log4jlogger.isEnabledFor(jLevel.ERROR);
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isFatalEnabled" output="false">
		<cfscript>
    	    return instance.log4jlogger.isEnabledFor(jLevel.FATAL);
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isInfoEnabled" output="false">
		<cfscript>
    	    return instance.log4jlogger.isEnabledFor(jLevel.INFO);
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isTraceEnabled" output="false">
		<cfscript>
            return instance.log4jlogger.isEnabledFor(jLevel.TRACE);
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isWarningEnabled" output="false">
		<cfscript>
    	    return instance.log4jlogger.isEnabledFor(jLevel.WARN);
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getUserInfo" output="false">
		<cfscript>
		    // create a random session number for the user to represent the user's 'session', if it doesn't exist already
		    local.sid = "";
		    local.request = instance.ESAPI.httpUtilities().getCurrentRequest();
		    if ( !isNull(local.request) && isObject(local.request) ) {
		        local.session = local.request.getSession( false );
		        if ( !isNull(local.session) && isObject(local.session) ) {
		            local.sid = local.session.getAttribute("ESAPI_SESSION");
		            // if there is no session ID for the user yet, we create one and store it in the user's session
		            if ( isNull(local.sid) ) {
		            	local.sid = "" & instance.ESAPI.randomizer().getRandomInteger(0, 1000000);
		            	local.session.setAttribute("ESAPI_SESSION", local.sid);
		            }
		        }
		    }

			// log user information - username:session@ipaddr
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			local.userInfo = "";
			//TODO - make type logging configurable
			if ( !isNull(local.user)) {
				local.userInfo &= local.user.getAccountName() & ":" & local.sid & "@" & local.user.getLastHostAddress();
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
