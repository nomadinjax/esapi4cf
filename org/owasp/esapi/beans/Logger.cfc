/*
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
import "org.owasp.esapi.util.Utils";

/**
 * Reference implementation of the Logger interface.
 *
 * It implements most of the recommendations defined in the Logger interface description. It does not
 * filter out any sensitive data specific to the current application or organization, such as credit
 * cards, social security numbers, etc.
 */
component implements="org.owasp.esapi.Logger" extends="org.owasp.esapi.util.Object" {

	variables.Level = createObject("java", "java.util.logging.Level");
	variables.JavaLoggerLevel = createObject("java", "org.owasp.esapi.reference.JavaLogFactory$JavaLoggerLevel");
	variables.Logger = createObject("java", "org.owasp.esapi.Logger");

	/**
     * A security type of log event that has succeeded. This is one of 6 predefined
     * ESAPI logging events. New events can be added.
     */
	this.SECURITY_SUCCESS = variables.Logger.SECURITY_SUCCESS;

	/**
     * A security type of log event that has failed. This is one of 6 predefined
     * ESAPI logging events. New events can be added.
     */
	this.SECURITY_FAILURE = variables.Logger.SECURITY_FAILURE;

	/**
	 * A security type of log event that is associated with an audit trail of some type,
	 * but the log event is not specifically something that has either succeeded or failed
	 * or that is irrelevant in the case of this logged message.
	 */
	this.SECURITY_AUDIT = variables.Logger.SECURITY_AUDIT;

	/**
     * A non-security type of log event that has succeeded. This is one of 6 predefined
     * ESAPI logging events. New events can be added.
     */
	this.EVENT_SUCCESS = variables.Logger.EVENT_SUCCESS;

	/**
     * A non-security type of log event that has failed. This is one of 6 predefined
     * ESAPI logging events. New events can be added.
     */
	this.EVENT_FAILURE = variables.Logger.EVENT_FAILURE;

	/**
     * A non-security type of log event that is unspecified. This is one of 6 predefined
     * ESAPI logging events. New events can be added.
     */
	this.EVENT_UNSPECIFIED = variables.Logger.EVENT_UNSPECIFIED;

	/*
     * The Logger interface defines 6 logging levels: FATAL, ERROR, WARNING, INFO, DEBUG, TRACE. It also
     * supports ALL, which logs all events, and OFF, which disables all logging.
     * Your implementation can extend or change this list if desired.
     */

	/** OFF indicates that no messages should be logged. This level is initialized to Integer.MAX_VALUE. */
	this.LEVEL_OFF = variables.Logger.OFF;

	/** FATAL indicates that only FATAL messages should be logged. This level is initialized to 1000. */
	this.LEVEL_FATAL = variables.Logger.FATAL;

	/** ERROR indicates that ERROR messages and above should be logged.
	 * This level is initialized to 800. */
	this.LEVEL_ERROR = variables.Logger.ERROR;

	/** WARNING indicates that WARNING messages and above should be logged.
     * This level is initialized to 600. */
    this.LEVEL_WARNING = variables.Logger.WARNING;

    /** INFO indicates that INFO messages and above should be logged.
     * This level is initialized to 400. */
	this.LEVEL_INFO = variables.Logger.INFO;

	/** DEBUG indicates that DEBUG messages and above should be logged.
     * This level is initialized to 200. */
	this.LEVEL_DEBUG = variables.Logger.DEBUG;

	/** TRACE indicates that TRACE messages and above should be logged.
     * This level is initialized to 100. */
	this.LEVEL_TRACE = variables.Logger.TRACE;

	/** ALL indicates that all messages should be logged. This level is initialized to Integer.MIN_VALUE. */
	this.LEVEL_ALL = variables.Logger.ALL;

	variables.Logger = "";


	variables.ESAPI = "";

	/** The jlogger object used by this class to log everything. */
    variables.jlogger = "";

    /** The module name using this log. */
    variables.moduleName = "";

    /** The application name defined in ESAPI.properties */
	variables.applicationName = "";

    /** Log the application name? */
	variables.logAppName = "";

	/** Log the server ip? */
	variables.logServerIP = "";

	/**
	 * Public constructor should only ever be called via the appropriate LogFactory
	 *
	 * @param moduleName the module name
	 */
	public org.owasp.esapi.Logger function init(required org.owasp.esapi.ESAPI ESAPI, required string moduleName) {
		variables.ESAPI = arguments.ESAPI;

		variables.applicationName = variables.ESAPI.securityConfiguration().getApplicationName();
		variables.logAppName = variables.ESAPI.securityConfiguration().getLogApplicationName();
		variables.logServerIP = variables.ESAPI.securityConfiguration().getLogServerIP();

		variables.moduleName = arguments.moduleName;
        variables.jlogger = createObject("java", "java.util.logging.Logger").getLogger(variables.applicationName & ":" & variables.moduleName);

		return this;
	}

    /**
     * Note: In this implementation, this change is not persistent,
     * meaning that if the application is restarted, the log level will revert to the level defined in the
     * ESAPI SecurityConfiguration properties file.
     */
	public void function setLevel(required numeric level) {
		try {
			variables.jlogger.setLevel(convertESAPILeveltoLoggerLevel(arguments.level));
		}
    	catch (java.lang.IllegalArgumentException e) {
   			this.error(this.SECURITY_FAILURE, "", e);
    	}
	}

	public numeric function getLevel() {
		return variables.jlogger.getLevel().intValue();
	}

	/**
	 * Converts the ESAPI logging level (a number) into the levels used by Java's logger.
	 * @param level The ESAPI to convert.
	 * @return The Java logging Level that is equivalent.
	 * @throws IllegalArgumentException if the supplied ESAPI level doesn't make a level that is currently defined.
	 */
	private function convertESAPILeveltoLoggerLevel(required numeric level) {
		switch (arguments.level) {
			case 2147483647:	/*this.LEVEL_OFF:*/     return variables.Level.OFF;
			case 1000:			/*this.LEVEL_FATAL:*/   return variables.Level.SEVERE;
			case 800:			/*this.LEVEL_ERROR:*/   return variables.JavaLoggerLevel.ERROR_LEVEL; // This is a custom level.
			case 600:			/*this.LEVEL_WARNING:*/ return variables.Level.WARNING;
			case 400:			/*this.LEVEL_INFO:*/    return variables.Level.INFO;
			case 200:			/*this.LEVEL_DEBUG:*/   return variables.Level.FINE;
			case 100:			/*this.LEVEL_TRACE:*/   return variables.Level.FINEST;
			case -2147483648:	/*this.LEVEL_ALL:*/     return variables.Level.ALL;
			default: {
				raiseException(createObject("java", "java.lang.IllegalArgumentException").init("Invalid logging level. Value was: " & arguments.level));
			}
		}
	}

	private string function convertJTypetoCFType(required type) {
		var utils = new Utils();
		if (utils.isEquals(arguments.type, this.SECURITY_SUCCESS)) {
			return "INFORMATION";
		}
		else if (utils.isEquals(arguments.type, this.SECURITY_FAILURE)) {
			return "WARNING";
		}
		else if (utils.isEquals(arguments.type, this.SECURITY_AUDIT)) {
			return "INFORMATION";
		}
		else if (utils.isEquals(arguments.type, this.EVENT_SUCCESS)) {
			return "INFORMATION";
		}
		else if (utils.isEquals(arguments.type, this.EVENT_FAILURE)) {
			return "WARNING";
		}
		else if (utils.isEquals(arguments.type, this.EVENT_UNSPECIFIED)) {
			return "INFORMATION";
		}
	}

	public void function trace(required type, required string message, throwable) {
		arguments.level = variables.Level.FINEST;
		logMessage(argumentCollection=arguments);
	}

	public void function debug(required type, required string message, throwable) {
		arguments.level = variables.Level.FINE;
		logMessage(argumentCollection=arguments);
	}

	public void function info(required type, required string message, throwable) {
		arguments.level = variables.Level.INFO;
		logMessage(argumentCollection=arguments);
	}

	public void function warning(required type, required string message, throwable) {
		arguments.level = variables.Level.WARNING;
		logMessage(argumentCollection=arguments);
	}

	public void function error(required type, required string message, throwable) {
		arguments.level = variables.Level.SEVERE;
		logMessage(argumentCollection=arguments);
	}

	public void function fatal(required type, required string message, throwable) {
		arguments.level = variables.Level.SEVERE;
		logMessage(argumentCollection=arguments);
	}

	/**
     * Log the message after optionally encoding any special characters that might be dangerous when viewed
     * by an HTML based log viewer. Also encode any carriage returns and line feeds to prevent log
     * injection attacks. This logs all the supplied parameters plus the user ID, user's source IP, a logging
     * specific session ID, and the current date/time.
     *
     * It will only log the message if the current logging level is enabled, otherwise it will
     * discard the message.
     *
     * @param level defines the set of recognized logging levels (TRACE, INFO, DEBUG, WARNING, ERROR, FATAL)
     * @param type the type of the event (SECURITY SUCCESS, SECURITY FAILURE, EVENT SUCCESS, EVENT FAILURE)
     * @param message the message
     * @param throwable the throwable
     */
    private void function logMessage(required level, required type, required string message, throwable) {

    	// Check to see if we need to log
    	if (!variables.jlogger.isLoggable(arguments.level)) return;

        // ensure there's something to log
        if (isNull(arguments.message)) {
        	arguments.message = "";
        }

        // ensure no CRLF injection into logs for forging records
        var clean = arguments.message.replace(chr(13), "_").replace(chr(10), "_");
        if (variables.ESAPI.securityConfiguration().getLogEncodingRequired()) {
        	clean = variables.ESAPI.encoder().encodeForHTML(arguments.message);
            if (!arguments.message.equals(clean)) {
                clean &= " (Encoded)";
            }
        }

		// log server, port, app name, module name -- server:80/app/module
		var appInfo = createObject("java", "java.lang.StringBuilder").init();
		var currentRequest = variables.ESAPI.httpUtilities().getCurrentRequest();
		if (!isNull(currentRequest) && isObject(currentRequest) && variables.logServerIP) {
			// local addr/port are not always accessible
			var localAddr = "";
			try { localAddr = currentRequest.getLocalAddr(); }
			catch (java.lang.AbstractMethodError e) {}
			var localPort = "";
			try { localPort = currentRequest.getLocalPort(); }
			catch (java.lang.AbstractMethodError e) {}
			appInfo.append(listAppend(localAddr, localPort, ":"));
		}
		if (variables.logAppName) {
			appInfo.append("/" & variables.applicationName);
		}
		appInfo.append("/" & variables.moduleName);

		//get the type text if it exists
		var typeInfo = "";
		if (!isNull(arguments.type)) {
			typeInfo &= arguments.type & " ";
		}

		// log the message
		var text = "[" & typeInfo & getUserInfo() & " -> " & appInfo & "] " & clean;
		if (structKeyExists(arguments, "throwable")) {
			variables.jlogger.log(arguments.level, text, arguments.throwable);
		}
		else {
			variables.jlogger.log(arguments.level, text);
		}
		writeLog(text, convertJTypetoCFType(arguments.type), true, variables.ESAPI.securityConfiguration().getLogFileName());
    }

	public boolean function isDebugEnabled() {
		return variables.jlogger.isLoggable(variables.Level.FINE);
	}

	public boolean function isErrorEnabled() {
		return variables.jlogger.isLoggable(variables.JavaLoggerLevel.ERROR_LEVEL);
	}

	public boolean function isFatalEnabled() {
		return variables.jlogger.isLoggable(variables.Level.SEVERE);
	}

	public boolean function isInfoEnabled() {
		return variables.jlogger.isLoggable(variables.Level.INFO);
	}

	public boolean function isTraceEnabled() {
		return variables.jlogger.isLoggable(variables.Level.FINEST);
	}

	public boolean function isWarningEnabled() {
		return variables.jlogger.isLoggable(variables.Level.WARNING);
	}

	public string function getUserInfo() {
		// create a random session number for the user to represent the user's 'session', if it doesn't exist already
		var sid = "";
		var httpRequest = variables.ESAPI.httpUtilities().getCurrentRequest();
		if (!isNull(httpRequest) && isObject(httpRequest)) {
			var httpSession = httpRequest.getSession(false);
			if (!isNull(httpSession) && isObject(httpSession)) {
				sid = httpSession.getAttribute("ESAPI_SESSION");
				// if there is no session ID for the user yet, we create one and store it in the user's session
				if (isNull(sid) || !len(trim(sid))) {
					sid = variables.ESAPI.randomizer().getRandomInteger(0, 1000000);
					httpSession.setAttribute("ESAPI_SESSION", sid);
				}
			}
		}

		// log user information - username:session@ipaddr
		var user = variables.ESAPI.authenticator().getCurrentUser();
		var userInfo = "";
		//TODO - Make Type Logging configurable
		if (!isNull(user)) {
			userInfo &= user.getAccountName() & ":" & sid & "@" & user.getLastHostAddress();
		}

		return userInfo;
	}

	public void function always(required type, required string message, throwable) {
		arguments.level = variables.Level.OFF;  // Seems backward, but this is what works, not Level.ALL
        logMessage(argumentCollection=arguments);
	}

	public string function toString() {
		return variables.moduleName;
	}

}