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
/**
 * Reference implementation of the Logger interface.
 * 
 * It implements most of the recommendations defined in the Logger interface description. It does not
 * filter out any sensitive data specific to the current application or organization, such as credit 
 * cards, social security numbers, etc.  
 */
component JavaLogger extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.Logger" {

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

	/**
	 * Public constructor should only ever be called via the appropriate LogFactory
	 * 
	 * @param moduleName the module name
	 */
	
	public JavaLogger function init(required cfesapi.org.owasp.esapi.ESAPI ESAPI, required String moduleName) {
		instance.ESAPI = arguments.ESAPI;
		instance.applicationName = instance.ESAPI.securityConfiguration().getApplicationName();
		instance.logAppName = instance.ESAPI.securityConfiguration().getLogApplicationName();
		instance.logServerIP = instance.ESAPI.securityConfiguration().getLogServerIP();
	
		instance.moduleName = arguments.moduleName;
		instance.jlogger = newJava("java.util.logging.Logger").getLogger(instance.applicationName & ":" & arguments.moduleName);
	
		return this;
	}
	
	/**
	 * {@inheritDoc}
	 * Note: In this implementation, this change is not persistent,
	 * meaning that if the application is restarted, the log level will revert to the level defined in the 
	 * ESAPI SecurityConfiguration properties file.
	 */
	
	public void function setLevel(required numeric level) {
		try {
			instance.jlogger.setLevel(convertESAPILeveltoLoggerLevel(arguments.level));
		}
		catch(java.lang.IllegalArgumentException e) {
			this.error(newJava("org.owasp.esapi.Logger").SECURITY_FAILURE, "", e);
		}
	}
	
	/**
	 * {@inheritDoc}
	 * @see org.owasp.esapi.reference.Log4JLogger#getESAPILevel()
	 */
	
	public numeric function getESAPILevel() {
		return instance.jlogger.getLevel().intValue();
	}
	
	/**
	 * Converts the ESAPI logging level (a number) into the levels used by Java's logger.
	 * @param level The ESAPI to convert.
	 * @return The Java logging Level that is equivalent.
	 * @throws IllegalArgumentException if the supplied ESAPI level doesn't make a level that is currently defined.
	 */
	
	private function convertESAPILeveltoLoggerLevel(required numeric level) {
	
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
		
	}
	
	/**
	* {@inheritDoc}
	*/
	
	public void function trace(required type, required String message, throwable) {
		arguments.level = newJava("java.util.logging.Level").FINEST;
		logMessage(argumentCollection=arguments);
	}
	
	/**
	* {@inheritDoc}
	*/
	
	public void function debug(required type, required String message, throwable) {
		arguments.level = newJava("java.util.logging.Level").FINE;
		logMessage(argumentCollection=arguments);
	}
	
	/**
	* {@inheritDoc}
	*/
	
	public void function info(required type, required String message, throwable) {
		arguments.level = newJava("java.util.logging.Level").INFO;
		logMessage(argumentCollection=arguments);
	}
	
	/**
	* {@inheritDoc}
	*/
	
	public void function warning(required type, required String message, throwable) {
		arguments.level = newJava("java.util.logging.Level").WARNING;
		logMessage(argumentCollection=arguments);
	}
	
	/**
	* {@inheritDoc}
	*/
	
	public void function error(required type, required String message, throwable) {
		arguments.level = newJava("java.util.logging.Level").SEVERE;
		logMessage(argumentCollection=arguments);
	}
	
	/**
	* {@inheritDoc}
	*/
	
	public void function fatal(required type, required String message, throwable) {
		arguments.level = newJava("java.util.logging.Level").SEVERE;
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
	
	private void function logMessage(required level, required type, required String message, throwable) {
	
		// Check to see if we need to log
		if(!instance.jlogger.isLoggable(arguments.level))
			return;
	
		// ensure there's something to log
		if(isNull(arguments.message)) {
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
		local.appInfo = newJava("java.lang.StringBuilder").init();
		if(!isNull(instance.ESAPI.currentRequest()) && instance.logServerIP) {
			local.appInfo.append(instance.ESAPI.currentRequest().getLocalAddr() & ":" & instance.ESAPI.currentRequest().getLocalPort());
		}
		if(instance.logAppName) {
			local.appInfo.append("/" & instance.applicationName);
		}
		local.appInfo.append("/" & instance.moduleName);
	
		//get the type text if it exists
		local.typeInfo = "";
		if(!isNull(arguments.type)) {
			local.typeInfo &= arguments.type & " ";
		}
	
		// log the message
		if(!isNull(arguments.throwable) && isInstanceOf(arguments.throwable, "java.lang.Exception")) {
			instance.jlogger.log(arguments.level, "[" & local.typeInfo & getUserInfo() & " -> " & local.appInfo & "] " & local.clean, arguments.throwable);
		}
		else {
			instance.jlogger.log(arguments.level, "[" & local.typeInfo & getUserInfo() & " -> " & local.appInfo & "] " & local.clean);
		}
	}
	
	/**
	* {@inheritDoc}
	*/
	
	public boolean function isDebugEnabled() {
		return instance.jlogger.isLoggable(newJava("java.util.logging.Level").FINE);
	}
	
	/**
	* {@inheritDoc}
	*/
	
	public boolean function isErrorEnabled() {
		return instance.jlogger.isLoggable(newJava("org.owasp.esapi.reference.JavaLogFactory$JavaLoggerLevel").ERROR_LEVEL);
	}
	
	/**
	* {@inheritDoc}
	*/
	
	public boolean function isFatalEnabled() {
		return instance.jlogger.isLoggable(newJava("java.util.logging.Level").SEVERE);
	}
	
	/**
	* {@inheritDoc}
	*/
	
	public boolean function isInfoEnabled() {
		return instance.jlogger.isLoggable(newJava("java.util.logging.Level").INFO);
	}
	
	/**
	* {@inheritDoc}
	*/
	
	public boolean function isTraceEnabled() {
		return instance.jlogger.isLoggable(newJava("java.util.logging.Level").FINEST);
	}
	
	/**
	* {@inheritDoc}
	*/
	
	public boolean function isWarningEnabled() {
		return instance.jlogger.isLoggable(newJava("java.util.logging.Level").WARNING);
	}
	
	public String function getUserInfo() {
		// create a random session number for the user to represent the user's 'session', if it doesn't exist already
		local.sid = "";
		local.request = instance.ESAPI.httpUtilities().getCurrentRequest();
		if(!isNull(local.request)) {
			local.session = local.request.getSession(false);
			if(!isNull(local.session) && isObject(local.session)) {
				local.sid = local.session.getAttribute("ESAPI_SESSION");
				// if there is no session ID for the user yet, we create one and store it in the user's session
				if(isNull(local.sid) || local.sid == "") {
					local.sid = instance.ESAPI.randomizer().getRandomInteger(0, 1000000);
					local.session.setAttribute("ESAPI_SESSION", local.sid);
				}
			}
		}
	
		// log user information - username:session@ipaddr
		local.user = instance.ESAPI.authenticator().getCurrentUser();
		local.userInfo = "";
		//TODO - Make Type Logging configurable
		if(!isNull(local.user)) {
			local.userInfo &= local.user.getAccountName() & ":" & local.sid & "@" & local.user.getLastHostAddress();
		}
	
		return local.userInfo;
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function always(required type, required String message, throwable) {
		arguments.level = newJava("java.util.logging.Level").OFF;// Seems backward, but this is what works, not Level.ALL
		logMessage(argumentCollection=arguments);
	}
	
	public String function toString() {
		return getMetaData().fullName;
	}
	
}