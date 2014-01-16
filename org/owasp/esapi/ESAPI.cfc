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
<cfcomponent extends="org.owasp.esapi.util.Object" output="false" hint="ESAPI locator class is provided to make it easy to gain access to the current ESAPI classes in use. Use the set methods to override the reference implementations with instances of any custom ESAPI implementations.">

	<cfscript>
		variables.instance = {};
		variables.instance.applicationName = "";
		variables.instance.accessController = "";
		variables.instance.authenticator = "";
		variables.instance.encoder = "";
		variables.instance.encryptor = "";
		variables.instance.executor = "";
		variables.instance.httpUtilities = "";
		variables.instance.intrusionDetector = "";
		variables.instance.logFactory = "";
		variables.instance.defaultLogger = "";
		variables.instance.randomizer = "";
		variables.instance.securityConfiguration = "";
		variables.instance.validator = "";
		variables.instance.resourceBundle = "";

		variables.resourceDirectory = "";
	</cfscript>

	<cffunction access="public" returntype="ESAPI" name="init" output="false">
		<cfargument type="String" name="resourceDirectory">

		<cfscript>
			if (structKeyExists(arguments, "resourceDirectory")) {
				variables.resourceDirectory = arguments.resourceDirectory;
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="org.owasp.esapi.util.HttpServletRequest" name="currentRequest" output="false"
	            hint="Get the current HTTP Servlet Request being processed.">

		<cfscript>
			return this.httpUtilities().getCurrentRequest();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="org.owasp.esapi.util.HttpServletResponse" name="currentResponse" output="false"
	            hint="Get the current HTTP Servlet Response being generated.">

		<cfscript>
			return this.httpUtilities().getCurrentResponse();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="AccessController" name="accessController" output="false"
	            hint="return the current ESAPI AccessController object being used to maintain the access control rules for this application.">

		<cfscript>
			if(!isObject(variables.instance.accessController)) {
				variables.instance.accessController = createObject("component", "org.owasp.esapi.reference.FileBasedAccessController").init(this);
			}
			return variables.instance.accessController;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAccessController" output="false"
	            hint="Change the current ESAPI AccessController to the AccessController provided.">
		<cfargument required="true" type="AccessController" name="accessController" hint="the AccessController to set to be the current ESAPI AccessController. "/>

		<cfscript>
			variables.instance.accessController = arguments.accessController;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Authenticator" name="authenticator" output="false"
	            hint="return the current ESAPI Authenticator object being used to authenticate users for this application.">

		<cfscript>
			if(!isObject(variables.instance.authenticator)) {
				variables.instance.authenticator = createObject("component", "org.owasp.esapi.reference.FileBasedAuthenticator").init(this);
			}
			return variables.instance.authenticator;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAuthenticator" output="false"
	            hint="Change the current ESAPI Authenticator to the Authenticator provided.">
		<cfargument required="true" type="Authenticator" name="authenticator" hint="the Authenticator to set to be the current ESAPI Authenticator. "/>

		<cfscript>
			variables.instance.authenticator = arguments.authenticator;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Encoder" name="encoder" output="false"
	            hint="return the current ESAPI Encoder object being used to encode and decode data for this application.">

		<cfscript>
			if(!isObject(variables.instance.encoder)) {
				variables.instance.encoder = createObject("component", "org.owasp.esapi.reference.DefaultEncoder").init(this);
			}
			return variables.instance.encoder;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setEncoder" output="false"
	            hint="Change the current ESAPI Encoder to the Encoder provided.">
		<cfargument required="true" type="Encoder" name="encoder" hint="the Encoder to set to be the current ESAPI Encoder."/>

		<cfscript>
			variables.instance.encoder = arguments.encoder;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Encryptor" name="encryptor" output="false"
	            hint="return the current ESAPI Encryptor object being used to encrypt and decrypt data for this application.">

		<cfscript>
			if(!isObject(variables.instance.encryptor)) {
				variables.instance.encryptor = createObject("component", "org.owasp.esapi.reference.JavaEncryptor").init(this);
			}
			return variables.instance.encryptor;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setEncryptor" output="false"
	            hint="Change the current ESAPI Encryptor to the Encryptor provided.">
		<cfargument required="true" type="Encryptor" name="encryptor" hint="the Encryptor to set to be the current ESAPI Encryptor."/>

		<cfscript>
			variables.instance.encryptor = arguments.encryptor;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Executor" name="executor" output="false"
	            hint="return the current ESAPI Executor object being used to safely execute OS commands for this application.">

		<cfscript>
			if(!isObject(variables.instance.executor)) {
				variables.instance.executor = createObject("component", "org.owasp.esapi.reference.DefaultExecutor").init(this);
			}
			return variables.instance.executor;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setExecutor" output="false"
	            hint="Change the current ESAPI Executor to the Executor provided.">
		<cfargument required="true" type="Executor" name="executor" hint="the Executor to set to be the current ESAPI Executor."/>

		<cfscript>
			variables.instance.executor = arguments.executor;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="HTTPUtilities" name="httpUtilities" output="false"
	            hint="return the current ESAPI HTTPUtilities object being used to safely access HTTP requests and responses for this application.">

		<cfscript>
			if(!isObject(variables.instance.httpUtilities)) {
				variables.instance.httpUtilities = createObject("component", "org.owasp.esapi.reference.DefaultHTTPUtilities").init(this);
			}
			return variables.instance.httpUtilities;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setHttpUtilities" output="false"
	            hint="Change the current ESAPI HTTPUtilities object to the HTTPUtilities object provided.">
		<cfargument required="true" type="HTTPUtilities" name="httpUtilities" hint="the HTTPUtilities object to set to be the current ESAPI HTTPUtilities object."/>

		<cfscript>
			variables.instance.httpUtilities = arguments.httpUtilities;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="IntrusionDetector" name="intrusionDetector" output="false"
	            hint="return the current ESAPI IntrusionDetector being used to monitor for intrusions in this application.">

		<cfscript>
			if(!isObject(variables.instance.intrusionDetector)) {
				variables.instance.intrusionDetector = createObject("component", "org.owasp.esapi.reference.DefaultIntrusionDetector").init(this);
			}
			return variables.instance.intrusionDetector;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setIntrusionDetector" output="false"
	            hint="Change the current ESAPI IntrusionDetector to the IntrusionDetector provided.">
		<cfargument required="true" type="IntrusionDetector" name="intrusionDetector" hint="the IntrusionDetector to set to be the current ESAPI IntrusionDetector."/>

		<cfscript>
			variables.instance.intrusionDetector = arguments.intrusionDetector;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="LogFactory" name="logFactory" output="false"
	            hint="Get the current LogFactory being used by ESAPI. If there isn't one yet, it will create one, and then return this same LogFactory from then on.">

		<cfscript>
			if(!isObject(variables.instance.logFactory) || variables.instance.applicationName != this.securityConfiguration().getApplicationName()) {
				variables.instance.applicationName = this.securityConfiguration().getApplicationName();
				if(this.securityConfiguration().getLogDefaultLog4J()) {
					variables.instance.logFactory = createObject("component", "org.owasp.esapi.reference.Log4JLogFactory").init(this, variables.instance.applicationName);
				}
				else {
					variables.instance.logFactory = createObject("component", "org.owasp.esapi.reference.JavaLogFactory").init(this, variables.instance.applicationName);
				}
			}
			return variables.instance.logFactory;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Logger" name="getLogger" output="false"
	            hint="return The current Logger associated with the specified module.">
		<cfargument required="true" type="String" name="moduleName" hint="The module to associate the logger with."/>

		<cfscript>
			return this.logFactory().getLogger(arguments.moduleName);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Logger" name="logger" output="false"
	            hint="The default Logger.">

		<cfscript>
			if(!isObject(variables.instance.defaultLogger)) {
				variables.instance.defaultLogger = this.logFactory().getLogger("DefaultLogger");
			}
			return variables.instance.defaultLogger;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLogFactory" output="false"
	            hint="Change the current ESAPI LogFactory to the LogFactory provided.">
		<cfargument required="true" type="LogFactory" name="factory" hint="the LogFactory to set to be the current ESAPI LogFactory."/>

		<cfscript>
			variables.instance.logFactory = arguments.factory;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Randomizer" name="randomizer" output="false"
	            hint="return the current ESAPI Randomizer being used to generate random numbers in this application.">

		<cfscript>
			if(!isObject(variables.instance.randomizer)) {
				variables.instance.randomizer = createObject("component", "org.owasp.esapi.reference.DefaultRandomizer").init(this);
			}
			return variables.instance.randomizer;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setRandomizer" output="false"
	            hint="Change the current ESAPI Randomizer to the Randomizer provided.">
		<cfargument required="true" type="Randomizer" name="randomizer" hint="the Randomizer to set to be the current ESAPI Randomizer."/>

		<cfscript>
			variables.instance.randomizer = arguments.randomizer;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="SecurityConfiguration" name="securityConfiguration" output="false"
	            hint="return the current ESAPI SecurityConfiguration being used to manage the security configuration for ESAPI for this application.">

		<cfscript>
			if(!isObject(variables.instance.securityConfiguration)) {
				if (len(trim(variables.resourceDirectory))) {
					variables.instance.securityConfiguration = createObject("component", "org.owasp.esapi.reference.DefaultSecurityConfiguration").init(this, variables.resourceDirectory);
				}
				else {
					variables.instance.securityConfiguration = createObject("component", "org.owasp.esapi.reference.DefaultSecurityConfiguration").init(this);
				}
			}
			return variables.instance.securityConfiguration;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setSecurityConfiguration" output="false"
	            hint="Change the current ESAPI SecurityConfiguration to the SecurityConfiguration provided.">
		<cfargument required="true" type="SecurityConfiguration" name="securityConfiguration" hint="the SecurityConfiguration to set to be the current ESAPI SecurityConfiguration."/>

		<cfscript>
			variables.instance.securityConfiguration = arguments.securityConfiguration;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Validator" name="validator" output="false"
	            hint="return the current ESAPI Validator being used to validate data in this application.">

		<cfscript>
			if(!isObject(variables.instance.validator)) {
				variables.instance.validator = createObject("component", "org.owasp.esapi.reference.DefaultValidator").init(this);
			}
			return variables.instance.validator;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setValidator" output="false"
	            hint="Change the current ESAPI Validator to the Validator provided.">
		<cfargument required="true" type="Validator" name="validator" hint="the Validator to set to be the current ESAPI Validator."/>

		<cfscript>
			variables.instance.validator = arguments.validator;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="ResourceBundle" name="resourceBundle" output="false"
	            hint="return the current ESAPI ResourceBundle being used to translate error messages in this application.">

		<cfscript>
			if(!isObject(variables.instance.resourceBundle)) {
				variables.instance.resourceBundle = createObject("component", "org.owasp.esapi.reference.DefaultResourceBundle").init(this);
			}
			return variables.instance.resourceBundle;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setResourceBundle" output="false"
	            hint="Change the current ESAPI ResourceBundle to the ResourceBundle provided.">
		<cfargument required="true" type="ResourceBundle" name="resourceBundle" hint="the ResourceBundle to set to be the current ESAPI ResourceBundle."/>

		<cfscript>
			variables.instance.resourceBundle = arguments.resourceBundle;
		</cfscript>

	</cffunction>

</cfcomponent>
