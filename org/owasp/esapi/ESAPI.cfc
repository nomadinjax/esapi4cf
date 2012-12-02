<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2008 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 --->
<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" output="false" hint="ESAPI locator class is provided to make it easy to gain access to the current ESAPI classes in use. Use the set methods to override the reference implementations with instances of any custom ESAPI implementations.">

	<cfscript>
		instance.ESAPI = {
			accessController="",
			authenticator="",
			encoder="",
			encryptor="",
			executor="",
			httpUtilities="",
			intrusionDetector="",
			logFactory="",
			defaultLogger="",
			randomizer="",
			securityConfiguration="",
			validator=""
		};
	</cfscript>

	<cffunction access="public" returntype="ESAPI" name="init" output="false">

		<cfscript>
			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="HttpServletRequest" name="currentRequest" output="false" hint="Get the current HTTP Servlet Request being processed.">

		<cfscript>
			return httpUtilities().getCurrentRequest();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="HttpServletResponse" name="currentResponse" output="false" hint="Get the current HTTP Servlet Response being generated.">

		<cfscript>
			return httpUtilities().getCurrentResponse();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="AccessController" name="accessController" output="false" hint="return the current ESAPI AccessController object being used to maintain the access control rules for this application.">

		<cfscript>
			if(!isObject( instance.ESAPI.accessController ))
				instance.ESAPI.accessController = createObject( "component", "cfesapi.org.owasp.esapi.reference.FileBasedAccessController" ).init( this );
			return instance.ESAPI.accessController;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAccessController" output="false" hint="Change the current ESAPI AccessController to the AccessController provided.">
		<cfargument required="true" type="AccessController" name="accessController" hint="the AccessController to set to be the current ESAPI AccessController. "/>

		<cfscript>
			instance.ESAPI.accessController = arguments.accessController;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Authenticator" name="authenticator" output="false" hint="return the current ESAPI Authenticator object being used to authenticate users for this application.">

		<cfscript>
			if(!isObject( instance.ESAPI.authenticator ))
				instance.ESAPI.authenticator = createObject( "component", "cfesapi.org.owasp.esapi.reference.FileBasedAuthenticator" ).init( this );
			return instance.ESAPI.authenticator;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAuthenticator" output="false" hint="Change the current ESAPI Authenticator to the Authenticator provided.">
		<cfargument required="true" type="Authenticator" name="authenticator" hint="the Authenticator to set to be the current ESAPI Authenticator. "/>

		<cfscript>
			instance.ESAPI.authenticator = arguments.authenticator;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Encoder" name="encoder" output="false" hint="return the current ESAPI Encoder object being used to encode and decode data for this application.">

		<cfscript>
			if(!isObject( instance.ESAPI.encoder ))
				instance.ESAPI.encoder = createObject( "component", "cfesapi.org.owasp.esapi.reference.DefaultEncoder" ).init( this );
			return instance.ESAPI.encoder;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setEncoder" output="false" hint="Change the current ESAPI Encoder to the Encoder provided.">
		<cfargument required="true" type="Encoder" name="encoder" hint="the Encoder to set to be the current ESAPI Encoder."/>

		<cfscript>
			instance.ESAPI.encoder = arguments.encoder;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Encryptor" name="encryptor" output="false" hint="return the current ESAPI Encryptor object being used to encrypt and decrypt data for this application.">

		<cfscript>
			if(!isObject( instance.ESAPI.encryptor ))
				instance.ESAPI.encryptor = createObject( "component", "cfesapi.org.owasp.esapi.reference.JavaEncryptor" ).init( this );
			return instance.ESAPI.encryptor;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setEncryptor" output="false" hint="Change the current ESAPI Encryptor to the Encryptor provided.">
		<cfargument required="true" type="Encryptor" name="encryptor" hint="the Encryptor to set to be the current ESAPI Encryptor."/>

		<cfscript>
			instance.ESAPI.encryptor = arguments.encryptor;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Executor" name="executor" output="false" hint="return the current ESAPI Executor object being used to safely execute OS commands for this application.">

		<cfscript>
			if(!isObject( instance.ESAPI.executor ))
				instance.ESAPI.executor = createObject( "component", "cfesapi.org.owasp.esapi.reference.DefaultExecutor" ).init( this );
			return instance.ESAPI.executor;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setExecutor" output="false" hint="Change the current ESAPI Executor to the Executor provided.">
		<cfargument required="true" type="Executor" name="executor" hint="the Executor to set to be the current ESAPI Executor."/>

		<cfscript>
			instance.ESAPI.executor = arguments.executor;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="HTTPUtilities" name="httpUtilities" output="false" hint="return the current ESAPI HTTPUtilities object being used to safely access HTTP requests and responses for this application.">

		<cfscript>
			if(!isObject( instance.ESAPI.httpUtilities ))
				instance.ESAPI.httpUtilities = createObject( "component", "cfesapi.org.owasp.esapi.reference.DefaultHTTPUtilities" ).init( this );
			return instance.ESAPI.httpUtilities;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setHttpUtilities" output="false" hint="Change the current ESAPI HTTPUtilities object to the HTTPUtilities object provided.">
		<cfargument required="true" type="HTTPUtilities" name="httpUtilities" hint="the HTTPUtilities object to set to be the current ESAPI HTTPUtilities object."/>

		<cfscript>
			instance.ESAPI.httpUtilities = arguments.httpUtilities;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="IntrusionDetector" name="intrusionDetector" output="false" hint="return the current ESAPI IntrusionDetector being used to monitor for intrusions in this application.">

		<cfscript>
			if(!isObject( instance.ESAPI.intrusionDetector ))
				instance.ESAPI.intrusionDetector = createObject( "component", "cfesapi.org.owasp.esapi.reference.DefaultIntrusionDetector" ).init( this );
			return instance.ESAPI.intrusionDetector;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setIntrusionDetector" output="false" hint="Change the current ESAPI IntrusionDetector to the IntrusionDetector provided.">
		<cfargument required="true" type="IntrusionDetector" name="intrusionDetector" hint="the IntrusionDetector to set to be the current ESAPI IntrusionDetector."/>

		<cfscript>
			instance.ESAPI.intrusionDetector = arguments.intrusionDetector;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="LogFactory" name="logFactory" output="false" hint="Get the current LogFactory being used by ESAPI. If there isn't one yet, it will create one, and then return this same LogFactory from then on.">

		<cfscript>
			if(!isObject( instance.ESAPI.logFactory ) || instance.applicationName != securityConfiguration().getApplicationName()) {
				instance.applicationName = securityConfiguration().getApplicationName();
				if(securityConfiguration().getLogDefaultLog4J()) {
					instance.ESAPI.logFactory = createObject( "component", "cfesapi.org.owasp.esapi.reference.Log4JLogFactory" ).init( this, instance.applicationName );
				}
				else {
					instance.ESAPI.logFactory = createObject( "component", "cfesapi.org.owasp.esapi.reference.JavaLogFactory" ).init( this, instance.applicationName );
				}
			}
			return instance.ESAPI.logFactory;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Logger" name="getLogger" output="false" hint="return The current Logger associated with the specified module.">
		<cfargument required="true" type="String" name="moduleName" hint="The module to associate the logger with."/>

		<cfscript>
			return logFactory().getLogger( arguments.moduleName );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Logger" name="logger" output="false" hint="The default Logger.">

		<cfscript>
			if(!isObject( instance.ESAPI.defaultLogger ))
				instance.ESAPI.defaultLogger = logFactory().getLogger( "DefaultLogger" );
			return instance.ESAPI.defaultLogger;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setLogFactory" output="false" hint="Change the current ESAPI LogFactory to the LogFactory provided.">
		<cfargument required="true" type="LogFactory" name="factory" hint="the LogFactory to set to be the current ESAPI LogFactory."/>

		<cfscript>
			instance.ESAPI.logFactory = arguments.factory;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Randomizer" name="randomizer" output="false" hint="return the current ESAPI Randomizer being used to generate random numbers in this application.">

		<cfscript>
			if(!isObject( instance.ESAPI.randomizer ))
				instance.ESAPI.randomizer = createObject( "component", "cfesapi.org.owasp.esapi.reference.DefaultRandomizer" ).init( this );
			return instance.ESAPI.randomizer;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setRandomizer" output="false" hint="Change the current ESAPI Randomizer to the Randomizer provided.">
		<cfargument required="true" type="Randomizer" name="randomizer" hint="the Randomizer to set to be the current ESAPI Randomizer."/>

		<cfscript>
			instance.ESAPI.randomizer = arguments.randomizer;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="SecurityConfiguration" name="securityConfiguration" output="false" hint="return the current ESAPI SecurityConfiguration being used to manage the security configuration for ESAPI for this application.">

		<cfscript>
			if(!isObject( instance.ESAPI.securityConfiguration ))
				instance.ESAPI.securityConfiguration = createObject( "component", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration" ).init( this );
			return instance.ESAPI.securityConfiguration;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setSecurityConfiguration" output="false" hint="Change the current ESAPI SecurityConfiguration to the SecurityConfiguration provided.">
		<cfargument required="true" type="SecurityConfiguration" name="securityConfiguration" hint="the SecurityConfiguration to set to be the current ESAPI SecurityConfiguration."/>

		<cfscript>
			instance.ESAPI.securityConfiguration = arguments.securityConfiguration;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Validator" name="validator" output="false" hint="return the current ESAPI Validator being used to validate data in this application.">

		<cfscript>
			if(!isObject( instance.ESAPI.validator ))
				instance.ESAPI.validator = createObject( "component", "cfesapi.org.owasp.esapi.reference.DefaultValidator" ).init( this );
			return instance.ESAPI.validator;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setValidator" output="false" hint="Change the current ESAPI Validator to the Validator provided.">
		<cfargument required="true" type="Validator" name="validator" hint="the Validator to set to be the current ESAPI Validator."/>

		<cfscript>
			instance.ESAPI.validator = arguments.validator;
		</cfscript>

	</cffunction>

</cfcomponent>