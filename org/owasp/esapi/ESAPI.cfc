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
<cfcomponent displayname="ESAPI" extends="cfesapi.org.owasp.esapi.lang.Object" output="false" hint="ESAPI locator class is provided to make it easy to gain access to the current ESAPI classes in use. Use the set methods to override the reference implementations with instances of any custom ESAPI implementations.">

	<cfscript>
		instance.securityConfigurationImplName = newJava("java.lang.System").getProperty("cfesapi.org.owasp.esapi.SecurityConfiguration", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration");
	</cfscript>

	<cffunction access="public" returntype="void" name="clearCurrent" output="false"
	            hint="Clears the current User, HttpRequest, and HttpResponse associated with the current thread. This method MUST be called as some containers do not properly clear threadlocal variables when the execution of a thread is complete. The suggested approach is to put this call in a finally block inside a filter. The advantages of having identity everywhere are worth the risk here.">

		<cfscript>
			authenticator().clearCurrent();
			httpUtilities().clearCurrent();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="currentRequest" output="false"
	            hint="Get the current HTTP Servlet Request being processed.">

		<cfscript>
			return httpUtilities().getCurrentRequest();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="currentResponse" output="false"
	            hint="Get the current HTTP Servlet Response being generated.">

		<cfscript>
			return httpUtilities().getCurrentResponse();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.AccessController" name="accessController" output="false"
	            hint="The current ESAPI AccessController object being used to maintain the access control rules for this application.">

		<cfscript>
			return make(securityConfiguration().getAccessControlImplementation(), "AccessController");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Authenticator" name="authenticator" output="false"
	            hint="The current ESAPI Authenticator object being used to authenticate users for this application.">

		<cfscript>
			return make(securityConfiguration().getAuthenticationImplementation(), "Authenticator");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Encoder" name="encoder" output="false"
	            hint="The current ESAPI Encoder object being used to encode and decode data for this application.">

		<cfscript>
			return make(securityConfiguration().getEncoderImplementation(), "Encoder");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Encryptor" name="encryptor" output="false"
	            hint="The current ESAPI Encryptor object being used to encrypt and decrypt data for this application.">

		<cfscript>
			return make(securityConfiguration().getEncryptionImplementation(), "Encryptor");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Executor" name="executor" output="false"
	            hint="The current ESAPI Executor object being used to safely execute OS commands for this application.">

		<cfscript>
			return make(securityConfiguration().getExecutorImplementation(), "Executor");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.HTTPUtilities" name="httpUtilities" output="false"
	            hint="The current ESAPI HTTPUtilities object being used to safely access HTTP requests and responses for this application.">

		<cfscript>
			return make(securityConfiguration().getHTTPUtilitiesImplementation(), "HTTPUtilities");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.IntrusionDetector" name="intrusionDetector" output="false"
	            hint="The current ESAPI IntrusionDetector being used to monitor for intrusions in this application.">

		<cfscript>
			return make(securityConfiguration().getIntrusionDetectionImplementation(), "IntrusionDetector");
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="cfesapi.org.owasp.esapi.LogFactory" name="logFactory" output="false"
	            hint="Get the current LogFactory being used by ESAPI. If there isn't one yet, it will create one, and then return this same LogFactory from then on.">

		<cfscript>
			return make(securityConfiguration().getLogImplementation(), "LogFactory");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Logger" name="getLogger" output="false"
	            hint="The current Logger associated with the specified module.">
		<cfargument required="true" type="String" name="moduleName" hint="The module to associate the logger with."/>

		<cfscript>
			return logFactory().getLogger(arguments.moduleName);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Logger" name="logESAPI" output="false"
	            hint="The default Logger.">

		<cfscript>
			return logFactory().getLogger("DefaultLogger");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Randomizer" name="randomizer" output="false"
	            hint="The current ESAPI Randomizer being used to generate random numbers in this application.">

		<cfscript>
			return make(securityConfiguration().getRandomizerImplementation(), "Randomizer");
		</cfscript>

	</cffunction>

	<cfscript>
		instance.overrideConfig = "";
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.SecurityConfiguration" name="securityConfiguration" output="false"
	            hint="The current ESAPI SecurityConfiguration being used to manage the security configuration for ESAPI for this application.">
		<cfset var local = {}/>

		<cfscript>
			// copy the volatile into a non-volatile to prevent TOCTTOU race condition
			local.override = instance.overrideConfig;
			if(isObject(local.override)) {
				return local.override;
			}

			return make(instance.securityConfigurationImplName, "SecurityConfiguration");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Validator" name="validator" output="false"
	            hint="The current ESAPI Validator being used to validate data in this application.">

		<cfscript>
			return make(securityConfiguration().getValidationImplementation(), "Validator");
		</cfscript>

	</cffunction>

	<!---
	// TODO: This should probably use the SecurityManager or some value within the current
	// securityConfiguration to determine if this method is allowed to be called. This could
	// allow for unit tests internal to ESAPI to modify the configuration for the purpose of
	// testing stuff, and allow developers to allow this in development environments but make
	// it so the securityConfiguration implementation *cannot* be modified in production environments.
	//
	// The purpose of this method is to replace the functionality provided by the setSecurityConfiguration
	// method that is no longer on this class, and allow the context configuration of the ESAPI
	// to be modified at Runtime.
	--->

	<cffunction access="public" returntype="String" name="initializeESAPI" output="false">
		<cfargument required="true" type="String" name="impl"/>

		<cfset var local = {}/>

		<cfscript>
			local.oldImpl = instance.securityConfigurationImplName;
			instance.securityConfigurationImplName = arguments.impl;
			return local.oldImpl;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="override" output="false"
	            hint="Overrides the current security configuration with a new implementation. This is meant to be used as a temporary means to alter the behavior of the ESAPI and should *NEVER* be used in a production environment as it will affect the behavior and configuration of the ESAPI *GLOBALLY*. To clear an overridden Configuration, simple call this method with null for the config parameter.">
		<cfargument required="true" name="config"/>

		<cfscript>
			instance.overrideConfig = arguments.config;
		</cfscript>

	</cffunction>

	<cfscript>
		instance.make = {};
	</cfscript>

	<cffunction access="private" name="make" output="false" hint="Create an object based on the className parameter.">
		<cfargument required="true" type="String" name="className" hint="The name of the class to construct. Should be a fully qualified name."/>
		<cfargument required="true" type="String" name="typeName" hint="A type name used in error messages / exceptions."/>

		<cfset var local = {}/>

		<cfscript>
			local.obj = "";
			local.errMsg = "";

			if(!structKeyExists(arguments, "className") || "" == arguments.className) {
				throwError(IllegalArgumentException.init("Classname cannot be null or empty."));
			}
			if(!structKeyExists(arguments, "typeName") || "" == arguments.typeName) {
				// No big deal...just use "[unknown?]" for this as it's only for an err msg.
				arguments.typeName = "[unknown?]";// CHECKME: Any better suggestions?
			}

			if(!structKeyExists(instance.make, arguments.typeName)) {
				instance.make[arguments.typeName] = newComponent(arguments.className).init(this);
			}

			return instance.make[arguments.typeName];
		</cfscript>

	</cffunction>

</cfcomponent>