<!---
/*
 * OWASP ESAPI for ColdFusion/CFML Project
 * Purpose: This is the ColdFusion/CFML language version of OWASP ESAPI.
 * License: BSD license
 *
 * @author Damon Miller
 */
--->
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" output="false" hint="ESAPI locator class is provided to make it easy to gain access to the current ESAPI classes in use. Use the set methods to override the reference implementations with instances of any custom ESAPI implementations.">

	<cfscript>
		instance.overrideConfig = "";

		static.securityConfigurationImplName = System.getProperty("cfesapi.org.owasp.esapi.SecurityConfiguration", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration");
	</cfscript>

	<cffunction access="public" returntype="void" name="clearCurrent" output="false" hint="Clears the current User, HttpRequest, and HttpResponse associated with the current thread. This method MUST be called as some containers do not properly clear threadlocal variables when the execution of a thread is complete. The suggested approach is to put this call in a finally block inside a filter. The advantages of having identity everywhere are worth the risk here.">
		<cfscript>
			authenticator().clearCurrent();
			httpUtilities().clearCurrent();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="currentRequest" output="false" hint="cfesapi.org.owasp.esapi.HttpServletRequest: Get the current HTTP Servlet Request being processed.">
		<cfscript>
			return httpUtilities().getCurrentRequest();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.HttpServletResponse" name="currentResponse" output="false" hint="Get the current HTTP Servlet Response being generated.">
		<cfscript>
			return httpUtilities().getCurrentResponse();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="AccessController" name="accessController" output="false" hint="the current ESAPI AccessController object being used to maintain the access control rules for this application.">
		<cfscript>
        	return make( securityConfiguration().getAccessControlImplementation(), "AccessController" );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Authenticator" name="authenticator" output="false" hint="the current ESAPI Authenticator object being used to authenticate users for this application.">
		<cfscript>
	        return make( securityConfiguration().getAuthenticationImplementation(), "Authenticator" );
	    </cfscript>
	</cffunction>


	<cffunction access="public" returntype="Encoder" name="encoder" output="false" hint="the current ESAPI Encoder object being used to encode and decode data for this application.">
		<cfscript>
			return make( securityConfiguration().getEncoderImplementation(), "Encoder" );
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="Encryptor" name="encryptor" output="false" hint="the current ESAPI Encryptor object being used to encrypt and decrypt data for this application.">
		<cfscript>
			return make( securityConfiguration().getEncryptionImplementation(), "Encryptor" );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Executor" name="executor" output="false" hint="the current ESAPI Executor object being used to safely execute OS commands for this application.">
		<cfscript>
        	return make( securityConfiguration().getExecutorImplementation(), "Executor" );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="HTTPUtilities" name="httpUtilities" output="false" hint="the current ESAPI HTTPUtilities object being used to safely access HTTP requests and responses for this application.">
		<cfscript>
        	return make( securityConfiguration().getHTTPUtilitiesImplementation(), "HTTPUtilities" );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="IntrusionDetector" name="intrusionDetector" output="false" hint="the current ESAPI IntrusionDetector being used to monitor for intrusions in this application.">
		<cfscript>
        	return make( securityConfiguration().getIntrusionDetectionImplementation(), "IntrusionDetector" );
        </cfscript>
	</cffunction>


	<cffunction access="private" returntype="LogFactory" name="logFactory" output="false" hint="Get the current LogFactory being used by ESAPI. If there isn't one yet, it will create one, and then return this same LogFactory from then on.">
		<cfscript>
        	return make( securityConfiguration().getLogImplementation(), "LogFactory" );
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="Logger" name="getLogger" output="false" hint="The current Logger associated with the specified module.">
		<cfargument type="String" name="moduleName" required="true" hint="The module to associate the logger with.">
		<cfscript>
			return logFactory().getLogger(arguments.moduleName);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Logger" name="log" output="false" hint="The default Logger.">
		<cfscript>
       		return logFactory().getLogger("DefaultLogger");
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Randomizer" name="randomizer" output="false" hint="the current ESAPI Randomizer being used to generate random numbers in this application.">
		<cfscript>
        	return make( securityConfiguration().getRandomizerImplementation(), "Randomizer" );
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="SecurityConfiguration" name="securityConfiguration" output="false" hint="the current ESAPI SecurityConfiguration being used to manage the security configuration for ESAPI for this application.">
		<cfscript>
			if ( isObject(instance.overrideConfig) ) {
	            return instance.overrideConfig;
	        }
	        return make( static.securityConfigurationImplName, "SecurityConfiguration" );
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="Validator" name="validator" output="false" hint="the current ESAPI Validator being used to validate data in this application.">
		<cfscript>
        	return make( securityConfiguration().getValidationImplementation(), "Validator" );
        </cfscript>
	</cffunction>


	<cffunction access="private" returntype="any" name="make" output="false">
		<cfargument type="String" name="className" required="true">
		<cfargument type="String" name="typeName" required="true">
		<cfscript>
			if (!structKeyExists(instance, arguments.typeName)) {
				if (structKeyExists(arguments, "className") && structKeyExists(arguments, "typeName")) {
					instance[arguments.typeName] = createObject('component', arguments.className).init(this);
				}
			}
			return instance[arguments.typeName];
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="override" output="false" hint="Overrides the current security configuration with a new implementation. This is meant to be used as a temporary means to alter the behavior of the ESAPI and should *NEVER* be used in a production environment as it will affect the behavior and configuration of the ESAPI *GLOBALLY*. To clear an overridden Configuration, simple call this method with null for the config parameter.">
		<cfargument type="any" name="config" required="true" hint="cfesapi.org.owasp.esapi.SecurityConfiguration">
		<cfscript>
        	instance.overrideConfig = arguments.config;
        </cfscript>
	</cffunction>


</cfcomponent>
