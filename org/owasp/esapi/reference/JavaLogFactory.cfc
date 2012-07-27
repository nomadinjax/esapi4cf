<!---
 * Reference implementation of the LogFactory and Logger interfaces. This implementation uses the Java logging package, and marks each
 * log message with the currently logged in user and the word "SECURITY" for security related events. See the
 * <a href="JavaLogFactory.JavaLogger.html">JavaLogFactory.JavaLogger</a> Javadocs for the details on the JavaLogger reference implementation.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.LogFactory
 * @see org.owasp.esapi.reference.JavaLogFactory.JavaLogger
 --->
<cfcomponent implements="cfesapi.org.owasp.esapi.LogFactory" extends="cfesapi.org.owasp.esapi.util.Object" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.applicationName = "";

		instance.loggersMap = {};
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.LogFactory" name="init" output="false"
	            hint="Constructor for this implementation of the LogFactory interface.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" type="String" name="applicationName" hint="The name of this application this logger is being constructed for."/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.applicationName = applicationName;
			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Logger" name="getLogger" output="false">
		<cfargument required="true" type="String" name="moduleName"/>

		<cfscript>
			var local = {};
			// If a logger for this module already exists, we return the same one, otherwise we create a new one.
			if(structKeyExists( instance.loggersMap, arguments.moduleName )) {
				local.moduleLogger = instance.loggersMap.get( arguments.moduleName );
			}
			if(!structKeyExists( local, "moduleLogger" )) {
				local.moduleLogger = createObject( "component", "JavaLogger" ).init( instance.ESAPI, instance.applicationName, arguments.moduleName );
				instance.loggersMap.put( arguments.moduleName, local.moduleLogger );
			}
			return local.moduleLogger;
		</cfscript>

	</cffunction>

</cfcomponent>