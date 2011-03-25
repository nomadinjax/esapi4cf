<cfcomponent extends="Exception" output="false" hint="A ConfigurationException should be thrown when a problem arises because of a problem in one of ESAPI's configuration files, such as a missing required property or invalid setting of a property, or missing or unreadable configuration file, etc.">


	<cffunction access="public" returntype="ConfigurationException" name="init" output="false">
		<cfargument type="String" name="s" required="true">
		<cfargument type="any" name="cause" required="false" hint="java.lang.Throwable:">
		<cfscript>
			super.init(argumentCollection=arguments);

			return this;
		</cfscript>
	</cffunction>


</cfcomponent>
