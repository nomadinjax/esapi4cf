<cfcomponent extends="EnterpriseSecurityException" output="false">

	<cffunction access="public" returntype="EnterpriseSecurityException" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="string" name="userMessage" required="false">
		<cfargument type="string" name="logMessage" required="false">
		<cfargument type="any" name="cause" required="false" hint="java.lang.Throwable">
		<cfscript>
			super.init(argumentCollection=arguments);

			return this;
		</cfscript>
	</cffunction>

</cfcomponent>