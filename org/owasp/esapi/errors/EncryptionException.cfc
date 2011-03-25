<cfcomponent extends="EnterpriseSecurityException" output="false">


	<cffunction access="public" returntype="EncryptionException" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="string" name="userMessage" required="false" hint="the message displayed to the user">
		<cfargument type="string" name="logMessage" required="false" hint="the message logged">
		<cfargument type="any" name="cause" required="false" hint="the cause">
		<cfscript>
			super.init(argumentCollection=arguments);

			return this;
		</cfscript>
	</cffunction>


</cfcomponent>
