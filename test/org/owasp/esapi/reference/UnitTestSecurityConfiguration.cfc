<cfcomponent extends="cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration" output="false">


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.SecurityConfiguration" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration" name="cfg" required="false">
		<cfscript>
			super.init(arguments.ESAPI, arguments.cfg.getESAPIProperties());

	        return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setLogImplementation" output="false">
		<cfargument type="String" name="v" required="true">
		<cfscript>
    		getESAPIProperties().setProperty(this.LOG_IMPLEMENTATION, arguments.v);
    	</cfscript>
	</cffunction>


</cfcomponent>
