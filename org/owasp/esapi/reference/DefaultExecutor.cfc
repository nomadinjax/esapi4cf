<cfcomponent implements="cfesapi.org.owasp.esapi.Executor"
             extends="cfesapi.org.owasp.esapi.util.Object" output="false">

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Executor" name="init"
	            output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			return this;
		</cfscript>

	</cffunction>


</cfcomponent>