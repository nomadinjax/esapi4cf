<cfcomponent output="false">


	<cffunction access="public" returntype="void" name="forward" output="false">
		<cfargument type="ServletRequest" name="request" required="true">
		<cfargument type="ServletResponse" name="response" required="true">
		<cfscript>
    		System.out.println( "Forwarding" );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="include" output="false">
		<cfargument type="ServletRequest" name="request" required="true">
		<cfargument type="ServletResponse" name="response" required="true">
		<cfscript>
    		System.out.println( "Including" );
    	</cfscript>
	</cffunction>


</cfcomponent>
