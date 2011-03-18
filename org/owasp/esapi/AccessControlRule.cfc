<cfinterface>

	<cffunction access="public" returntype="void" name="setPolicyParameters" output="false">
		<cfargument type="any" name="policyParameter" required="true">
	</cffunction>


	<cffunction access="public" returntype="any" name="getPolicyParameters" output="false">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isAuthorized" output="false">
		<cfargument type="any" name="runtimeParameter" required="true">
	</cffunction>

</cfinterface>
