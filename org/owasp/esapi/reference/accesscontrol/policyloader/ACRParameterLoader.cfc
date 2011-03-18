<cfinterface>

	<cffunction access="public" returntype="any" name="getParameters" output="false">
		<cfargument type="any" name="config" required="true" hint="org.apache.commons.configuration.XMLConfiguration">
		<cfargument type="numeric" name="currentRule" required="true">
	</cffunction>

</cfinterface>
