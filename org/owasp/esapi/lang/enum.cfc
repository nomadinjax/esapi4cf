<cfcomponent output="false">

	<cfscript>
		instance.ordinal = "";
	</cfscript>

	<cffunction access="public" returntype="enum" name="init" output="false">
		<cfargument type="numeric" name="ordinal" required="true">
		<cfscript>
			instance.ordinal = arguments.ordinal;

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="ordinal" output="false">
		<cfscript>
			return instance.ordinal;
		</cfscript>
	</cffunction>


</cfcomponent>
