<cfcomponent output="false">

	<cfscript>
		this.path = "";
		this.roles = [];
		this.allow = false;
		this.clazz = "";
		this.actions = [];
	</cfscript>

	<cffunction access="public" returntype="FileBasedAccessController$Rule" name="init" output="false">

		<cfscript>
			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="toStringData" output="false">

		<cfscript>
			return "URL:" & this.path & " | " & arrayToList( this.roles ) & " | " & iif( this.allow, de( "allow" ), de( "deny" ) );
		</cfscript>

	</cffunction>

</cfcomponent>