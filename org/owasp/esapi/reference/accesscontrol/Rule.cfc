<cfcomponent output="false" hint="The Class Rule.">

	<cfscript>
		this.path = "";
		this.roles = [];
		this.allow = false;
		this.clazz = "";
		this.actions = [];
	</cfscript>

	<cffunction access="package" returntype="Rule" name="init" output="false" hint="Creates a new Rule object.">
		<cfscript>
			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="toString" output="false">
		<cfscript>
			return "URL:" & this.path & " | " & this.roles & " | " & (this.allow ? "allow" : "deny");
		</cfscript>
	</cffunction>


</cfcomponent>
