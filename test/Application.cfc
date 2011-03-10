<cfcomponent output="false">

	<cfscript>
		// NOTE: these both must be set for tests to run properly
		// CFESAPI itself only requires that sessionManagement be on
		this.name = "CFESAPI-MXUnit";
		this.sessionManagement = true;

		// CFESAPI does not use CFID/CFTOKEN
		this.clientManagement = false;
		this.setClientCookies = false;
	</cfscript>

</cfcomponent>
