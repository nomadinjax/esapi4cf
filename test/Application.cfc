<cfcomponent output="false">

	<cfscript>
		// CFESAPI only requires that sessionManagement be on
		this.name = "CFESAPI-MXUnitTest";
		this.sessionManagement = true;

		// CFESAPI does not use CFID/CFTOKEN
		this.clientManagement = false;
		this.setClientCookies = false;
	</cfscript>

</cfcomponent>
