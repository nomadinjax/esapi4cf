<cfcomponent output="false">

	<cfscript>
		// CFESAPI only requires that sessionManagement be on
		this.name = "CFESAPITestingSuite" & hash(getCurrentTemplatePath());
		this.sessionManagement = true;
		this.sessionTimeout = createTimeSpan(0,0,30,0);

		// CFESAPI does not use CFID/CFTOKEN
		this.clientManagement = false;
		this.setClientCookies = false;
	</cfscript>
 
</cfcomponent>
