<cfcomponent hint="CFESAPI MXUnit initialization">

	<cfscript>
		// 1. Required - set an application name
		this.name = hash( "CFESAPI-MXUnit" );

		// 2. Required - turn on J2EE session management (requires J2EE Sessions be turned on in administrator)
		this.sessionManagement = true;

		// 3. Optional - turn off client management
		this.clientManagement = false;

		// 4. Optional - don't set CFID/CFTOKEN cookies
		this.setClientCookies = false;
	</cfscript>


</cfcomponent>