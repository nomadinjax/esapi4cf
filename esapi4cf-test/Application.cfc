<cfcomponent hint="esapi4cf MXUnit initialization">

	<cfscript>
		this.mappings = {
			"esapi4cf" = "/esapi4cf/esapi4cf",
			"esapi4cf-test" = "/esapi4cf/esapi4cf-test"	
		};

		// 1. Required - set an application name
		this.name = hash( "esapi4cf-MXUnit" );

		// 2. Required - turn on J2EE session management (requires J2EE Sessions be turned on in administrator)
		this.sessionManagement = true;

		// 3. Optional - turn off client management
		this.clientManagement = false;

		// 4. Optional - don't set CFID/CFTOKEN cookies
		this.setClientCookies = false;
	</cfscript>


</cfcomponent>