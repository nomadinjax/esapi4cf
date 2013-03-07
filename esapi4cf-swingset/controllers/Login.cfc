<cfcomponent output="false">

	<cffunction access="public" returntype="void" name="solution" output="false">
		<cfargument required="true" type="Struct" name="rc">
		<cfscript>
			try {
				if ( structKeyExists(arguments.rc, "logout") ) //if URL contains logout, logout
					arguments.rc.ESAPI.authenticator().logout();
				
				authenticator = arguments.rc.ESAPI.authenticator();
				//Create user for demo if user does not exist
				if(!authenticator.exists("admin")) 
					authenticator.createUser("admin", "lookatme01@", "lookatme01@");
				
				//Enable user if disabled (disabled after creation by default)
				if(!authenticator.getUserByAccountName("admin").isEnabled()) 
					authenticator.getUserByAccountName("admin").enable();
				
				// set a remember cookie
				if ( structKeyExists(arguments.rc, "remember") ) {				
					// password must be right at this point since we're logged in.
					password = arguments.rc.password;
					maxAge = ( 60 * 60 * 24 * 14 );
					token = arguments.rc.ESAPI.httpUtilities().setRememberToken( arguments.rc.ESAPI.httpUtilities().getCurrentRequest(), arguments.rc.ESAPI.httpUtilities().getCurrentResponse(), password, maxAge, "", "" );
					arguments.rc.ESAPI.currentRequest().setAttribute("message", "New remember token:" & token );
				}
			}
			catch( esapi4cf.org.owas.esapi.errors.EnterpriseSecurityException e ) {
				// Any unhandled security exceptions result in an immediate logout and login screen
				arguments.rc.ESAPI.authenticator().logout();
			}
		</cfscript>
	</cffunction>
	
</cfcomponent>