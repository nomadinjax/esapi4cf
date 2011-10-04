<cfcomponent extends="cfesapi.demo.fba.filters.ApplicationFilter" output="false">

	<cfscript>
		instance.obfuscate = [ "password" ];
	</cfscript>
 
	<cffunction access="public" returntype="void" name="onRequest" output="true">
		<cfargument type="String" name="targetPage" required="true">
		<cfscript>
			setupESAPI();
			
			// attempt to retrieve logged in user or log them in if credentials are provided
			try {
				ESAPI().authenticator().login();
			}
			/*
			 * "Authentication failed"
			 * 
			 * If any of the below conditions occur, an AuthenticationCredentialsException will be thrown
			 * - The username and/or password are blank
			 * - The username does not exist
			 */
			catch (cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e ) {
				ESAPI().authenticator().logout();
				// normally you would want to hide the true error with a generic
				//ESAPI().currentRequest().setAttribute("message", "Authentication failed");
				ESAPI().currentRequest().setAttribute("message", e.message & " - " & e.detail);
				include "../includes/login.cfm";
				return;	
			}
			/*
			 * "Attempt to login with an insecure request"
			 * 
			 * If any of the below conditions fail, an AuthenticationException will be thrown
			 * - A secure (SSL) connection via HTTPS is required for all requests that access the authenticator().login() method
			 * - During the credential authentication request, username/password validation, the request must be sent via the POST method - credential authentication via GET is not allowed!
			 */
			catch( cfesapi.org.owasp.esapi.errors.AuthenticationException e ) {
				ESAPI().authenticator().logout();
				// normally you would want to hide the true error with a generic
				//ESAPI().currentRequest().setAttribute("message", "Authentication failed");
				ESAPI().currentRequest().setAttribute("message", e.message & " - " & e.detail);
				include "../includes/login.cfm";
				return;
			}
			/* 
			 * "Host change"
			 * 
			 * If a user's session jumps from one host address to another host address, an AuthenticationHostException will be thrown
			 */
			// this should not occur // catch (cfesapi.org.owasp.esapi.errors.AuthenticationHostException e ) {}
			
			/* 
			 * "Login failed"
			 * 
			 * If any of the below conditions occur, an AuthenticationLoginException will be thrown
			 * - Missing password [DefaultUser]
			 * - Disabled user attempt to login [DefaultUser]
			 * - Locked user attempt to login [DefaultUser]
			 * - Expired user attempt to login [DefaultUser]
			 * - Incorrect password provided [DefaultUser]
* 			 * - Anonymous user cannot be set to current user [AbstractAuthenticator]
			 * - Disabled user cannot be set to current user [AbstractAuthenticator]
			 * - Locked user cannot be set to current user [AbstractAuthenticator]
			 * - Expired user cannot be set to current user [AbstractAuthenticator]
			 * - Session inactivity timeout [AbstractAuthenticator]
			 * - Session absolute timeout [AbstractAuthenticator]
			 */
			catch( cfesapi.org.owasp.esapi.errors.AuthenticationLoginException e ) {
				ESAPI().authenticator().logout();
				// normally you would want to hide the true error with a generic
				//ESAPI().currentRequest().setAttribute("message", "Authentication failed");
				ESAPI().currentRequest().setAttribute("message", e.message & " - " & e.detail);
				include "../includes/login.cfm";
				return;
			}
			 
			if (structKeyExists(url, "logout")) {
				ESAPI().authenticator().logout();
				location("../index.cfm", false);
				return;
			}

			// log this request, obfuscating any parameters defined
			ESAPI().httpUtilities().logHTTPRequest(ESAPI().currentRequest(), application["logger"], instance.obfuscate);

			// check access to this URL
			// TODO: we are using the AC 1.0 URL file which is deprecated - should we not be using the newer AC component and rules?
			if ( !ESAPI().accessController().isAuthorizedForURL(ESAPI().currentRequest().getRequestURI()) ) {
				ESAPI().currentRequest().setAttribute("message", "Unauthorized" );
				include "../includes/unauthorized.cfm";
				return;
			}
		</cfscript> 
		<cfsavecontent variable="generatedContent">
			<cfinclude template="#arguments.targetPage#" />
		</cfsavecontent>
		<cfoutput>
			#generatedContent# 
		</cfoutput>
	</cffunction>


</cfcomponent>
