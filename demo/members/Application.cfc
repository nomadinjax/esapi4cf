<cfcomponent extends="cfesapi.demo.Core" output="false">


	<cffunction access="public" returntype="void" name="onRequest" output="true">
		<cfargument type="String" name="targetPage" required="true">
		<cfscript>
			include "/cfesapi/helpers/ESAPI.cfm";

			// set up response with content type
			ESAPI().httpUtilities().setContentType();

            // set no-cache headers on every response
            // only do this if the entire site should not be cached otherwise you should do this strategically in your controller or actions
			ESAPI().httpUtilities().setNoCacheHeaders();

			if (!structKeyExists(session, "logger")) {
				session.logger = ESAPI().getLogger("CFESAPI-Demo");
			}

			local.request = ESAPI().currentRequest();

			try {
				ESAPI().authenticator().login();
			}
			catch( cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e ) {
				ESAPI().authenticator().logout();
				//local.request.setAttribute("message", "Authentication failed");
				local.request.setAttribute("message", e.message & " - " & e.detail);
				include "../login.cfm";
				return;
			}
			catch( cfesapi.org.owasp.esapi.errors.AuthenticationLoginException e ) {
				ESAPI().authenticator().logout();
				//local.request.setAttribute("message", "Authentication failed");
				local.request.setAttribute("message", e.message & " - " & e.detail);
				include "../login.cfm";
				return;
			}
			catch ( cfesapi.org.owasp.esapi.errors.AuthenticationException e) {
				ESAPI().authenticator().logout();
				//local.request.setAttribute("message", "Authentication failed");
				local.request.setAttribute("message", e.message & " - " & e.detail);
				include "../login.cfm";
				return;
			}
			catch ( cfesapi.org.owasp.esapi.errors.AuthenticationHostException e) {
				// ignore host changes
			}

			// log this request, obfuscating any parameter named password
			ESAPI().httpUtilities().logHTTPRequest(local.request, session.logger, [ "password" ]);

			// check access to this URL
			if ( !ESAPI().accessController().isAuthorizedForURL(local.request.getRequestURI()) ) {
				local.request.setAttribute("message", "Unauthorized" );
				include "index.cfm";
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
