<cfcomponent extends="esapi4cf.esapi4cf-swingset.org.corfield.framework" output="false">

	<cfprocessingdirective pageEncoding="utf-8" />
	
	<cfscript>
		this.scriptProtect = "none";	// don't let CF interfere with the ESAPI demos
		this.mappings = {
			"esapi4cf" = "/esapi4cf/esapi4cf"	
		};
	</cfscript>

	<cffunction access="private" returntype="esapi4cf.org.owasp.esapi.ESAPI" name="ESAPI" output="false">
		<cfif not structKeyExists(application, "ESAPI")>
			<cflock timeout="5" scope="application" type="exclusive">
				<cfif not structKeyExists(application, "ESAPI")>
					<cfset application.ESAPI = createObject("component", "esapi4cf.org.owasp.esapi.ESAPI").init()/>
				</cfif>
			</cflock>
		</cfif>
		<cfreturn application.ESAPI/>
	</cffunction>
	
	<cffunction access="private" name="ESAPILogger" output="false">
		<cfif not structKeyExists(application, "ESAPILogger")>
			<cflock timeout="5" scope="application" type="exclusive">
				<cfif not structKeyExists(application, "ESAPILogger")>
					<cfset application.ESAPILogger = createObject("java", "org.owasp.esapi.Logger")/>
				</cfif>
			</cflock>
		</cfif>
		<cfreturn application.ESAPILogger/>
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setupApplication" output="false">
		<cfscript>
			// allows the FW/1 'reload' to also reload ESAPI for us
			structDelete(application, "ESAPI");
			
			ESAPI().securityConfiguration().setResourceDirectory( "/esapi4cf/esapi4cf-swingset/WEB-INF/.esapi/" );
			application.logger = ESAPI().getLogger( "SwingsetFilter" );
			application.ignore = [ "password" ];
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="setupRequest" output="false">
		<cfscript>
			var local = {};
			
			try {
				// register request and response in ESAPI (usually done through login)
				ESAPI().httpUtilities().setCurrentHTTP( getPageContext().getRequest(), getPageContext().getResponse() );
				
				// log this request, obfuscating any parameter named password
				ESAPI().httpUtilities().logHTTPRequest(ESAPI().httpUtilities().getCurrentRequest(), application.logger, application.ignore);
				
				// if the user can be identified via the session ID, the following will set "currentUser" 
				// in the Authenticator for consistent user identification across all requests in log messages
				local.session = ESAPI().httpUtilities().getCurrentRequest().getSession(false);
				if(isObject(local.session)){
					try{
						ESAPI().authenticator().login(ESAPI().currentRequest(), ESAPI().currentResponse());
					}
					catch (esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
						// noop
						ESAPI().authenticator(); // for breakpoint debugging only
					}
				}
				else{
					//noop
					ESAPI().authenticator(); // for breakpoint debugging only
				}
			} catch (java.lang.Exception e) {
				application.logger.error( ESAPILogger().SECURITY_FAILURE, false, "Error in ESAPI security filter: " & e.message, e );
				ESAPI().currentRequest().setAttribute("message", e.getMessage() );
			}
		</cfscript>
	</cffunction>
	
	<cffunction access="public" returntype="void" name="onRequestEnd" output="false">
		<cfargument required="true" type="String" name="targetPage">
		<cfscript>
			// VERY IMPORTANT
			// clear out the ThreadLocal variables in the authenticator
			// some containers could possibly reuse this thread without clearing the User
			ESAPI().authenticator().clearCurrent();
		</cfscript>
	</cffunction>

	<cffunction access="private" returntype="String" name="getCurrentTemplateWebPath" output="false">
		<cfscript>
			return replace(getCurrentTemplatePath(), expandPath("/"), "\");
		</cfscript>
	</cffunction>

	
</cfcomponent>