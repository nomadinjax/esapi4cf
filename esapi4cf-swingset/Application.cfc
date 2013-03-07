<cfcomponent extends="esapi4cf.esapi4cf-swingset.org.corfield.framework" output="false">

	<!--- enforce UTF-8 encoding --->
	<cfprocessingdirective pageEncoding="utf-8" />
	<cfscript>
		// don't let CF interfere with the ESAPI demos
		this.scriptProtect = "none";
		
		this.mappings = {
			"esapi4cf" = "/esapi4cf/esapi4cf"	
		};
	</cfscript> 
	<!---
		This function is how we access the ESAPI instance throughout our web application.
		The function takes care of lazy loading the main ESAPI component if it is not already loaded in our application scope.
		--->

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

	<!---
		This function is how we access the ESAPI Logger instance throughout our web application.
		The function takes care of lazy loading the ESAPI Logger Java class if it is not already loaded in our application scope.
		--->

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
			
			/*
			 * This is our first call to ESAPI.  3 things occur here:
			 * 
			 * 1) Calling the ESAPI() function references the method in this file which lazy loads our main ESAPI component
			 * 		and stores this reference in our application scope.
			 * 2) Calling the securityConfiguration() method inside our main ESAPI component will lazy load the securityConfiguration
			 * 		module of ESAPI.  This initilizes the securityConfiguration module loading the default resource path.  This also
			 * 		stores a reference to this module inside of our main ESAPI component for subsequent uses.
			 * 3) Calling the setResourceDirectory() method overrides the default resource path and loads your application specific
			 * 		configuration into ESAPI.
			 */
			ESAPI().securityConfiguration().setResourceDirectory( "/esapi4cf/esapi4cf-swingset/WEB-INF/.esapi/" );
			
			// define an application specific logger instance
			application.logger = ESAPI().getLogger( "SwingsetFilter" );
			
			// define any input parameters that should be ignored by the logger.
			// we never want a user's password to get logged
			application.ignore = [ "password" ];
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setupRequest" output="false">
		<cfscript>
			var local = {};
				
			try {
				// register request and response in ESAPI
				ESAPI().httpUtilities().setCurrentHTTP( getPageContext().getRequest(), getPageContext().getResponse() );
				
				// get references to the current request/response wrappers
				local.request = ESAPI().currentRequest();
				local.response = ESAPI().currentResponse();
				
				// if the user can be identified via the session ID, the following will set "currentUser" 
				// in the Authenticator for consistent user identification across all requests in log messages
				local.session = local.request.getSession(false);
				if (isObject(local.session)){
					try {
						ESAPI().authenticator().login(local.request, local.response);
					}
					catch (esapi4cf.org.owasp.esapi.errors.AuthenticationException e) {}
					catch (esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException e) {}
					catch (esapi4cf.org.owasp.esapi.errors.AuthenticationLoginException e) {}
				}
	
				// log this request, obfuscating any parameter named password
				ESAPI().httpUtilities().logHTTPRequest(local.request, application.logger, application.ignore);
	
				// verify if this request meets the baseline input requirements
				// DISABLED: some of the SwingSet demos intentionally have security holes so this check may fail
				// in normal use case - you want this validation enabled
				//if ( !instance.ESAPI.validator().isValidHTTPRequest() ) {}
			}
			catch (Any e) {
				application.logger.error( ESAPILogger().SECURITY_FAILURE, false, "Error in ESAPI security filter: " & e.message, e );
				ESAPI().currentRequest().setAttribute("message", e.message );
			}
			
			// FW/1: always ensure that ESAPI is available in the request context
			rc.ESAPI = ESAPI();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="onRequestEnd" output="false">
		<cfargument required="true" type="String" name="targetPage">
		<cfscript>
			// clear thread references to user and request/response data
			ESAPI().authenticator().clearCurrent();
			ESAPI().httpUtilities().setCurrentHTTP("", "");
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="String" name="getCurrentTemplateWebPath" output="false">
		<cfscript>
			return replace(getCurrentTemplatePath(), expandPath("/"), "\");
		</cfscript> 
	</cffunction>


</cfcomponent>
