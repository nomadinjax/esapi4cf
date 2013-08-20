<cfcomponent extends="esapi4cf.swingset.org.corfield.framework" output="false">

	<!--- enforce UTF-8 encoding --->
	<cfprocessingdirective pageEncoding="utf-8" />
	<cfscript>
		this.name = "SwingSetInteractive";
		// don't let CF interfere with the ESAPI demos
		this.scriptProtect = "none";
		
		this.mappings["/org"] = expandPath("/esapi4cf/org");
	</cfscript>
 
	<cffunction access="public" returntype="void" name="setupApplication" output="false">
		<cflock scope="application" type="exclusive" timeout="5">
			<cfscript>
				application.ESAPI = createObject("component", "org.owasp.esapi.ESAPI").init();
				application.ESAPI.securityConfiguration().setResourceDirectory( "/swingset/WEB-INF/.esapi/" );

				// define an application specific logger instance
				application.logger = application.ESAPI.getLogger( application.applicationName );
				application.ESAPILogger = createObject("java", "org.owasp.esapi.Logger");
				
				// define any input parameters that should be ignored by the logger.
				// we never want a user's password to get logged
				application.ignore = [ "password" ];
			</cfscript> 
		</cflock>
	</cffunction>


	<cffunction access="public" returntype="void" name="setupRequest" output="false">
		<cfscript>
			// determine whether this was an AJAX request
			var httpHeaders = getHttpRequestData().headers;
			request.isAjaxRequest = false;
			if(structKeyExists( httpHeaders, "X-Requested-With" ) && httpHeaders["X-Requested-With"] == "XMLHttpRequest") {
				request.isAjaxRequest = true;
			}
				
			try {
				// register request and response in ESAPI
				application.ESAPI.httpUtilities().setCurrentHTTP( getPageContext().getRequest(), getPageContext().getResponse() );
				
				// get references to the current request/response wrappers
				var httpRequest = application.ESAPI.currentRequest();
				var httpResponse = application.ESAPI.currentResponse();
				
				// if the user can be identified via the session ID, the following will set "currentUser" 
				// in the Authenticator for consistent user identification across all requests in log messages
				var httpSession = httpRequest.getSession(false);
				if (isObject(httpSession)){
					try {
						application.ESAPI.authenticator().login(httpRequest, httpResponse);
					}
					catch (org.owasp.esapi.errors.AuthenticationException e) {}
					catch (org.owasp.esapi.errors.AuthenticationCredentialsException e) {}
					catch (org.owasp.esapi.errors.AuthenticationLoginException e) {}
				}
	
				// log this request, obfuscating any parameter named password
				application.ESAPI.httpUtilities().logHTTPRequest(httpRequest, application.logger, application.ignore);
			}
			catch (Any e) {
				application.logger.error( application.ESAPILogger.SECURITY_FAILURE, false, "Error in ESAPI security filter: " & e.message, e );
				application.ESAPI.currentRequest().setAttribute("message", e.message );
			}
			
			// FW/1: always ensure that ESAPI is available in the request context
			rc.ESAPI = application.ESAPI;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="onRequestEnd" output="false">
		<cfargument required="true" type="String" name="targetPage">
		<cfscript>
			// clear thread references to user and request/response data
			application.ESAPI.authenticator().clearCurrent();
			application.ESAPI.httpUtilities().setCurrentHTTP("", "");
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="getCurrentTemplateWebPath" output="false">
		<cfscript>
			return replace(getCurrentTemplatePath(), expandPath("/"), "\");
		</cfscript> 
	</cffunction>


</cfcomponent>
