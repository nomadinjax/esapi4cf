<!--- /**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 */ --->
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.lang.Filter" output="false" hint="This filter wraps the incoming request and outgoing response and overrides many methods with safer versions. Many of the safer versions simply validate parts of the request or response for unwanted characters before allowing the call to complete. Some examples of attacks that use these vectors include request splitting, response splitting, and file download injection. Attackers use techniques like CRLF injection and null byte injection to confuse the parsing of requests and responses.">

	<cfscript>
		instance.ESAPI = "";
		instance.logger = "";
	</cfscript>

	<cfscript>
		/**
		 * This is the root path of what resources this filter will allow a RequestDispatcher to be dispatched to. This
		 * defaults to WEB-INF as best practice dictates that dispatched requests should be done to resources that are
		 * not browsable and everything behind WEB-INF is protected by the container. However, it is possible and sometimes
		 * required to dispatch requests to places outside of the WEB-INF path (such as to another servlet).
		 */
		instance.allowableResourcesRoot = "WEB-INF";
	</cfscript>

	<cffunction access="public" returntype="SecurityWrapper" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" type="Struct" name="filterConfig"/>

		<cfset var local = {}/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			instance.allowableResourcesRoot = newJava("org.owasp.esapi.StringUtilities").replaceNull(arguments.filterConfig.get("allowableResourcesRoot"), instance.allowableResourcesRoot);

			// define custom resourceDirectory - condition to only perform this once otherwise it will force a config reload
			local.resourceDirectory = arguments.filterConfig.get("resourceDirectory");
			if(structKeyExists(local, "resourceDirectory")) {
				instance.ESAPI.securityConfiguration().setResourceDirectory(local.resourceDirectory);
			}

			instance.logger = instance.ESAPI.getLogger("SecurityWrapper");

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="doFilter" output="false">
		<cfargument required="true" name="request"/>
		<cfargument required="true" name="response"/>

		<cfset var local = {}/>

		<cfscript>
			local.hrequest = arguments.request;
			local.hresponse = arguments.response;

			local.secureRequest = newComponent("cfesapi.org.owasp.esapi.filters.SecurityWrapperRequest").init(instance.ESAPI, local.hrequest);
			local.secureResponse = newComponent("cfesapi.org.owasp.esapi.filters.SecurityWrapperResponse").init(instance.ESAPI, local.hresponse);

			// Set the configuration on the wrapped request
			local.secureRequest.setAllowableContentRoot(instance.allowableResourcesRoot);

			instance.ESAPI.httpUtilities().setCurrentHTTP(local.secureRequest, local.secureResponse);

			// this will verify whether J2EE sessions are turned on which are required for CFESAPI to function
			// TODO: is this the right way to do this?
			// I don't think RailoCF is liking this - perhaps the cookie is not set yet at this point?
			// Where would be a better place to check this?
			//if(!local.secureRequest.isRequestedSessionIdValid()) {
			//    throwError(newComponent("cfesapi.org.owasp.esapi.errors.ConfigurationException").init("J2EE sessions must be turned on."));
			//}
			return true;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="destroy" output="false">

		<cfscript>
			// VERY IMPORTANT
			// clear out the ThreadLocal variables in the authenticator
			// some containers could possibly reuse this thread without clearing the User
			// Issue 70 - http://code.google.com/p/owasp-esapi-java/issues/detail?id=70
			instance.ESAPI.httpUtilities().clearCurrent();
		</cfscript>

	</cffunction>

</cfcomponent>