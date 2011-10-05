<!---
	/**
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
	*/
	--->
<cfcomponent implements="Filter" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.logger = "";
		
	    /**
	     * This is the root path of what resources this filter will allow a RequestDispatcher to be dispatched to. This
	     * defaults to WEB-INF as best practice dictates that dispatched requests should be done to resources that are
	     * not browsable and everything behind WEB-INF is protected by the container. However, it is possible and sometimes
	     * required to dispatch requests to places outside of the WEB-INF path (such as to another servlet).
	     *
	     * See <a href="http://code.google.com/p/owasp-esapi-java/issues/detail?id=70">http://code.google.com/p/owasp-esapi-java/issues/detail?id=70</a>
	     * and <a href="https://lists.owasp.org/pipermail/owasp-esapi/2009-December/001672.html">https://lists.owasp.org/pipermail/owasp-esapi/2009-December/001672.html</a>
	     * for details.
	     */
	    instance.allowableResourcesRoot = "WEB-INF";
	</cfscript>
 
	<cffunction access="public" returntype="Filter" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="Struct" name="filterConfig" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("SecurityWrapper");
			
			instance.allowableResourcesRoot = createObject("java", "org.owasp.esapi.StringUtilities").replaceNull( arguments.filterConfig.get("allowableResourcesRoot"), instance.allowableResourcesRoot );
			
			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="doFilter" output="false">
		<cfargument type="any" name="request" required="true" hint="javax.servlet.ServletRequest">
		<cfargument type="any" name="response" required="true" hint="javax.servlet.ServletResponse">
		<cfscript>
	        //try {
	            local.hrequest = arguments.request;
	            local.hresponse = arguments.response;
	
	            local.secureRequest = new SecurityWrapperRequest(instance.ESAPI, local.hrequest);
	            local.secureResponse = new SecurityWrapperResponse(instance.ESAPI, local.hresponse);
	
	            // Set the configuration on the wrapped request
	            local.secureRequest.setAllowableContentRoot(instance.allowableResourcesRoot);
	
	            instance.ESAPI.httpUtilities().setCurrentHTTP(local.secureRequest, local.secureResponse);
	        /*} catch (Exception e) {
	            instance.logger.error( createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Error in SecurityWrapper: " & e.getMessage(), e );
	            arguments.request.setAttribute("message", e.getMessage() );
	        } finally {*/
	            // VERY IMPORTANT
	            // clear out the ThreadLocal variables in the authenticator
	            // some containers could possibly reuse this thread without clearing the User
	            // Issue 70 - http://code.google.com/p/owasp-esapi-java/issues/detail?id=70
	            instance.ESAPI.httpUtilities().clearCurrent();
	        //}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="destroy" output="false">
		<cfscript>
			// no special action
		</cfscript> 
	</cffunction>


</cfcomponent>
