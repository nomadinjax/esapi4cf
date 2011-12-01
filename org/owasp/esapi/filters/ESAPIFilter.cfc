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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.lang.Filter" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.logger = "";
		instance.obfuscate = ["password"];
		instance.response = "";
		instance.unauthenticatedPath = "WEB-INF/login.cfm";
		instance.unauthenticatedMessage = "Authentication Failed";
		instance.unauthorizedPath = "WEB-INF/index.cfm";
		instance.unauthorizedMessage = "Unauthorized";
	</cfscript>

	<cffunction access="public" returntype="ESAPIFilter" name="init" output="false"
	            hint="Called by the web container to indicate to a filter that it is being placed into service. The servlet container calls the init method exactly once after instantiating the filter. The init method must complete successfully before the filter is asked to do any filtering work.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" type="Struct" name="filterConfig" hint="configuration object"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("ESAPIFilter");

			// create defaults
			local.empty = {unauthenticatedPath="", unauthenticatedMessage="", unauthorizedPath="", unauthorizedMessage=""};
			structAppend(arguments.filterConfig, local.empty, false);

			instance.unauthenticatedPath = newJava("org.owasp.esapi.StringUtilities").replaceNull(arguments.filterConfig.get("unauthenticatedPath"), instance.unauthenticatedPath);
			instance.unauthenticatedMessage = newJava("org.owasp.esapi.StringUtilities").replaceNull(arguments.filterConfig.get("unauthenticatedMessage"), instance.unauthenticatedMessage);
			instance.unauthorizedPath = newJava("org.owasp.esapi.StringUtilities").replaceNull(arguments.filterConfig.get("unauthorizedPath"), instance.unauthorizedPath);
			instance.unauthorizedMessage = newJava("org.owasp.esapi.StringUtilities").replaceNull(arguments.filterConfig.get("unauthorizedMessage"), instance.unauthorizedMessage);

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="doFilter" output="false"
	            hint="The doFilter method of the Filter is called by the container each time a request/response pair is passed through the chain due to a client request for a resource at the end of the chain. The FilterChain passed in to this method allows the Filter to pass on the request and response to the next entity in the chain.">
		<cfargument required="true" name="request" hint="Request object to be processed"/>
		<cfargument required="true" name="response" hint="Response object"/>

		<cfset var local = {}/>

		<cfscript>
			local.request = arguments.request;
			instance.response = arguments.response;
			instance.ESAPI.httpUtilities().setCurrentHTTP(local.request, instance.response);

			// figure out who the current user is
			try {
				instance.ESAPI.authenticator().login(local.request, instance.response);
			}
			catch(cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				/*
				 * "Authentication failed"
				 *
				 * Possibilities:
				 * - Authentication failed for [username] because of blank username or password
				 * - Authentication failed because user [username] doesn't exist
				 */
				instance.ESAPI.authenticator().logout();
				local.request.setAttribute("message", instance.unauthenticatedMessage);
				//local.request.setAttribute("message", e.detail);
				local.dispatcher = local.request.getRequestDispatcher(instance.unauthenticatedPath);
				local.dispatcher.forward(local.request.getHttpServletRequest(), instance.response.getHttpServletResponse());
				return false;
			}
			catch(cfesapi.org.owasp.esapi.errors.AuthenticationLoginException e) {
				/*
				 * "Login failed"
				 *
				 * Possibilities:
				 * - Missing password
				 * - Disabled user attempt to login
				 * - Locked user attempt to login
				 * - Expired user attempt to login
				 * - Incorrect password provided for [accountName]
				 *
				 * Possibilities:
				 * - Anonymous user cannot be set to current user.
				 * - Disabled user cannot be set to current user.
				 * - Locked user cannot be set to current user.
				 * - Expired user cannot be set to current user.
				 * - Session inactivity timeout
				 * - Session absolute timeout
				 */
				instance.ESAPI.authenticator().logout();
				local.request.setAttribute("message", instance.unauthenticatedMessage);
				//local.request.setAttribute("message", e.detail);
				local.dispatcher = local.request.getRequestDispatcher(instance.unauthenticatedPath);
				local.dispatcher.forward(local.request.getHttpServletRequest(), instance.response.getHttpServletResponse());
				return false;
			}
			catch(cfesapi.org.owasp.esapi.errors.AuthenticationException e) {
				/*
				 * "Attempt to access secure content with an insecure request"
				 *
				 * Possibilities:
				 * - HTTP request did not use SSL
				 *
				 * "Attempt to login with an insecure request"
				 *
				 * Possibilities:
				 * - Received request using GET when only POST is allowed
				 */
				instance.ESAPI.authenticator().logout();
				local.request.setAttribute("message", instance.unauthenticatedMessage);
				//local.request.setAttribute("message", e.detail);
				local.dispatcher = local.request.getRequestDispatcher(instance.unauthenticatedPath);
				local.dispatcher.forward(local.request.getHttpServletRequest(), instance.response.getHttpServletResponse());
				return false;
			}

			// log this request, obfuscating any parameter named password
			instance.ESAPI.httpUtilities().logHTTPRequest(local.request, instance.logger, instance.obfuscate);

			// check access to this URL
			if(!instance.ESAPI.accessController().isAuthorizedForURL(local.request.getRequestURI())) {
				local.request.setAttribute("message", instance.unauthorizedMessage);
				local.dispatcher = local.request.getRequestDispatcher(instance.unauthorizedPath);
				local.dispatcher.forward(local.request.getHttpServletRequest(), instance.response.getHttpServletResponse());
				return false;
			}

			// check for CSRF attacks
			// instance.ESAPI.httpUtilities().checkCSRFToken();
			return true;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="destroy" output="false"
	            hint="Called by the web container to indicate to a filter that it is being taken out of service. This method is only called once all threads within the filter's doFilter method have exited or after a timeout period has passed. After the web container calls this method, it will not call the doFilter method again on this instance of the filter.">

		<cfscript>
			// set up response with content type
			instance.ESAPI.httpUtilities().setContentType(instance.response);

			// set no-cache headers on every response
			// only do this if the entire site should not be cached
			// otherwise you should do this strategically in your controller or actions
			//instance.ESAPI.httpUtilities().setNoCacheHeaders(instance.response);
			// VERY IMPORTANT
			// clear out the ThreadLocal variables in the authenticator
			// some containers could possibly reuse this thread without clearing the User
			instance.ESAPI.clearCurrent();
		</cfscript>

	</cffunction>

</cfcomponent>