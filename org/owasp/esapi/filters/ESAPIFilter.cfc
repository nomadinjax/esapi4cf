<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 --->
<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.logger = "";
		instance.obfuscate = [ "password" ];

		instance.authenticationMessage = "Authentication failed";
		instance.authenticationURL = "WEB-INF/login.cfm";
		instance.authorizationMessage = "Unauthorized";
		instance.authorizationURL = "WEB-INF/index.cfm";
		instance.validationMessage = "Validation error";
		instance.validationURL = "WEB-INF/index.cfm";
	</cfscript>

	<cffunction access="public" returntype="ESAPIFilter" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI">
		<cfargument type="Struct" name="filterConfig" default="#structNew()#" hint="configuration object">
		<cfscript>
			var local = {};

			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("ESAPIFilter");

			if (structKeyExists(arguments, "filterConfig")) {

				// resourceDirectory
				if ( structKeyExists(arguments.filterConfig, "resourceDirectory") && instance.ESAPI.securityConfiguration().getResourceDirectory() == "" ) {
					instance.ESAPI.securityConfiguration().setResourceDirectory( arguments.filterConfig.resourceDirectory );
				}

				// authenticationMessage
				if ( structKeyExists(arguments.filterConfig, "authenticationMessage") ) {
					instance.authenticationMessage = arguments.filterConfig.authenticationMessage;
				}

				// authenticationURL (must be within WEB-INF)
				if ( structKeyExists(arguments.filterConfig, "authenticationURL") ) {
					instance.authenticationURL = arguments.filterConfig.authenticationURL;
				}

				// authorizationMessage
				if ( structKeyExists(arguments.filterConfig, "authorizationMessage") ) {
					instance.authorizationMessage = arguments.filterConfig.authorizationMessage;
				}

				// authorizationURL (must be within WEB-INF)
				if ( structKeyExists(arguments.filterConfig, "authorizationURL") ) {
					instance.authorizationURL = arguments.filterConfig.authorizationURL;
				}

				// validationMessage
				if ( structKeyExists(arguments.filterConfig, "validationMessage") ) {
					instance.validationMessage = arguments.filterConfig.validationMessage;
				}

				// validationURL (must be within WEB-INF)
				if ( structKeyExists(arguments.filterConfig, "validationURL") ) {
					instance.validationURL = arguments.filterConfig.validationURL;
				}
			}
			return this;
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="boolean" name="onRequestStartFilter" output="false">
		<cfargument required="true" name="request" hint="Request object to be processed">
		<cfargument required="true" name="response" hint="Response object">
		<cfscript>
			var local = {};

			instance.ESAPI.httpUtilities().setCurrentHTTP(arguments.request, arguments.response);
			local.request = instance.ESAPI.currentRequest();
			local.response = instance.ESAPI.currentResponse();

			try {
				// figure out who the current user is
				try {
					instance.ESAPI.authenticator().login(local.request, local.response);
				} catch( cfesapi.org.owasp.esapi.errors.AuthenticationException e ) {
					instance.ESAPI.authenticator().logout();
					local.request.setAttribute("message", instance.authenticationMessage);
					local.dispatcher = local.request.getRequestDispatcher(instance.authenticationURL);
					local.dispatcher.forward( local.request.getHttpServletRequest(), local.response.getHttpServletResponse() );
					return false;
				} catch( cfesapi.org.owasp.esapi.errors.AuthenticationCredentialsException e ) {
					instance.ESAPI.authenticator().logout();
					local.request.setAttribute("message", instance.authenticationMessage);
					local.dispatcher = local.request.getRequestDispatcher(instance.authenticationURL);
					local.dispatcher.forward( local.request.getHttpServletRequest(), local.response.getHttpServletResponse() );
					return false;
				} catch( cfesapi.org.owasp.esapi.errors.AuthenticationLoginException e ) {
					instance.ESAPI.authenticator().logout();
					local.request.setAttribute("message", instance.authenticationMessage);
					local.dispatcher = local.request.getRequestDispatcher(instance.authenticationURL);
					local.dispatcher.forward( local.request.getHttpServletRequest(), local.response.getHttpServletResponse() );
					return false;
				}

				// log this request, obfuscating any parameter named password
				instance.ESAPI.httpUtilities().logHTTPRequest(local.request, instance.logger, instance.obfuscate);

				// check access to this URL
				if ( !instance.ESAPI.accessController().isAuthorizedForURL(local.request.getRequestURI().toString()) ) {
					local.request.setAttribute("message", instance.authorizationMessage );
					local.dispatcher = local.request.getRequestDispatcher(instance.authorizationURL);
					local.dispatcher.forward(local.request.getHttpServletRequest(), local.response.getHttpServletResponse());
					return false;
				}

				// verify if this request meets the baseline input requirements
				if ( !instance.ESAPI.validator().isValidHTTPRequest() ) {
					local.request.setAttribute("message", instance.validationMessage );
					local.dispatcher = local.request.getRequestDispatcher(instance.validationURL);
					local.dispatcher.forward(local.request.getHttpServletRequest(), local.response.getHttpServletResponse());
					return false;
				}

				// check for CSRF attacks
				// utils.checkCSRFToken();

			} catch (Exception e) {
				e.printStackTrace();
				instance.logger.error( getJava("org.owasp.esapi.Logger").SECURITY, false, "Error in ESAPI security onRequestStartFilter: " & e.getMessage(), e );
				local.request.setAttribute("message", e.getMessage() );
				return false;
			}

			return true;
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="boolean" name="onRequestEndFilter" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletRequest" name="request" hint="Request object to be processed">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.HttpServletResponse" name="response" hint="Response object">
		<cfscript>
			var local = {};

			local.request = arguments.request;
			local.response = arguments.response;

			try {
				// set up response with content type
				instance.ESAPI.httpUtilities().setSafeContentType( local.response );

	            // set no-cache headers on every response
	            // only do this if the entire site should not be cached
	            // otherwise you should do this strategically in your controller or actions
				instance.ESAPI.httpUtilities().setNoCacheHeaders( local.response );

			} catch (Exception e) {
				e.printStackTrace();
				instance.logger.error( getJava("org.owasp.esapi.Logger").SECURITY, false, "Error in ESAPI security onRequestEndFilter: " & e.getMessage(), e );
				local.request.setAttribute("message", e.getMessage() );
				return false;
			}

			// VERY IMPORTANT
			// clear out the ThreadLocal variables in the authenticator
			// some containers could possibly reuse this thread without clearing the User
			instance.ESAPI.authenticator().clearCurrent();
			instance.ESAPI.httpUtilities().setCurrentHTTP("", "");

			return true;
		</cfscript>
	</cffunction>

</cfcomponent>