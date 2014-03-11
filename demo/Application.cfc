<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfcomponent extends="esapi4cf.demo.org.corfield.framework" output="false">

	<cfscript>
		// you should always name your application
		// ESAPI4CF needs a name for logging
		this.name = "ESAPI-DemoApp";
		this.clientManagement = false;
		this.setClientCookies = false;

		// required in order to persist a user
		this.sessionManagement = true;
		this.sessionTimeout = createTimeSpan(0, 0, 20, 0);

		// ESAPI4CF is under a sub-folder due to the structure of the project - add a mapping to find esapi4cf
		this.mappings["/org"] = expandPath("/esapi4cf/org");

		function setupApplication() {
			// this is your main reference point to ESAPI4CF that you will use throughout your application
			// tell ESAPI4CF where you config files are stored
			// You want your security config in a place not accessible from your web application like /WEB-INF/esapi-resources/
			// so you would have to move this to the appropriate location
			application.ESAPI = createObject("component", "org.owasp.esapi.ESAPI").init("/esapi4cf/demo/WEB-INF/esapi-resources/");

			// define an application specific logger instance
			// you can use this to log custom errors to the ESAPI4CF Logger at any place throughout your application
			application.ESAPILogger = application.ESAPI.getLogger(application.applicationName & "-Logger");

			// define any input parameters that should be ignored by the logger.
			// we never want a user's password to get logged
			application.ignoredByLogger = ["password"];
		}

		function setupRequest() {
			var httpHeaders = "";
			var httpRequest = "";
			var httpResponse = "";

			// for debugging, allow reload of application
			if (structKeyExists(url, "reload") && url["reload"] == "true") {
				onApplicationStart();
			}

			// determine whether this was an AJAX request and save boolean to a request scope variable for use
			// any frontend library worth using sets the X-Requested-With HTTP header so we can detect that
			httpHeaders = getHttpRequestData().headers;
			request.isAjax = false;
			if (structKeyExists(httpHeaders, "X-Requested-With") && httpHeaders["X-Requested-With"] == "XMLHttpRequest") {
				request.isAjax = true;
			}

			try {
				// register request and response in ESAPI4CF
				application.ESAPI.httpUtilities().setCurrentHTTP(getPageContext().getRequest(), getPageContext().getResponse());

				// get references to the registered request/response safe wrappers
				httpRequest = application.ESAPI.currentRequest();
				httpResponse = application.ESAPI.currentResponse();

				// verify if this request meets the baseline input requirements
				try {
					application.ESAPI.validator().assertIsValidHTTPRequest();
				}
				catch(org.owasp.esapi.errors.ValidationException e) {
					redirectToLogin(e, 500);
				}
				catch(org.owasp.esapi.errors.IntrusionException e) {
					redirectToLogin(e, 500);
				}

				try {
					// this will verify authentication for your entire web application
					// rememberToken is not implemented by default; if you wish to use rememberToken,
					// you must call it inside your login() method after the user has been verified
					application.ESAPI.authenticator().login(httpRequest, httpResponse);
				}
				catch(org.owasp.esapi.errors.AuthenticationException e) {
					// Possible exceptions:
					// Attempt to login with an insecure request : Received non-SSL request
					// Attempt to login with an insecure request : Received request using GET when only POST is allowed
					// Attempt to access secure content with an insecure request : Received non-SSL request
					redirectToLogin(e);
				}
				catch(org.owasp.esapi.errors.AuthenticationCredentialsException e) {
					// Possible exceptions:
					// Invalid request : Request or response objects were empty
					// Authentication failed : blank username/password
					// Authentication failed : username does not exist
					redirectToLogin(e);
				}
				catch(org.owasp.esapi.errors.AuthenticationLoginException e) {
					// Possible exceptions:
					// Login failed : Missing password
					// Login failed : Disabled user attempt to login
					// Login failed : Locked user attempt to login
					// Login failed : Expired user attempt to login
					// Login failed : Incorrect password provided
					// Login failed : Anonymous user cannot be set to current user
					// Login failed : Disabled user cannot be set to current user
					// Login failed : Locked user cannot be set to current user
					// Login failed : Expired user cannot be set to current user
					// Login failed : Session inactivity timeout
					// Login failed : Session absolute timeout
					redirectToLogin(e);
				}

				// log this request, obfuscating any parameter named password
				application.ESAPI.httpUtilities().logHTTPRequest(httpRequest, application.ESAPILogger, application.ignoredByLogger);

				// check for CSRF attacks
				//application.ESAPI.httpUtilities().verifyCSRFToken(httpRequest);

				// set up response with content type
				application.ESAPI.httpUtilities().setSafeContentType(httpResponse);

				// set no-cache headers on every response
	            // only do this if the entire site should not be cached
	            // otherwise you should do this strategically in your controller or actions
				application.ESAPI.httpUtilities().setNoCacheHeaders(httpResponse);
			}
			catch(Any e) {
				application.ESAPILogger.error(application.ESAPILogger.getSecurityType("SECURITY_FAILURE"), false, "Error in ESAPI4CF onRequestStart: " & e.message, e);
				// let's rethrow this error so your global error handler catches it if you have one
				// not sure why throw chokes on 'Expression'
				if (e.type == "Expression") {
					throw(e.message, e.type & "!", e.detail);
				}
				else {
					throw(e.message, e.type, e.detail);
				}
			}

			// handle logout from any page
			if (structKeyExists(request.context, "logout")) {
				isLogout = request.context["logout"];
				if (len(trim(isLogout)) && isBoolean(isLogout) && isLogout) {
					application.ESAPI.authenticator().logout();
					ex = {message = "You have been logged out successfully."};
					redirectToLogin(ex);
				}
			}

			decryptQueryString();

		}

		function onRequestEnd() {
			// VERY IMPORTANT
			// clear thread references to user and request/response data
			application.ESAPI.authenticator().clearCurrent();
			application.ESAPI.httpUtilities().setCurrentHTTP("", "");
		}

	</cfscript>

	<!--- functions are outside of cfscript due to CF8 compatibility --->

	<cffunction name="isSecurePage">
		<cfargument required="true" name="action">
		<cfscript>
			// basic example - do this better!
			if (listFindNoCase("main.default,main.login,encoder.default", arguments.action)) {
				return false;
			}
			return true;
		</cfscript>
	</cffunction>

	<cffunction name="encryptQueryString">
		<cfargument required="true" type="String" name="params">
		<cfscript>
			return application.ESAPI.encoder().encodeForURL(application.ESAPI.httpUtilities().encryptQueryString(arguments.params));
		</cfscript>
	</cffunction>

	<cffunction name="decryptQueryString">
		<cfscript>
			var urlX = {};
			var key = "";

			// if we passed our encrypted url parameter "x", decrypt it and make these available via FW/1's rc scope
			if (structKeyExists(request.context, "x")) {
				try {
					urlX = application.ESAPI.httpUtilities().decryptQueryString(request.context.x);
					for (key in urlX) {
						request.context[key] = urlX[key];
					}
				}
				catch (org.owasp.esapi.errors.EncryptionException e) {}
				catch(expression e) {}
			}
		</cfscript>
	</cffunction>

	<cffunction name="redirectToLogin">
		<cfargument required="true" name="ex">
		<cfargument name="statusCode" default="401">
		<cfscript>
			var encoder = application.ESAPI.encoder();
			var params = "";
			// the ESAPI4CF login exception was already logged so we do not have to do anything with the message/detail
			// unless you have specific business requirements to do so.

			if (!isSecurePage(request.action)) {
				return;
			}

			// we were not in the whitelist so we must fail this request
			params &= "redirect=" & encoder.encodeForURL(request.action);
			params &= "&message=" & encoder.encodeForURL(ex.message);
		</cfscript>
		<!--- send appropriate HTTP status code --->
		<cfheader statuscode="#arguments.statusCode#">
		<!---
			Only perform a redirect on non-AJAX requests.
			Your global AJAX handler should be able to detect the HTTP status code and handle appropriately from frontend.
		--->
		<cfif not request.isAjax>
			<cflocation addtoken="false" url="index.cfm?action=main.login&x=#encryptQueryString(params)#" />
		</cfif>
	</cffunction>

</cfcomponent>