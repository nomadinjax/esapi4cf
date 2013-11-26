<cfcomponent output="false">

	<cfscript>
		// you should always name your application
		// ESAPI4CF needs a name for logging
		this.name = "ESAPITutorialsApp";
		this.clientManagement = false;
		this.setClientCookies = false;

		// required in order to persist a user
		this.sessionManagement = true;
		this.sessionTimeout = createTimeSpan(0, 0, 20, 0);

		// ESAPI4CF is under a sub-folder due to the structure of the project - add a mapping to find esapi4cf
		this.mappings["/org"] = expandPath("/esapi4cf/org");

		function onApplicationStart() {
			// this is your main reference point to ESAPI4CF that you will use throughout your application
			// tell ESAPI4CF where you config files are stored
			// You want your security config in a place not accessible from your web application like /WEB-INF/esapi-resources/
			// but for the sake of simplicity in our samples, it is not
			application.ESAPI = createObject("component", "org.owasp.esapi.ESAPI").init("/esapi4cf/samples/tutorials/esapi-resources/");

			// define an application specific logger instance
			// you can use this to log custom errors to the ESAPI4CF Logger at any place throughout your application
			application.ESAPILogger = application.ESAPI.getLogger(application.applicationName & "-Logger");

			// define any input parameters that should be ignored by the logger.
			// we never want a user's password to get logged
			application.ignoredByLogger = ["password"];
		}

		function onRequestStart() {
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

				// validate the current request to ensure nothing is suspicious
				application.ESAPI.validator().assertIsValidHTTPRequest();

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
			isLogout = httpRequest.getParameter("logout");
			if (len(trim(isLogout)) && isBoolean(isLogout) && isLogout) {
				application.ESAPI.authenticator().logout();
				ex = {message = "You have been logged out successfully."};
				redirectToLogin(ex);
			}

		}

		function onRequestEnd() {
			// clear thread references to user and request/response data
			application.ESAPI.authenticator().clearCurrent();
			application.ESAPI.httpUtilities().setCurrentHTTP("", "");
		}

	</cfscript>

	<cffunction name="redirectToLogin">
		<cfargument required="true" name="ex">
		<cfscript>
			var encoder = application.ESAPI.encoder();
			var httpUtilities = application.ESAPI.httpUtilities();
			var params = "";
			// the ESAPI4CF login exception was already logged so we do not have to do anything with the message/detail
			// unless you have specific business requirements to do so.

			// let's provide a whitelist of pages that do not require authentication (this is basic, use a better solution)
			if (listFindNoCase("login.cfm", listLast(cgi.script_name, "/"))) {
				return;
			}

			// we were not in the whitelist so we must fail this request
			params &= "redirect=" & encoder.encodeForURL(cgi.script_name);
			params &= "&message=" & encoder.encodeForURL(ex.message);
		</cfscript>
		<!--- send appropriate Authentication Required/Failed HTTP status code --->
		<cfheader statuscode="401">
		<!---
			Only perform a redirect on non-AJAX requests.
			Your global AJAX handler should be able to detect a 401 response and handle appropriately from frontend.
		--->
		<cfif not request.isAjax>
			<cflocation addtoken="false" url="login.cfm?x=#encoder.encodeForURL(httpUtilities.encryptQueryString(params))#" />
		</cfif>
	</cffunction>

</cfcomponent>