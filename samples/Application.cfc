component {
	// you should always name your application
	// ESAPI4CF needs a name for logging
	this.name = "MyESAPITestApp";

	// ESAPI4CF requires J2EE sessions
	this.sessionManagement = true;
	this.sessionTimeout = createTimeSpan(0, 0, 20, 0);

	// ESAPI4CF is under a sub-folder due to the structure of the project - add a mapping to find esapi4cf
	this.mappings["/org"] = expandPath("/esapi4cf/org");

	function onApplicationStart() {
		// this is your main reference point to ESAPI4CF that you will use throughout your application
		application.ESAPI = new org.owasp.esapi.ESAPI();

		// tell ESAPI4CF where you config files are stored
		// You want your security config in a place not accessible from your web application like /WEB-INF/esapi-resources/
		// but for the sake of simplicity in our samples, it is not
		application.ESAPI.securityConfiguration().setResourceDirectory("/samples/esapi-resources/");

		// define an application specific logger instance
		// you can use this to log custom errors to the ESAPI4CF Logger at any place throughout your application
		application.logger = application.ESAPI.getLogger(application.applicationName);

		// define any input parameters that should be ignored by the logger.
		// we never want a user's password to get logged
		application.ignoredByLogger = ["password"];
	}

	function onRequestStart() {
		try {
			// register request and response in ESAPI4CF
			application.ESAPI.httpUtilities().setCurrentHTTP(getPageContext().getRequest(), getPageContext().getResponse());

			// get references to the registered request/response safe wrappers
			var httpRequest = application.ESAPI.currentRequest();
			var httpResponse = application.ESAPI.currentResponse();

			// validate the current request to ensure nothing is suspicious
			application.ESAPI.validator().assertIsValidHTTPRequest();

			// log this request, obfuscating any parameter named password
			application.ESAPI.httpUtilities().logHTTPRequest(httpRequest, application.logger, application.ignoredByLogger);
		}
		catch(Any e) {
			application.logger.error(application.logger.getSecurity("SECURITY_FAILURE"), false, "Error in ESAPI4CF onRequestStart: " & e.message, e);
			// let's rethrow this error so your global error handler catches it if you have one
			throw(e.message, e.type, e.detail);
		}
	}

	function onRequestEnd() {
		// clear thread references to user and request/response data
		application.ESAPI.authenticator().clearCurrent();
		application.ESAPI.httpUtilities().setCurrentHTTP("", "");
	}

}