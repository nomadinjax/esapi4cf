<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.HttpServletResponse" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.logger = "";
		instance.response = "";

		// modes are "log", "skip", "sanitize", "throw"
	    instance.mode = "log";
	</cfscript>

	<cffunction access="public" returntype="SecurityWrapperResponse" name="init" output="false" hint="Construct a safe response that overrides the default response methods with safer versions.">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="any" name="response" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("SecurityWrapperResponse");
			instance.response = arguments.response;

    		return this;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="addCookie" output="false" hint="Add a cookie to the response after ensuring that there are no encoded or illegal characters in the name and name and value. This method also sets the secure and HttpOnly flags on the cookie. This implementation uses a custom 'set-cookie' header instead of using Java's cookie interface which doesn't allow the use of HttpOnly.">
		<cfargument type="any" name="cookie" required="true" hint="javax.servlet.http.Cookie">
		<cfscript>
	        local.name = arguments.cookie.getName();
	        local.value = arguments.cookie.getValue();
	        local.maxAge = arguments.cookie.getMaxAge();
	        local.domain = arguments.cookie.getDomain();
	        if (isNull(local.domain)) {
				local.domain = "";
	        }
	        local.path = arguments.cookie.getPath();
	        if (isNull(local.path)) {
	        	local.path = "";
			}
	        local.secure = arguments.cookie.getSecure();

	        // validate the name and value
	        local.errors = createObject("component", "cfesapi.org.owasp.esapi.ValidationErrorList");
	        local.cookieName = instance.ESAPI.validator().getValidInput(context="cookie name", input=local.name, type="HTTPCookieName", maxLength=50, allowNull=false, errorList=local.errors);
	        local.cookieValue = instance.ESAPI.validator().getValidInput(context="cookie value", input=local.value, type="HTTPCookieValue", maxLength=instance.ESAPI.securityConfiguration().getMaxHttpHeaderSize(), allowNull=false, errorList=local.errors);

	        // if there are no errors, then just set a cookie header
	        if (local.errors.size() == 0) {
	            local.header = createCookieHeader(local.name, local.value, local.maxAge, local.domain, local.path, local.secure);
	            this.addHeader("Set-Cookie", local.header);
	            return;
	        }

	        // if there was an error
	        if (instance.mode.equals("skip")) {
	            instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Attempt to add unsafe data to cookie (skip mode). Skipping cookie and continuing.");
	            return;
	        }

	        // add the original cookie to the response and continue
	        if (instance.mode.equals("log")) {
	            instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Attempt to add unsafe data to cookie (log mode). Adding unsafe cookie anyway and continuing.");
	            getHttpServletResponse().addCookie(arguments.cookie);
	            return;
	        }

	        // create a sanitized cookie header and continue
	        if (instance.mode.equals("sanitize")) {
	            instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Attempt to add unsafe data to cookie (sanitize mode). Sanitizing cookie and continuing.");
	            local.header = createCookieHeader(local.cookieName, local.cookieValue, local.maxAge, local.domain, local.path, local.secure);
	            this.addHeader("Set-Cookie", local.header);
	            return;
	        }

	        // throw an exception if necessary or add original cookie header
	        cfex = createObject('component', 'cfesapi.org.owasp.esapi.errors.IntrusionException').init(instance.ESAPI, "Security error", "Attempt to add unsafe data to cookie (throw mode)");
       		throw(message=cfex.getMessage(), type=cfex.getType());
        </cfscript>
	</cffunction>


	<cffunction access="private" returntype="String" name="createCookieHeader" output="false">
		<cfargument type="String" name="name" required="true">
		<cfargument type="String" name="value" required="true">
		<cfargument type="numeric" name="maxAge" required="true">
		<cfargument type="String" name="domain" required="true">
		<cfargument type="String" name="path" reqired="true">
		<cfargument type="boolean" name="secure" required="true">
		<cfscript>
	        // create the special cookie header instead of creating a Java cookie
	        // Set-Cookie:<name>=<value>[; <name>=<value>][; expires=<date>][;
	        // domain=<domain_name>][; path=<some_path>][; secure][;HttpOnly
	        local.header = arguments.name & "=" & arguments.value;
	        local.header &= "; Max-Age=" & arguments.maxAge;
	        if (arguments.domain != "") {
	            local.header &= "; Domain=" & arguments.domain;
	        }
	        if (arguments.path != "") {
	            local.header &= "; Path=" & arguments.path;
	        }
	        if ( arguments.secure || instance.ESAPI.securityConfiguration().getForceSecureCookies() ) {
				local.header &= "; Secure";
	        }
	        if ( instance.ESAPI.securityConfiguration().getForceHttpOnlyCookies() ) {
				local.header &= "; HttpOnly";
	        }
	        return local.header;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="addHeader" output="false" hint="Add a header to the response after ensuring that there are no encoded or illegal characters in the name and name and value.">
		<cfargument type="String" name="name" required="true">
		<cfargument type="String" name="value" required="true">
		<cfscript>
	        try {
	            local.strippedName = javaLoader().create("org.owasp.esapi.StringUtilities").stripControls(arguments.name);
	            local.strippedValue = javaLoader().create("org.owasp.esapi.StringUtilities").stripControls(arguments.value);
	            local.safeName = instance.ESAPI.validator().getValidInput("addHeader", local.strippedName, "HTTPHeaderName", 20, false);
	            local.safeValue = instance.ESAPI.validator().getValidInput("addHeader", local.strippedValue, "HTTPHeaderValue", instance.ESAPI.securityConfiguration().getMaxHttpHeaderSize(), false);
	            getHttpServletResponse().setHeader(local.safeName, local.safeValue);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Attempt to add invalid header denied", e);
	        }
        </cfscript>
	</cffunction>


	<cffunction access="private" returntype="any" name="getHttpServletResponse" output="false" hint="javax.servlet.http.HttpServletResponse">
		<cfscript>
    		return instance.response;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setHeader" output="false" hint="Add a header to the response after ensuring that there are no encoded or illegal characters in the name and value.">
		<cfargument type="String" name="name" required="true">
		<cfargument type="String" name="value" required="true">
		<cfscript>
	        try {
	            local.strippedName = javaLoader().create("org.owasp.esapi.StringUtilities").stripControls(arguments.name);
	            local.strippedValue = javaLoader().create("org.owasp.esapi.StringUtilities").stripControls(arguments.value);
	            local.safeName = instance.ESAPI.validator().getValidInput("setHeader", local.strippedName, "HTTPHeaderName", 20, false);
	            local.safeValue = instance.ESAPI.validator().getValidInput("setHeader", local.strippedValue, "HTTPHeaderValue", instance.ESAPI.securityConfiguration().getMaxHttpHeaderSize(), false);
	            getHttpServletResponse().setHeader(local.safeName, local.safeValue);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Attempt to set invalid header denied", e);
	        }
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setDateHeader" output="false" hint="Add a date header to the response after ensuring that there are no encoded or illegal characters in the name.">
		<cfargument type="String" name="name" required="true">
		<cfargument type="numeric" name="date" required="true">
		<cfscript>
	        try {
	            local.safeName = instance.ESAPI.validator().getValidInput("safeSetDateHeader", arguments.name, "HTTPHeaderName", 20, false);
	            getHttpServletResponse().setDateHeader(local.safeName, arguments.date);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            instance.logger.warning(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "Attempt to set invalid date header name denied", e);
	        }
		</cfscript>
	</cffunction>


</cfcomponent>
