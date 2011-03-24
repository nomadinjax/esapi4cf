<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.HttpServletRequest" output="false">

	<cfscript>
		instance.ESAPI = "";
		instance.logger = "";
		instance.request = "";
	</cfscript>

	<cffunction access="public" returntype="SecurityWrapperRequest" name="init" output="false" hint="Construct a safe request that overrides the default request methods with safer versions.">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="any" name="request" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("SecurityWrapperRequest");
			instance.request = arguments.request;

    		return this;
    	</cfscript>
	</cffunction>


	<cffunction access="private" returntype="any" name="getHttpServletRequest" output="false" hint="javax.servlet.http.HttpServletRequest">
		<cfscript>
    		return instance.request;
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getCookies" output="false" hint="Returns the array of Cookies from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfscript>
	        local.cookies = getHttpServletRequest().getCookies();
	        if (isNull(local.cookies)) return [];

	        local.newCookies = [];
	        for (local.i = 1; local.i <= arrayLen(local.cookies); local.i++) {
				local.c = local.cookies[local.i];
	            // build a new clean cookie
	            try {
	                // get data from original cookie
	                local.name = instance.ESAPI.validator().getValidInput("Cookie name: " & local.c.getName(), local.c.getName(), "HTTPCookieName", 150, true);
	                local.value = instance.ESAPI.validator().getValidInput("Cookie value: " & local.c.getValue(), local.c.getValue(), "HTTPCookieValue", 1000, true);
	                local.maxAge = local.c.getMaxAge();
	                local.domain = local.c.getDomain();
	                local.path = local.c.getPath();

	                local.n = createObject("java", "javax.servlet.http.Cookie").init(local.name, local.value);
	                local.n.setMaxAge(local.maxAge);

	                if (!isNull(local.domain)) {
	                    local.n.setDomain(instance.ESAPI.validator().getValidInput("Cookie domain: " & local.domain, local.domain, "HTTPHeaderValue", 200, false));
	                }
	                if (!isNull(local.path)) {
	                    local.n.setPath(instance.ESAPI.validator().getValidInput("Cookie path: " & local.path, local.path, "HTTPHeaderValue", 200, false));
	                }
	                local.newCookies.add(local.n);
	            } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	                instance.logger.warning(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Skipping bad cookie: " & local.c.getName() & "=" & local.c.getValue(), e );
	            }
	        }
	        return local.newCookies;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getSession" output="false" hint="cfesapi.org.owasp.esapi.HttpSession: Returns a session, creating it if necessary, and sets the HttpOnly flag on the JSESSIONID cookie.">
		<cfargument type="boolean" name="create" required="false">
		<cfscript>
			if (structKeyExists(arguments, 'create')) {
				local.jsession = getHttpServletRequest().getSession(arguments.create);
			}
			else {
				local.jsession = getHttpServletRequest().getSession();
			}

			if (isNull(local.jsession)) {
				return;
			}

			local.session = createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapperSession").init(instance.ESAPI, local.jsession);

			// send a new cookie header with HttpOnly on first and second responses
		    if (instance.ESAPI.securityConfiguration().getForceHttpOnlySession()) {
		        if (isNull(local.session.getAttribute("HTTP_ONLY"))) {
					local.session.setAttribute("HTTP_ONLY", "set");
					local.cookie = new Cookie("JSESSIONID", local.session.getId());
					local.cookie.setPath( getHttpServletRequest().getContextPath() );
					local.cookie.setMaxAge(-1); // session cookie
		            local.response = instance.ESAPI.currentResponse();
		            if (!isNull(local.response)) {
		                instance.ESAPI.currentResponse().addCookie(local.cookie);
		            }
		        }
		    }
	        return local.session;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getHeader" output="false" hint="Returns the named header from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument type="String" name="name" required="true">
		<cfscript>
	        local.value = getHttpServletRequest().getHeader(arguments.name);
	        local.clean = "";
	        try {
				if (!isNull(local.value)) {
	            	local.clean = instance.ESAPI.validator().getValidInput("HTTP header value: " & local.value, local.value, "HTTPHeaderValue", 150, true);
				}
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return local.clean;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getParameter" output="false" hint="Returns the named parameter from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument type="String" name="name" required="true" hint="The parameter name for the request">
		<cfargument type="boolean" name="allowNull" required="false" default="true" hint="Whether null values are allowed">
		<cfargument type="numeric" name="maxLength" required="false" default="2000" hint="The maximum length allowed">
		<cfargument type="String" name="regexName" required="false" default="HTTPParameterValue" hint="The name of the regex mapped from ESAPI.properties">
		<cfscript>
	        local.orig = getHttpServletRequest().getParameter(arguments.name);

	        if (isNull(local.orig)) {
	        	return "";
			}

	        local.clean = "";
	        try {
	            local.clean = instance.ESAPI.validator().getValidInput("HTTP parameter name: " & arguments.name, local.orig, arguments.regexName, arguments.maxLength, arguments.allowNull);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return local.clean;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="Struct" name="getParameterMap" output="false" hint="Returns the parameter map from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfscript>
	        local.map = getHttpServletRequest().getParameterMap();
	        local.cleanMap = {};
	        local.i = local.map.entrySet().iterator();
	        while (local.i.hasNext()) {
	            try {
	                local.e = local.i.next();
	                local.name = local.e.getKey();
	                local.cleanName = instance.ESAPI.validator().getValidInput("HTTP parameter name: " & local.name, local.name, "HTTPParameterName", 100, true);

	                local.value = local.e.getValue();
	                local.cleanValues = [];
	                for (local.j = 1; local.j <= arrayLen(local.value); local.j++) {
	                    local.cleanValue = instance.ESAPI.validator().getValidInput("HTTP parameter value: " & local.value[local.j], local.value[local.j], "HTTPParameterValue", 2000, true);
	                    local.cleanValues[local.j] = local.cleanValue;
	                }
	                local.cleanMap.put(local.cleanName, local.cleanValues);
	            } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	                // already logged
	            }
	        }
	        return local.cleanMap;
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getMethod" output="false" hint="Returns the name of the HTTP method with which this request was made.">
		<cfscript>
        	return getHttpServletRequest().getMethod();
       	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getRequestURL" output="false" hint="java.lang.StringBuffer: The currect request URL">
		<cfscript>
	        local.url = getHttpServletRequest().getRequestURL().toString();
	        local.clean = "";
	        try {
	            local.clean = instance.ESAPI.validator().getValidInput("HTTP URL: " & local.url, local.url, "HTTPURL", 2000, false);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return createObject("java", "java.lang.StringBuffer").init(local.clean);
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getLocalAddr" output="false" hint="A String containing the IP address on which the request was received.">
		<cfscript>
			// getLocalAddr is not in request - WHY?
        	//return getHttpServletRequest().getLocalAddr();
			return getRemoteAddr();
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getLocalPort" output="false" hint="Returns the Internet Protocol (IP) port number of the interface on which the request was received.">
		<cfscript>
			// getLocalPort is not in request - WHY?
        	//return getHttpServletRequest().getLocalPort();
        	return getServerPort();
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getRemoteAddr" output="false" hint="Returns the IP address of the client or last proxy that sent the request.">
		<cfscript>
        	return getHttpServletRequest().getRemoteAddr();
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getRemotePort" output="false" hint="The remote port">
		<cfscript>
			// getRemotePort is not in request - WHY?
        	//return getHttpServletRequest().getRemotePort();
        	return getServerPort();
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getServerPort" output="false" hint="Returns the server port (after the : in the host header) from the HttpServletRequest after parsing and checking the range 0-65536.">
		<cfscript>
			local.port = getHttpServletRequest().getServerPort();
			if ( local.port < 0 || local.port > 65536 ) {
				instance.logger.warning( createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "HTTP server port out of range: " & local.port );
				local.port = 0;
			}
			return local.port;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getAttribute" output="false" hint="The attribute value">
		<cfargument type="String" name="name" required="true" hint="The attribute name">
		<cfscript>
        	return getHttpServletRequest().getAttribute(name);
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getParameterValues" output="false" hint="Returns the array of matching parameter values from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfargument type="String" name="name" required="true" hint="The parameter name">
		<cfscript>
			local.values = getHttpServletRequest().getParameterValues(arguments.name);

			if (isNull(local.values)) {
				return "";
			}
			local.newValues = [];
			for (local.value in local.values) {
				try {
					local.cleanValue = instance.ESAPI.validator().getValidInput("HTTP parameter value: " & local.value, local.value, "HTTPParameterValue", 2000, true);
					local.newValues.add(local.cleanValue);
				} catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
					instance.logger.warning(createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Skipping bad parameter");
				}
			}
			return local.newValues;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getQueryString" output="false" hint="Returns the query string from the HttpServletRequest after canonicalizing and filtering out any dangerous characters.">
		<cfscript>
	        local.query = getHttpServletRequest().getQueryString();
	        local.clean = "";
	        try {
	            local.clean = instance.ESAPI.validator().getValidInput("HTTP query string: " & local.query, local.query, "HTTPQueryString", 2000, true);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // already logged
	        }
	        return local.clean;
    	</cfscript>
	</cffunction>


</cfcomponent>
