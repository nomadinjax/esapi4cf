<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.HttpServletRequest" output="false">

	<cfscript>
		static.HDR_CONTENT_TYPE = "Content-Type";
		//static.EMPTY_STRING_ARRAY = new String[0];

		/* The requestDispatcher */
		//instance.requestDispatcher = new MockRequestDispatcher();

		/* The session. */
		instance.session = "";

		/* The cookies. */
		instance.cookies = [];

		/* The parameters. */
		instance.parameters = {};

		/* The headers. */
		instance.headers = {};

		instance.body = "";

		instance.scheme = "https";

		instance.remoteHost = "64.14.103.52";

		instance.serverHost = "64.14.103.52";

		instance.uri = "/test";

		instance.url = "https://www.example.com" & instance.uri;

		instance.queryString = "pid=1&qid=test";

		instance.method = "POST";

		instance.attrs = {};
	</cfscript>

	<cffunction access="public" returntype="MockHttpServletRequest" name="init" output="false">
		<cfargument type="any" name="url" required="false" hint="java.net.URL">
		<cfargument type="String" name="uri" required="false">
		<cfargument type="binary" name="body" required="false">
		<cfscript>
			if (structKeyExists(arguments, "url")) {
				instance.scheme = arguments.url.getProtocol();
				instance.serverHost = arguments.url.getHost();
				instance.uri = arguments.url.getPath();
			}

			if (structKeyExists(arguments, "body")) {
				instance.body = body;
			}
			if (structKeyExists(arguments, "uri")) {
				instance.uri = uri;
			}

			return this;
		</cfscript>
	</cffunction>

	<!--- getAuthType --->

	<cffunction access="public" returntype="String" name="getContextPath" output="false">
		<cfscript>
			return "";
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="addParameter" output="false" hint="Adds the parameter.">
		<cfargument type="String" name="name" required="true" hint="the name">
		<cfargument type="String" name="value" required="true" hint="the value">
		<cfscript>
			local.old = instance.parameters.get(arguments.name);
			if ( isNull(local.old) ) {
				local.old = [];
			}
			local.updated = [];
			for ( local.i = 1; local.i <= arrayLen(local.old); local.i++ ) {
				local.updated[local.i] = local.old[local.i];
			}
			local.updated[arrayLen(local.old)+1] = arguments.value;
			instance.parameters.put(arguments.name, local.updated);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="removeParameter" output="false" hint="removes the parameter name from the parameters map if it exists">
		<cfargument type="String" name="name" required="true" hint="parameter name to be removed">
		<cfscript>
			instance.parameters.remove( arguments.name );
		</cfscript>
	</cffunction>

	<!--- addHeader --->

	<cffunction access="public" returntype="void" name="setHeader" output="false" hint="Set a header replacing any previous value(s).">
		<cfargument type="String" name="name" required="true" hint="the header name">
		<cfargument type="String" name="value" required="true" hint="the header value">
		<cfscript>
			local.values = [];

			local.values.add(arguments.value);
			instance.headers.put(arguments.name, local.values);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setCookies" output="false" hint="Sets the cookies.">
		<cfargument type="Array" name="list" required="true" hint="the new cookies">
		<cfscript>
			instance.cookies = arguments.list;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setCookie" output="false">
		<cfargument type="String" name="name" required="true">
		<cfargument type="String" name="value" required="true">
		<cfscript>
			local.c = createObject("java", "javax.servlet.http.Cookie").init( arguments.name, arguments.value );
			instance.cookies.add( local.c );
		</cfscript>
	</cffunction>

	<!--- clearCookie --->
	<!--- clearCookies --->

	<cffunction access="public" returntype="Array" name="getCookies" output="false">
		<cfscript>
			if ( instance.cookies.isEmpty() ) return [];
			return duplicate(instance.cookies);
		</cfscript>
	</cffunction>

	<!--- getDateHeader --->
	<!--- getHeader --->
	<!--- getHeaderNames --->
	<!--- getHeaders --->
	<!--- getIntHeader --->

	<cffunction access="public" returntype="String" name="getMethod" output="false">
		<cfscript>
			return instance.method;
		</cfscript>
	</cffunction>

	<!--- setMethod --->
	<!--- getPathInfo --->
	<!--- getPathTranslated --->

	<cffunction access="public" returntype="String" name="getQueryString" output="false">
		<cfscript>
			return instance.queryString;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setQueryString" output="false" hint="Set the query string to return.">
		<cfargument type="String" name="str" required="true" hint="The query string to return.">
		<cfscript>
			instance.queryString = arguments.str;
		</cfscript>
	</cffunction>

	<!--- getRemoteUser --->

	<cffunction access="public" returntype="String" name="getRequestURI" output="false">
		<cfscript>
			return instance.uri;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getRequestURL" output="false" hint="java.lang.StringBuffer">
		<cfscript>
			return createObject("java", "java.lang.StringBuffer").init( getScheme() & "://" & getServerName() & getRequestURI() & "?" & getQueryString() );
		</cfscript>
	</cffunction>

	<!--- getRequestedSessionId --->
	<!--- getServletPath --->

	<cffunction access="public" returntype="any" name="getSession" output="false" hint="cfesapi.org.owasp.esapi.HttpSession">
		<cfargument type="boolean" name="create" required="false">
		<cfscript>
			if (structKeyExists(arguments, "create")) {
				if (!isObject(instance.session) && arguments.create) {
					instance.session = createObject("component", "MockHttpSession").init();
				} else if (isObject(instance.session) && instance.session.getInvalidated()) {
					instance.session = createObject("component", "MockHttpSession").init();
				}
				return instance.session;	// may return empty string or cfesapi.org.owasp.esapi.HttpSession
			}
			else {
				if (isObject(instance.session)) {
					return getSession(false);
				}
				return getSession(true);
			}
		</cfscript>
	</cffunction>

	<!--- getUserPrincipal --->
	<!--- isRequestedSessionIdFromCookie --->
	<!--- isRequestedSessionIdFromURL --->
	<!--- isRequestedSessionIdValid --->
	<!--- isUserInRole --->

	<cffunction access="public" returntype="any" name="getAttribute" output="false">
		<cfargument type="String" name="name" required="true">
		<cfscript>
			return instance.attrs.get(arguments.name);
		</cfscript>
	</cffunction>

	<!--- getAttributeNames --->
	<!--- getCharacterEncoding --->
	<!--- getContentLength --->
	<!--- getContentType --->

	<cffunction access="public" returntype="void" name="setContentType" output="false">
		<cfargument type="String" name="value" required="true">
		<cfscript>
			this.setHeader(static.HDR_CONTENT_TYPE, arguments.value);
		</cfscript>
	</cffunction>

	<!--- getInputStream --->

	<cffunction access="public" returntype="String" name="getLocalAddr" output="false">
		<cfscript>
			return "10.1.43.6";
		</cfscript>
	</cffunction>

	<!--- getLocalName --->

	<cffunction access="public" returntype="numeric" name="getLocalPort" output="false">
		<cfscript>
			return 80;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getLocale" output="false" hint="java.util.Locale">
		<cfscript>
			return "";
		</cfscript>
	</cffunction>

	<!--- getLocales --->

	<cffunction access="public" returntype="String" name="getParameter" output="false">
		<cfargument type="String" name="name" required="true">
		<cfscript>
			local.values = instance.parameters.get(arguments.name);
			if ( isNull(local.values) ) return "";
			return local.values[1];
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="clearParameters" output="false">
		<cfscript>
			instance.parameters.clear();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Struct" name="getParameterMap" output="false">
		<cfscript>
			// need duplicate() here so we do not alter internal object externally
			return duplicate(instance.parameters);
		</cfscript>
	</cffunction>

	<!--- getParameterNames --->

	<cffunction access="public" returntype="Array" name="getParameterValues" output="false">
		<cfargument type="String" name="name" required="true">
		<cfscript>
			if (structKeyExists(instance.parameters, arguments.name)) {
				return instance.parameters.get(arguments.name);
			}
			else {
				return [];
			}
		</cfscript>
	</cffunction>

	<!--- getProtocol --->
	<!--- getReader --->

	<cffunction access="public" returntype="String" name="getRemoteAddr" output="false">
		<cfscript>
			return instance.remoteHost;
		</cfscript>
	</cffunction>

	<!--- setRemoteAddr --->

	<cffunction access="public" returntype="String" name="getRemoteHost" output="false">
		<cfscript>
			return instance.remoteHost;
		</cfscript>
	</cffunction>

	<!--- getRemotePort --->
	<!--- getRequestDispatcher --->

	<cffunction access="public" returntype="String" name="getScheme" output="false">
		<cfscript>
			return instance.scheme;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getServerName" output="false">
		<cfscript>
			return instance.serverHost;
		</cfscript>
	</cffunction>

	<!--- getServerPort --->
	<!--- isSecure --->
	<!--- removeAttribute --->

	<cffunction access="public" returntype="void" name="setAttribute" output="false">
		<cfargument type="String" name="name" required="true">
		<cfargument type="any" name="o" required="true">
		<cfscript>
			instance.attrs.put(arguments.name,arguments.o);
		</cfscript>
	</cffunction>

	<!--- setCharacterEncoding --->
	<!--- setRequestURI --->

	<cffunction access="public" returntype="void" name="setRequestURL" output="false">
		<cfargument type="String" name="url" required="true">
		<cfscript>
			if (arguments.url == "") {
				instance.url = "";
				return;
			}
			// get the scheme
			local.p = arguments.url.indexOf( ":" );
			instance.scheme = arguments.url.substring( 0, local.p );

			// get the queryString
			local.q = arguments.url.indexOf( "?" );
			if ( local.q != -1 ) {
				instance.queryString = arguments.url.substring( local.q+1 );
				arguments.url = arguments.url.substring( 0, local.q );
			}
			else
				instance.queryString = "";
			instance.url = arguments.url;
		</cfscript>
	</cffunction>

	<!--- setScheme --->
	<!--- dump --->

	<cffunction access="public" returntype="boolean" name="isMultipartContent" output="false">
		<cfscript>
			local.contentTypes = instance.headers.get(static.HDR_CONTENT_TYPE);
			if (!isNull(local.contentTypes)) {
				for (local.i=1; local.i<=arrayLen(local.contentTypes); i++) {
					local.contentType = local.contentTypes[local.i];
					if (local.contentType contains "multipart/form-data;") {
						return true;
					}
				}
			}
			return false;
		</cfscript>
	</cffunction>


</cfcomponent>
