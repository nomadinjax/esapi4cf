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
<!---  implements="cfesapi.org.owasp.esapi.HttpServletRequest" --->
<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" output="false">

	<cfscript>
		/** The requestDispatcher */
		instance.requestDispatcher = createObject( "component", "TestRequestDispatcher" ).init();

		/** The session. */
		instance.session = "";

		/** The cookies. */
		instance.cookies = [];

		/** The parameters. */
		instance.parameters = {};

		/** The headers. */
		instance.headers = {};

		instance.body = "";

		instance.uri = "/test";

		instance.contentType = "";

		instance.method = "POST";
	</cfscript>

	<cffunction access="public" returntype="TestHttpServletRequest" name="init" output="false">
		<cfargument type="String" name="uri"/>
		<cfargument type="binary" name="body"/>

		<cfscript>
			if(structKeyExists( arguments, "body" )) {
				instance.body = arguments.body;
			}
			if(structKeyExists( arguments, "uri" )) {
				instance.uri = arguments.uri;
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getAuthType" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getContextPath" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addParameter" output="false"
	            hint="Adds the parameter.">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="String" name="value"/>

		<cfscript>
			var local = {};
			if(structKeyExists( instance.parameters, arguments.name )) {
				local.old = instance.parameters.get( arguments.name );
			}
			if(!structKeyExists( local, "old" )) {
				local.old = [];
			}
			local.updated = [];
			for(local.i = 1; local.i <= arrayLen( local.old ); local.i++)
				local.updated[local.i] = local.old[local.i];
			local.updated[arrayLen( local.old ) + 1] = arguments.value;
			instance.parameters.put( arguments.name, local.updated );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeParameter" output="false"
	            hint="removeParameter removes the parameter name from the parameters map if it exists">
		<cfargument required="true" type="String" name="name" hint="parameter name to be removed"/>

		<cfscript>
			instance.parameters.remove( arguments.name );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="addHeader" output="false"
	            hint="Adds the header.">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="String" name="value"/>

		<cfscript>
			instance.headers.put( arguments.name, arguments.value );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCookies" output="false"
	            hint="Sets the cookies.">
		<cfargument required="true" type="Array" name="list" hint="the new cookies"/>

		<cfscript>
			instance.cookies = arguments.list;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCookie" output="false">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="String" name="value"/>

		<cfscript>
			var local = {};
			local.c = getJava( "javax.servlet.http.Cookie" ).init( arguments.name, arguments.value );
			instance.cookies.add( local.c );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="clearCookies" output="false">

		<cfscript>
			instance.cookies.clear();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getCookies" output="false">

		<cfscript>
			return instance.cookies.toArray();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Date" name="getDateHeader" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return 0;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getHeader" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			if(arguments.name.equals( "Content-type" )) {
				return "multipart/form-data; boundary=xxx";
			}
			return instance.headers.get( arguments.name );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getHeaderNames" output="false">

		<cfscript>
			return getJava("java.util.Hashtable").init(instance.headers).elements();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getHeaders" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			var local = {};
			local.v = [];
			local.v.add( getHeader( arguments.name ) );
			return local.v;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getIntHeader" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return 0;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getMethod" output="false">

		<cfscript>
			return instance.method;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setMethod" output="false">
		<cfargument required="true" type="String" name="value"/>

		<cfscript>
			instance.method = arguments.value;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getPathInfo" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getPathTranslated" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getQueryString" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRemoteUser" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRequestURI" output="false">

		<cfscript>
			return instance.uri;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getRequestURL" output="false">

		<cfscript>
			return getJava( "java.lang.StringBuffer" ).init( "https://localhost" & instance.uri );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRequestedSessionId" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getServletPath" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getSession" output="false">
		<cfargument type="boolean" name="create"/>

		<cfscript>
			if(structKeyExists( arguments, "create" )) {
				if(!isObject( instance.session ) && arguments.create) {
					instance.session = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpSession" ).init();
				}
				else if(isObject( instance.session ) && instance.session.getInvalidated()) {
					instance.session = createObject( "component", "cfesapi.test.org.owasp.esapi.http.TestHttpSession" ).init();
				}
				return instance.session;// may return empty string or TestHttpSession
			}
			else {
				if(isObject( instance.session )) {
					return getSession( false );
				}
				return getSession( true );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getUserPrincipal" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdFromCookie" output="false">

		<cfscript>
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdFromURL" output="false">

		<cfscript>
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isRequestedSessionIdValid" output="false">

		<cfscript>
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="hasUserInRole" output="false">
		<cfargument required="true" type="String" name="role"/>

		<cfscript>
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getAttribute" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getAttributeNames" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getContentLength" output="false">

		<cfscript>
			return instance.body.length;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getContentType" output="false">

		<cfscript>
			return instance.contentType;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setContentType" output="false">
		<cfargument required="true" type="String" name="value"/>

		<cfscript>
			instance.contentType = arguments.value;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getInputStream" output="false">

		<cfscript>
			return getJava( "org.owasp.esapi.http.TestServletInputStream" ).init( instance.body );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLocalAddr" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLocalName" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getLocalPort" output="false">

		<cfscript>
			return 0;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getLocaleData" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getLocales" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getParameter" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			var local = {};
			if(structKeyExists( instance.parameters, arguments.name )) {
				local.values = instance.parameters.get( arguments.name );
			}
			if(!structKeyExists( local, "values" ))
				return "";
			return local.values[1];
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Struct" name="getParameterMap" output="false">

		<cfscript>
			// need duplicate() here so we do not alter internal object externally
			return duplicate( instance.parameters );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getParameterNames" output="false">

		<cfscript>
			return listToArray( structKeyList( instance.parameters ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getParameterValues" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>
			if(structKeyExists( instance.parameters, arguments.name )) {
				return instance.parameters.get( arguments.name );
			}
			else {
				local.empty = [];
				return local.empty;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getProtocol" output="false">

		<cfscript>
			return "HTTP/1.1";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getReader" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRealPath" output="false">
		<cfargument required="true" type="String" name="path"/>

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRemoteAddr" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getRemoteHost" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getRemotePort" output="false">

		<cfscript>
			return 0;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getRequestDispatcher" output="false">
		<cfargument required="true" type="String" name="path"/>

		<cfscript>
			return instance.requestDispatcher;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getScheme" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getServerName" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="getServerPort" output="false">

		<cfscript>
			return 0;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isSecure" output="false">

		<cfscript>
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="removeAttribute" output="false">
		<cfargument required="true" type="String" name="name"/>

		<cfscript>

		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setAttribute" output="false">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" name="o"/>

		<cfscript>

		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setCharacterEncoding" output="false">
		<cfargument required="true" type="String" name="enc"/>

		<cfscript>

		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setRequestURI" output="false">
		<cfargument required="true" type="String" name="uri"/>

		<cfscript>
			instance.uri = arguments.uri;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isUserInRoleData" output="false">
		<cfargument required="true" type="String" name="role"/>

	</cffunction>

</cfcomponent>