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
<!---  implements="org.owasp.esapi.util.HttpServletRequest" --->
<cfcomponent extends="org.owasp.esapi.util.Object" output="false">

	<cfscript>
		/** The requestDispatcher */
		variables.requestDispatcher = createObject("component", "TestRequestDispatcher").init();
	
		/** The session. */
		variables.session = "";
	
		/** The cookies. */
		variables.cookies = [];
	
		/** The parameters. */
		variables.parameters = {};
	
		/** The headers. */
		variables.headers = {};
	
		variables.body = "";
	
		variables.uri = "/test";
	
		variables.contentType = "";
	
		variables.method = "POST";
	</cfscript>
	
	<cffunction access="public" returntype="TestHttpServletRequest" name="init" output="false">
		<cfargument type="String" name="uri"/>
		<cfargument type="binary" name="body"/>
	
		<cfscript>
			if(structKeyExists(arguments, "body")) {
				variables.body = arguments.body;
			}
			if(structKeyExists(arguments, "uri")) {
				variables.uri = arguments.uri;
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
			// CF8 requires 'var' at the top
			var updated = "";
			var i = "";
		
			var old = [];
			if(structKeyExists(variables.parameters, arguments.name)) {
				old = variables.parameters[arguments.name];
			}
			updated = [];
			for(i = 1; i <= arrayLen(old); i++)
				updated[i] = old[i];
			arrayAppend(updated, arguments.value);
			variables.parameters[arguments.name] = updated;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="removeParameter" output="false"
	            hint="removeParameter removes the parameter name from the parameters map if it exists">
		<cfargument required="true" type="String" name="name" hint="parameter name to be removed"/>
	
		<cfscript>
			variables.parameters.remove(arguments.name);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="addHeader" output="false"
	            hint="Adds the header.">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="String" name="value"/>
	
		<cfscript>
			variables.headers.put(arguments.name, arguments.value);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setCookies" output="false"
	            hint="Sets the cookies.">
		<cfargument required="true" type="Array" name="list" hint="the new cookies"/>
	
		<cfscript>
			variables.cookies = arguments.list;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setCookie" output="false">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="String" name="value"/>
	
		<cfscript>
			var c = newJava("javax.servlet.http.Cookie").init(arguments.name, arguments.value);
			variables.cookies.add(c);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="clearCookies" output="false">
		
		<cfscript>
			variables.cookies.clear();
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="Array" name="getCookies" output="false">
		
		<cfscript>
			return variables.cookies.toArray();
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
			if(arguments.name.equals("Content-type")) {
				return "multipart/form-data; boundary=xxx";
			}
			return variables.headers.get(arguments.name);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="Array" name="getHeaderNames" output="false">
		
		<cfscript>
			return newJava("java.util.Hashtable").init(variables.headers).elements();
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="Array" name="getHeaders" output="false">
		<cfargument required="true" type="String" name="name"/>
	
		<cfscript>
			var v = [];
			v.add(getHeader(arguments.name));
			return v;
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
			return variables.method;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setMethod" output="false">
		<cfargument required="true" type="String" name="value"/>
	
		<cfscript>
			variables.method = arguments.value;
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
			return variables.uri;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" name="getRequestURL" output="false">
		
		<cfscript>
			return newJava("java.lang.StringBuffer").init("https://localhost" & variables.uri);
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
			if(structKeyExists(arguments, "create")) {
				if(!isObject(variables.session) && arguments.create) {
					variables.session = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpSession").init();
				}
				else if(isObject(variables.session) && variables.session.getInvalidated()) {
					variables.session = createObject("component", "esapi4cf.test.org.owasp.esapi.http.TestHttpSession").init();
				}
				return variables.session;// may return empty string or TestHttpSession
			}
			else { 
				if(isObject(variables.session)) {
					return getSession(false);
				}
				return getSession(true);
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
			return variables.body.length;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getContentType" output="false">
		
		<cfscript>
			return variables.contentType;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setContentType" output="false">
		<cfargument required="true" type="String" name="value"/>
	
		<cfscript>
			variables.contentType = arguments.value;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" name="getInputStream" output="false">
		
		<cfscript>
			return newJava("org.owasp.esapi.http.TestServletInputStream").init(variables.body);
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
			var values = [];
			if(structKeyExists(variables.parameters, arguments.name)) {
				values = variables.parameters[arguments.name];
			}
			if(arrayLen(values))
				return values[1];
			return "";
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="Struct" name="getParameterMap" output="false">
		
		<cfscript>
			// need duplicate() here so we do not alter internal object externally
			return duplicate(variables.parameters);
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="Array" name="getParameterNames" output="false">
		
		<cfscript>
			return listToArray(structKeyList(variables.parameters));
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="Array" name="getParameterValues" output="false">
		<cfargument required="true" type="String" name="name"/>
	
		<cfscript>
			if(structKeyExists(variables.parameters, arguments.name)) {
				return variables.parameters.get(arguments.name);
			}
			else {
				return arrayNew(1);
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
			return variables.requestDispatcher;
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
			variables.uri = arguments.uri;
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="boolean" name="isUserInRoleData" output="false">
		<cfargument required="true" type="String" name="role"/>
	
	</cffunction>
	
</cfcomponent>