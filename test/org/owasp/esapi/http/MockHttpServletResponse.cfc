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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.HttpServletResponse" output="false">

	<cfscript>
		/* The cookies. */
		instance.cookies = [];

		/* The header names. */
		instance.headerNames = [];

		/* The header values. */
		instance.headerValues = [];

		/* The status. */
		instance.status = 200;

		instance.body = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init();

		//instance.contentType = "text/html; charset=ISO-8895-1";
	</cfscript>

	<cffunction access="public" returntype="MockHttpServletResponse" name="init" output="false">

		<cfscript>
			return this;
		</cfscript>

	</cffunction>

	<!--- getBody --->

	<cffunction access="public" returntype="void" name="addCookie" output="false">
		<cfargument type="any" name="cookie" required="true" hint="javax.servlet.http.Cookie"/>

		<cfscript>
			instance.cookies.add(arguments.cookie);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getCookies" output="false"
	            hint="Gets the cookies.">

		<cfscript>
			return duplicate(instance.cookies);
		</cfscript>

	</cffunction>

	<!--- getCookie --->
	<!--- addDateHeader --->

	<cffunction access="public" returntype="void" name="addHeader" output="false">
		<cfargument type="String" name="name" required="true"/>
		<cfargument type="String" name="value" required="true"/>

		<cfscript>
			instance.headerNames.add(arguments.name);
			instance.headerValues.add(arguments.value);
		</cfscript>

	</cffunction>

	<!--- addIntHeader --->

	<cffunction access="public" returntype="boolean" name="containsHeader" output="false">
		<cfargument type="String" name="name" required="true"/>

		<cfscript>
			return instance.headerNames.contains(arguments.name);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getHeader" output="false"
	            hint="Gets the header.">
		<cfargument type="String" name="name" required="true" hint="the name"/>

		<cfset var local = {}/>

		<cfscript>
			local.index = instance.headerNames.indexOf(arguments.name);
			if(local.index != -1) {
				return instance.headerValues.get(local.index);
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getHeaderNames" output="false"
	            hint="Gets the header names.">

		<cfscript>
			return instance.headerNames;
		</cfscript>

	</cffunction>

	<!--- encodeRedirectURL --->
	<!--- encodeURL --->
	<!--- sendError --->

	<cffunction access="public" returntype="void" name="sendRedirect" output="false">
		<cfargument type="String" name="location" required="true"/>

		<cfscript>
			instance.status = newJava("javax.servlet.http.HttpServletResponse").SC_MOVED_PERMANENTLY;
			instance.body = newComponent("cfesapi.org.owasp.esapi.lang.StringBuilder").init("Redirect to " & arguments.location);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setDateHeader" output="false">
		<cfargument type="String" name="name" required="true"/>
		<cfargument type="numeric" name="date" required="true"/>

		<cfscript>
			instance.headerNames.add(arguments.name);
			instance.headerValues.add("" & arguments.date);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setHeader" output="false">
		<cfargument type="String" name="name" required="true"/>
		<cfargument type="String" name="value" required="true"/>

		<cfscript>
			instance.headerNames.add(arguments.name);
			instance.headerValues.add(arguments.value);
		</cfscript>

	</cffunction>

	<!--- setIntHeader --->
	<!--- setStatus --->
	<!--- getStatus --->
	<!--- flushBuffer --->
	<!--- getBufferSize --->

	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false">

		<cfscript>
			return "UTF-8";
		</cfscript>

	</cffunction>

	<!--- getContentType --->
	<!--- getLocale --->
	<!--- getOutputStream --->
	<!--- getWriter --->
	<!--- isCommitted --->
	<!--- reset --->
	<!--- resetBuffer --->
	<!--- setBody --->
	<!--- setBufferSize --->
	<!--- setCharacterEncoding --->
	<!--- setContentLength --->
	<!--- setContentType --->
	<!--- setLocale --->
	<!--- dump --->
</cfcomponent>