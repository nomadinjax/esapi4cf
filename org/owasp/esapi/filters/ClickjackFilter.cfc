<!--- /**
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
 */ --->
<cfcomponent displayname="ClickjackFilter" implements="cfesapi.org.owasp.esapi.lang.Filter" output="false">

	<cfscript>
		instance.mode = "DENY";
		instance.response = "";
	</cfscript>

	<cffunction access="public" returntype="ClickjackFilter" name="init" output="false"
	            hint="Initialize 'mode' parameter from web.xml. Valid values are 'DENY' and 'SAMEORIGIN'. If you leave this parameter out, the default is to use the DENY mode.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" type="Struct" name="filterConfig" hint="A filter configuration object used by a servlet container to pass information to a filter during initialization."/>

		<cfset var local = {}/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			if(structKeyExists(arguments.filterConfig, "mode")) {
				local.configMode = arguments.filterConfig.get("mode");
			}
			if(structKeyExists(local, "configMode") && (local.configMode.equals("DENY") || local.configMode.equals("SAMEORIGIN"))) {
				instance.mode = local.configMode;
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="doFilter" output="false"
	            hint="Add X-FRAME-OPTIONS response header to tell the browser not to display this content in a frame. For details, please refer to {@link http://blogs.msdn.com/sdl/archive/2009/02/05/clickjacking-defense-in-ie8.aspx}.">
		<cfargument required="true" name="request" hint="The request object."/>
		<cfargument required="true" name="response" hint="The response object."/>

		<cfscript>
			instance.response = arguments.response;
			return true;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="destroy" output="false">

		<cfscript>
			instance.response.addHeader("X-FRAME-OPTIONS", instance.mode);
		</cfscript>

	</cffunction>

</cfcomponent>