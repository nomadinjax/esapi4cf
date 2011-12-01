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
<cfcomponent extends="cfesapi.demo.fba.filters.ApplicationFilter" output="false">

	<cfscript>
		// CFESAPI filters
		instance.ESAPIFilter = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="onRequest">
		<cfargument required="true" type="String" name="targetPage"/>

		<cfif setupESAPI()>
			<cfif structKeyExists(url, "logout")>
				<cfset ESAPI().authenticator().logout()/>
				<cflocation url="../index.cfm" addtoken="false"/>
				<cfreturn/>
			</cfif>

			<cfsavecontent variable="generatedContent">
				<cfinclude template="#arguments.targetPage#">
			</cfsavecontent>

			<cfscript>
				writeOutput(trim(generatedContent));
			</cfscript>

		</cfif>

		<cfscript>
			tearDownESAPI();
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="setupESAPI">

		<cfscript>
			super.setupESAPI();

			/* FIXME:
			Filters are supposed to be chained but I could not think of a way to make this work in CF.
			This is best solution I've got for the time being.
			*/
			// ESAPI authentication filter
			local.filterConfig = {unauthenticatedPath="/cfesapi/demo/fba/includes/login.cfm", unauthorizedPath="/cfesapi/demo/fba/includes/unauthorized.cfm"};
			instance.ESAPIFilter = createObject("component", "cfesapi.org.owasp.esapi.filters.ESAPIFilter").init(ESAPI(), local.filterConfig);
			return instance.ESAPIFilter.doFilter(ESAPI().currentRequest(), ESAPI().currentResponse());
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="tearDownESAPI" output="false">

		<cfscript>
			// destroy filters in reverse order
			instance.ESAPIFilter.destroy();
			instance.ESAPIFilter = "";
			super.tearDownESAPI();
		</cfscript>

	</cffunction>

</cfcomponent>