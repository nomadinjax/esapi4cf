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
<cfcomponent output="false">

	<cfscript>
		// CFESAPI only requires that sessionManagement be on
		this.name = "CFESAPI-FBADemoCFApplication";
		this.sessionManagement = true;

		// CFESAPI does not use CFID/CFTOKEN
		this.clientManagement = false;
		this.setClientCookies = false;

		// CFESAPI filters
		instance.SecurityWrapper = "";
		instance.ClickjackFilter = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="onRequest">
		<cfargument required="true" type="String" name="targetPage"/>

		<cfif setupESAPI()>
			<cfsavecontent variable="generatedContent">
				<cfinclude template="#arguments.targetPage#" />
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
			// this allows us to reinit ESAPI in case we make changes - for dev purposes
			if(structKeyExists(url, "reinit") && url.reinit == "ESAPI") {
				application["ESAPI"] = "";
			}
		</cfscript>

		<!--- initialize ESAPI and load encoder UDFs --->
		<cfinclude template="/cfesapi/helpers/ESAPI.cfm">

		<cfscript>
			/* FIXME:
			Filters are supposed to be chained but I could not think of a way to make this work in CF.
			This is best solution I've got for the time being.
			*/
			// SecurityWrapper filter - required - secures request/response objects
			local.filterConfig = {allowableResourcesRoot="/cfesapi/demo/fba/", resourceDirectory="/cfesapi/demo/fba/config/"};
			instance.SecurityWrapper = createObject("component", "cfesapi.org.owasp.esapi.filters.SecurityWrapper").init(ESAPI(), local.filterConfig);
			local.isSecureRequest = instance.SecurityWrapper.doFilter(getPageContext().getRequest(), getPageContext().getResponse());

			// ClickjackFilter - optional - prevent your site from being framed
			// mode options: DENY | SAMEORIGIN
			local.filterConfig = {mode="DENY"};
			instance.ClickjackFilter = createObject("component", "cfesapi.org.owasp.esapi.filters.ClickjackFilter").init(ESAPI(), local.filterConfig);
			instance.ClickjackFilter.doFilter(ESAPI().currentRequest(), ESAPI().currentResponse());

			return local.isSecureRequest;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="tearDownESAPI" output="false">

		<cfscript>
			// destroy filters in reverse order
			instance.ClickjackFilter.destroy();
			instance.ClickjackFilter = "";
			instance.SecurityWrapper.destroy();
			instance.SecurityWrapper = "";
		</cfscript>

	</cffunction>

</cfcomponent>