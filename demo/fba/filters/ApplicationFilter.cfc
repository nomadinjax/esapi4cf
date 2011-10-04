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
<cfcomponent output="false">

	<cfscript>
		// CFESAPI only requires that sessionManagement be on
		this.name = "CFESAPI-FBADemoCFApplication";
		this.sessionManagement = true;

		// CFESAPI does not use CFID/CFTOKEN
		this.clientManagement = false;
		this.setClientCookies = false;
		
		// CFESAPI config settings
		instance.ESAPIconfig = "/cfesapi/demo/fba/config/";
	</cfscript>
 
	<cffunction access="public" returntype="boolean" name="onRequestStart" output="false">
		<cfargument type="String" name="targetPage" required="true">
		<cfscript>
			return true;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="onRequest" output="true">
		<cfargument type="String" name="targetPage" required="true">
		<cfscript>
			setupESAPI();
		</cfscript> 
		<cfsavecontent variable="generatedContent">
			<cfinclude template="#arguments.targetPage#" />
		</cfsavecontent>
		<cfoutput>
			#generatedContent# 
		</cfoutput>
	</cffunction>


	<cffunction access="public" returntype="void" name="onRequestEnd" output="false">
		<cfargument type="String" name="targetPage" required="true">
		<cfscript>
			tearDownESAPI();
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="void" name="setupESAPI" output="false">
		<cfscript>
			// this allows us to reinit ESAPI in case we make changes - for dev purposes
			if (structKeyExists(url, "reinit") && url.reinit == "ESAPI") {
				application["ESAPI"] = "";
			}
			
			// initialize ESAPI and load encoder UDFs
			include "/cfesapi/helpers/ESAPI.cfm";
			
			// define the ESAPI config location - condition so that this does not reload config on each request
			if (instance.ESAPIconfig != ESAPI().securityConfiguration().getResourceDirectory()) {
				ESAPI().securityConfiguration().setResourceDirectory(instance.ESAPIconfig);
			}
			
			// setup ESAPI logger with CF app name
			if (!structKeyExists(application, "logger")) {
				application["logger"] = ESAPI().getLogger(application.applicationName);
			}

            // set no-cache headers on every response
            // only do this if the entire site should not be cached otherwise you should do this strategically in your controller or actions
			ESAPI().httpUtilities().setNoCacheHeaders();
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="void" name="tearDownESAPI" output="false">
		<cfscript>
			ESAPI().clearCurrent();
		</cfscript> 
	</cffunction>


</cfcomponent>
