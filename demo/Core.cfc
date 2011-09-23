<cfcomponent output="false">

	<cfscript>
		// CFESAPI only requires that sessionManagement be on
		this.name = "CFESAPI-Demo";
		this.sessionManagement = true;

		// CFESAPI does not use CFID/CFTOKEN
		this.clientManagement = false;
		this.setClientCookies = false;
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
			// this allows us to reinit ESAPI in case we make changes - for dev purposes
			if (structKeyExists(url, "reinit") && url.reinit == "ESAPI") {
				application["ESAPI"] = "";
			}
			include "/cfesapi/helpers/ESAPI.cfm";

			// set up response with content type
			ESAPI().httpUtilities().setContentType();

            // set no-cache headers on every response
            // only do this if the entire site should not be cached otherwise you should do this strategically in your controller or actions
			ESAPI().httpUtilities().setNoCacheHeaders();
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
			ESAPI().clearCurrent();
		</cfscript>
	</cffunction>


</cfcomponent>
