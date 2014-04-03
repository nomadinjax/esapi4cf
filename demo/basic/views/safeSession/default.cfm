<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfscript>
	variables.ignoredVars = "ESAPIUserSessionKey,urltoken,sessionid,esapi_session,http_only";

	// ensure our test vars don't exist
	structDelete(session, "myVAR");
	structDelete(session, "myESAPIvar");

	session.mySessionVar = "test1";

	variables.esapiSession = application.ESAPI.currentRequest().getSession();
</cfscript>

<cffunction name="outputCFSession" output="false">
	<cfsavecontent variable="generatedContent">
		<cfoutput>
			<h3>CF Session Dump</h3>
			<ul>
				<cfloop item="key" collection="#session#">
					<cfif not listFindNoCase(variables.ignoredVars, key)>
						<li>#key#=#session[key]#</li>
					</cfif>
				</cfloop>
			</ul>
		</cfoutput>
	</cfsavecontent>
	<cfreturn generatedContent>
</cffunction>

<cffunction name="outputESAPISession" output="false">
	<cfscript>
		var esapiAttrNames = variables.esapiSession.getAttributeNames();
		var key = "";
	</cfscript>
	<cfsavecontent variable="generatedContent">
		<cfoutput>
			<h3>ESAPI Session Dump</h3>
			<ul>
				<cfloop condition="#esapiAttrNames.hasMoreElements()#">
					<cfset key = esapiAttrNames.nextElement().toString()>
					<cfif not listFindNoCase(variables.ignoredVars, key)>
						<li>#key#=#variables.esapiSession.getAttribute(lCase(key))#</li>
					</cfif>
				</cfloop>
			</ul>
		</cfoutput>
	</cfsavecontent>
	<cfreturn generatedContent>
</cffunction>

<cfoutput>
#outputCFSession()#
#outputESAPISession()#

<p>Adding new var via setAttribute("myESAPIvar", "test2")</p>
<cfset variables.esapiSession.setAttribute("myESAPIvar", "test2")>

#outputCFSession()#
#outputESAPISession()#

<p>Removing var via removeAttribute("mySessionVAR")</p>
<cfset variables.esapiSession.removeAttribute("mySessionVAR")>

#outputCFSession()#
#outputESAPISession()#
</cfoutput>
