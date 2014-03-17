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
<cfcomponent output="false">

	<cfscript>
		variables.fw = {};
	</cfscript>

	<cffunction access="public" returntype="account" name="init" output="false">
		<cfargument required="true" type="Struct" name="fw">
		<cfscript>
			variables.fw = arguments.fw;
			return this;
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="changePassword" output="false">
		<cfscript>
			var httpRequest = application.ESAPI.currentRequest();
			var httpResponse = application.ESAPI.currentResponse();
			var currentUser = application.ESAPI.authenticator().getCurrentUser();

			try {
				currentUser.changePassword(httpRequest.getParameter("currentPassword"), httpRequest.getParameter("newPassword1"), httpRequest.getParameter("newPassword2"));
			}
			catch(org.owasp.esapi.errors.AuthenticationCredentialsException e) {
				variables.rc["message"] = e.message;
				variables.rc["detail"] = e.detail;
			}
			catch(org.owasp.esapi.errors.AuthenticationException e) {
				variables.rc["message"] = e.message;
				variables.rc["detail"] = e.detail;
			}
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="settings" output="false">
		<cfscript>
			var httpRequest = application.ESAPI.currentRequest();
			var localeSetting = "";

			// always check for POST before attempting any data changes
			if (httpRequest.getMethod() == "POST") {
				localeSetting = httpRequest.getParameter("localeSetting");
				if (!isNull(localeSetting)) {
					application.ESAPI.authenticator().getCurrentUser().setLocaleData(createObject("java", "java.util.Locale").init(listFirst(localeSetting, "_"), listLast(localeSetting, "_")));
				}
				variables.fw.redirect("account.settings");
			}
		</cfscript>
	</cffunction>

</cfcomponent>