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

	<cffunction access="public" returntype="void" name="changePassword" output="false">
		<cfscript>
			httpRequest = application.ESAPI.currentRequest();
			httpResponse = application.ESAPI.currentResponse();
			currentUser = application.ESAPI.authenticator().getCurrentUser();

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

</cfcomponent>