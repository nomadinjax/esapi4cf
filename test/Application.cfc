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
<cfcomponent hint="ESAPI MXUnit initialization">

	<cfscript>
		this.name = "ESAPI-MXUnit";
		this.sessionManagement = false;
		this.clientManagement = false;
		this.setClientCookies = false;

		this.mappings["/org"] = expandPath("/esapi4cf/org");
		this.mappings["/test"] = expandPath("/esapi4cf/test");
	</cfscript>

</cfcomponent>