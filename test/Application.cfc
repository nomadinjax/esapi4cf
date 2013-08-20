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
		// 1. Required - set an application name
		this.name = "ESAPI-MXUnit";

		// 2. Required - turn on J2EE session management (requires J2EE Sessions be turned on in administrator)
		this.sessionManagement = true;

		// 3. Optional - turn off deprecated client management
		this.clientManagement = false;

		// 4. Optional - don't set CFID/CFTOKEN cookies - these are garbage
		this.setClientCookies = false;

		this.mappings["/org"] = expandPath("/esapi4cf/org");
	</cfscript>
 
</cfcomponent>
