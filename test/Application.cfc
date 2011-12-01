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
		this.name = "CFESAPITestingSuite" & hash(getCurrentTemplatePath());
		this.sessionManagement = true;
		this.sessionTimeout = createTimeSpan(0, 0, 30, 0);
	
		// CFESAPI does not use CFID/CFTOKEN
		this.clientManagement = false;
		this.setClientCookies = false;
	</cfscript>
	

</cfcomponent>