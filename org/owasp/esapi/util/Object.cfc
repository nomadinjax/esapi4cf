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
		// all ESAPI components will have these
		this.ESAPINAME = "ESAPI4CF";				// ESAPI library name
		this.VERSION = "1.2.0a";					// ESAPI library version
		this.ESAPI4JVERSION = 1;					// ESAPI4J version
		if (structKeyExists(createObject("java", "org.owasp.esapi.ESAPI").securityConfiguration(), "APPLICATION_NAME")) {
			this.ESAPI4JVERSION = 2;
		}
	</cfscript>

	<cffunction access="public" name="init" output="false" hint="Default constructor">

		<cfscript>
			return this;
		</cfscript>

	</cffunction>

	<cfinclude template="utils.cfm"/>

</cfcomponent>