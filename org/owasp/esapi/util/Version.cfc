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
<cfcomponent extends="Object" output="false" hint="Contains version information about the library.">

	<cffunction access="public" returntype="String" name="getCFMLEngine" output="false">
		<cfscript>
			return listFirst(server.ColdFusion.ProductName, " ");
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getCFMLVersion" output="false">
		<cfscript>
			if (structKeyExists(server, "railo")) {
				return server.railo.version;
			}
			return server.ColdFusion.ProductVersion;
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getJVMVersion" output="false">
		<cfscript>
			return createObject("java", "java.lang.System").getProperty("java.version");
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getESAPI4CFName" output="false">
		<cfscript>
			return "ESAPI4CF";
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getESAPI4CFVersion" output="false">
		<cfscript>
			return "1.2.0a";
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getESAPI4JVersion" output="false">
		<cfscript>
			if (structKeyExists(createObject("java", "org.owasp.esapi.ESAPI").securityConfiguration(), "APPLICATION_NAME")) {
				return 2;
			}
			return 1;
		</cfscript>
	</cffunction>

</cfcomponent>