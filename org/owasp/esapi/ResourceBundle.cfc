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
<cfinterface>

	<cffunction access="public" returntype="String" name="getLocaleData" output="false">
	</cffunction>

	<cffunction access="public" returntype="String" name="getString" output="false">
		<cfargument required="true" type="String" name="key">

	</cffunction>

	<cffunction access="public" returntype="String" name="messageFormat" output="false">
		<cfargument required="true" type="String" name="key">
		<cfargument required="true" type="Array" name="data">

	</cffunction>

</cfinterface>
