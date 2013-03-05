<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 --->
<cfcomponent extends="esapi4cf.org.owasp.esapi.util.Object" output="false">

	<cffunction access="public" returntype="void" name="forward" output="false">
		<cfargument required="true" name="request"/>
		<cfargument required="true" name="response"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="include" output="false">
		<cfargument required="true" name="request"/>
		<cfargument required="true" name="response"/>

	</cffunction>

</cfcomponent>