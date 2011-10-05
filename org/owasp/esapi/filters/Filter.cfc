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
<cfinterface>

	<cffunction access="public" returntype="Filter" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="Struct" name="filterConfig" required="true">
	</cffunction>


	<cffunction access="public" returntype="void" name="doFilter" output="false">
		<cfargument type="any" name="request" required="true" hint="javax.servlet.ServletRequest">
		<cfargument type="any" name="response" required="true" hint="javax.servlet.ServletResponse">
		<!--- not using <cfargument type="Filter" name="chain" required="false"> --->
	</cffunction>


	<cffunction access="public" returntype="void" name="destroy" output="false">
	</cffunction>

</cfinterface>
