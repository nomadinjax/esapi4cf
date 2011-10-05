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
<cfcomponent output="false">


	<cffunction access="public" returntype="void" name="forward" output="false">
		<cfargument type="ServletRequest" name="request" required="true">
		<cfargument type="ServletResponse" name="response" required="true">
		<cfscript>
    		System.out.println( "Forwarding" );
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="include" output="false">
		<cfargument type="ServletRequest" name="request" required="true">
		<cfargument type="ServletResponse" name="response" required="true">
		<cfscript>
    		System.out.println( "Including" );
    	</cfscript> 
	</cffunction>


</cfcomponent>
