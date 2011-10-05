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
<cfcomponent extends="cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration" output="false">


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.SecurityConfiguration" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration" name="cfg" required="false">
		<cfscript>
			super.init(arguments.ESAPI, arguments.cfg.getESAPIProperties());

	        return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setLogImplementation" output="false">
		<cfargument type="String" name="v" required="true">
		<cfscript>
    		getESAPIProperties().setProperty(this.LOG_IMPLEMENTATION, arguments.v);
    	</cfscript> 
	</cffunction>


</cfcomponent>
