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
<cfcomponent extends="AuthenticationException" output="false">


	<cffunction access="public" returntype="AuthenticationAccountsException" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="string" name="userMessage" required="false" hint="the message displayed to the user">
		<cfargument type="string" name="logMessage" required="false" hint="the message logged">
		<cfargument type="any" name="cause" required="false" hint="the cause">
		<cfscript>
			super.init(argumentCollection=arguments);

			return this;
		</cfscript> 
	</cffunction>


</cfcomponent>
