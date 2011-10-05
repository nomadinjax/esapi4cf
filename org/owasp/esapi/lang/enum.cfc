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

	<cfscript>
		instance.ordinal = "";
	</cfscript>
 
	<cffunction access="public" returntype="enum" name="init" output="false">
		<cfargument type="numeric" name="ordinal" required="true">
		<cfscript>
			instance.ordinal = arguments.ordinal;

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="ordinal" output="false">
		<cfscript>
			return instance.ordinal;
		</cfscript> 
	</cffunction>


</cfcomponent>
