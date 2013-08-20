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
<cfcomponent output="false" hint="The Class Rule.">

	<cfscript>
		this.path = "";
		this.roles = [];
		this.allow = false;
		this.clazz = "";
		this.actions = [];
	</cfscript>
 
	<cffunction access="public" returntype="FileBasedAccessController$Rule" name="init" output="false">
		<cfscript>
			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="toStringData" output="false">
		<cfscript>
			return "URL:" & this.path & " | " & arrayToList( this.roles ) & " | " & iif( this.allow, de( "allow" ), de( "deny" ) );
		</cfscript> 
	</cffunction>


</cfcomponent>
