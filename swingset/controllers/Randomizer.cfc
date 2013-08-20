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


	<cffunction access="public" returntype="void" name="getRandomBoolean" output="false">
		<cfargument required="true" type="Struct" name="rc">
		<cfscript>
			try {
				arguments.rc.ESAPI.currentResponse().setContentType("text/html");
				arguments.rc.randomBoolean = false; // TODO 1: Generate random boolean
			} catch (IOException e) {
				e.printStackTrace();
			}
		</cfscript> 
	</cffunction>


</cfcomponent>
