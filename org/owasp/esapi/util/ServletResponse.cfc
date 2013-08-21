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

	<cffunction access="public" returntype="void" name="flushBuffer" output="false">
	</cffunction>
	
	<cffunction access="public" returntype="numeric" name="getBufferSize" output="false">
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getCharacterEncoding" output="false">
	</cffunction>
	
	<cffunction access="public" returntype="String" name="getContentType" output="false">
	</cffunction>
	
	<cffunction access="public" name="getLocaleData" output="false">
	</cffunction>
	
	<cffunction access="public" name="getOutputStream" output="false">
	</cffunction>
	
	<cffunction access="public" name="getWriter" output="false">
	</cffunction>
	
	<cffunction access="public" returntype="boolean" name="isCommitted" output="false">
	</cffunction>
	
	<cffunction access="public" returntype="void" name="reset" output="false">
	</cffunction>
	
	<cffunction access="public" returntype="void" name="resetBuffer" output="false">
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setBufferSize" output="false">
		<cfargument required="true" type="numeric" name="size"/>
	
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setCharacterEncoding" output="false">
		<cfargument required="true" type="String" name="charset"/>
	
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setContentLength" output="false">
		<cfargument required="true" type="numeric" name="len"/>
	
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setContentType" output="false">
		<cfargument required="true" type="String" name="type"/>
	
	</cffunction>
	
	<cffunction access="public" returntype="void" name="setLocaleData" output="false">
		<cfargument required="true" name="loc"/>
	
	</cffunction>
	
</cfinterface>