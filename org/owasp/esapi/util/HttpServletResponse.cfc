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
<cfinterface extends="org.owasp.esapi.util.ServletResponse">

	<cffunction access="public" returntype="void" name="addCookie" output="false">
		<cfargument required="true" name="httpCookie">
	</cffunction>


	<cffunction access="public" returntype="void" name="addDateHeader" output="false">
		<cfargument required="true" type="String" name="name">
		<cfargument required="true" type="Date" name="date">
	</cffunction>


	<cffunction access="public" returntype="void" name="addHeader" output="false">
		<cfargument required="true" type="String" name="name">
		<cfargument required="true" type="String" name="value">
	</cffunction>


	<cffunction access="public" returntype="void" name="addIntHeader" output="false">
		<cfargument required="true" type="String" name="name">
		<cfargument required="true" type="numeric" name="value">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="containsHeader" output="false">
		<cfargument required="true" type="String" name="name">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeRedirectURL" output="false">
		<cfargument required="true" type="String" name="url">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeURL" output="false">
		<cfargument required="true" type="String" name="url">
	</cffunction>


	<cffunction access="public" returntype="void" name="sendError" output="false">
		<cfargument required="true" type="numeric" name="sc">
		<cfargument type="String" name="msg">
	</cffunction>


	<cffunction access="public" returntype="void" name="sendRedirect" output="false">
		<cfargument required="true" type="String" name="location">
	</cffunction>


	<cffunction access="public" returntype="void" name="setDateHeader" output="false">
		<cfargument required="true" type="String" name="name">
		<cfargument required="true" type="Date" name="date">
	</cffunction>


	<cffunction access="public" returntype="void" name="setHeader" output="false">
		<cfargument required="true" type="String" name="name">
		<cfargument required="true" type="String" name="value">
	</cffunction>


	<cffunction access="public" returntype="void" name="setIntHeader" output="false">
		<cfargument required="true" type="String" name="name">
		<cfargument required="true" type="numeric" name="value">
	</cffunction>


	<cffunction access="public" returntype="void" name="setStatus" output="false">
		<cfargument required="true" type="numeric" name="sc">
		<cfargument type="String" name="sm">
	</cffunction>

</cfinterface>
