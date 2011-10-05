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

	<cffunction access="public" returntype="any" name="getAttribute" output="false" hint="Returns the object bound with the specified name in this session, or null if no object is bound under the name.">
		<cfargument type="String" name="name" required="true">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getAttributeNames" output="false" hint="Returns an Enumeration of String objects containing the names of all the objects bound to this session.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getCreationTime" output="false" hint="Returns the time when this session was created, measured in milliseconds since midnight January 1, 1970 GMT.">
	</cffunction>


	<cffunction access="public" returntype="String" name="getId" output="false" hint="Returns a string containing the unique identifier assigned to this session.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getLastAccessedTime" output="false" hint="Returns the last time the client sent a request associated with this session, as the number of milliseconds since midnight January 1, 1970 GMT, and marked by the time the container received the request.">
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getMaxInactiveInterval" output="false" hint="Returns the maximum time interval, in seconds, that the servlet container will keep this session open between client accesses.">
	</cffunction>


	<cffunction access="public" returntype="any" name="getServletContext" output="false" hint="javax.servlet.ServletContext: Returns the ServletContext to which this session belongs.">
	</cffunction>


	<cffunction access="public" returntype="void" name="invalidate" output="false" hint="Invalidates this session then unbinds any objects bound to it.">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isNew" output="false" hint="Returns true if the client does not yet know about the session or if the client chooses not to join the session.">
	</cffunction>


	<cffunction access="public" returntype="void" name="removeAttribute" output="false" hint="Removes the object bound with the specified name from this session.">
		<cfargument type="String" name="name" required="true">
	</cffunction>


	<cffunction access="public" returntype="void" name="setAttribute" output="false" hint="Binds an object to this session, using the name specified.">
		<cfargument type="String" name="name" required="true">
		<cfargument type="any" name="value" required="true">
	</cffunction>


	<cffunction access="public" returntype="void" name="setMaxInactiveInterval" output="false" hint="Specifies the time, in seconds, between client requests before the servlet container will invalidate this session.">
		<cfargument type="numeric" name="interval" required="true">
	</cffunction>

</cfinterface>
