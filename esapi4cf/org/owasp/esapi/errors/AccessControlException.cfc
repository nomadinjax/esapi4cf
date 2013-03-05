<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 --->
<cfcomponent extends="EnterpriseSecurityException" output="false" hint="An AccessControlException should be thrown when a user attempts to access a resource that they are not authorized for.">

	<cffunction access="public" returntype="AccessControlException" name="init" output="false"
	            hint="Instantiates a new access control exception.">
		<cfargument required="true" type="esapi4cf.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" type="String" name="userMessage" hint="the message to display to users"/>
		<cfargument required="true" type="String" name="logMessage" hint="the message logged"/>
		<cfargument name="cause" hint="the cause"/>

		<cfscript>
			super.init( argumentCollection=arguments );

			return this;
		</cfscript>

	</cffunction>


</cfcomponent>