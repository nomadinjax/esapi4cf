<!--- /**
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
 */ --->
<cfcomponent displayname="AuthenticationCredentialsException" extends="AuthenticationException" output="false" hint="An AuthenticationException should be thrown when anything goes wrong during login or logout. They are also appropriate for any problems related to identity management.">

	<cffunction access="public" returntype="AuthenticationCredentialsException" name="init" output="false"
	            hint="Instantiates a new authentication exception.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument type="String" name="userMessage" hint="the message displayed to the user"/>
		<cfargument type="String" name="logMessage" hint="the message logged"/>
		<cfargument name="cause" hint="the root cause"/>

		<cfscript>
			super.init(argumentCollection=arguments);
			return this;
		</cfscript>

	</cffunction>


</cfcomponent>