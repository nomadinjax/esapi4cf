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
<cfcomponent displayname="IntegrityException" extends="EnterpriseSecurityException" output="false" hint="An IntegrityException should be thrown when a problem with the integrity of data has been detected. For example, if a financial account cannot be reconciled after a transaction has been performed, an integrity exception should be thrown.">

	<cffunction access="public" returntype="IntegrityException" name="init" output="false"
	            hint="Instantiates a new IntegrityException.">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument type="String" name="userMessage" hint="the message displayed to the user"/>
		<cfargument type="String" name="logMessage" hint="the message logged"/>
		<cfargument name="cause" hint="the cause"/>

		<cfscript>
			super.init(argumentCollection=arguments);
			return this;
		</cfscript>

	</cffunction>


</cfcomponent>