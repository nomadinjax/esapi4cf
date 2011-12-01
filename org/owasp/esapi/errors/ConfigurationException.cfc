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
<cfcomponent displayname="ConfigurationException" extends="cfesapi.org.owasp.esapi.lang.RuntimeException" output="false" hint="A {@code ConfigurationException} should be thrown when a problem arises because of a problem in one of ESAPI's configuration files, such as a missing required property or invalid setting of a property, or missing or unreadable configuration file, etc. A {@code ConfigurationException} is a {@code RuntimeException} because 1) configuration properties can, for the most part, only be checked at run-time, and 2) we want this to be an unchecked exception to make ESAPI easy to use and not cluttered with catching a bunch of try/catch blocks.">

	<cffunction access="public" returntype="ConfigurationException" name="init" output="false">
		<cfargument required="true" type="String" name="message"/>
		<cfargument name="cause"/>
	
		<cfscript>
			super.init(argumentCollection=arguments);
			return this;
		</cfscript>
		
	</cffunction>
	

</cfcomponent>