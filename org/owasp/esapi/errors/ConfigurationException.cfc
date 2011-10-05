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
<cfcomponent extends="Exception" output="false" hint="A ConfigurationException should be thrown when a problem arises because of a problem in one of ESAPI's configuration files, such as a missing required property or invalid setting of a property, or missing or unreadable configuration file, etc.">


	<cffunction access="public" returntype="ConfigurationException" name="init" output="false">
		<cfargument type="String" name="s" required="true">
		<cfargument type="any" name="cause" required="false" hint="java.lang.Throwable:">
		<cfscript>
			if (structKeyExists(arguments, "cause")) {
				super.init(arguments.s, arguments.cause);
			}
			else {
				super.init(arguments.s);
			}

			return this;
		</cfscript> 
	</cffunction>


</cfcomponent>
