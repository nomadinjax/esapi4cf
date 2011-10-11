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

	<cfscript>
		System = createObject("java", "java.lang.System");

		instance.version = "2.0.1";
	</cfscript> 
	<!--- public methods --->

	<cffunction access="public" returntype="String" name="version" output="false" hint="Returns the CFESAPI version">
		<cfscript>
			return instance.version;
		</cfscript> 
	</cffunction>

	<!--- private methods --->

	<cffunction access="private" returntype="void" name="assert" output="false">
		<cfargument type="boolean" name="boolean_expression" required="true">
		<cfargument type="String" name="string_expression" required="false">
		<cfscript>
			if (!arguments.boolean_expression) {
				throw(object=createObject("java", "java.lang.AssertionError").init(arguments.string_expression));
			}
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="binary" name="newByte" outuput="false">
		<cfargument type="numeric" name="len" required="true">
		<cfscript>
			StringBuilder = createObject("java", "java.lang.StringBuilder").init();
			StringBuilder.setLength(arguments.len);
			return StringBuilder.toString().getBytes();
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="numeric" name="newLong" output="false">
		<cfargument type="numeric" name="long" required="true">
		<cfscript>
			return createObject("java", "java.lang.Long").init(arguments.long);
		</cfscript> 
	</cffunction>


</cfcomponent>
