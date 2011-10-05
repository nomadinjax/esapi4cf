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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.enum" output="false">

	<cfscript>
		instance.value = "";	// Value stored in serialized encrypted data to represent PRF
		instance.bits = "";
		instance.algName = "";
	</cfscript>
 
	<cffunction access="public" returntype="PRF_ALGORITHMS" name="init" output="false">
		<cfargument type="numeric" name="value" required="true">
		<cfargument type="numeric" name="bits" required="true">
		<cfargument type="String" name="algName" required="true">
		<cfscript>
			instance.value = arguments.value;
			instance.bits  = arguments.bits;
			instance.algName = arguments.algName;
			
			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getValue" output="false">
		<cfscript>
			return instance.value;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="getBits" output="false">
		<cfscript>
			return instance.bits;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="getAlgName" output="false">
		<cfscript>
			return instance.algName;
		</cfscript> 
	</cffunction>


</cfcomponent>
