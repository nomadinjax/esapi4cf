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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.ThreadLocal" output="false" hint="The currentUser ThreadLocal variable is used to make the currentUser available to any call in any part of an application.">

	<cfscript>
		instance.ESAPI = '';
	</cfscript>
 
	<cffunction access="public" returntype="ThreadLocalUser" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.User" name="initialValue" output="false">
		<cfscript>
            return createObject("component", "AnonymousUser").init(instance.ESAPI);
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.User" name="getUser" output="false">
		<cfscript>
			return super.get();
        </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="setUser" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.User" name="newUser" required="true">
		<cfscript>
            super.set(arguments.newUser);
        </cfscript> 
	</cffunction>


</cfcomponent>
