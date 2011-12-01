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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.ThreadLocal" output="false" hint="Defines the ThreadLocalResponse to store the current response for this thread.">

	<cfscript>
		instance.ESAPI = "";
	</cfscript>

	<cffunction access="public" returntype="ThreadLocalResponse" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getResponse" output="false">

		<cfscript>
			return super.get();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setResponse" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.HttpServletResponse" name="newResponse" required="true"/>

		<cfscript>
			super.set(arguments.newResponse);
		</cfscript>

	</cffunction>

</cfcomponent>