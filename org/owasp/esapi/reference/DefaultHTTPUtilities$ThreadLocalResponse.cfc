<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfcomponent extends="org.owasp.esapi.util.ThreadLocal" output="false" hint="Defines the ThreadLocalResponse to store the current response for this thread.">

	<cfscript>
		variables.ESAPI = "";
	</cfscript>

	<cffunction access="public" returntype="DefaultHTTPUtilities$ThreadLocalResponse" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="initialValue" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" type="org.owasp.esapi.filters.SafeResponse" name="getResponse" output="false">

		<cfscript>
			return super.get();
		</cfscript>

	</cffunction>

	<cffunction access="public" type="void" name="setResponse" output="false">
		<cfargument required="true" type="org.owasp.esapi.filters.SafeResponse" name="newResponse"/>

		<cfscript>
			super.set(arguments.newResponse);
		</cfscript>

	</cffunction>

</cfcomponent>