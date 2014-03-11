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
<cfcomponent extends="org.owasp.esapi.util.ThreadLocal" output="false" hint="Defines the ThreadLocalRequest to store the current request for this thread.">

	<cfscript>
		variables.ESAPI = "";
	</cfscript>

	<cffunction access="public" returntype="DefaultHTTPUtilities$ThreadLocalRequest" name="init" output="false">
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

	<cffunction access="public" name="getRequest" output="false">

		<cfscript>
			return super.get();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setRequest" output="false">
		<cfargument required="true" type="org.owasp.esapi.filters.SafeRequest" name="newRequest"/>

		<cfscript>
			super.set(arguments.newRequest);
		</cfscript>

	</cffunction>

</cfcomponent>