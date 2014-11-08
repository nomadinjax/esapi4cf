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
<cfcomponent extends="Object" output="false">

	<cffunction access="public" name="get" output="false">

		<cfscript>
			var threadId = getThreadId();
			if(structKeyExists(request, threadId)) {
				return request[threadId];
			}
			return setInitialValue();
		</cfscript>

	</cffunction>

	<cffunction access="public" name="initialValue" output="false">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="set" output="false">
		<cfargument required="true" name="value"/>

		<cflock scope="request" type="exclusive" timeout="5">
			<cfscript>
				request[getThreadId()] = arguments.value;
			</cfscript>
		</cflock>

	</cffunction>

	<cffunction access="public" returntype="void" name="remove" output="false">

		<cflock scope="request" type="exclusive" timeout="5">
			<cfset structDelete(request, getThreadId())>
		</cflock>

	</cffunction>

	<!--- PRIVATE METHODS --->

	<cffunction access="public" returntype="String" name="getThreadId" output="false">

		<cfscript>
			return createObject("java","java.lang.Thread").currentThread().getName() & "_" & getMetaData(this).name;
		</cfscript>

	</cffunction>

	<cffunction access="private" name="setInitialValue" output="false">

		<cfscript>
			var threadId = getThreadId();
			var value = initialValue();
		</cfscript>
		<cflock scope="request" type="exclusive" timeout="5">
			<cfset request[threadId] = value>
		</cflock>
		<cfscript>
			return value;
		</cfscript>

	</cffunction>

</cfcomponent>