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

		<cfscript>
			var threadId = getThreadId();
			request[threadId] = arguments.value;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="remove" output="false">

		<cfscript>
			var threadId = getThreadId();
			structDelete(request, threadId);

			// reset the Thread ID so we never use this request variable again
			resetThreadId();
		</cfscript>

	</cffunction>

	<!--- PRIVATE METHODS --->

	<cfscript>
		variables.threadId = "";
	</cfscript>

	<cffunction access="private" returntype="String" name="getThreadId" output="false">

		<cfscript>
			if(variables.threadId == "") {
				resetThreadId();
			}
			return variables.threadId;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="resetThreadId" output="false">

		<cfscript>
			variables.threadId = "ThreadLocal_" & getMetaData(this).name;
		</cfscript>

	</cffunction>

	<cffunction access="private" name="setInitialValue" output="false">

		<cfscript>
			var threadId = getThreadId();
			var value = initialValue();
			request[threadId] = value;
			return value;
		</cfscript>

	</cffunction>

</cfcomponent>