<cfcomponent extends="Object" output="false">

	<cffunction access="public" name="get" output="false">

		<cfscript>
			var local = {};
			local.threadId = getThreadId();
			if(structKeyExists( request, local.threadId )) {
				return request[local.threadId];
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
			var local = {};
			local.threadId = getThreadId();
			request[local.threadId] = arguments.value;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="remove" output="false">

		<cfscript>
			var local = {};
			local.threadId = getThreadId();
			structDelete( request, local.threadId );

			// reset the Thread ID so we never use this request variable again
			resetThreadId();
		</cfscript>

	</cffunction>

	<!--- PRIVATE METHODS --->

	<cfscript>
		instance.threadId = "";
	</cfscript>

	<cffunction access="private" returntype="String" name="getThreadId" output="false">

		<cfscript>
			if(instance.threadId == "") {
				resetThreadId();
			}
			return instance.threadId;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="resetThreadId" output="false">

		<cfscript>
			instance.threadId = "ThreadLocal_" & getMetaData(this).name;
		</cfscript>

	</cffunction>

	<cffunction access="private" name="setInitialValue" output="false">

		<cfscript>
			var local = {};
			local.threadId = getThreadId();
			local.value = initialValue();
			request[local.threadId] = local.value;
			return local.value;
		</cfscript>

	</cffunction>

</cfcomponent>