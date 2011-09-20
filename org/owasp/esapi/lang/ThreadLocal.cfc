<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" output="false" hint="Creates a thread local variable.">

	<cfscript>
		instance.key = "CFESAPI_ThreadLocal_" & createUUID();
	</cfscript>

	<cffunction access="private" returntype="void" name="setup" output="false">
		<cfscript>
			if (!structKeyExists(request, instance.key)) {
				request[instance.key] = {
					useInitialValue = true,
					value = ""
				};
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="get" output="false" hint="Returns the value in the current thread's copy of this thread-local variable.">
		<cfscript>
			setup();
			if (request[instance.key].useInitialValue) {
				request[instance.key].value = initialValue();
				request[instance.key].useInitialValue = false;
			}
			return request[instance.key].value;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="initialValue" output="false" hint="Returns the current thread's initial value for this thread-local variable.">
		<cfscript>
			return ""; // must override
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="remove" output="false" hint="Removes the value for this ThreadLocal.">
		<cfscript>
			setup();
			request[instance.key].value = "";
			request[instance.key].useInitialValue = true;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="set" output="false" hint="Sets the current thread's copy of this thread-local variable to the specified value.">
		<cfargument type="any" name="value" required="true">
		<cfscript>
			setup();
			request[instance.key].value = arguments.value;
			request[instance.key].useInitialValue = false;
		</cfscript>
	</cffunction>


</cfcomponent>
