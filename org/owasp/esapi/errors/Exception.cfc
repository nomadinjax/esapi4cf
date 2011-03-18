<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" output="false">

	<cfscript>
		instance.errorObject = '';
		instance.errorStackTrace = [];
	</cfscript>

	<cffunction access="public" returntype="Exception" name="init" output="false">
		<cfargument type="string" name="message" required="true">
		<cfargument type="any" name="cause" required="false" hint="java.lang.Throwable">
		<cfscript>
			if (structKeyExists(arguments, "cause")) {
				instance.errorObject = createObject('java', 'java.lang.Exception').init(arguments.message, arguments.cause);
			}
			else {
				instance.errorObject = createObject('java', 'java.lang.Exception').init(arguments.message);
			}
			instance.errorStackTrace = duplicate(instance.errorObject.tagContext);

			// drop indexes that contain 'cfesapi\org\owasp\esapi\errors'
			while (arrayLen(instance.errorStackTrace)) {
				stackTrace = instance.errorStackTrace[1];
				if (not findNoCase('cfesapi\org\owasp\esapi\errors', stackTrace.template)) {
					break;
				}
				arrayDeleteAt(instance.errorStackTrace, 1);
			}
			// 1st index should now be the actual caller object

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Exception" name="getClass" output="false">
		<cfscript>
			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="string" name="getName" output="false">
		<cfscript>
			return getType();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="string" name="getType" output="false">
		<cfscript>
			// NOTE: depending on how CFESAPI folder is mapped, getMetaData().name may be full path or just CFC name
			// need to make this consistent
			local.name = getMetaData().name;
			if (listLen(local.name, ".") EQ 1) {
				local.name = "cfesapi.org.owasp.esapi.errors." & local.name;
			}
			return local.name;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="string" name="getMessage" output="false">
		<cfscript>
			return instance.errorObject.message;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="array" name="getStackTrace" output="false">
		<cfscript>
			return instance.errorStackTrace;
		</cfscript>
	</cffunction>


</cfcomponent>
