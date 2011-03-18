<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" output="false" hint="A ConfigurationException should be thrown when a problem arises because of a problem in one of ESAPI's configuration files, such as a missing required property or invalid setting of a property, or missing or unreadable configuration file, etc.">

	<cfscript>
		importClass("java.lang.RuntimeException");

		instance.ESAPI = "";

		instance.errorObject = "";
	</cfscript>

	<cffunction access="public" returntype="ConfigurationException" name="init" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="String" name="s" required="true">
		<cfargument type="any" name="cause" required="false" hint="java.lang.Throwable:">
		<cfscript>
			if (structKeyExists(arguments, "cause")) {
				instance.errorObject = RuntimeException.init(arguments.s, arguments.cause);
			}
			else {
				instance.errorObject = RuntimeException.init(arguments.s);
			}

			instance.ESAPI = arguments.ESAPI;

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="string" name="getMessage" output="false">
		<cfscript>
			return instance.errorObject.message;
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


</cfcomponent>
