<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" output="false" hint="An IntrusionException should be thrown anytime an error condition arises that is likely to be the result of an attack in progress. IntrusionExceptions are handled specially by the IntrusionDetector, which is equipped to respond by either specially logging the event, logging out the current user, or invalidating the current user's account.">

	<cfscript>
		instance.ESAPI = "";
		instance.logMessage = "";

		/* The logger. */
		instsance.logger = "";

		instance.errorObject = "";
	</cfscript>

	<cffunction access="public" returntype="IntrusionException" name="init" output="false" hint="Creates a new instance of IntrusionException.">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="String" name="userMessage" required="true" hint="the message to display to users">
		<cfargument type="String" name="logMessage" required="true" hint="the message logged">
		<cfargument type="any" name="cause" required="false" hint="java.lang.Throwable: the cause">
		<cfscript>
			if (structKeyExists(arguments, "cause")) {
				instance.errorObject = createObject("java", "java.lang.RuntimeException").init(arguments.userMessage, arguments.cause);
			}
			else {
				instance.errorObject = createObject("java", "java.lang.RuntimeException").init(arguments.userMessage);
			}

			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger('IntrusionException');

	        instance.logMessage = arguments.logMessage;
			if (structKeyExists(arguments, "cause")) {
				instance.logger.error(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "INTRUSION - " & arguments.logMessage, arguments.cause);
			}
			else {
	        	instance.logger.error(javaLoader().create("org.owasp.esapi.Logger").SECURITY_FAILURE, "INTRUSION - " & arguments.logMessage);
			}

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getUserMessage" output="false" hint="Returns a String containing a message that is safe to display to users">
		<cfscript>
        	return getMessage();
        </cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getLogMessage" output="false" hint="Returns a String that is safe to display in logs, but probably not to users">
		<cfscript>
        	return instance.logMessage;
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


</cfcomponent>
