<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" output="false">

	<cfscript>
		instance.exception = "";
		instance.stackTrace = [];
		instance.type = "";
	</cfscript>

	<cffunction access="public" returntype="Exception" name="init" output="false">
		<cfargument type="string" name="message" required="false">
		<cfargument type="any" name="cause" required="false" hint="the cause">
		<cfscript>
			if (structKeyExists(arguments, "message")) {
				if (structKeyExists(arguments, "cause")) {
					instance.exception = createObject('java', 'java.lang.Exception').init(arguments.message, arguments.cause);
				}
				else {
					instance.exception = createObject('java', 'java.lang.Exception').init(arguments.message);
				}
			}
			else {
				instance.exception = createObject('java', 'java.lang.Exception').init();
			}

			setType();
			setStackTrace(instance.exception.tagContext);

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="any" name="getCause" output="false" hint="Returns the cause of this throwable or null if the cause is nonexistent or unknown.">
		<cfscript>
			return instance.exception.getCause();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getLocalizedMessage" output="false" hint="Creates a localized description of this throwable.">
		<cfscript>
			return instance.exception.getLocalizedMessage();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="getMessage" output="false" hint="Returns the detail message string of this throwable.">
		<cfscript>
			return instance.exception.getMessage();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Array" name="getStackTrace" output="false" hint="Provides programmatic access to the stack trace information printed by printStackTrace().">
		<cfscript>
			//return instance.exception.getStackTrace();
			return instance.stackTrace;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="string" name="getType" output="false">
		<cfscript>
			return instance.type;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="Exception" name="initCause" output="false" hint="Initializes the cause of this throwable to the specified value.">
		<cfargument type="any" name="cause" required="true" hint="the cause (which is saved for later retrieval by the getCause() method).">
		<cfscript>
			return instance.exception.initCause(arguments.cause);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="printStackTrace" output="false" hint="Prints this throwable and its backtrace to the standard error stream.">
		<cfscript>
			return instance.exception.printStackTrace();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="setStackTrace" output="false" hint="Sets the stack trace elements that will be returned by getStackTrace() and printed by printStackTrace() and related methods.">
		<cfargument type="Array" name="stackTrace" required="true">
		<cfscript>
			//instance.exception.setStackTrace(arguments.stackTrace);

			local.stackTrace = duplicate(arguments.stackTrace);

			// drop indexes that contain 'cfesapi\org\owasp\esapi\errors'
			while (arrayLen(local.stackTrace)) {
				local.item = local.stackTrace[1];
				if (not findNoCase('cfesapi\org\owasp\esapi\errors', local.item.template)) {
					break;
				}
				arrayDeleteAt(local.stackTrace, 1);
			}
			// 1st index should now be the actual caller object
			instance.stackTrace = local.stackTrace;
		</cfscript>
	</cffunction>


	<cffunction access="private" returntype="void" name="setType" output="false">
		<cfscript>
			instance.type = getMetaData().name;
			if (listLen(instance.type, ".") EQ 1) {
				instance.type = "cfesapi.org.owasp.esapi.errors." & instance.type;
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="toString" output="false" hint="Returns a short description of this throwable.">
		<cfscript>
			return instance.exception.toString();
		</cfscript>
	</cffunction>


</cfcomponent>
