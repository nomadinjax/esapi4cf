<cfcomponent extends="Object" output="false">

	<cfscript>
		instance.exception = "";
		instance.stackTrace = [];
		instance.type = "";
	</cfscript>

	<cffunction access="public" returntype="Exception" name="init" output="false">
		<cfargument type="String" name="message"/>
		<cfargument name="cause"/>

		<cfscript>
			var local = {};

			if(structKeyExists( arguments, "message" )) {
				if(structKeyExists( arguments, "cause" ) && isObject( arguments.cause )) {
					// CF exceptions extend java.lang.Exception
					if(isInstanceOf( arguments.cause, "java.lang.Throwable" )) {
						local.cause = arguments.cause;
					}
					// RAILO exceptions do not extend java.lang.Exception
					// ? is there a better way ? I hope so...
					else if(isStruct( arguments.cause )) {
						local.cause = getJava( "java.lang.Exception" ).init( arguments.cause.message );
					}
					instance.exception = getJava( "java.lang.Exception" ).init( arguments.message, local.cause );
				}
				else {
					instance.exception = getJava( "java.lang.Exception" ).init( arguments.message );
				}
			}
			else {
				instance.exception = getJava( "java.lang.Exception" ).init();
			}

			setType();
			// RAILO ERROR: setStackTrace(instance.exception.tagContext);
			setStackTrace( instance.exception.getStackTrace() );

			return this;
		</cfscript>

	</cffunction>

	<!--- fillInStackTrace --->

	<cffunction access="public" name="getCause" output="false">

		<cfscript>
			return instance.exception.getCause();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLocalizedMessage" output="false">

		<cfscript>
			return instance.exception.getLocalizedMessage();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getMessage" output="false">

		<cfscript>
			return instance.exception.getMessage();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getStackTrace" output="false">

		<cfscript>
			//return instance.exception.getStackTrace();
			return instance.stackTrace;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Exception" name="initCause" output="false">
		<cfargument required="true" name="cause"/>

		<cfscript>
			return instance.exception.initCause( arguments.cause );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="printStackTrace" output="false">

		<cfscript>
			return instance.exception.printStackTrace();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setStackTrace" output="false">
		<cfargument required="true" type="Array" name="stackTrace"/>

		<cfscript>
			var local = {};

			// loop to include only the template calls
			for(local.i = 1; local.i <= arrayLen( arguments.stackTrace ); local.i++) {
				local.item = arguments.stackTrace[local.i];
				// CF: runFunction; Railo: udfCall
				if(listFind( "runFunction,udfCall", local.item.getMethodName() )) {
					// drop indexes that contain "cfesapi\org\owasp\esapi\errors"
					if(findNoCase( "cfesapi\org\owasp\esapi\util\Exception.cfc", local.item.getFileName() ) || findNoCase( "cfesapi\org\owasp\esapi\errors", local.item.getFileName() )) {
						continue;
					}
					arrayAppend( instance.stackTrace, local.item );
				}
			}
		</cfscript>

	</cffunction>

	<!--- toString() --->

	<cffunction access="public" returntype="String" name="getType" output="false">

		<cfscript>
			return instance.type;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="setType" output="false">

		<cfscript>
			instance.type = getMetaData().name;
			// full path is missing when cfesapi is virtual directory
			if(listLen( instance.type, "." ) EQ 1) {
				instance.type = "cfesapi.org.owasp.esapi.errors." & instance.type;
			}
		</cfscript>

	</cffunction>

</cfcomponent>