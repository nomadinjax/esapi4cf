<!--- /**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 */ --->
<cfcomponent displayname="ValidationErrorList" extends="cfesapi.org.owasp.esapi.lang.Object" output="false" hint="The ValidationErrorList class defines a well-formed collection of ValidationExceptions so that groups of validation functions can be called in a non-blocking fashion.">

	<cfscript>
		/**
		 * Error list of ValidationException's
		 */
		instance.errorList = {};
	</cfscript>

	<cffunction access="public" returntype="void" name="addError" output="false"
	            hint="Adds a new error to list with a unique named context. No action taken if either element is null. Existing contexts will be overwritten.">
		<cfargument required="true" type="String" name="context" hint="Unique named context for this {@code ValidationErrorList}."/>
		<cfargument required="true" name="vex" hint="A {@code ValidationException}."/>

		<cfset var local = {}/>

		<cfscript>
			if(!structKeyExists(arguments, "context")) {
				throwError(newJava("java.lang.RuntimeException").init("Context for cannot be null: " & arguments.vex.getLogMessage(), arguments.vex.getCause()));
			}
			if(!structKeyExists(arguments, "vex")) {
				throwError(newJava("java.lang.RuntimeException").init("Context (" & arguments.context & ") cannot be null"));
			}
			local.error = getError(arguments.context);
			if(structKeyExists(local, "error")) {
				throwError(newJava("java.lang.RuntimeException").init("Context (" & arguments.context & ") already exists, must be unique"));
			}
			instance.errorList.put(arguments.context, arguments.vex);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="errors" output="false"
	            hint="Returns list of ValidationException, or empty list of no errors exist.">

		<cfscript>
			return newJava("java.util.ArrayList").init(instance.errorList.values());
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getError" output="false" hint="Retrieves ValidationException for given context if one exists.">
		<cfargument required="true" type="String" name="context" hint="unique name for each error"/>

		<cfscript>
			if(!structKeyExists(arguments, "context")) {
				return "";
			}
			if(structKeyExists(instance.errorList, arguments.context)) {
				return instance.errorList.get(arguments.context);
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isEmpty" output="false"
	            hint="Returns true if no error are present.">

		<cfscript>
			return instance.errorList.isEmpty();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="size" output="false"
	            hint="Returns the numbers of errors present.">

		<cfscript>
			return instance.errorList.size();
		</cfscript>

	</cffunction>

</cfcomponent>