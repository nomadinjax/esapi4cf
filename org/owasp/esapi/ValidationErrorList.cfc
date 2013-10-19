<!---
/**
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
 */
--->
<cfcomponent extends="org.owasp.esapi.util.Object" output="false" hint="The ValidationErrorList class defines a well-formed collection of ValidationExceptions so that groups of validation functions can be called in a non-blocking fashion.">

	<cfscript>
		// Error list of ValidationException's
		variables.errorList = {};
	</cfscript>

	<cffunction access="public" returntype="void" name="addError" output="false"
	            hint="Adds a new error to list with a unique named context. No action taken if either element is null. Existing contexts will be overwritten.">
		<cfargument required="true" type="String" name="context" hint="unique named context for this ValidationErrorList"/>
		<cfargument required="true" name="ve" hint="org.owasp.esapi.errors.ValidationException"/>

		<cfscript>
			if(structCount(getError(arguments.context))) {
				throwException(newJava("java.lang.RuntimeException").init("Context (" & context & ") already exists, programmer error"));
			}

			if((arguments.context != "") && (structCount(arguments.ve))) {
				variables.errorList[arguments.context] = arguments.ve;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="errors" output="false"
	            hint="Returns list of ValidationException, or empty list of no errors exist.">

		<cfscript>
			return variables.errorList.values().toArray();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Struct" name="getError" output="false"
	            hint="Retrieves ValidationException for given context if one exists.">
		<cfargument required="true" type="String" name="context" hint="unique name for each error"/>

		<cfscript>
			if(structKeyExists(variables.errorList, arguments.context)) {
				return variables.errorList[arguments.context];
			}
			return structNew();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isEmpty" output="false"
	            hint="Returns true if no error are present.">

		<cfscript>
			return variables.errorList.isEmpty();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="size" output="false"
	            hint="Returns the numbers of errors present.">

		<cfscript>
			return variables.errorList.size();
		</cfscript>

	</cffunction>

</cfcomponent>