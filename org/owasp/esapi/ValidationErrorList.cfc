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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" output="false" hint="The ValidationErrorList class defines a well-formed collection of ValidationExceptions so that groups of validation functions can be called in a non-blocking fashion.">

	<cfscript>
		instance.errorList = {};
	</cfscript>
 
	<cffunction access="public" returntype="void" name="addError" output="false" hint="Adds a new error to list with a unique named context. No action taken if either element is null. Existing contexts will be overwritten.">
		<cfargument type="String" name="context" required="true" hint="Unique named context for this ValidationErrorList.">
		<cfargument type="any" name="vex" required="true" hint="cfesapi.org.owasp.esapi.errors.ValidationException: A ValidationException.">
		<!--- ??? not sure why setting the correct type on arg2 throws error, the data type is correct --->
		<cfscript>
			if ( isNull(arguments.context) ) throw(object=createObject("java", "java.lang.RuntimeException").init( "Context for cannot be null: " & arguments.vex.getLogMessage(), arguments.vex ));
			if ( isNull(arguments.vex) ) throw(object=createObject("java", "java.lang.RuntimeException").init( "Context (" & arguments.context & ") cannot be null" ));
			if (!isNull(getError(arguments.context))) throw(object=createObject("java", "java.lang.RuntimeException").init("Context (" & arguments.context & ") already exists, must be unique"));
			instance.errorList.put(arguments.context, arguments.vex);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="Array" name="errors" output="false" hint="list of ValidationException, or empty list of no errors exist.">
		<cfscript>
			return listToArray(structValueList(instance.errorList));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="any" name="getError" output="false" hint="cfesapi.org.owasp.esapi.errors.ValidationException: Retrieves ValidationException for given context if one exists.">
		<cfargument type="String" name="context" required="true" hint="unique name for each error">
		<cfscript>
			if (isNull(arguments.context)) return "";
			if (structKeyExists(instance.errorList, arguments.context)) {
				return instance.errorList.get(arguments.context);
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isEmpty" output="false" hint="Returns true if no error are present.">
		<cfscript>
			return instance.errorList.isEmpty();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="numeric" name="size" output="false" hint="Returns the numbers of errors present.">
		<cfscript>
			return instance.errorList.size();
		</cfscript> 
	</cffunction>


</cfcomponent>
