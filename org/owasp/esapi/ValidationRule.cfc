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
<cfinterface>

	<cffunction access="public" returntype="void" name="setAllowNull" output="false"
	            hint="Whether or not a valid valid can be null. getValid will throw an Exception and getSafe will return the default value if flag is set to true">
		<cfargument type="boolean" name="flag" required="true" hint="whether or not null values are valid/safe"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="getTypeName" output="false"
	            hint="Programmatically supplied name for the validator">
	</cffunction>

	<cffunction access="public" returntype="void" name="setTypeName" output="false">
		<cfargument type="String" name="typeName" required="true" hint="a name, describing the validator"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="setEncoder" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.Encoder" name="encoder" required="true" hint="the encoder to use"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertValid" output="false"
	            hint="Check if the input is valid, throw an Exception otherwise">
		<cfargument type="String" name="context" required="true"/>
		<cfargument type="String" name="input" required="true"/>

	</cffunction>

	<cffunction access="public" returntype="any" name="getValid" output="false"
	            hint="Get a validated value, add the errors to an existing error list">
		<cfargument type="String" name="context" required="true"/>
		<cfargument type="String" name="input" required="true"/>
		<cfargument type="cfesapi.org.owasp.esapi.ValidationErrorList" name="errorList" required="false"/>

	</cffunction>

	<cffunction access="public" returntype="any" name="getSafe" output="false"
	            hint="Try to call get valid, then call sanitize, finally return a default value">
		<cfargument type="String" name="context" required="true"/>
		<cfargument type="String" name="input" required="true"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isValidESAPI" output="false"
	            hint="true if the input passes validation">
		<cfargument type="String" name="context" required="true"/>
		<cfargument type="String" name="input" required="true"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="whitelist" output="false"
	            hint="String the input of all chars contained in the list">
		<cfargument type="String" name="input" required="true"/>
		<cfargument type="Array" name="list" required="true"/>

	</cffunction>

</cfinterface>