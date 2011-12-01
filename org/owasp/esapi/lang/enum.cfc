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
<cfcomponent displayname="Enum" output="false">

	<cfscript>
		instance.name = "";
		instance.ordinal = "";
	</cfscript>

	<cffunction access="public" returntype="Enum" name="init" output="false">
		<cfargument required="true" type="String" name="name"/>
		<cfargument required="true" type="numeric" name="ordinal"/>

		<cfscript>
			instance.name = arguments.name;
			instance.ordinal = arguments.ordinal;

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="name" output="false">

		<cfscript>
			return instance.name;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="ordinal" output="false">

		<cfscript>
			return instance.ordinal;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="toStringESAPI" output="false">
	</cffunction>

	<cffunction access="public" returntype="boolean" name="equalsESAPI" output="false">
		<cfargument required="true" name="other"/>

		<cfset var local = {}/>

		<cfscript>
			local.result = false;
			if(!structKeyExists(arguments, "other")) {
				return false;
			}
			if(isInstanceOf(arguments.other, "cfesapi.org.owasp.esapi.lang.Enum")) {
				if(name() == arguments.other.name()) {
					local.result = true;
				}
			}
			return local.result;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="numeric" name="hashCodeESAPI" output="false">

	</cffunction>

	<cffunction access="public" returntype="Enum" name="clone" output="false">

	</cffunction>

	<cffunction access="public" returntype="numeric" name="compareTo" output="false">
		<cfargument required="true" name="o"/>

	</cffunction>

	<cffunction access="public" name="getDeclaringClass" output="false">

	</cffunction>

	<cffunction access="public" name="valueOf" output="false">
		<cfargument required="true" name="enumType"/>
		<cfargument required="true" type="String" name="name"/>

	</cffunction>

</cfcomponent>