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
<cfcomponent implements="org.owasp.esapi.ResourceBundle" extends="org.owasp.esapi.util.Object" output="false">

	<cfscript>
		variables.ESAPI = "";
		variables.logger = "";
		variables.resourceBundle = "";
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.ResourceBundle" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument required="true" name="locale"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.logger = variables.ESAPI.getLogger("ResourceBundle");

			variables.resourceBundle = createObject("java", "java.util.ResourceBundle").getBundle("RB-ESAPI", arguments.locale);
			variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "ResourceBundle for [" & arguments.locale.toString() & "] locale loaded.");

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLocaleData" output="false" hint="Returns the locale of this resource bundle.">

		<cfscript>
			return variables.resourceBundle.getLocale();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getString" output="false" hint="Gets a string for the given key from this resource bundle or one of its parents.">
		<cfargument required="true" type="String" name="key">

		<cfscript>
			try {
				return variables.resourceBundle.getString(arguments.key);
			}
			catch (java.util.MissingResourceException e) {
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Missing resource bundle for key: [" & arguments.key & "].");
				return "**" & arguments.key & "**";
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="messageFormat" output="false" hint="Takes a set of objects, formats them, then inserts the formatted strings into the pattern at the appropriate places.">
		<cfargument required="true" type="String" name="key">
		<cfargument required="true" type="Array" name="data">

		<cfscript>
			return createObject("java", "java.text.MessageFormat").format(this.getString(arguments.key), arguments.data);
		</cfscript>

	</cffunction>

</cfcomponent>
