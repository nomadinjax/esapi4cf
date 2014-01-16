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
		variables.resourceBundles = {};
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.ResourceBundle" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.logger = variables.ESAPI.getLogger("ResourceBundle");

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="private" name="getRBInstance" output="false">

		<cfscript>
			// grab currentUser locale
			var locale = variables.ESAPI.authenticator().getCurrentUser().getLocaleData();

			// fallback on server default
			if (!isObject(locale)) {
				locale = newJava("java.util.Locale").getDefault();
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Failed to determine locale for user: " & variables.ESAPI.authenticator().getCurrentUser().getAccountName() & ". Using default locale [" & locale.toString() & "].");
			}

			// in order to keep this thread safe for users of varying locales, we must store a ResourceBundle instance per locale
			if (!structKeyExists(variables.resourceBundles, locale.toString())) {
				variables.resourceBundles[locale.toString()] = newJava("java.util.ResourceBundle").getBundle("RB-ESAPI", locale);
				variables.logger.info(getSecurityType("SECURITY_SUCCESS"), true, "ResourceBundle for [" & locale.toString() & "] locale loaded.");
			}

			return variables.resourceBundles[locale.toString()];
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getMessage" output="false">
		<cfargument required="true" type="String" name="key">

		<cfscript>
			try {
				return getRBInstance().getString(arguments.key);
			}
			catch (java.util.MissingResourceException  e) {
				variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Missing resource bundle for key: [" & arguments.key & "].");
				return "***" & arguments.key & "***";
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="messageFormat" output="false">
		<cfargument required="true" type="String" name="key">
		<cfargument required="true" type="Array" name="data">

		<cfscript>
			return newJava("java.text.MessageFormat").format(this.getMessage(arguments.key), arguments.data);
		</cfscript>

	</cffunction>

</cfcomponent>
