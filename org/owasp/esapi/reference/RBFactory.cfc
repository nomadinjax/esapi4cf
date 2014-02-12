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
<cfcomponent implements="org.owasp.esapi.RBFactory" extends="org.owasp.esapi.util.Object" output="false">

	<cfscript>
		variables.ESAPI = "";
		variables.logger = "";
		variables.localeCodesMap = {};
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.RBFactory" name="init" output="false">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.logger = variables.ESAPI.getLogger("RBFactory");

			return this;
		</cfscript>

	</cffunction>

    <cffunction access="public" returntype="org.owasp.esapi.ResourceBundle" name="getResourceBundle" output="false">
		<cfargument type="String" name="localeCode"/>

		<cfscript>
			var locale = "";
			var useLocaleCode = "";
			var localeCodeRB = "";

			if (isNull(arguments.localeCode)) {
				// grab currentUser locale
				locale = variables.ESAPI.authenticator().getCurrentUser().getLocaleData();

				// fallback on server default
				if (!(!isNull(locale) && isObject(locale))) {
					locale = createObject("java", "java.util.Locale").getDefault();
					variables.logger.warning(getSecurityType("SECURITY_FAILURE"), false, "Failed to determine locale for user: " & variables.ESAPI.authenticator().getCurrentUser().getAccountName() & ". Using default locale [" & locale.toString() & "].");
					variables.ESAPI.authenticator().getCurrentUser().setLocaleData(locale);
				}
				useLocaleCode = locale.toString();
			}
			else {
				useLocaleCode = arguments.localeCode;
			}

	    	// If a RB for this localeCode already exists, we return the same one, otherwise we create a new one.
	    	if(structKeyExists(variables.localeCodesMap, useLocaleCode)) {
	    		localeCodeRB = variables.localeCodesMap.get(useLocaleCode);
			}
	    	if(isNull(localeCodeRB) || !isObject(localeCodeRB)) {
	    		localeCodeRB = createObject("component", "RBFactory$ResourceBundle").init(variables.ESAPI, useLocaleCode);
	    		variables.localeCodesMap.put(useLocaleCode, localeCodeRB);
	    	}
			return localeCodeRB;
		</cfscript>

	</cffunction>

</cfcomponent>