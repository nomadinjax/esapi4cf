<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfcomponent implements="org.owasp.esapi.EncryptedProperties" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the EncryptedProperties interface. This implementation wraps a normal properties file, and creates surrogates for the getProperty and setProperty methods that perform encryption and decryption based on the Encryptor. A very simple main program is provided that can be used to create an encrypted properties file. A better approach would be to allow unencrypted properties in the file and to encrypt them the first time the file is accessed.">

	<cfscript>
		// imports
		Utils = createObject("component", "org.owasp.esapi.util.Utils");

		variables.ESAPI = "";

		/** The properties. */
		variables.properties = createObject("java", "java.util.Properties").init();

		/** The logger. */
		variables.logger = "";
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.EncryptedProperties" name="init" output="false"
	            hint="Instantiates a new encrypted properties.">
		<cfargument required="true" returntype="org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.logger = variables.ESAPI.getLogger("EncryptedProperties");

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getProperty" output="false">
		<cfargument required="true" type="String" name="key"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var encryptedValue = "";

			try {
				encryptedValue = variables.properties.getProperty(arguments.key);

				if(!(isDefined("encryptedValue") && !isNull(encryptedValue)))
					return "";
				return variables.ESAPI.encryptor().decryptString(encryptedValue);
			}
			catch(java.lang.Exception e) {
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.EncryptionException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("EncryptedProperties_getProperty_badInput_userMessage"), variables.ESAPI.resourceBundle().getString("EncryptedProperties_getProperty_badInput_logMessage"), e));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="setProperty" output="false">
		<cfargument required="true" type="String" name="key"/>
		<cfargument required="true" type="String" name="value"/>

		<cfscript>
			try {
				return variables.properties.setProperty(arguments.key, variables.ESAPI.encryptor().encryptString(arguments.value));
			}
			catch(org.owasp.esapi.errors.EncryptionException e) {
				Utils.throwException(createObject("component", "org.owasp.esapi.errors.EncryptionException").init(variables.ESAPI, variables.ESAPI.resourceBundle().getString("EncryptedProperties_setProperty_badInput_userMessage"), variables.ESAPI.resourceBundle().getString("EncryptedProperties_setProperty_badInput_logMessage"), e));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" name="keySet" output="false">

		<cfscript>
			return variables.properties.keySet();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="load" output="false">
		<cfargument required="true" name="in"/>

		<cfscript>
			variables.properties.load(arguments.in);
			variables.logger.trace(Utils.getSecurityType("SECURITY_SUCCESS"), true, "Encrypted properties loaded successfully");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="store" output="false">
		<cfargument required="true" name="out"/>
		<cfargument required="true" type="String" name="comments"/>

		<cfscript>
			variables.properties.store(arguments.out, arguments.comments);
		</cfscript>

	</cffunction>

</cfcomponent>