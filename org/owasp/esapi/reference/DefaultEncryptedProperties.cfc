<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
--->
<cfcomponent implements="cfesapi.org.owasp.esapi.EncryptedProperties" extends="cfesapi.org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the EncryptedProperties interface. This implementation wraps a normal properties file, and creates surrogates for the getProperty and setProperty methods that perform encryption and decryption based on the Encryptor. A very simple main program is provided that can be used to create an encrypted properties file. A better approach would be to allow unencrypted properties in the file and to encrypt them the first time the file is accessed.">

	<cfscript>
		instance.ESAPI = "";

		/** The properties. */
		instance.properties = getJava("java.util.Properties").init();

		/** The logger. */
		instance.logger = "";
	</cfscript>

	<cffunction access="public" returntype="DefaultEncryptedProperties" name="init" output="false" hint="Instantiates a new encrypted properties.">
		<cfargument required="true" returntype="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("EncryptedProperties");

			return this;
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="getProperty" output="false">
		<cfargument required="true" type="String" name="key">
		<cfscript>
			try {
				local.encryptedValue = instance.properties.getProperty(arguments.key);

				if(!structKeyExists(local, "encryptedValue"))
					return "";
				return instance.ESAPI.encryptor().decryptString(local.encryptedValue);
			} catch (Exception e) {
				throwException(createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Property retrieval failure", "Couldn't decrypt property", e));
			}
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="String" name="setProperty" output="false">
		<cfargument required="true" type="String" name="key">
		<cfargument required="true" type="String" name="value">
		<cfscript>
			try {
				return instance.properties.setProperty(arguments.key, instance.ESAPI.encryptor().encryptString(arguments.value));
			} catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
				throwException(createObject("component", "cfesapi.org.owasp.esapi.errors.EncryptionException").init(instance.ESAPI, "Property setting failure", "Couldn't encrypt property", e));
			}
		</cfscript>
	</cffunction>

	<cffunction access="public" name="keySet" output="false">
		<cfscript>
			return instance.properties.keySet();
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="load" output="false">
		<cfargument required="true" name="in">
		<cfscript>
			instance.properties.load(arguments.in);
			instance.logger.trace(getSecurity("SECURITY"), true, "Encrypted properties loaded successfully");
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="store" output="false">
		<cfargument required="true" name="out">
		<cfargument required="true" type="String" name="comments">
		<cfscript>
			instance.properties.store(arguments.out, arguments.comments);
		</cfscript>
	</cffunction>

</cfcomponent>
