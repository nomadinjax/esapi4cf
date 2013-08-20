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
<cfinterface hint="The EncryptedProperties interface represents a properties file where all the data is encrypted before it is added, and decrypted when it retrieved. This interface can be implemented in a number of ways, the simplest being extending Properties and overloading the getProperty and setProperty methods.">

	<cffunction access="public" returntype="String" name="getProperty" output="false" hint="Gets the property value from the encrypted store, decrypts it, and returns the plaintext value to the caller.">
		<cfargument required="true" type="String" name="key" hint="the name of the property to get">
	</cffunction>


	<cffunction access="public" returntype="String" name="setProperty" output="false" hint="Encrypts the plaintext property value and stores the ciphertext value in the encrypted store.">
		<cfargument required="true" type="String" name="key" hint="the name of the property to set">
		<cfargument required="true" type="String" name="value" hint="the value of the property to set">
	</cffunction>


	<cffunction access="public" name="keySet" output="false" hint="Returns a Set view of properties. The Set is backed by a Hashtable, so changes to the Hashtable are reflected in the Set, and vice-versa. The Set supports element removal (which removes the corresponding entry from the Hashtable), but not element addition.">
	</cffunction>


	<cffunction access="public" returntype="void" name="load" output="false" hint="Reads a property list (key and element pairs) from the input stream.">
		<cfargument required="true" name="in" hint="the input stream that contains the properties file">
	</cffunction>


	<cffunction access="public" returntype="void" name="store" output="false" hint="Writes this property list (key and element pairs) in this Properties table to the output stream in a format suitable for loading into a Properties table using the load method.">
		<cfargument required="true" name="out" hint="the output stream that contains the properties file">
		<cfargument required="true" type="String" name="comments" hint="a description of the property list (ex. 'Encrypted Properties File').">
	</cffunction>

</cfinterface>
