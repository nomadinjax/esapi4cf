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
<cfcomponent extends="esapi4cf.test.org.owasp.esapi.util.TestCase" output="false">

	<cffunction access="public" returntype="void" name="testGetProperty" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var name = "";
			var value = "";
			var result = "";

			System.out.println("getProperty");
			instance = createObject("component", "org.owasp.esapi.reference.DefaultEncryptedProperties").init(request.ESAPI);
			name = "name";
			value = "value";
			instance.setProperty(name, value);
			result = instance.getProperty(name);
			assertEquals(value, result);
			assertTrue(instance.getProperty("ridiculous") == "");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testSetProperty" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var name = "";
			var value = "";
			var result = "";

			System.out.println("setProperty");
			instance = createObject("component", "org.owasp.esapi.reference.DefaultEncryptedProperties").init(request.ESAPI);
			name = "name";
			value = "value";
			instance.setProperty(name, value);
			result = instance.getProperty(name);
			assertEquals(value, result);
			try {
				// Railo 4.1 has full NULL support
			    instance.setProperty(javaCast("null", ""), javaCast("null", ""));
			    fail("");
			}
			catch(org.owasp.esapi.errors.EncryptionException e) {
			    // expected
			}
			catch (application e) {
				// fails if NULL support is not available - just skip
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testNonExistantKeyValue" output="false"
	            hint="Test the behavior when the requested key does not exist.">

		<cfscript>
			var instance = createObject("component", "org.owasp.esapi.reference.DefaultEncryptedProperties").init(request.ESAPI);
			assertTrue(instance.getProperty("not.there") == "");
		</cfscript>

	</cffunction>


	<cffunction access="public" returntype="void" name="testKeySet" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var i = "";
			var key = "";

			var sawTwo = false;
			var sawOne = false;

			System.out.println("keySet");
			instance = createObject("component", "org.owasp.esapi.reference.DefaultEncryptedProperties").init(request.ESAPI);
			instance.setProperty("one", "two");
			instance.setProperty("two", "three");
			i = instance.keySet().iterator();
			while(i.hasNext()) {
				key = i.next();

				assertFalse(isNull(key), "key returned from keySet() iterator was null");
				if(key.equals("one"))
					if(sawOne)
						fail("Key one seen more than once.");
					else
						sawOne = true;
				else if(key.equals("two"))
					if(sawTwo)
						fail("Key two seen more than once.");
					else
						sawTwo = true;
				else
					fail("Unset key " & key & " returned from keySet().iterator()");
			}
			assertTrue(sawOne, "Key one was never seen");
			assertTrue(sawTwo, "Key two was never seen");
		</cfscript>

	</cffunction>


	<cffunction access="public" returntype="void" name="testStoreLoad" output="false"
	            hint="Test storing and loading of encrypted properties.">

		<cfscript>
        	// CF8 requires 'var' at the top
        	var i = "";
        	var key = "";

        	var toStore = createObject("component", "org.owasp.esapi.reference.DefaultEncryptedProperties").init(request.ESAPI);
        	var toLoad = createObject("component", "org.owasp.esapi.reference.DefaultEncryptedProperties").init(request.ESAPI);
        	var baos = createObject("java", "java.io.ByteArrayOutputStream").init();
        	var bais = "";
        	var sawOne = false;
        	var sawTwo = false;

        	toStore = createObject("component", "org.owasp.esapi.reference.DefaultEncryptedProperties").init(request.ESAPI);
        	toStore.setProperty("one", "two");
        	toStore.setProperty("two", "three");
        	toStore.store(baos, "testStore");

        	bais = createObject("java", "java.io.ByteArrayInputStream").init(baos.toByteArray());
        	toLoad.load(bais);

			for(i=toLoad.keySet().iterator();i.hasNext();) {
				key = i.next();

				assertFalse(isNull(key), "key returned from keySet() iterator was null");
				if(key.equals("one"))
					if(sawOne)
						fail("Key one seen more than once.");
					else
					{
						sawOne = true;
						assertEquals("two", toLoad.getProperty("one"), "Key one's value was not two");
					}
				else if(key.equals("two"))
					if(sawTwo)
						fail("Key two seen more than once.");
					else
					{
						sawTwo = true;
						assertEquals("three", toLoad.getProperty("two"), "Key two's value was not three");
					}
				else
					fail("Unset key " & key & " returned from keySet().iterator()");
			}
			assertTrue(sawOne, "Key one was never seen");
			assertTrue(sawTwo, "Key two was never seen");
		</cfscript>

	</cffunction>


</cfcomponent>
