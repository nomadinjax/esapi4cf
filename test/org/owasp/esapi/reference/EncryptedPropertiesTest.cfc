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
<cfcomponent extends="esapi4cf.test.org.owasp.esapi.util.TestCase" output="false">
<!---
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Iterator;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.errors.EncryptionException;
--->
	<cfscript>
		instance.ESAPI = createObject( "component", "esapi4cf.org.owasp.esapi.ESAPI" ).init();
	</cfscript>

	<cffunction access="public" returntype="void" name="testGetProperty" output="false">
		<cfscript>
			var local = {};

			System.out.println("getProperty");
			local.dep = createObject("component", "esapi4cf.org.owasp.esapi.reference.DefaultEncryptedProperties").init(instance.ESAPI);
			local.name = "name";
			local.value = "value";
			local.dep.setProperty(local.name, local.value);
			local.result = local.dep.getProperty(local.name);
			assertEquals(local.value, local.result);
			assertTrue(local.dep.getProperty("ridiculous") == "");
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testSetProperty" output="false">
		<cfscript>
			var local = {};

			System.out.println("setProperty");
			local.dep = createObject("component", "esapi4cf.org.owasp.esapi.reference.DefaultEncryptedProperties").init(instance.ESAPI);
			local.name = "name";
			local.value = "value";
			local.dep.setProperty(local.name, local.value);
			local.result = local.dep.getProperty(local.name);
			assertEquals(local.value, local.result);
			/* NULL test not valid in CF
			try {
				local.dep.setProperty(null, null);
				fail("");
			} catch( esapi4cf.org.owasp.esapi.errors.EncryptionException e ) {
				// expected
			} */
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testNonExistantKeyValue" output="false" hint="Test the behavior when the requested key does not exist.">
		<cfscript>
			var local = {};

			local.dep = createObject("component", "esapi4cf.org.owasp.esapi.reference.DefaultEncryptedProperties").init(instance.ESAPI);
			assertTrue(local.dep.getProperty("not.there") == "");
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testKeySet" output="false">
		<cfscript>
			var local = {};

			local.sawTwo = false;
			local.sawOne = false;

			System.out.println("keySet");
			local.dep = createObject("component", "esapi4cf.org.owasp.esapi.reference.DefaultEncryptedProperties").init(instance.ESAPI);
			local.dep.setProperty("one", "two");
			local.dep.setProperty("two", "three");
			local.i = local.dep.keySet().iterator();
			while(local.i.hasNext())
			{
				local.key = local.i.next();

				assertFalse(local.key == "", "key returned from keySet() iterator was null");
				if(local.key.equals("one"))
					if(local.sawOne)
						fail("Key one seen more than once.");
					else
						local.sawOne = true;
				else if(local.key.equals("two"))
					if(local.sawTwo)
						fail("Key two seen more than once.");
					else
						local.sawTwo = true;
				else
					fail("Unset key " & local.key & " returned from keySet().iterator()");
			}
			assertTrue(local.sawOne, "Key one was never seen");
			assertTrue(local.sawTwo, "Key two was never seen");
		</cfscript>
	</cffunction>

	<cffunction access="public" returntype="void" name="testStoreLoad" output="false" hint="Test storing and loading of encrypted properties.">
		<cfscript>
			var local = {};

			local.toStore = createObject("component", "esapi4cf.org.owasp.esapi.reference.DefaultEncryptedProperties").init(instance.ESAPI);
			local.toLoad = createObject("component", "esapi4cf.org.owasp.esapi.reference.DefaultEncryptedProperties").init(instance.ESAPI);
			local.baos = getJava("java.io.ByteArrayOutputStream").init();
			local.bais = "";
			local.sawOne = false;
			local.sawTwo = false;

			local.toStore = createObject("component", "esapi4cf.org.owasp.esapi.reference.DefaultEncryptedProperties").init(instance.ESAPI);
			local.toStore.setProperty("one", "two");
			local.toStore.setProperty("two", "three");
			local.toStore.store(local.baos, "testStore");

			local.bais = getJava("java.io.ByteArrayInputStream").init(baos.toByteArray());
			local.toLoad.load(local.bais);

			for(local.i=local.toLoad.keySet().iterator();local.i.hasNext();)
			{
				local.key = local.i.next();

				assertFalse(local.key == "", "key returned from keySet() iterator was null");
				if(local.key.equals("one"))
					if(local.sawOne)
						fail("Key one seen more than once.");
					else
					{
						local.sawOne = true;
						assertEquals("two", local.toLoad.getProperty("one"), "Key one's value was not two");
					}
				else if(local.key.equals("two"))
					if(local.sawTwo)
						fail("Key two seen more than once.");
					else
					{
						local.sawTwo = true;
						assertEquals("three", local.toLoad.getProperty("two"), "Key two's value was not three");
					}
				else
					fail("Unset key " & local.key & " returned from keySet().iterator()");
			}
			assertTrue(local.sawOne, "Key one was never seen");
			assertTrue(local.sawTwo, "Key two was never seen");
		</cfscript>
	</cffunction>

</cfcomponent>
