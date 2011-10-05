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
<cfcomponent extends="cfesapi.test.TestCase" name="CryptoTokenTest" output="false">

	<cfscript>
		instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
		
		instance.skey1 = "";
		instance.skey2 = "";
	</cfscript>
 
	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
	        instance.skey1 = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoHelper").generateSecretKey("AES", 128);
	        instance.skey2 = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoHelper").generateSecretKey("AES", 128);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testCryptoToken" output="false">
		<cfscript>
	        // Test with default CTOR
	        local.ctok = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init(ESAPI=instance.ESAPI);
	        CTORtest( local.ctok );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testCryptoTokenSecretKey" output="false">
		<cfscript>
	     	// Test with default CTOR
	        local.ctok = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init(ESAPI=instance.ESAPI, skey=instance.skey1);
	        CTORtest( local.ctok, instance.skey1 );
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="void" name="CTORtest" output="false">
		<cfargument type="cfesapi.org.owasp.esapi.crypto.CryptoToken" name="ctok" required="true">
		<cfargument type="any" name="sk" required="false" hint="javax.crypto.SecretKey">
		<cfscript>
			System = createObject("java", "java.lang.System");
			
	        local.token = "";
	        try {
	            if ( isNull(arguments.sk) ) {
	                local.token = arguments.ctok.getToken();    // Use default key, Encryptor.MasterKey
	            } else {
	                local.token = arguments.ctok.getToken(arguments.sk);
	            }
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
	            fail("Caught unexpected exception on getToken() call: " & e.toString());
	        }
	        assertFalse(isNull(local.token));
	        assertEquals( arguments.ctok.getUserAccountName(), createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").ANONYMOUS_USER);
	        assertFalse( arguments.ctok.isExpired() );
	        local.expTime1 = arguments.ctok.getExpiration();
	        
	        local.ctok2 = "";
	        try {
	            if ( isNull(arguments.sk) ) {
	                local.ctok2 = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init( ESAPI=instance.ESAPI, token=local.token );    // Use default key, Encryptor.MasterKey
	            } else {
	                local.ctok2 = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init( ESAPI=instance.ESAPI, skey=arguments.sk, token=local.token );
	            }
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
	            e.printStackTrace(System.err);
	            fail("Caught unexpected exception on CryptoToken CTOR: " & e.toString());
	        }
	        local.expTime2 = local.ctok2.getExpiration();
	        assertTrue(( local.expTime2 >= local.expTime1 ), "Expected expiration for ctok2 (" & createObject("java", "java.util.Date").init(local.expTime2) & ") to be later than of ctok (" & createObject("java", "java.util.Date").init(local.expTime1) & ").");
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testCryptoTokenSecretKeyString" output="false">
		<cfscript>
	        local.ctok1 = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init(ESAPI=instance.ESAPI, skey=instance.skey1);
	        try {
	            local.ctok1.setUserAccountName("kevin.w.wall@gmail.com");
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            fail("Failed to set user account name because of ValidationException: " & e.toString());
	        }
	        try {
	            local.ctok1.setAttribute("role-name", "admin");
	            local.ctok1.setAttribute("company", "Qwest");
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            fail("Failed to set 'role-name' or 'company' attribute because of ValidationException: " & e.toString());
	        }
	        local.token1 = "";
	        local.token2 = "";
	        local.passedFirst = false;
	        try {
	            local.token1 = local.ctok1.getToken();
	            local.passedFirst = true;
	            local.token2 = local.ctok1.getToken(instance.skey2);
	            assertFalse(local.token1.equals(local.token2), "Tokens unexpectedly equal!");
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
	            fail("Failed to retrieve " & (local.passedFirst ? "1st" : "2nd" ) & " encrypted token");
	        }
	        local.ctok2 = "";
	        try {
	            local.ctok2 = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init(ESAPI=instance.ESAPI, skey=instance.skey1, token=local.token1);
	            local.token2 = local.ctok2.getToken();
	            local.ctok2.setAttribute("company", "CenturyLink");
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
	            fail("Failed to decrypt token1 or re-encrypt token; exception: " & e.toString());
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            fail("Failed with ValidationException on resetting 'company' attribute: " & e.toString());
	        }
	        local.userName = local.ctok2.getUserAccountName();
	        local.roleAttr = local.ctok2.getAttribute("role-name");
	        local.company  = local.ctok2.getAttribute("company");
	        assertEquals( local.userName, "kevin.w.wall@gmail.com");
	        assertEquals( local.roleAttr, "admin");
	        assertEquals( local.company, "CenturyLink");
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testExpiration" output="false">
		<cfscript>
	        local.ctok = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init(ESAPI=instance.ESAPI);
	        local.ctok.setExpiration(intervalSecs=2);  // 2 seconds
	        local.ctok2 = "";
	        try {
	            local.ctok2 = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init( ESAPI=instance.ESAPI, token=local.ctok.getToken() );
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException e1) {
	            fail("Failed to decrypt token");
	        }
	        assertFalse( local.ctok.isExpired() );
	        assertFalse( local.ctok2.isExpired() );
	        nap(2);
	
	        assertTrue( local.ctok.isExpired() );
	        assertTrue( local.ctok2.isExpired() );
	        
	        try {
	            local.ctok2.updateToken(2);
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
	            fail("EncryptionException for token ctok2 by adding additional 2 sec; exception: " & e.toString());
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // This would be caused if the token would already be expired even AFTER adding
	            // an additional 2 seconds. We don't expect this, but it could happen if the OS
	            // causes this process to stall for a bit while running higher priority processes.
	            // We don't expect this here though. (Have a test for that below.)
	            fail("Failed to update token ctok2 by adding additional 2 sec; exception: " & e.toString());
	        }
	        assertFalse( local.ctok2.isExpired() );
	        nap(3);
	        try {
	            local.ctok2.updateToken(1);
	            fail("Expected ValidationException!");
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
	            fail("EncryptionException for token ctok2 by adding additional 2 sec; exception: " & e.toString());
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            // Probably a bad idea to test this in the following manner as
	            // message could change whenever.
	            // assertEquals( e.getMessage(), "Token timed out.");
	            ;   // Ignore -- in this case, we expect it!
	        }
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testSetUserAccountName" output="false">
		<cfscript>
	        local.ctok = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init(ESAPI=instance.ESAPI);
	        try {
	            local.ctok.setUserAccountName("kevin.w.wall@gmail.com");
	            local.ctok.setUserAccountName("kevin");
	            local.ctok.setUserAccountName("name-with-hyphen");
	            local.ctok.setUserAccountName("x");
	            local.ctok.setUserAccountName("X");
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            fail("Failed to set user account name because of ValidationException: " + e);
	        }
	        try {
	            local.ctok.setUserAccountName("");    // Can't be empty
	            fail("Failed to throw expected ValidationException");
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            ;   // Success
	        }
	        /* NULL test - not valid for CF
	        try {
	            local.ctok.setUserAccountName(null);    // Can't be null
	                // Should get one of these, depending on whether or not assertions are enabled.
	            fail("Failed to throw expected AssertionError or NullPointerException");
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            fail("Wrong type of exception thrown (ValidationException): " + e);
	        } catch (java.lang.NullPointerException e) {
	            ;   // Success
	        } catch (java.lang.AssertionError e) {
	            ;   // Success
	        } */
	        try {
	            local.ctok.setUserAccountName("1773g4l");    // Can't start w/ numeric
	            fail("Failed to throw expected ValidationException");
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            ;   // Success
	        }
	        try {
	            local.ctok.setUserAccountName("invalid/char");    // '/' is not valid.
	            fail("Failed to throw expected ValidationException");
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            ;   // Success
	        }
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testSetExpirationDate" output="false">
		<cfscript>
	        local.ctok = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init(ESAPI=instance.ESAPI);
	        /* NULL test - not valid in CF
	        try {
	            local.ctok.setExpiration(null);
	            fail("Expected IllegalArgumentException on ctok.setExpiration(null).");
	        } catch (InvalidArgumentTypeException e) {
	            ;   // Success
	        } catch (java.lang.Exception e) {
	            fail("Caught unexpected exception: " & e.toString());
	        } */
	
	        try {
	            local.now = createObject("java", "java.util.Date").init();
	            nap(1);
	            local.ctok.setExpiration(expirationDate=local.now);
	            fail("Expected IllegalArgumentException on ctok.setExpiration(Date) w/ Date in past.");
	        } catch (java.lang.IllegalArgumentException e) {
	            ;   // Success
	        } catch (java.lang.Exception e) {
	            fail("Caught unexpected exception: " & e.toString());
	        }
	
	        try {
	            local.ctok.setExpiration(intervalSecs=-1);
	            fail("Expected IllegalArgumentException on ctok.setExpiration(int) w/ negative interval.");
	        } catch (java.lang.IllegalArgumentException e) {
	            ;   // Success
	        } catch (java.lang.Exception e) {
	            fail("Caught unexpected exception: " & e.toString());
	        }
	
	        try {
	            local.maxDate = createObject("java", "java.util.Date").init( createObject("java", "java.lang.Long").MAX_VALUE - 1 );
	            local.ctok.setExpiration( expirationDate=local.maxDate );
	            local.ctok.updateToken(1);
	            fail("Expected ArithmeticException on ctok.setExpiration(int).");
	        } catch (java.lang.ArithmeticException e) {
	            ;   // Success
	        } catch (java.lang.Exception e) {
	            fail("Caught unexpected exception: " & e.toString());
	        }   
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testSetAndGetAttribute" output="false">
		<cfscript>
			System = createObject("java", "java.lang.System");

	        local.ctok = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init(ESAPI=instance.ESAPI);
	
	        // Test case where attr name is empty string. Expect ValidationException
	        try {
	            local.ctok.setAttribute("", "someValue");
	            fail("Expected ValidationException on ctok.setAttribute().");
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            ;   // Success
	        } catch (java.lang.Exception e) {
	            fail("Caught unexpected exception: " & e.toString());
	        }
	        
	        // Test case where attr name does not match regex "[A-Za-z0-9_.-]+".
	        // Expect ValidationException.
	        try {
	            local.ctok.setAttribute("/my/attr/", "someValue");
	            fail("Expected ValidationException on ctok.setAttribute() w/ invalid name.");
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            ;   // Success
	        } catch (java.lang.Exception e) {
	            fail("Caught unexpected exception: " & e.toString());
	        }
	        
	        /* NULL test - not valid for CF
	        // Test case where attr VALUE is not. Expect ValidationException.
	        try {
	            local.ctok.setAttribute("myAttr", null);
	            fail("Expected ValidationException on ctok.setAttribute() w/ null value.");
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            ;   // Success
	        } catch (java.lang.Exception e) {
	            fail("Caught unexpected exception: " & e.toString());
	        } */
	
	        // Test cases that should work. Specifically we want to test cases
	        // where attribute values contains each of the values that will
	        // be quoted, namely:   '\', '=', and ';'
	        try {
	            local.complexValue = "kwwall;1291183520293;abc=x=yx;xyz=;efg=a;a;;bbb=quotes\\tuff";
	            
	            local.ctok.setAttribute("..--__", ""); // Ugly, but legal attr name; empty is legal value.
	            local.ctok.setAttribute("attr1", "\\");
	            local.ctok.setAttribute("attr2", ";");
	            local.ctok.setAttribute("attr3", "=");
	            local.ctok.setAttribute("complexAttr", local.complexValue);
	            local.tokenVal = local.ctok.getToken();
	            assertTrue(!isNull(local.tokenVal), "tokenVal should not be null");
	            
	            local.ctok2 = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init(ESAPI=instance.ESAPI, token=local.tokenVal);
	            local.weirdAttr = local.ctok2.getAttribute("..--__");
	            assertTrue(local.weirdAttr.equals(""), "Expecting empty string for value of weird attr, but got: " & local.weirdAttr);
	
	            local.attr1 = local.ctok2.getAttribute("attr1");
	            assertTrue(local.attr1.equals("\\"), "attr1 has unexpected value of " & local.attr1);
	
	            local.attr2 = local.ctok2.getAttribute("attr2");
	            assertTrue(local.attr2.equals(";"), "attr2 has unexpected value of " & local.attr2);
	
	            local.attr3 = local.ctok2.getAttribute("attr3");
	            assertTrue(local.attr3.equals("="), "attr3 has unexpected value of " & local.attr3);
	
	            local.complexAttr = local.ctok2.getAttribute("complexAttr");
	            assertTrue(!isNull(local.complexAttr));
	            assertTrue(local.complexAttr.equals(local.complexValue), "complexAttr has unexpected value of " & local.complexAttr);
	
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            fail("Caught unexpected ValidationException: " & e.toString());
	        } catch (java.lang.Exception e) {
	            e.printStackTrace(System.err);
	            fail("Caught unexpected exception: " & e.toString());
	        }
		</cfscript> 
	</cffunction>

	<!---
		// Test the following two methods in CryptoToken:
		// public void addAttributes(final Map<String, String> attrs) throws ValidationException
		// public Map<String, String> getAttributes()
		--->

	<cffunction access="public" returntype="void" name="tesAddandGetAttributes" output="false">
		<cfscript>
			System = createObject("java", "java.lang.System");

	        local.ctok = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init(ESAPI=instance.ESAPI);    
	        local.origAttrs = "";
	
	        try {
	            local.ctok.setAttribute("attr1", "value1");
	            local.ctok.setAttribute("attr2", "value2");
	            local.origAttrs = local.ctok.getAttributes();
	            local.origAttrs.put("attr2", "NewValue2");
	            local.val = local.ctok.getAttribute("attr2");
	            assertTrue(local.val.equals("value2"), "Attribute map not cloned; crypto token attr changed!");  // Confirm original attr2 did not change
	            
	            local.origAttrs.put("attr3", "value3");
	            local.origAttrs.put("attr4", "value4");
	            local.ctok.addAttributes(local.origAttrs);
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            fail("Caught unexpected ValidationException: " & e.toString());
	        }
	        try {
	            local.token = local.ctok.getToken();
	            local.ctok = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init(ESAPI=instance.ESAPI, token=local.token);
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
	            fail("Caught unexpected EncryptionException: " & e.toString());
	        }
	        
	        local.extractedAttrs = local.ctok.getAttributes();
	        assertTrue(local.origAttrs.equals(local.extractedAttrs), "Expected extracted attrs to be equal to original attrs");
	                
	        local.origAttrs.put("/illegalAttrName/", "someValue");
	        try {
	            local.ctok.addAttributes(local.origAttrs);
	            fail("Expected ValidationException");
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            ;   // Success
	        } catch (java.lang.Exception e) {
	            e.printStackTrace(System.err);
	            fail("Caught unexpected exception: " & e.toString());
	        }
	        
	        local.origAttrs.clear();
	        local.ctok2 = "";
	        try {
	            local.ctok.clearAttributes();     // Clear any attributes
	            local.ctok2 = createObject("component", "cfesapi.org.owasp.esapi.crypto.CryptoToken").init( ESAPI=instance.ESAPI, token=local.ctok.getToken() );
	        } catch (cfesapi.org.owasp.esapi.errors.EncryptionException e) {
	            fail("Unexpected EncryptionException");
	        }
	        
	        try {
	            local.ctok2.addAttributes(local.origAttrs);     // Add (empty) attribute map
	        } catch (cfesapi.org.owasp.esapi.errors.ValidationException e) {
	            fail("Unexpected ValidationException");
	        }
	        local.extractedAttrs = local.ctok2.getAttributes();
	        assertTrue(local.extractedAttrs.isEmpty(), "Expected extracted attributes to be empty");
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="void" name="nap" output="false" hint="Sleep n seconds.">
		<cfargument type="numeric" name="n" required="true">
		<cfscript>
			System = createObject("java", "java.lang.System");

	        try {
	            System.out.println("Sleeping " & n & " seconds...");
	            createObject("java", "java.lang.Thread").sleep( n * 1000 );
	        } catch (java.lang.InterruptedException e) {
	            ;   // Ignore
	        }
		</cfscript> 
	</cffunction>


</cfcomponent>
