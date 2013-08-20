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

	<cfscript>
		variables.ESAPI = createObject( "component", "org.owasp.esapi.ESAPI" ).init();
		clearUserFile();
	</cfscript>
 
<!--- there are the wrong tests - these are for RandomAccessReferenceMap
	<cffunction access="public" returntype="void" name="testUpdate" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var arm = "";
			var auth = "";
			var pass = "";
			var u = "";
			var indirect = "";
			var newIndirect = "";
			
	        System.out.println("update");
	    	arm = createObject("component", "org.owasp.esapi.reference.RandomAccessReferenceMap").init( variables.ESAPI );
	    	auth = variables.ESAPI.authenticator();

	    	pass = auth.generateStrongPassword();
	    	u = auth.createUser( "armUpdate", pass, pass );

	    	// test to make sure update returns something
			arm.update(auth.getUserNames());
			indirect = arm.getIndirectReference( u.getAccountName() );
			if ( indirect == "" ) fail();

			// test to make sure update removes items that are no longer in the list
			auth.removeUser( u.getAccountName() );
			arm.update(auth.getUserNames());
			indirect = arm.getIndirectReference( u.getAccountName() );
			if ( indirect != "" ) fail();

			// test to make sure old indirect reference is maintained after an update
			arm.update(auth.getUserNames());
			newIndirect = arm.getIndirectReference( u.getAccountName() );
			assertEquals(indirect, newIndirect);
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testIterator" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var arm = "";
			var auth = "";
			var i = "";
			var userName = "";
			var u = "";
			
	        System.out.println("iterator");
	    	arm = createObject("component", "org.owasp.esapi.reference.RandomAccessReferenceMap").init( variables.ESAPI );
	        auth = variables.ESAPI.authenticator();

			arm.update(auth.getUserNames());

			i = arm.iterator();
			while ( i.hasNext() ) {
				userName = i.next();
				u = auth.getUserByAccountName( userName );
				if ( !isObject(u) ) fail();
			}
	    </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetIndirectReference" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var directReference = "";
			var list = "";
			var instance = "";
			var expResult = "";
			var result = "";
			
	        System.out.println("getIndirectReference");

	        directReference = "234";
	        list = [];
	        list.add( "123" );
	        list.add( directReference );
	        list.add( "345" );
	        instance = createObject("component", "org.owasp.esapi.reference.RandomAccessReferenceMap").init( variables.ESAPI, list );

	        expResult = directReference;
	        result = instance.getIndirectReference(directReference);
	        assertNotSame(expResult, result);
	    </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetDirectReference" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var directReference = "";
			var list = "";
			var instance = "";
			var ind = "";
			var dir = "";
			
	        System.out.println("getDirectReference");

	        directReference = "234";
	        list = [];
	        list.add( "123" );
	        list.add( directReference );
	        list.add( "345" );
	        instance = createObject("component", "org.owasp.esapi.reference.RandomAccessReferenceMap").init( variables.ESAPI, list );

	        ind = instance.getIndirectReference(directReference);
	        dir = instance.getDirectReference(ind);
	        assertEquals(directReference, dir);
	        try {
	        	instance.getDirectReference("invalid");
	        	fail("");
	        } catch( org.owasp.esapi.errors.AccessControlException e ) {
	        	// success
	        }
	    </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testAddDirectReference" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var directReference = "";
			var list = "";
			var instance = "";
			var newDirect = "";
			var ind = "";
			var dir = "";
			var newInd = "";
			
	        System.out.println("addDirectReference");

	        directReference = "234";
	        list = [];
	        list.add( "123" );
	        list.add( directReference );
	        list.add( "345" );
	        instance = createObject("component", "org.owasp.esapi.reference.RandomAccessReferenceMap").init( variables.ESAPI, list );

	        newDirect = instance.addDirectReference("newDirect");
	        assertFalse( newDirect == "");
	        ind = instance.addDirectReference(directReference);
	        dir = instance.getDirectReference(ind);
	        assertEquals(directReference, dir);
	    	newInd = instance.addDirectReference(directReference);
	    	assertEquals(ind, newInd);
	    </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testRemoveDirectReference" output="false">
		<cfscript>
			// CF8 requires 'var' at the top
			var directReference = "";
			var list = "";
			var instance = "";
			var indirect = "";
			var deleted = "";

	        System.out.println("removeDirectReference");

	        directReference = "234";
	        list = [];
	        list.add( "123" );
	        list.add( directReference );
	        list.add( "345" );
	        instance = createObject("component", "org.owasp.esapi.reference.RandomAccessReferenceMap").init( variables.ESAPI, list );

	        indirect = instance.getIndirectReference(directReference);
	        assertFalse(indirect == "");
	        deleted = instance.removeDirectReference(directReference);
	        assertEquals(indirect,deleted);
	    	deleted = instance.removeDirectReference("ridiculous");
	    	assertTrue(deleted == "");
	    </cfscript> 
	</cffunction>
--->

</cfcomponent>
