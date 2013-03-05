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
<cfcomponent extends="esapi4cf-test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		instance.ESAPI = createObject( "component", "esapi4cf.org.owasp.esapi.ESAPI" ).init();
		clearUserFile();
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			structClear( session );
			structClear( request );
		</cfscript>

	</cffunction>

    <cffunction access="public" returntype="void" name="testUpdate" output="false">
		<cfscript>
			var local = {};

	        System.out.println("update");
	    	local.arm = createObject("component", "esapi4cf.org.owasp.esapi.reference.RandomAccessReferenceMap").init(instance.ESAPI);
	    	local.auth = instance.ESAPI.authenticator();

	    	local.pass = local.auth.generateStrongPassword();
	    	local.u = local.auth.createUser( "armUpdate", local.pass, local.pass );

	    	// test to make sure update returns something
			local.arm.update(local.auth.getUserNames());
			local.indirect = local.arm.getIndirectReference( local.u.getAccountName() );
			if ( local.indirect == "" ) fail("");

			// test to make sure update removes items that are no longer in the list
			local.auth.removeUser( local.u.getAccountName() );
			local.arm.update(local.auth.getUserNames());
			local.indirect = local.arm.getIndirectReference( local.u.getAccountName() );
			if ( local.indirect != "" ) fail("");

			// test to make sure old indirect reference is maintained after an update
			local.arm.update(local.auth.getUserNames());
			local.newIndirect = local.arm.getIndirectReference( local.u.getAccountName() );
			assertEquals(local.indirect, local.newIndirect);
		</cfscript>
	</cffunction>

    <cffunction access="public" returntype="void" name="testIterator" output="false">
		<cfscript>
			var local = {};

	        System.out.println("iterator");
	    	local.arm = createObject("component", "esapi4cf.org.owasp.esapi.reference.RandomAccessReferenceMap").init(instance.ESAPI);
	        local.auth = instance.ESAPI.authenticator();

			local.arm.update(local.auth.getUserNames());

			local.i = local.arm.iterator();
			while ( local.i.hasNext() ) {
				local.userName = local.i.next();
				local.u = local.auth.getUserByAccountName( local.userName );
				if ( !isObject(local.u) ) fail("");
			}
		</cfscript>
	</cffunction>

    <cffunction access="public" returntype="void" name="testGetIndirectReference" output="false">
		<cfscript>
			var local = {};

	        System.out.println("getIndirectReference");

	        local.directReference = "234";
	        local.list = [];
	        local.list.add( "123" );
	        local.list.add( local.directReference );
	        local.list.add( "345" );
	        local.arm = createObject("component", "esapi4cf.org.owasp.esapi.reference.RandomAccessReferenceMap").init(instance.ESAPI, local.list );

	        local.expResult = local.directReference;
	        local.result = local.arm.getIndirectReference(local.directReference);
	        assertNotSame(local.expResult, local.result);
		</cfscript>
	</cffunction>

    <cffunction access="public" returntype="void" name="testGetDirectReference" output="false">
		<cfscript>
			var local = {};

	        System.out.println("getDirectReference");

	        local.directReference = "234";
	        local.list = [];
	        local.list.add( "123" );
	        local.list.add( local.directReference );
	        local.list.add( "345" );
	        local.arm = createObject("component", "esapi4cf.org.owasp.esapi.reference.RandomAccessReferenceMap").init(instance.ESAPI, local.list );

	        local.ind = local.arm.getIndirectReference(local.directReference);
	        local.dir = local.arm.getDirectReference(local.ind);
	        assertEquals(local.directReference, local.dir);
	        try {
	        	local.arm.getDirectReference("invalid");
	        	fail("");
	        } catch( esapi4cf.org.owasp.esapi.errors.AccessControlException e ) {
	        	// success
	        }
		</cfscript>
	</cffunction>

    <cffunction access="public" returntype="void" name="testAddDirectReference" output="false">
		<cfscript>
			var local = {};

	        System.out.println("addDirectReference");

	        local.directReference = "234";
	        local.list = [];
	        local.list.add( "123" );
	        local.list.add( local.directReference );
	       	local.list.add( "345" );
	        local.arm = createObject("component", "esapi4cf.org.owasp.esapi.reference.RandomAccessReferenceMap").init(instance.ESAPI, local.list );

	        local.newDirect = local.arm.addDirectReference("newDirect");
	        assertFalse( local.newDirect == "" );
	        local.ind = local.arm.addDirectReference(local.directReference);
	        local.dir = local.arm.getDirectReference(local.ind);
	        assertEquals(local.directReference, local.dir);
	    	local.newInd = local.arm.addDirectReference(local.directReference);
	    	assertEquals(local.ind, local.newInd);
		</cfscript>
	</cffunction>

    <cffunction access="public" returntype="void" name="testRemoveDirectReference" output="false">
		<cfscript>
			var local = {};

	        System.out.println("removeDirectReference");

	        local.directReference = "234";
	        local.list = [];
	        local.list.add( "123" );
	        local.list.add( local.directReference );
	        local.list.add( "345" );
	        local.arm = createObject("component", "esapi4cf.org.owasp.esapi.reference.RandomAccessReferenceMap").init(instance.ESAPI, local.list );

	        local.indirect = local.arm.getIndirectReference(local.directReference);
	        assertFalse(local.indirect == "");
	        local.deleted = local.arm.removeDirectReference(local.directReference);
	        assertEquals(local.indirect,local.deleted);
	    	local.deleted = local.arm.removeDirectReference("ridiculous");
	    	assertTrue(local.deleted == "");
		</cfscript>
	</cffunction>

</cfcomponent>
