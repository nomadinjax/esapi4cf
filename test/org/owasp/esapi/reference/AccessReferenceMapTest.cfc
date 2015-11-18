/*
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
import "org.owasp.esapi.reference.RandomAccessReferenceMap";

/**
 * The Class AccessReferenceMapTest.
 */
component extends="test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

    /**
	 * Test of update method, of class org.owasp.esapi.AccessReferenceMap.
	 *
	 * @throws AuthenticationException
     *             the authentication exception
     * @throws EncryptionException
	 */
    public void function testUpdate() {
        System.out.println("update");
    	var arm = new RandomAccessReferenceMap(variables.ESAPI);
    	var auth = variables.ESAPI.authenticator();

    	var pass = auth.generateStrongPassword();
    	var u = auth.createUser( "armUpdate", pass, pass );

    	// test to make sure update returns something
		arm.update(auth.getUserNames());
		var indirect = arm.getIndirectReference( u.getAccountName() );
		if (isNull(indirect)) fail("");

		// test to make sure update removes items that are no longer in the list
		auth.removeUser( u.getAccountName() );
		arm.update(auth.getUserNames());
		indirect = arm.getIndirectReference( u.getAccountName() );
		if (!isNull(indirect)) fail("");

		// test to make sure old indirect reference is maintained after an update
		arm.update(auth.getUserNames());
		var newIndirect = arm.getIndirectReference( u.getAccountName() );
		assertTrue(isNull(indirect));
		assertTrue(isNull(newIndirect));
		//assertEquals(indirect, newIndirect);
    }


    /**
	 * Test of iterator method, of class org.owasp.esapi.AccessReferenceMap.
	 */
    public void function testIterator() {
        System.out.println("iterator");
    	var arm = new RandomAccessReferenceMap(variables.ESAPI);
        var auth = variables.ESAPI.authenticator();

		arm.update(auth.getUserNames());

		var i = arm.iterator();
		while ( i.hasNext() ) {
			var userName = i.next();
			var u = auth.getUserByAccountName( userName );
			if (isNull(u)) fail("");
		}
    }

    /**
	 * Test of getIndirectReference method, of class
	 * org.owasp.esapi.AccessReferenceMap.
	 */
    public void function testGetIndirectReference() {
        System.out.println("getIndirectReference");

        var directReference = "234";
        var list = [];
        list.add( "123" );
        list.add( directReference );
        list.add( "345" );
        var instance = new RandomAccessReferenceMap(variables.ESAPI, list);

        var expResult = directReference;
        var result = instance.getIndirectReference(directReference);
        assertNotSame(expResult, result);
    }

    /**
	 * Test of getDirectReference method, of class
	 * org.owasp.esapi.AccessReferenceMap.
	 *
	 * @throws AccessControlException
	 *             the access control exception
	 */
    public void function testGetDirectReference() {
        System.out.println("getDirectReference");

        var directReference = "234";
        var list = [];
        list.add( "123" );
        list.add( directReference );
        list.add( "345" );
        var instance = new RandomAccessReferenceMap(variables.ESAPI, list);

        var ind = instance.getIndirectReference(directReference);
        var dir = instance.getDirectReference(ind);
        assertEquals(directReference, dir);
        try {
        	instance.getDirectReference("invalid");
        	fail("");
        } catch(org.owasp.esapi.errors.AccessControlException e ) {
        	// success
        }
    }

    /**
     *
     * @throws org.owasp.esapi.errors.AccessControlException
     */
    public void function testAddDirectReference() {
        System.out.println("addDirectReference");

        var directReference = "234";
        var list = [];
        list.add( "123" );
        list.add( directReference );
        list.add( "345" );
        var instance = new RandomAccessReferenceMap(variables.ESAPI, list);

        var newDirect = instance.addDirectReference("newDirect");
        assertTrue( !isNull(newDirect) );
        var ind = instance.addDirectReference(directReference);
        var dir = instance.getDirectReference(ind);
        assertEquals(directReference, dir);
    	var newInd = instance.addDirectReference(directReference);
    	assertEquals(ind, newInd);
    }

    /**
     *
     * @throws org.owasp.esapi.errors.AccessControlException
     */
    public void function testRemoveDirectReference() {
        System.out.println("removeDirectReference");

        var directReference = "234";
        var list = [];
        list.add( "123" );
        list.add( directReference );
        list.add( "345" );
        var instance = new RandomAccessReferenceMap(variables.ESAPI, list);

        var indirect = instance.getIndirectReference(directReference);
        assertTrue(!isNull(indirect));
        var deleted = instance.removeDirectReference(directReference);
        assertEquals(indirect,deleted);
    	deleted = instance.removeDirectReference("ridiculous");
    	assertTrue(isNull(deleted));
    }

}
