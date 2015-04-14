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

/**
 * The Class RandomizerTest.
 */
component extends="esapi4cf.test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

    /**
	 * Test of getRandomString method, of class org.owasp.esapi.Randomizer.
	 */
    public void function testGetRandomString() {
        variables.System.out.println("getRandomString");
        var length = 20;
        var instance = variables.ESAPI.randomizer();
        for ( var i = 0; i < 100; i++ ) {
            var result = instance.getRandomString(length, variables.ESAPI.encoder().CHAR_ALPHANUMERICS );
            for ( var j=0;j<result.length();j++ ) {
            	if ( !createObject("java", "org.owasp.esapi.codecs.Codec").containsCharacter( result.charAt(j), variables.ESAPI.encoder().CHAR_ALPHANUMERICS) ) {
            		fail("");
            	}
            }
            assertEquals(length, result.length());
        }
    }

    /**
	 * Test of getRandomInteger method, of class org.owasp.esapi.Randomizer.
	 */
    public void function testGetRandomInteger() {
        variables.System.out.println("getRandomInteger");
        var min = -20;
        var max = 100;
        var instance = variables.ESAPI.randomizer();
        var minResult = ( max - min ) / 2;
        var maxResult = ( max - min ) / 2;
        for ( var i = 0; i < 100; i++ ) {
            var result = instance.getRandomInteger(min, max);
            if ( result < minResult ) minResult = result;
            if ( result > maxResult ) maxResult = result;
        }
        assertEquals(true, (minResult >= min && maxResult < max) );
    }

    /**
	 * Test of getRandomReal method, of class org.owasp.esapi.Randomizer.
	 */
    public void function testGetRandomReal() {
        variables.System.out.println("getRandomReal");
		var min = createObject("java", "java.lang.Float").init("-20.5234F").floatValue();
		var max = createObject("java", "java.lang.Float").init("100.12124F").floatValue();
        var instance = variables.ESAPI.randomizer();
        var minResult = ( max - min ) / 2;
        var maxResult = ( max - min ) / 2;
        for ( var i = 0; i < 100; i++ ) {
            var result = instance.getRandomReal(min, max);
            if ( result < minResult ) minResult = result;
            if ( result > maxResult ) maxResult = result;
        }
        assertEquals(true, (minResult >= min && maxResult < max));
    }


    /**
     * Test of getRandomGUID method, of class org.owasp.esapi.Randomizer.
     * @throws EncryptionException
     */
    public void function testGetRandomGUID() {
        variables.System.out.println("getRandomGUID");
        var instance = variables.ESAPI.randomizer();
        var list = [];
        for ( var i = 0; i < 100; i++ ) {
            var guid = instance.getRandomGUID();
            if ( list.contains( guid ) ) fail("");
            list.add( guid );
        }
    }


}
