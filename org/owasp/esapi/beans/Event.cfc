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
import "org.owasp.esapi.errors.IntrusionException";

component extends="org.owasp.esapi.util.Object" {

    property type="string" name="key";
    property type="array" name="times";

	variables.ESAPI = "";

    variables.times = [];
    variables.key = "";

    public Event function init( required org.owasp.esapi.ESAPI ESAPI, required string key ) {
    	variables.ESAPI = arguments.ESAPI;
        variables.key = arguments.key;
        return this;
    }

    public void function increment(required numeric count, required numeric interval) {
    	if (variables.ESAPI.securityConfiguration().getDisableIntrusionDetection()) return;

        var timestamp = now();
        arrayPrepend( variables.times, timestamp );
        while ( arrayLen(variables.times) > arguments.count ) arrayDeleteAt( variables.times, arrayLen(variables.times) );
        if ( arrayLen(variables.times) == arguments.count ) {
            var past = variables.times[ arguments.count-1 ];
            var plong = past.getTime();
            var nlong = timestamp.getTime();
            if ( nlong - plong < arguments.interval * 1000 ) {
                throws(new IntrusionException( variables.ESAPI, "Threshold exceeded", "Exceeded threshold for " & variables.key ));
            }
        }
    }

}