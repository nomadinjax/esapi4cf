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
component extends="org.owasp.esapi.util.Object" {

	variables.value = "";	// Value stored in serialized encrypted data to represent PRF
    variables.bits = "";
    variables.algName = "";

    public PRF_ALGORITHMS function init(required numeric value, required numeric bits, required string algName) {
    	variables.value = arguments.value;
    	variables.bits  = arguments.bits;
    	variables.algName = arguments.algName;
    	return this;
    }

    public numeric function getValue() { return variables.value; }
    public numeric function getBits() { return variables.bits; }
    public string function getAlgName() { return variables.algName; }

}