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
component implements="org.owasp.esapi.LogFactory" extends="org.owasp.esapi.util.Object" {

	variables.ESAPI = "";
	variables.factory = {};

	public LogFactory function init(required org.owasp.esapi.ESAPI ESAPI) {
		variables.ESAPI = arguments.ESAPI;
		return this;
	}

	public org.owasp.esapi.Logger function getLogger(required string moduleName) {
		if (structKeyExists(variables.factory, arguments.moduleName)) {
			return variables.factory[arguments.moduleName];
		}

		variables.factory[arguments.moduleName] = new org.owasp.esapi.beans.Logger(variables.ESAPI, arguments.moduleName);
		return variables.factory[arguments.moduleName];
	}

}