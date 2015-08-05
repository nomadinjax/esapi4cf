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
 * Contains version information about the library.
 */
component extends="org.owasp.esapi.util.Object" {

	public string function getCFMLEngine() {
		return listFirst(server.ColdFusion.ProductName, " ");
	}

	public string function getCFMLVersion() {
		if (structKeyExists(server, "railo")) {
			return server.railo.version;
		}
		else if (structKeyExists(server, "lucee")) {
			return server.lucee.version;
		}
		return server.ColdFusion.ProductVersion;
	}

	public string function getJVMVersion() {
		return createObject("java", "java.lang.System").getProperty("java.version");
	}

	public string function getESAPI4CFName() {
		return "ESAPI4CF";
	}

	public string function getESAPI4CFVersion() {
		return "2.0.0a";
	}

	public string function getESAPI4JVersion() {
		if (structKeyExists(createObject("java", "org.owasp.esapi.ESAPI").securityConfiguration(), "APPLICATION_NAME")) {
			return 2;
		}
		return 1;
	}

}