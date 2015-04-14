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
 * A {@code ConfigurationException} should be thrown when a problem arises because of
 * a problem in one of ESAPI's configuration files, such as a missing required
 * property or invalid setting of a property, or missing or unreadable
 * configuration file, etc.
 * <p>
 * A {@code ConfigurationException} is a {@code RuntimeException}
 * because 1) configuration properties can, for the most part, only be checked
 * at run-time, and 2) we want this to be an unchecked exception to make ESAPI
 * easy to use and not cluttered with catching a bunch of try/catch blocks.
 * </p>
 */
component extends="org.owasp.esapi.util.RuntimeException" {

	public ConfigurationException function init(string s, cause) {
		if (structKeyExists(arguments, "s") && structKeyExists(arguments, "cause")) {
			super.init(arguments.s, arguments.cause);
		}
		else if (structKeyExists(arguments, "s")) {
			super.init(arguments.s);
		}
		else if (structKeyExists(arguments, "cause")) {
			super.init(cause=arguments.cause);
		}
		return this;
	}

}
