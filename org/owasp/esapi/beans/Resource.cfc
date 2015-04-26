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
component implements="org.owasp.esapi.Resource" extends="org.owasp.esapi.util.Object" {

	variables.ESAPI = "";

	public org.owasp.esapi.Resource function init(required org.owasp.esapi.ESAPI ESAPI, required string baseName, required Locale) {
		variables.ESAPI = arguments.ESAPI;
		try {
			variables.ResourceBundle = createObject("java", "java.util.ResourceBundle").getBundle(javaCast("string", arguments.baseName), arguments.Locale, createObject("java", "java.lang.Thread").currentThread().getContextClassLoader());
		}
		catch (java.util.MissingResourceException e) {}
		return this;
	}

	/**
	 * Gets a string for the given key from this resource bundle or one of its parents.
	 *
	 * @param key the key for the desired string
	 */
	public string function getString(required string key) {
		try {
			return variables.ResourceBundle.getString(javaCast("string", arguments.key));
		}
		catch (java.util.MissingResourceException e) {}
		return "**" & arguments.key & "**";
	}

}