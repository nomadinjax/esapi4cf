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
 * Extension to java.io.File to prevent against null byte injections and
 * other unforeseen problems resulting from unprintable characters
 * causing problems in path lookups. This does _not_ prevent against
 * directory traversal attacks.
 */
component extends="org.owasp.esapi.util.File" {

	variables.ESAPI = "";

	variables.PERCENTS_PAT = createObject("java", "java.util.regex.Pattern").compile("(%)([0-9a-fA-F])([0-9a-fA-F])");
	variables.FILE_BLACKLIST_PAT = createObject("java", "java.util.regex.Pattern").compile("([\\\\/:*?<>|])");	// Windows blacklist: \ / : * ? " < > |
	variables.DIR_BLACKLIST_PAT = createObject("java", "java.util.regex.Pattern").compile("([*?<>|])");

	public SafeFile function init(required org.owasp.esapi.ESAPI ESAPI, string pathname, parent, string child, uri) {
		variables.ESAPI = arguments.ESAPI;

		super.init(argumentCollection=arguments);
		doDirCheck(this.getParent());
		doFileCheck(this.getName());

		return this;
	}

	private void function doDirCheck(required string path) {
		var m1 = variables.DIR_BLACKLIST_PAT.matcher(arguments.path);
		if(m1.find()) {
			throws(new org.owasp.esapi.errors.ValidationException(variables.ESAPI, "Invalid directory", "Directory path (" & arguments.path & ") contains illegal character: " & m1.group()));
		}

		var m2 = variables.PERCENTS_PAT.matcher(arguments.path);
		if(m2.find()) {
			throws(new org.owasp.esapi.errors.ValidationException(variables.ESAPI, "Invalid directory", "Directory path (" & arguments.path & ") contains encoded characters: " & m2.group()));
		}

		var ch = containsUnprintableCharacters(arguments.path);
		if(ch != -1) {
			throws(new org.owasp.esapi.errors.ValidationException(variables.ESAPI, "Invalid directory", "Directory path (" & arguments.path & ") contains unprintable character: " & ch));
		}
	}

	private void function doFileCheck(required string path) {
		var m1 = variables.FILE_BLACKLIST_PAT.matcher(arguments.path);
		if(m1.find()) {
			throws(new org.owasp.esapi.errors.ValidationException(variables.ESAPI, "Invalid directory", "Directory path (" & arguments.path & ") contains illegal character: " & m1.group()));
		}

		var m2 = variables.PERCENTS_PAT.matcher(arguments.path);
		if(m2.find()) {
			throws(new org.owasp.esapi.errors.ValidationException(variables.ESAPI, "Invalid file", "File path (" & arguments.path & ") contains encoded characters: " & m2.group()));
		}

		var ch = containsUnprintableCharacters(arguments.path);
		if(ch != -1) {
			throws(new org.owasp.esapi.errors.ValidationException(variables.ESAPI, "Invalid file", "File path (" & arguments.path & ") contains unprintable character: " & ch));
		}
	}

	private numeric function containsUnprintableCharacters(required string s) {
		for(var i = 1; i <= len(arguments.s); i++) {
			var ch = asc(mid(arguments.s, i, 1));
			if(ch < 32 || ch > 126) {
				return ch;
			}
		}
		return -1;
	}

}