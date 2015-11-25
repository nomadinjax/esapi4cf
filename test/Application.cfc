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
component {

	this.name = "ESAPI4CF-UnitTests";
	this.sessionManagement = false;
	this.clientManagement = false;

	this.mappings["/mxunit"] = expandPath("/testbox/system/compat");

	public boolean function onRequestStart(required string targetPage) {
		setting requesttimeout = 0;	// disables timeout
		return true;
	}

}