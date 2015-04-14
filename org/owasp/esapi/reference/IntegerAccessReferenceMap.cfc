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
 * Reference implementation of the AccessReferenceMap interface. This
 * implementation generates integers for indirect references.
 */
component extends="AbstractAccessReferenceMap" {

	variables.count = 1;

	/**
	 * Note: this is final as redefinition by subclasses
	 * can lead to use before initialization issues as
	 * {@link #RandomAccessReferenceMap(Set)} and
	 * {@link #RandomAccessReferenceMap(Set,int)} both call it
	 * internally.
	 */
	private string function getUniqueReference() {
		return "" & count++;  // returns a string version of the counter
	}

}
