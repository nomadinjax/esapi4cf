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
component extends="Object" {

	public function get() {
		var threadId = getThreadId();
		if(structKeyExists(request, threadId)) {
			return request[threadId];
		}
		return setInitialValue();
	}

	public function initialValue() {
		return;
	}

	public void function set(required value) {
		lock scope="request" type="exclusive" timeout="5" {
			request[getThreadId()] = arguments.value;
		}
	}

	public void function remove() {
		lock scope="request" type="exclusive" timeout="5" {
			structDelete(request, getThreadId());
		}
	}

	/* PRIVATE METHODS */

	public string function getThreadId() {
		return createObject("java","java.lang.Thread").currentThread().getName() & "_" & getMetaData(this).name;
	}

	private function setInitialValue() {
		var threadId = getThreadId();
		var value = initialValue();

		if (structKeyExists(local, "value")) {
			lock scope="request" type="exclusive" timeout="5" {
				request[threadId] = value;
			}
			return value;
		}
	}

}