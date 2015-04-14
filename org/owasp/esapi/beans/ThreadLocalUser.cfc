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
 * The currentUser ThreadLocal variable is used to make the currentUser available to any call in any part of an application. Otherwise, each thread would have to pass the User object through the calltree to any methods that need it. Because we want exceptions and log calls to contain user data, that could be almost anywhere. Therefore, the ThreadLocal approach simplifies things greatly. As a possible extension, one could create a delegation framework by adding another ThreadLocal to hold the delegating user identity.
 */
component extends="org.owasp.esapi.util.ThreadLocal" {

	variables.ESAPI = "";

	public ThreadLocalUser function init(required org.owasp.esapi.ESAPI ESAPI) {
		variables.ESAPI = arguments.ESAPI;

		return this;
	}

	public function initialValue() {
		return variables.ESAPI.authenticator().getAnonymousUserInstance();
	}

	public User function getUser() {
		return super.get();
	}

	public void function setUser(required org.owasp.esapi.User newUser) {
		super.set(arguments.newUser);
	}

}