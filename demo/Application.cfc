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
component extends="esapi4cf.demo.framework.one" {

	// you should always name your application
	// ESAPI4CF needs a name for logging
	this.name = "ESAPI4CF-Demo";
	this.clientManagement = false;
	this.setClientCookies = false;

	// required in order to persist a user
	this.sessionManagement = true;
	this.sessionTimeout = createTimeSpan(0, 0, 20, 0);

	// ESAPI4CF is under a sub-folder due to the structure of the project - add a mapping to find esapi4cf
	this.mappings["/org"] = expandPath("/esapi4cf/org");

	// FW/1 settings
	variables.framework = {
		reloadApplicationOnEveryRequest = true
	};

	public void function setupApplication() {
		// this is your main reference point to ESAPI4CF that you will use throughout your application
		application.ESAPI = new org.owasp.esapi.ESAPI({
			"Encryptor": {
				"MasterKey": "Yf8epZ2LA01LJTwFiZfG6w==",
				"MasterSalt": "pEcX7fpmJzrekoodwDSYmdnjZDXrVPiEhVJMUqyWo9EliH0sphs04WjSeo3Q9MFUSM3oayzqTTVuM1W36Jn4/zr1MzpIhlRRZpU6PJamFotKgKgYFbEgkjAqLFb6PWCyjCyof58HJHPKa62jaMt3EQu5gP6yPr96Scnz9BVrJQOc7xBa5aO6CrBXg7c/Mc+i1Hw8/B7oKyMVOqZfYUNlFQ=="
			}
		});
	}

}