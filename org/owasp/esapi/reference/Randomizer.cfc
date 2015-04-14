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
 * Reference implementation of the Randomizer interface. This implementation builds on the JCE provider to provide a
 * cryptographically strong source of entropy. The specific algorithm used is configurable in ESAPI.properties.
 */
component implements="org.owasp.esapi.Randomizer" extends="org.owasp.esapi.util.Object" {

	variables.ESAPI = "";

	/** The sr. */
	variables.secureRandom = createObject("java", "org.owasp.esapi.ESAPI").randomizer();

	/** The logger. */
	variables.logger = "";

	public org.owasp.esapi.Randomizer function init(required org.owasp.esapi.ESAPI ESAPI) {
		variables.ESAPI = arguments.ESAPI;
		variables.logger = variables.ESAPI.getLogger("Randomizer");
		return this;
	}

	public string function getRandomString(required numeric length, required array characterSet) {
		return variables.secureRandom.getRandomString(javaCast("int", arguments.length), arguments.characterSet);
	}

	public boolean function getRandomBoolean() {
		return variables.secureRandom.getRandomBoolean();
	}

	public numeric function getRandomInteger(required numeric min, required numeric max) {
		return variables.secureRandom.getRandomInteger(javaCast("int", arguments.min), javaCast("int", arguments.max));
	}

	public numeric function getRandomLong() {
		return variables.secureRandom.getRandomLong();
	}

	public numeric function getRandomReal(required numeric min, required numeric max) {
		return variables.secureRandom.getRandomReal(javaCast("float", arguments.min), javaCast("float", arguments.max));
	}

	public string function getRandomFilename(required string extension) {
		var fn = variables.secureRandom.getRandomFilename(javaCast("string", arguments.extension));
		variables.logger.debug(variables.Logger.SECURITY_SUCCESS, "Generated new random filename: " & fn );
		return fn;
	}

	public string function getRandomGUID() {
		return variables.secureRandom.getRandomGUID();
	}

	public binary function getRandomBytes(required numeric n) {
		return variables.secureRandom.getRandomBytes(javaCast("int", arguments.n));
	}

	public string function getRandomUUID() {
		return createUUID();
	}

}