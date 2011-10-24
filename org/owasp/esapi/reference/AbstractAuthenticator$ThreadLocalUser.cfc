/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Damon Miller
 * @created 2011
 */
component ThreadLocalUser extends="cfesapi.org.owasp.esapi.lang.ThreadLocal" {

	instance.ESAPI = "";

	public AbstractAuthenticator$ThreadLocalUser function init(required cfesapi.org.owasp.esapi.ESAPI ESAPI) {
		instance.ESAPI = arguments.ESAPI;
		return this;
	}
	
	public cfesapi.org.owasp.esapi.User function initialValue() {
		return new cfesapi.org.owasp.esapi.User$ANONYMOUS(instance.ESAPI);
	}
	
	public cfesapi.org.owasp.esapi.User function getUser() {
		return super.get();
	}
	
	public void function setUser(required cfesapi.org.owasp.esapi.User newUser) {
		super.set(arguments.newUser);
	}
	
}