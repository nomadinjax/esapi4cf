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
component extends="cfesapi.demo.fba.filters.ApplicationFilter" {

	// CFESAPI filters
	instance.ESAPIFilter = "";

	public void function onRequest(required String targetPage) {
		if(setupESAPI()) {
			if(structKeyExists(url, "logout")) {
				ESAPI().authenticator().logout();
				location("../index.cfm", false);
				return;
			}
		
			savecontent variable="generatedContent"
			{
				include arguments.targetPage;
			}
			writeOutput(trim(generatedContent));
		}
		tearDownESAPI();
	}
	
	private boolean function setupESAPI() {
		super.setupESAPI();
	
		// ESAPI authentication filter
		instance.ESAPIFilter = new cfesapi.org.owasp.esapi.filters.ESAPIFilter(ESAPI(), 
	                                                                        {loginPath="/cfesapi/demo/fba/includes/login.cfm", unauthorizedPath="/cfesapi/demo/fba/includes/unauthorized.cfm"});
		return instance.ESAPIFilter.doFilter(ESAPI().currentRequest(), ESAPI().currentResponse());
	}
	
	private void function tearDownESAPI() {
		// destroy filters in reverse order
		instance.ESAPIFilter.destroy();
		super.tearDownESAPI();
	}
	
}