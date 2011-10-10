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
component  {

	// CFESAPI only requires that sessionManagement be on
	this.name = "CFESAPI-FBADemoCFApplication";
	this.sessionManagement = true;

	// CFESAPI does not use CFID/CFTOKEN
	this.clientManagement = false;
	this.setClientCookies = false;

	// CFESAPI filters
	instance.SecurityWrapper = "";
	instance.ClickjackFilter = "";

	public void function onRequest(required String targetPage) {
		if(setupESAPI()) {
			savecontent variable="generatedContent"
			{
				include arguments.targetPage;
			}
			writeOutput(trim(generatedContent));
		}
		tearDownESAPI();
	}
	
	private boolean function setupESAPI() {
		// this allows us to reinit ESAPI in case we make changes - for dev purposes
		if(structKeyExists(url, "reinit") && url.reinit == "ESAPI") {
			application["ESAPI"] = "";
		}
	
		// initialize ESAPI and load encoder UDFs
		include "/cfesapi/helpers/ESAPI.cfm";
		
		// SecurityWrapper filter - required - secures request/response objects
		instance.SecurityWrapper = new cfesapi.org.owasp.esapi.filters.SecurityWrapper(ESAPI(), 
	                                                                                {allowableResourcesRoot="/cfesapi/demo/fba/", resourceDirectory="/cfesapi/demo/fba/config/"});
		local.isSecureRequest = instance.SecurityWrapper.doFilter(getPageContext().getRequest(), 
	                                                           getPageContext().getResponse());
	
		// ClickjackFilter - optional - prevent your site from being framed
		// mode options: DENY | SAMEORIGIN
		instance.ClickjackFilter = new cfesapi.org.owasp.esapi.filters.ClickjackFilter(ESAPI(), {mode="DENY"});
		instance.ClickjackFilter.doFilter(ESAPI().currentRequest(), ESAPI().currentResponse());
	
		return local.isSecureRequest;
	}
	
	private void function tearDownESAPI() {
		// destroy filters in reverse order
		instance.ClickjackFilter.destroy();
		instance.SecurityWrapper.destroy();
	}
	
}