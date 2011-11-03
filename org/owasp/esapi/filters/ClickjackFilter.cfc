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
component implements="cfesapi.org.owasp.esapi.lang.Filter" {

	instance.mode = "DENY";
	instance.response = "";

	/**
	 * Initialize "mode" parameter from web.xml. Valid values are "DENY" and "SAMEORIGIN". 
	 * If you leave this parameter out, the default is to use the DENY mode.
	 * 
	 * @param filterConfig A filter configuration object used by a servlet container
	 *                     to pass information to a filter during initialization. 
	 */
	
	public ClickjackFilter function init(required cfesapi.org.owasp.esapi.ESAPI ESAPI, required Struct filterConfig) {
		instance.ESAPI = arguments.ESAPI;
	
		if(structKeyExists(arguments.filterConfig, "mode")) {
			local.configMode = arguments.filterConfig.get("mode");
		}
		if(!isNull(local.configMode) && (local.configMode.equals("DENY") || local.configMode.equals("SAMEORIGIN"))) {
			instance.mode = local.configMode;
		}
	
		return this;
	}
	
	/**
	 * Add X-FRAME-OPTIONS response header to tell the browser not to display this content in a frame. For details, please 
	 * refer to {@link http://blogs.msdn.com/sdl/archive/2009/02/05/clickjacking-defense-in-ie8.aspx}.
	 * 
	 * Minimum supported browsers:
	 * - Internet Explorer 8.0
	 * - Firefox (Gecko) 3.6.9 (1.9.2.9)
	 * - Opera 10.50
	 * - Safari 4.0
	 * - Chrome 4.1.249.1042
	 * 
	 * @param request The request object.
	 * @param response The response object.
	 */
	
	public boolean function doFilter(required request, required response) {
		instance.response = arguments.response;
		return true;
	}
	
	public void function destroy() {
		instance.response.addHeader("X-FRAME-OPTIONS", instance.mode);
	}
	
}