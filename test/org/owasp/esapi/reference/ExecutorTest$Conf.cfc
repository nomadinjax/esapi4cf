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
component Conf extends="cfesapi.test.org.owasp.esapi.SecurityConfigurationWrapper" {
	instance.allowedExes = "";
	instance.workingDir = "";

	public ExecutorTest$Conf function init(required cfesapi.org.owasp.esapi.SecurityConfiguration orig, 
	                          required Array allowedExes,required workingDir) {
		super.init(arguments.orig);
		instance.allowedExes = arguments.allowedExes;
		instance.workingDir = arguments.workingDir;
	
		return this;
	}
	
	// @Override
	
	public Array function getAllowedExecutables() {
		return instance.allowedExes;
	}
	
	// @Override
	
	public function getWorkingDirectory() {
		return instance.workingDir;
	}
	
}