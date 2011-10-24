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
component ReadThread extends="cfesapi.org.owasp.esapi.lang.Thread" {
	this.exception = "";
	instance.stream = "";
	instance.buffer = "";

	public DefaultExecutor$ReadThread function init(required stream, 
	                                                required buffer) {
		instance.stream = arguments.stream;
		instance.buffer = arguments.buffer;
		return this;
	}
	
	//@Override
	
	public void function run() {
		try {
			readStream(instance.stream, instance.buffer);
		}
		catch(IOException e) {
			this.exception = e;
		}
	}
	
}