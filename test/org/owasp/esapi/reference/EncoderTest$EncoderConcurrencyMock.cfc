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
/**
 *  A simple class that calls the Encoder to test thread safety
 */
component EncoderTest$EncoderConcurrencyMock extends="cfesapi.test.org.owasp.esapi.lang.TestCase" {

	instance.num = 0;

	public EncoderConcurrencyMock function init(required numeric num) {
		instance.num = arguments.num;
		return this;
	}
	
	public void function run() {
		while(true) {
			local.nonce = instance.ESAPI.randomizer().getRandomString(20, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_SPECIALS);
			local.result = javaScriptEncode(local.nonce);
			// randomize the threads
			try {
				sleep(instance.ESAPI.randomizer().getRandomInteger(100, 500));
			}
			catch(java.lang.InterruptedException e) {
				// just continue
			}
			assertTrue(local.result.equals(javaScriptEncode(local.nonce)));
		}
	}
	
	public String function javaScriptEncode(required String str) {
		local.encoder = new cfesapi.org.owasp.esapi.reference.DefaultEncoder(instance.ESAPI);
		return local.encoder.encodeForJavaScript(arguments.str);
	}
	
}