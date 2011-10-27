<!---
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
	--->
<cfcomponent extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false" hint="A simple class that calls the Encoder to test thread safety">

	<cfscript>
    	instance.num = 0;
    </cfscript>
 
	<cffunction access="public" returntype="EncoderConcurrencyMock" name="init" output="false">
		<cfargument type="numeric" name="num" required="true">
		<cfscript>
   			instance.num = arguments.num;

   			return this;
   		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="run" output="false">
		<cfscript>
			while( true ) {
				local.nonce = instance.ESAPI.randomizer().getRandomString( 20, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_SPECIALS );
				local.result = javaScriptEncode( local.nonce );
				// randomize the threads
				try {
					sleep( instance.ESAPI.randomizer().getRandomInteger( 100, 500 ) );
				} catch (java.lang.InterruptedException e) {
					// just continue
				}
				assertTrue( local.result.equals ( javaScriptEncode( local.nonce ) ) );
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="javaScriptEncode" output="false">
		<cfargument type="String" name="str" required="true">
		<cfscript>
			local.encoder = new cfesapi.org.owasp.esapi.reference.DefaultEncoder(instance.ESAPI);
			return local.encoder.encodeForJavaScript(arguments.str);
		</cfscript> 
	</cffunction>


</cfcomponent>
