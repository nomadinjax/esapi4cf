<cfcomponent extends="cfesapi.test.TestCase" output="false" hint="A simple class that calls the Encoder to test thread safety">

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
				local.nonce = instance.ESAPI.randomizer().getRandomString( 20, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_SPECIALS );
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
			local.encoder = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultEncoder").init(instance.ESAPI);
			return local.encoder.encodeForJavaScript(arguments.str);
		</cfscript>
	</cffunction>


</cfcomponent>
