<cfcomponent extends="cfesapi.test.org.owasp.esapi.TestCase" output="false">

	<!--- TODO: need tests for:
		getRandomBoolean()
		getRandomLong()
		getRandomFilename()
		getRandomBytes()
		--->
	<cfscript>
		System = createObject("java", "java.lang.System");

		instance.ESAPI = "";
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			structClear(session);
			structClear(request);

			instance.ESAPI = createObject("component", "cfesapi.org.owasp.esapi.ESAPI");
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="tearDown" output="false">
		<cfscript>
			instance.ESAPI = "";

			structClear(session);
			structClear(request);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetRandomString" output="false" hint="Test of getRandomString method, of class org.owasp.esapi.Randomizer.">
		<cfscript>
	        System.out.println("getRandomString");
			DefaultEncoder = createObject("java", "org.owasp.esapi.Encoder");

	        local.length = 20;
	        local.instance = instance.ESAPI.randomizer();
	        for ( local.i = 0; local.i < 100; local.i++ ) {
	            local.result = local.instance.getRandomString(local.length, DefaultEncoder.CHAR_ALPHANUMERICS );
	            for ( local.j=0;local.j<local.result.length();local.j++ ) {
	            	if ( !createObject("java", "org.owasp.esapi.codecs.Codec").containsCharacter( local.result.charAt(local.j), DefaultEncoder.CHAR_ALPHANUMERICS) ) {
	            		fail();
	            	}
	            }
	            assertEquals(local.length, local.result.length());
	        }
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetRandomInteger" output="false" hint="Test of getRandomInteger method, of class org.owasp.esapi.Randomizer.">
		<cfscript>
	        System.out.println("getRandomInteger");
	        local.min = -20;
	        local.max = 100;
	        local.instance = instance.ESAPI.randomizer();
	        local.minResult = ( local.max - local.min ) / 2;
	        local.maxResult = ( local.max - local.min ) / 2;
	        for ( local.i = 0; local.i < 100; local.i++ ) {
	            local.result = local.instance.getRandomInteger(local.min, local.max);
	            if ( local.result < local.minResult ) local.minResult = local.result;
	            if ( local.result > local.maxResult ) local.maxResult = local.result;
	        }
	        assertEquals(true, (local.minResult >= local.min && local.maxResult < local.max) );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetRandomReal" output="false" hint="Test of getRandomReal method, of class org.owasp.esapi.Randomizer.">
		<cfscript>
	        System.out.println("getRandomReal");
	        Float = createObject("java", "java.lang.Float");
	        local.min = Float.init("-20.5234F").floatValue();
	        local.max = Float.init("100.12124F").floatValue();
	        local.instance = instance.ESAPI.randomizer();
	        local.minResult = ( local.max - local.min ) / 2;
	        local.maxResult = ( local.max - local.min ) / 2;
	        for ( local.i = 0; local.i < 100; local.i++ ) {
	            local.result = local.instance.getRandomReal(local.min, local.max);
	            if ( local.result < local.minResult ) local.minResult = local.result;
	            if ( local.result > local.maxResult ) local.maxResult = local.result;
	        }
	        assertEquals(true, (local.minResult >= local.min && local.maxResult < local.max));
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testGetRandomGUID" output="false" hint="Test of getRandomGUID method, of class org.owasp.esapi.Randomizer.">
		<cfscript>
	        System.out.println("getRandomGUID");
	        local.instance = instance.ESAPI.randomizer();
	        local.list = [];
	        for ( local.i = 0; local.i < 100; local.i++ ) {
	            local.guid = local.instance.getRandomGUID();
	            if ( local.list.contains( local.guid ) ) fail();
	            local.list.add( local.guid );
	        }
    	</cfscript>
	</cffunction>


</cfcomponent>
