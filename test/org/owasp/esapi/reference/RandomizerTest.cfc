<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Damon Miller
 * @created 2011
 --->
<cfcomponent extends="cfesapi.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		instance.ESAPI = createObject( "component", "cfesapi.org.owasp.esapi.ESAPI" ).init();
	</cfscript>

	<cffunction access="public" returntype="void" name="testGetRandomString" output="false"
	            hint="Test of getRandomString method, of class org.owasp.esapi.Randomizer.">

		<cfscript>
			var local = {};

			System.out.println( "getRandomString" );
			local.length = 20;
			local.randomizer = instance.ESAPI.randomizer();
			for(local.i = 0; local.i < 100; local.i++) {
				local.result = local.randomizer.getRandomString( local.length, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS );
				for(local.j = 0; local.j < local.result.length(); local.j++) {
					if(!instance.ESAPI.encoder().isContained( getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, local.result.charAt( local.j ) )) {
						fail();
					}
				}
				assertEquals( local.length, local.result.length() );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetRandomInteger" output="false"
	            hint="Test of getRandomInteger method, of class org.owasp.esapi.Randomizer.">

		<cfscript>
			var local = {};

			System.out.println( "getRandomInteger" );
			local.min = -20;
			local.max = 100;
			local.randomizer = instance.ESAPI.randomizer();
			local.minResult = (local.max - local.min) / 2;
			local.maxResult = (local.max - local.min) / 2;
			for(local.i = 0; local.i < 100; local.i++) {
				local.result = local.randomizer.getRandomInteger( local.min, local.max );
				if(local.result < local.minResult)
					local.minResult = local.result;
				if(local.result > local.maxResult)
					local.maxResult = local.result;
			}
			assertEquals( true, (local.minResult >= local.min && local.maxResult < local.max) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetRandomReal" output="false"
	            hint="Test of getRandomReal method, of class org.owasp.esapi.Randomizer.">

		<cfscript>
			var local = {};

			System.out.println( "getRandomReal" );
			local.min = getJava( "java.lang.Float" ).init( "-20.5234F" ).floatValue();
			local.max = getJava( "java.lang.Float" ).init( "100.12124F" ).floatValue();
			local.randomizer = instance.ESAPI.randomizer();
			local.minResult = (local.max - local.min) / 2;
			local.maxResult = (local.max - local.min) / 2;
			for(local.i = 0; local.i < 100; local.i++) {
				local.result = local.randomizer.getRandomReal( local.min, local.max );
				if(local.result < local.minResult)
					local.minResult = local.result;
				if(local.result > local.maxResult)
					local.maxResult = local.result;
			}
			assertEquals( true, (local.minResult >= local.min && local.maxResult < local.max) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetRandomGUID" output="false"
	            hint="Test of getRandomGUID method, of class org.owasp.esapi.Randomizer.">

		<cfscript>
			var local = {};

			System.out.println( "getRandomGUID" );
			local.randomizer = instance.ESAPI.randomizer();
			local.list = getJava( "java.util.ArrayList" ).init();
			for(local.i = 0; local.i < 100; local.i++) {
				local.guid = local.randomizer.getRandomGUID();
				if(local.list.contains( local.guid ))
					fail();
				local.list.add( local.guid );
			}
		</cfscript>

	</cffunction>

</cfcomponent>