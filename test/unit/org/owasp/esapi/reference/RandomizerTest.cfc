<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfcomponent extends="esapi4cf.test.unit.org.owasp.esapi.util.TestCase" output="false">

	<cffunction access="public" returntype="void" name="testGetRandomString" output="false"
	            hint="Test of getRandomString method, of class org.owasp.esapi.Randomizer.">

		<cfscript>
			// CF8 requires 'var' at the top
			var length = "";
			var instance = "";
			var i = "";
			var result = "";
			var j = "";

			System.out.println("getRandomString");
			length = 20;
			instance = request.ESAPI.randomizer();
			for(i = 0; i < 100; i++) {
				result = instance.getRandomString(length, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
				for(j = 0; j < result.length(); j++) {
					if(!containsCharacter(result.charAt(j), createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS)) {
						fail("");
					}
				}
				assertEquals(length, result.length());
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetRandomInteger" output="false"
	            hint="Test of getRandomInteger method, of class org.owasp.esapi.Randomizer.">

		<cfscript>
			// CF8 requires 'var' at the top
			var min = "";
			var max = "";
			var instance = "";
			var minResult = "";
			var maxResult = "";
			var i = "";
			var result = "";

			System.out.println("getRandomInteger");
			min = -20;
			max = 100;
			instance = request.ESAPI.randomizer();
			minResult = (max - min) / 2;
			maxResult = (max - min) / 2;
			for(i = 0; i < 100; i++) {
				result = instance.getRandomInteger(min, max);
				if(result < minResult)
					minResult = result;
				if(result > maxResult)
					maxResult = result;
			}
			assertEquals(true, (minResult >= min && maxResult < max));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetRandomReal" output="false"
	            hint="Test of getRandomReal method, of class org.owasp.esapi.Randomizer.">

		<cfscript>
			// CF8 requires 'var' at the top
			var min = "";
			var max = "";
			var instance = "";
			var minResult = "";
			var maxResult = "";
			var i = "";
			var result = "";

			System.out.println("getRandomReal");
			min = createObject("java", "java.lang.Float").init("-20.5234F").floatValue();
			max = createObject("java", "java.lang.Float").init("100.12124F").floatValue();
			instance = request.ESAPI.randomizer();
			minResult = (max - min) / 2;
			maxResult = (max - min) / 2;
			for(i = 0; i < 100; i++) {
				result = instance.getRandomReal(min, max);
				if(result < minResult)
					minResult = result;
				if(result > maxResult)
					maxResult = result;
			}
			assertEquals(true, (minResult >= min && maxResult < max));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetRandomGUID" output="false"
	            hint="Test of getRandomGUID method, of class org.owasp.esapi.Randomizer.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";
			var list = "";
			var i = "";
			var guid = "";

			System.out.println("getRandomGUID");
			instance = request.ESAPI.randomizer();
			list = createObject("java", "java.util.ArrayList").init();
			for(i = 0; i < 100; i++) {
				guid = instance.getRandomGUID();
				if(list.contains(guid))
					fail();
				list.add(guid);
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="containsCharacter" output="false">
		<cfargument required="true" name="c">
		<cfargument required="true" name="arr">
		<cfscript>
			var i = 1;
			for (i=1; i<=arrayLen(arguments.arr); i++) {
				if (arguments.c == arguments.arr[i]) return true;
			}
			return false;
		</cfscript>
	</cffunction>

</cfcomponent>