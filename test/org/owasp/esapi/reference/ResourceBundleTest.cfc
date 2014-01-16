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
<cfcomponent extends="esapi4cf.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		variables.locale = newJava("java.util.Locale");
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">

		<cfscript>
			super.setUp();
			request.ESAPI.authenticator().getCurrentUser().setLocaleData(variables.locale.getDefault());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="tearDown" output="false">

		<cfscript>
			request.ESAPI.authenticator().getCurrentUser().setLocaleData(variables.locale.getDefault());
			super.tearDown();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetMessage" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = request.ESAPI.resourceBundle();
			var en_GB = variables.locale.init(variables.locale.ENGLISH.toString(), variables.locale.UK.toString());
			var fr_FR = variables.locale.init(variables.locale.FRENCH.toString(), variables.locale.FRANCE.toString());

			assertEquals("Test Basic Message", instance.getMessage("Unit.Test.message.basic"));

			// test inheritance with another English locale
			request.ESAPI.authenticator().getCurrentUser().setLocaleData(en_GB);
			assertEquals("Test Basic Message", instance.getMessage("Unit.Test.message.basic"));

			// test overrides with non-English locale
			request.ESAPI.authenticator().getCurrentUser().setLocaleData(fr_FR);
			assertEquals("Test de message de base", instance.getMessage("Unit.Test.message.basic"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testMessageFormat" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = request.ESAPI.resourceBundle();
			var params = ["zero", "one", "two"];
			var en_GB = variables.locale.init(variables.locale.ENGLISH.toString(), variables.locale.UK.toString());
			var fr_FR = variables.locale.init(variables.locale.FRENCH.toString(), variables.locale.FRANCE.toString());

			assertEquals("zeroTest one Message two Formatzero", instance.messageFormat("Unit.Test.message.format", params));

			// test inheritance with another English locale
			request.ESAPI.authenticator().getCurrentUser().setLocaleData(en_GB);
			assertEquals("zeroTest one Message two Formatzero", instance.messageFormat("Unit.Test.message.format", params));

			// test overrides with non-English locale
			request.ESAPI.authenticator().getCurrentUser().setLocaleData(fr_FR);
			assertEquals("zero one test message two zero Format", instance.messageFormat("Unit.Test.message.format", params));
		</cfscript>

	</cffunction>

</cfcomponent>
