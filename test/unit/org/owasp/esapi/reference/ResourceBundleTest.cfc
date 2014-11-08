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

	<cfscript>
		variables.locale = createObject("java", "java.util.Locale");
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

	<cffunction access="public" returntype="void" name="testGetLocale" output="false">

		<cfscript>
			// default
			assertEquals("", request.ESAPI.resourceBundle().getLocaleData().toString());

			// manual override
			assertEquals("fr", request.ESAPI.resourceBundle(variables.locale.FRENCH).getLocaleData().toString());

			// from user
			request.ESAPI.authenticator().getCurrentUser().setLocaleData(variables.locale.JAPAN);
			assertEquals("ja", request.ESAPI.resourceBundle().getLocaleData().toString());
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testGetString" output="false">

		<cfscript>
			assertEquals("Test Basic Message", request.ESAPI.resourceBundle().getString("Unit_Test_message_basic"));

			// test inheritance with another English locale
			request.ESAPI.authenticator().getCurrentUser().setLocaleData(variables.locale.UK);
			assertEquals("Test Basic Message", request.ESAPI.resourceBundle().getString("Unit_Test_message_basic"));

			// test overrides with non-English locale
			request.ESAPI.authenticator().getCurrentUser().setLocaleData(variables.locale.FRANCE);
			assertEquals("Test de message de base", request.ESAPI.resourceBundle().getString("Unit_Test_message_basic"));

			// test manual override of locale
			assertEquals("Mensaje de prueba básico", request.ESAPI.resourceBundle(variables.locale.init("es", "ES")).getString("Unit_Test_message_basic"));

			// test unicode locale
			assertEquals("テストの基本的なメッセージ", request.ESAPI.resourceBundle(variables.locale.JAPANESE).getString("Unit_Test_message_basic"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testMessageFormat" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var params = ["0", "1", "2"];

			assertEquals("0Test 1 Message 2 Format0", request.ESAPI.resourceBundle().messageFormat("Unit_Test_message_format", params));

			// test inheritance with another English locale
			request.ESAPI.authenticator().getCurrentUser().setLocaleData(variables.locale.UK);
			assertEquals("0Test 1 Message 2 Format0", request.ESAPI.resourceBundle().messageFormat("Unit_Test_message_format", params));

			// test overrides with non-English locale
			request.ESAPI.authenticator().getCurrentUser().setLocaleData(variables.locale.FRANCE);
			assertEquals("0 1 test message 2 0 Format", request.ESAPI.resourceBundle().messageFormat("Unit_Test_message_format", params));

			// test manual override of locale
			assertEquals("0 1 Prueba de mensaje 2 Formato 0", request.ESAPI.resourceBundle(variables.locale.init("es", "ES")).messageFormat("Unit_Test_message_format", params));

			// test unicode locale
			assertEquals("0テスト1メッセージ2形式0", request.ESAPI.resourceBundle(variables.locale.JAPANESE).messageFormat("Unit_Test_message_format", params));
		</cfscript>

	</cffunction>

</cfcomponent>
