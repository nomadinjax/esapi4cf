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

	<cffunction access="public" returntype="void" name="testCanonicalize" output="false">

		<cfscript>
			// CF8 requires 'var' at the top
			var list = "";
			var instance = "";
			var js = "";
			var css = "";

			System.out.println("canonicalize");

			list = newJava("java.util.ArrayList").init();
			if (this.ESAPI4JVERSION == 2) {
				list.add("org.owasp.esapi.codecs.HTMLEntityCodec");
				list.add("org.owasp.esapi.codecs.PercentCodec");
			}
			else {
				list.add(newJava("org.owasp.esapi.codecs.HTMLEntityCodec").init());
				list.add(newJava("org.owasp.esapi.codecs.PercentCodec").init());
			}
			instance = createObject("component", "org.owasp.esapi.reference.DefaultEncoder").init(variables.ESAPI, list);

			/* NULL test not valid in CF
			// Test null paths
			assertEquals( null, instance.canonicalize( null ) );
			assertEquals( null, instance.canonicalize( null, true ) );
			assertEquals( null, instance.canonicalize( null, false ) );
			*/
			// test exception paths
			assertEquals("%", instance.canonicalize("%25", true));
			assertEquals("%", instance.canonicalize("%25", false));

			assertEquals("%", instance.canonicalize("%25"));
			assertEquals("%F", instance.canonicalize("%25F"));
			assertEquals("<", instance.canonicalize("%3c"));
			assertEquals("<", instance.canonicalize("%3C"));
			assertEquals("%X1", instance.canonicalize("%X1"));

			assertEquals("<", instance.canonicalize("&lt"));
			assertEquals("<", instance.canonicalize("&LT"));
			assertEquals("<", instance.canonicalize("&lt;"));
			assertEquals("<", instance.canonicalize("&LT;"));

			assertEquals("%", instance.canonicalize("&##37;"));
			assertEquals("%", instance.canonicalize("&##37"));
			assertEquals("%b", instance.canonicalize("&##37b"));

			assertEquals("<", instance.canonicalize("&##x3c"));
			assertEquals("<", instance.canonicalize("&##x3c;"));
			assertEquals("<", instance.canonicalize("&##x3C"));
			assertEquals("<", instance.canonicalize("&##X3c"));
			assertEquals("<", instance.canonicalize("&##X3C"));
			assertEquals("<", instance.canonicalize("&##X3C;"));

			// percent encoding
			assertEquals("<", instance.canonicalize("%3c"));
			assertEquals("<", instance.canonicalize("%3C"));

			// html entity encoding
			assertEquals("<", instance.canonicalize("&##60"));
			assertEquals("<", instance.canonicalize("&##060"));
			assertEquals("<", instance.canonicalize("&##0060"));
			assertEquals("<", instance.canonicalize("&##00060"));
			assertEquals("<", instance.canonicalize("&##000060"));
			assertEquals("<", instance.canonicalize("&##0000060"));
			assertEquals("<", instance.canonicalize("&##60;"));
			assertEquals("<", instance.canonicalize("&##060;"));
			assertEquals("<", instance.canonicalize("&##0060;"));
			assertEquals("<", instance.canonicalize("&##00060;"));
			assertEquals("<", instance.canonicalize("&##000060;"));
			assertEquals("<", instance.canonicalize("&##0000060;"));
			assertEquals("<", instance.canonicalize("&##x3c"));
			assertEquals("<", instance.canonicalize("&##x03c"));
			assertEquals("<", instance.canonicalize("&##x003c"));
			assertEquals("<", instance.canonicalize("&##x0003c"));
			assertEquals("<", instance.canonicalize("&##x00003c"));
			assertEquals("<", instance.canonicalize("&##x000003c"));
			assertEquals("<", instance.canonicalize("&##x3c;"));
			assertEquals("<", instance.canonicalize("&##x03c;"));
			assertEquals("<", instance.canonicalize("&##x003c;"));
			assertEquals("<", instance.canonicalize("&##x0003c;"));
			assertEquals("<", instance.canonicalize("&##x00003c;"));
			assertEquals("<", instance.canonicalize("&##x000003c;"));
			assertEquals("<", instance.canonicalize("&##X3c"));
			assertEquals("<", instance.canonicalize("&##X03c"));
			assertEquals("<", instance.canonicalize("&##X003c"));
			assertEquals("<", instance.canonicalize("&##X0003c"));
			assertEquals("<", instance.canonicalize("&##X00003c"));
			assertEquals("<", instance.canonicalize("&##X000003c"));
			assertEquals("<", instance.canonicalize("&##X3c;"));
			assertEquals("<", instance.canonicalize("&##X03c;"));
			assertEquals("<", instance.canonicalize("&##X003c;"));
			assertEquals("<", instance.canonicalize("&##X0003c;"));
			assertEquals("<", instance.canonicalize("&##X00003c;"));
			assertEquals("<", instance.canonicalize("&##X000003c;"));
			assertEquals("<", instance.canonicalize("&##x3C"));
			assertEquals("<", instance.canonicalize("&##x03C"));
			assertEquals("<", instance.canonicalize("&##x003C"));
			assertEquals("<", instance.canonicalize("&##x0003C"));
			assertEquals("<", instance.canonicalize("&##x00003C"));
			assertEquals("<", instance.canonicalize("&##x000003C"));
			assertEquals("<", instance.canonicalize("&##x3C;"));
			assertEquals("<", instance.canonicalize("&##x03C;"));
			assertEquals("<", instance.canonicalize("&##x003C;"));
			assertEquals("<", instance.canonicalize("&##x0003C;"));
			assertEquals("<", instance.canonicalize("&##x00003C;"));
			assertEquals("<", instance.canonicalize("&##x000003C;"));
			assertEquals("<", instance.canonicalize("&##X3C"));
			assertEquals("<", instance.canonicalize("&##X03C"));
			assertEquals("<", instance.canonicalize("&##X003C"));
			assertEquals("<", instance.canonicalize("&##X0003C"));
			assertEquals("<", instance.canonicalize("&##X00003C"));
			assertEquals("<", instance.canonicalize("&##X000003C"));
			assertEquals("<", instance.canonicalize("&##X3C;"));
			assertEquals("<", instance.canonicalize("&##X03C;"));
			assertEquals("<", instance.canonicalize("&##X003C;"));
			assertEquals("<", instance.canonicalize("&##X0003C;"));
			assertEquals("<", instance.canonicalize("&##X00003C;"));
			assertEquals("<", instance.canonicalize("&##X000003C;"));
			assertEquals("<", instance.canonicalize("&lt"));
			assertEquals("<", instance.canonicalize("&lT"));
			assertEquals("<", instance.canonicalize("&Lt"));
			assertEquals("<", instance.canonicalize("&LT"));
			assertEquals("<", instance.canonicalize("&lt;"));
			assertEquals("<", instance.canonicalize("&lT;"));
			assertEquals("<", instance.canonicalize("&Lt;"));
			assertEquals("<", instance.canonicalize("&LT;"));

			assertEquals('<script>alert("hello");</script>', instance.canonicalize("%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E"));
			assertEquals('<script>alert("hello");</script>', instance.canonicalize("%3Cscript&##x3E;alert%28%22hello&##34%29%3B%3C%2Fscript%3E", false));

			// javascript escape syntax
			js = newJava("java.util.ArrayList").init();
			if (this.ESAPI4JVERSION == 2) {
				js.add("org.owasp.esapi.codecs.JavaScriptCodec");
			}
			else {
				js.add(newJava("org.owasp.esapi.codecs.JavaScriptCodec").init());
			}
			instance = createObject("component", "org.owasp.esapi.reference.DefaultEncoder").init(variables.ESAPI, js);
			System.out.println("JavaScript Decoding");

			/* NULL test not valid in CF
			assertEquals( "\0", instance.canonicalize("\0"));
			*/
			assertEquals(chr(8), instance.canonicalize("\b"));
			assertEquals(chr(9), instance.canonicalize("\t"));
			assertEquals(chr(10), instance.canonicalize("\n"));
			assertEquals(chr(11), instance.canonicalize("\v"));
			assertEquals(chr(12), instance.canonicalize("\f"));
			assertEquals(chr(13), instance.canonicalize("\r"));
			assertEquals("'", instance.canonicalize("\'"));
			assertEquals('"', instance.canonicalize('\"'));
			assertEquals("\", instance.canonicalize("\\"));
			assertEquals("<", instance.canonicalize("\<"));

			assertEquals("<", instance.canonicalize("\u003c"));
			assertEquals("<", instance.canonicalize("\U003c"));
			assertEquals("<", instance.canonicalize("\u003C"));
			assertEquals("<", instance.canonicalize("\U003C"));
			assertEquals("<", instance.canonicalize("\x3c"));
			assertEquals("<", instance.canonicalize("\X3c"));
			assertEquals("<", instance.canonicalize("\x3C"));
			assertEquals("<", instance.canonicalize("\X3C"));

			// css escape syntax
			// be careful because some codecs see \0 as null byte
			css = newJava("java.util.ArrayList").init();
			if (this.ESAPI4JVERSION == 2) {
				css.add("org.owasp.esapi.codecs.CSSCodec");
			}
			else {
				css.add(newJava("org.owasp.esapi.codecs.CSSCodec").init());
			}
			instance = createObject("component", "org.owasp.esapi.reference.DefaultEncoder").init(variables.ESAPI, css);
			System.out.println("CSS Decoding");

			assertEquals("<", instance.canonicalize("\3c"));// add strings to prevent null byte
			assertEquals("<", instance.canonicalize("\03c"));
			assertEquals("<", instance.canonicalize("\003c"));
			assertEquals("<", instance.canonicalize("\0003c"));
			assertEquals("<", instance.canonicalize("\00003c"));
			assertEquals("<", instance.canonicalize("\3C"));
			assertEquals("<", instance.canonicalize("\03C"));
			assertEquals("<", instance.canonicalize("\003C"));
			assertEquals("<", instance.canonicalize("\0003C"));
			assertEquals("<", instance.canonicalize("\00003C"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testDoubleEncodingCanonicalization" output="false"
	            hint="Test of canonicalize method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			// CF8 requires 'var' at the top
			var instance = "";

			System.out.println("doubleEncodingCanonicalization");
			instance = variables.ESAPI.encoder();

			// note these examples use the strict=false flag on canonicalize to allow
			// full decoding without throwing an IntrusionException. Generally, you
			// should use strict mode as allowing double-encoding is an abomination.
			// double encoding examples
			assertEquals("<", instance.canonicalize("&##x26;lt&##59", false));//double entity
			assertEquals("\", instance.canonicalize("%255c", false));//double percent
			assertEquals("%", instance.canonicalize("%2525", false));//double percent
			// double encoding with multiple schemes example
			assertEquals("<", instance.canonicalize("%26lt%3b", false));//first entity, then percent
			assertEquals("&", instance.canonicalize("&##x25;26", false));//first percent, then entity
			// nested encoding examples
			assertEquals("<", instance.canonicalize("%253c", false));//nested encode % with percent
			assertEquals("<", instance.canonicalize("%%33%63", false));//nested encode both nibbles with percent
			assertEquals("<", instance.canonicalize("%%33c", false));// nested encode first nibble with percent
			assertEquals("<", instance.canonicalize("%3%63", false));//nested encode second nibble with percent
			assertEquals("<", instance.canonicalize("&&##108;t;", false));//nested encode l with entity
			assertEquals("<", instance.canonicalize("%2&##x35;3c", false));//triple percent, percent, 5 with entity
			// nested encoding with multiple schemes examples
			assertEquals("<", instance.canonicalize("&%6ct;", false));// nested encode l with percent
			assertEquals("<", instance.canonicalize("%&##x33;c", false));//nested encode 3 with entity
			// multiple encoding tests
			assertEquals("% & <script> <script>", instance.canonicalize("%25 %2526 %26##X3c;script&##x3e; &##37;3Cscript%25252525253e", false));
			assertEquals("< < < < < < <", instance.canonicalize("%26lt; %26lt; &##X25;3c &##x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", false));

			// test strict mode with both mixed and multiple encoding
			try {
				assertEquals("< < < < < < <", instance.canonicalize("%26lt; %26lt; &##X25;3c &##x25;3c %2526lt%253B %2526lt%253B %2526lt%253B"));
			}
			catch(org.owasp.esapi.errors.IntrusionException e) {
				// expected
			}

			try {
				assertEquals("<script", instance.canonicalize("%253Cscript"));
			}
			catch(org.owasp.esapi.errors.IntrusionException e) {
				// expected
			}
			try {
				assertEquals("<script", instance.canonicalize("&##37;3Cscript"));
			}
			catch(org.owasp.esapi.errors.IntrusionException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForHTML" output="false"
	            hint="Test of encodeForHTML method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			/* NULL tests not valid for CF
			assertEquals( null, instance.encodeForHTML( null ) );
			*/
			assertEquals("&lt;script&gt;", instance.encodeForHTML("<script>"));
			assertEquals("&amp;lt&##x3b;script&amp;gt&##x3b;", instance.encodeForHTML("&lt;script&gt;"));
			assertEquals("&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", instance.encodeForHTML("!@$%()=+{}[]"));
			assertEquals("&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", instance.encodeForHTML(instance.canonicalize("&##33;&##64;&##36;&##37;&##40;&##41;&##61;&##43;&##123;&##125;&##91;&##93;")));
			assertEquals(",.-_ ", instance.encodeForHTML(",.-_ "));
			assertEquals("dir&amp;", instance.encodeForHTML("dir&"));
			assertEquals("one&amp;two", instance.encodeForHTML("one&two"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForHTMLAttribute" output="false"
	            hint="Test of encodeForHTMLAttribute method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals("&lt;script&gt;", instance.encodeForHTMLAttribute("<script>"));
			assertEquals(",.-_", instance.encodeForHTMLAttribute(",.-_"));
			if (this.ESAPI4JVERSION == 2) {
				assertEquals("&##x20;&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", instance.encodeForHTMLAttribute(" !@$%()=+{}[]"));
			}
			else {
				assertEquals(" &##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", instance.encodeForHTMLAttribute(" !@$%()=+{}[]"));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForCSS" output="false">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals("\3C script\3E ", instance.encodeForCSS("<script>"));
			assertEquals("\21 \40 \24 \25 \28 \29 \3D \2B \7B \7D \5B \5D \22 ", instance.encodeForCSS('!@$%()=+{}[]"'));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForJavascript" output="false"
	            hint="Test of encodeForJavaScript method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals("\x3Cscript\x3E", instance.encodeForJavaScript("<script>"));
			if (this.ESAPI4JVERSION == 2) {
				assertEquals(",.\x2D_\x20", instance.encodeForJavaScript(",.-_ "));
			}
			else {
				assertEquals(",.-_ ", instance.encodeForJavaScript(",.-_ "));
			}
			assertEquals("\x21\x40\x24\x25\x28\x29\x3D\x2B\x7B\x7D\x5B\x5D", instance.encodeForJavaScript("!@$%()=+{}[]"));
			/* NULL test not valid in CF
			assertEquals( "\0", instance.encodeForJavaScript("\0"));
			*/
			// assertEquals( "\b", instance.encodeForJavaScript( chr( 8 ) ) );
			// assertEquals( "\t", instance.encodeForJavaScript( chr( 9 ) ) );
			// assertEquals( "\n", instance.encodeForJavaScript( chr( 10 ) ) );
			// assertEquals( "\v", instance.encodeForJavaScript( chr( inputBaseN( "0b", 16 ) ) ) );
			// assertEquals( "\f", instance.encodeForJavaScript( chr( 12 ) ) );
			// assertEquals( "\r", instance.encodeForJavaScript( chr( 13 ) ) );
			// assertEquals( "\'", instance.encodeForJavaScript( "'" ) );
			// assertEquals( '\"', instance.encodeForJavaScript( '"' ) );
			// assertEquals( "\\", instance.encodeForJavaScript( "\" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForVBScript" output="false">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			if (this.ESAPI4JVERSION == 2) {
				assertEquals('chrw(60)&"script"&chrw(62)', instance.encodeForVBScript("<script>"));
				assertEquals('x"&chrw(32)&chrw(33)&chrw(64)&chrw(36)&chrw(37)&chrw(40)&chrw(41)&chrw(61)&chrw(43)&chrw(123)&chrw(125)&chrw(91)&chrw(93)', instance.encodeForVBScript('x !@$%()=+{}[]'));
			}
			else {
				assertEquals('"<script">', instance.encodeForVBScript("<script>"));
				assertEquals(' "!"@"$"%"(")"="+"{"}"["]""', instance.encodeForVBScript(' !@$%()=+{}[]"'));
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXPath" output="false"
	            hint="Test of encodeForXPath method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals("&##x27;or 1&##x3d;1", instance.encodeForXPath("'or 1=1"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForSQL" output="false"
	            hint="Test of encodeForSQL method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			// CF8 requires 'var' at the top
			var mySQL1 = "";
			var mySQL2 = "";
			var oracle = "";

			var instance = variables.ESAPI.encoder();
			var MySQLCodec = newJava("org.owasp.esapi.codecs.MySQLCodec");

			mySQL1 = MySQLCodec.init(MySQLCodec.ANSI_MODE);
			assertEquals("Jeff'' or ''1''=''1", instance.encodeForSQL(mySQL1, "Jeff' or '1'='1"), "ANSI_MODE");

			mySQL2 = MySQLCodec.init(MySQLCodec.MYSQL_MODE);
			assertEquals("Jeff\' or \'1\'\=\'1", instance.encodeForSQL(mySQL2, "Jeff' or '1'='1"), "MYSQL_MODE");

			oracle = newJava("org.owasp.esapi.codecs.OracleCodec").init();
			assertEquals("Jeff'' or ''1''=''1", instance.encodeForSQL(oracle, "Jeff' or '1'='1"), "Oracle");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForLDAP" output="false"
	            hint="Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals("Hi This is a test ##��", instance.encodeForLDAP("Hi This is a test ##��"), "No special characters to escape");
			/* NULL test not valid in CF
			assertEquals( "Hi \00", instance.encodeForLDAP( "Hi " & toUnicode("\u0000") ), "Zeros" );
			*/
			assertEquals("Hi \28This\29 = is \2a a \5c test ## � � �", instance.encodeForLDAP("Hi (This) = is * a \ test ## � � �"), "LDAP Christams Tree");
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForDN" output="false"
	            hint="Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals("Hello�", instance.encodeForDN("Hello�"), "No special characters to escape");
			assertEquals("\## Hello�", instance.encodeForDN("## Hello�"), "leading ##");
			assertEquals("\ Hello�", instance.encodeForDN(" Hello�"), "leading space");
			assertEquals("Hello�\ ", instance.encodeForDN("Hello� "), "trailing space");
			assertEquals("Hello\<\>", instance.encodeForDN("Hello<>"), "less than greater than");
			assertEquals("\  \ ", instance.encodeForDN("   "), "only 3 spaces");
			assertEquals('\ Hello\\ \+ \, \"World\" \;\ ', instance.encodeForDN(' Hello\ + , "World" ; '), "Christmas Tree DN");
		</cfscript>

	</cffunction>

	<!--- NULL test not valid for CF

	    <cffunction access="public" returntype="void" name="testEncodeForXMLNull" output="false">
	    <cfscript>
	    var instance = variables.ESAPI.encoder();
	    assertEquals( null, instance.encodeForXML( null ) );
	    </cfscript>
	    </cffunction>

	    --->

	<cffunction access="public" returntype="void" name="testEncodeForXMLSpace" output="false">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals(" ", instance.encodeForXML(" "));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLScript" output="false">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals("&##x3c;script&##x3e;", instance.encodeForXML("<script>"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLImmune" output="false">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals(",.-_", instance.encodeForXML(",.-_"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLSymbol" output="false">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals("&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", instance.encodeForXML("!@$%()=+{}[]"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLPound" output="false">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals("&##xa3;", instance.encodeForXML(toUnicode("\u00A3")));
		</cfscript>

	</cffunction>

	<!--- NULL test not valid for CF

	    <cffunction access="public" returntype="void" name="testEncodeForXMLAttributeNull" output="false">
	    <cfscript>
	    var instance = variables.ESAPI.encoder();
	    assertEquals( null, instance.encodeForXMLAttribute( null ) );
	    </cfscript>
	    </cffunction>
	 --->

	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributeSpace" output="false">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals(" ", instance.encodeForXMLAttribute(" "));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributeScript" output="false">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals("&##x3c;script&##x3e;", instance.encodeForXMLAttribute("<script>"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributeImmune" output="false">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals(",.-_", instance.encodeForXMLAttribute(",.-_"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributeSymbol" output="false">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals(" &##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", instance.encodeForXMLAttribute(" !@$%()=+{}[]"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributePound" output="false">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals("&##xa3;", instance.encodeForXMLAttribute(toUnicode("\u00A3")));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForURL" output="false"
	            hint="Test of encodeForURL method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			assertEquals("%3Cscript%3E", instance.encodeForURL("<script>"));
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testDecodeFromURL" output="false"
	            hint="Test of decodeFromURL method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var instance = variables.ESAPI.encoder();
			try {
				assertEquals("<script>", instance.decodeFromURL("%3Cscript%3E"));
				assertEquals("     ", instance.decodeFromURL("+++++"));
			}
			catch(java.lang.Exception e) {
				fail("");
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForBase64" output="false"
	            hint="Test of encodeForBase64 method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var r = "";
			var encoded = "";
			var decoded = "";

			var instance = variables.ESAPI.encoder();
			try {
				for(i = 0; i < 100; i++) {
					r = variables.ESAPI.randomizer().getRandomString(20, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_SPECIALS).getBytes();
					encoded = instance.encodeForBase64(r, variables.ESAPI.randomizer().getRandomBoolean());
					decoded = instance.decodeFromBase64(encoded);
					//assertTrue( Arrays.equals( r, decoded ) );
					assertEquals(charsetEncode(r, "utf-8"), charsetEncode(decoded, "utf-8"));
				}
			}
			catch(java.io.IOException e) {
				fail("");
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testDecodeFromBase64" output="false"
	            hint="Test of decodeFromBase64 method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var r = "";
			var encoded = "";
			var decoded = "";

			var instance = variables.ESAPI.encoder();
			for(i = 0; i < 100; i++) {
				try {
					r = variables.ESAPI.randomizer().getRandomString(20, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_SPECIALS).getBytes();
					encoded = instance.encodeForBase64(r, variables.ESAPI.randomizer().getRandomBoolean());
					decoded = instance.decodeFromBase64(encoded);
					assertEquals(charsetEncode(r, "utf-8"), charsetEncode(decoded, "utf-8"));
				}
				catch(java.io.IOException e) {
					fail("");
				}
			}
			for(i = 0; i < 100; i++) {
				try {
					r = variables.ESAPI.randomizer().getRandomString(20, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_SPECIALS).getBytes();
					encoded = variables.ESAPI.randomizer().getRandomString(1, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS) & instance.encodeForBase64(r, variables.ESAPI.randomizer().getRandomBoolean());
					decoded = instance.decodeFromBase64(encoded);
					assertNotEquals(charsetEncode(r, "utf-8"), charsetEncode(decoded, "utf-8"));
				}
				catch(java.io.IOException e) {
					// expected
				}
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="toUnicode" output="false">
		<cfargument required="true" type="String" name="string"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var thisChr = "";

			var sb = newJava("java.lang.StringBuffer").init();
			for(i = 1; i <= len(arguments.string); i++) {
				thisChr = mid(arguments.string, i, 6);
				if(left(thisChr, 2) == "\u") {
					sb.append(chr(inputBaseN(right(thisChr, 4), 16)));
					i = i + 5;
				}
				else {
					sb.append(left(thisChr, 1));
				}
			}
			return sb.toString();
		</cfscript>

	</cffunction>

	<!--- issues --->

	<cffunction access="public" returntype="void" name="testIssue12" output="false" hint="https://github.com/damonmiller/esapi4cf/issues/12">
		<cfscript>
			var instance = variables.ESAPI.encoder();

			var testString1	= "dir=4&num=00000745'%20and%20char(124)%2Buser%2Bchar(124)=0%20and%20'%25'='";
			// decodes to	= "dir=4?m=00000745' and char(124)+user+char(124)=0 and '%'='";
			// this is double-encoded; the &nu is seen as an HTML entity along with the Percent encoding

			var testString2	= "dir=4&num=00013588+++++++++++++++++++++++Result:+%ED%E5+%ED%E0%F8%EB%EE%F1%FC+%F4%EE%F0%EC%FB+%E4%EB%FF+%EE%F2%EF%F0%E0%E2%EA%E8;";
			// decodes to	= "dir=4?m=00013588+++++++++++++++++++++++Result:+íå+íàøëîñü+ôîðìû+äëÿ+îòïðàâêè;";
			// this is double-encoded; the &nu is seen as an HTML entity along with the Percent encoding

			try {
				instance.canonicalize(testString1);
				fail("");
			}
			catch (org.owasp.esapi.errors.IntrusionException ex) {
				// expected
			}

			try {
				instance.canonicalize(testString2);
				fail("");
			}
			catch (org.owasp.esapi.errors.IntrusionException ex) {
				// expected
			}
		</cfscript>
	</cffunction>

</cfcomponent>