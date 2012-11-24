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
 --->`
<cfcomponent extends="cfesapi.test.org.owasp.esapi.util.TestCase" output="false">

	<cfscript>
		instance.ESAPI = createObject( "component", "cfesapi.org.owasp.esapi.ESAPI" ).init();
	</cfscript>

	<cffunction access="public" returntype="void" name="testCanonicalize" output="false">

		<cfscript>
			var local = {};
			System.out.println( "canonicalize" );

			local.list = getJava( "java.util.ArrayList" ).init();
			local.list.add( getJava( "org.owasp.esapi.codecs.HTMLEntityCodec" ).init() );
			local.list.add( getJava( "org.owasp.esapi.codecs.PercentCodec" ).init() );
			local.encoder = createObject( "component", "cfesapi.org.owasp.esapi.reference.DefaultEncoder" ).init( instance.ESAPI, local.list );

			/* NULL test not valid in CF
			// Test null paths
			assertEquals( null, local.encoder.canonicalize( null ) );
			assertEquals( null, local.encoder.canonicalize( null, true ) );
			assertEquals( null, local.encoder.canonicalize( null, false ) );
			*/
			// test exception paths
			assertEquals( "%", local.encoder.canonicalize( "%25", true ) );
			assertEquals( "%", local.encoder.canonicalize( "%25", false ) );

			assertEquals( "%", local.encoder.canonicalize( "%25" ) );
			assertEquals( "%F", local.encoder.canonicalize( "%25F" ) );
			assertEquals( "<", local.encoder.canonicalize( "%3c" ) );
			assertEquals( "<", local.encoder.canonicalize( "%3C" ) );
			assertEquals( "%X1", local.encoder.canonicalize( "%X1" ) );

			assertEquals( "<", local.encoder.canonicalize( "&lt" ) );
			assertEquals( "<", local.encoder.canonicalize( "&LT" ) );
			assertEquals( "<", local.encoder.canonicalize( "&lt;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&LT;" ) );

			assertEquals( "%", local.encoder.canonicalize( "&##37;" ) );
			assertEquals( "%", local.encoder.canonicalize( "&##37" ) );
			assertEquals( "%b", local.encoder.canonicalize( "&##37b" ) );

			assertEquals( "<", local.encoder.canonicalize( "&##x3c" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x3c;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x3C" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X3c" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X3C" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X3C;" ) );

			// percent encoding
			assertEquals( "<", local.encoder.canonicalize( "%3c" ) );
			assertEquals( "<", local.encoder.canonicalize( "%3C" ) );

			// html entity encoding
			assertEquals( "<", local.encoder.canonicalize( "&##60" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##060" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##0060" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##00060" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##000060" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##0000060" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##60;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##060;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##0060;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##00060;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##000060;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##0000060;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x3c" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x03c" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x003c" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x0003c" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x00003c" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x000003c" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x3c;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x03c;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x003c;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x0003c;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x00003c;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x000003c;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X3c" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X03c" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X003c" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X0003c" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X00003c" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X000003c" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X3c;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X03c;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X003c;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X0003c;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X00003c;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X000003c;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x3C" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x03C" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x003C" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x0003C" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x00003C" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x000003C" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x3C;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x03C;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x003C;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x0003C;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x00003C;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##x000003C;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X3C" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X03C" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X003C" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X0003C" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X00003C" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X000003C" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X3C;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X03C;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X003C;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X0003C;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X00003C;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&##X000003C;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&lt" ) );
			assertEquals( "<", local.encoder.canonicalize( "&lT" ) );
			assertEquals( "<", local.encoder.canonicalize( "&Lt" ) );
			assertEquals( "<", local.encoder.canonicalize( "&LT" ) );
			assertEquals( "<", local.encoder.canonicalize( "&lt;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&lT;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&Lt;" ) );
			assertEquals( "<", local.encoder.canonicalize( "&LT;" ) );

			assertEquals( '<script>alert("hello");</script>', local.encoder.canonicalize( "%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E" ) );
			assertEquals( '<script>alert("hello");</script>', local.encoder.canonicalize( "%3Cscript&##x3E;alert%28%22hello&##34%29%3B%3C%2Fscript%3E", false ) );

			// javascript escape syntax
			local.js = getJava( "java.util.ArrayList" ).init();
			local.js.add( getJava( "org.owasp.esapi.codecs.JavaScriptCodec" ).init() );
			local.encoder = createObject( "component", "cfesapi.org.owasp.esapi.reference.DefaultEncoder" ).init( instance.ESAPI, local.js );
			System.out.println( "JavaScript Decoding" );

			/* NULL test not valid in CF
			assertEquals( "\0", local.encoder.canonicalize("\0"));
			*/
			assertEquals( chr( 8 ), local.encoder.canonicalize( "\b" ) );
			assertEquals( chr( 9 ), local.encoder.canonicalize( "\t" ) );
			assertEquals( chr( 10 ), local.encoder.canonicalize( "\n" ) );
			assertEquals( chr( 11 ), local.encoder.canonicalize( "\v" ) );
			assertEquals( chr( 12 ), local.encoder.canonicalize( "\f" ) );
			assertEquals( chr( 13 ), local.encoder.canonicalize( "\r" ) );
			assertEquals( "'", local.encoder.canonicalize( "\'" ) );
			assertEquals( '"', local.encoder.canonicalize( '\"' ) );
			assertEquals( "\", local.encoder.canonicalize( "\\" ) );
			assertEquals( "<", local.encoder.canonicalize( "\<" ) );

			assertEquals( "<", local.encoder.canonicalize( "\u003c" ) );
			assertEquals( "<", local.encoder.canonicalize( "\U003c" ) );
			assertEquals( "<", local.encoder.canonicalize( "\u003C" ) );
			assertEquals( "<", local.encoder.canonicalize( "\U003C" ) );
			assertEquals( "<", local.encoder.canonicalize( "\x3c" ) );
			assertEquals( "<", local.encoder.canonicalize( "\X3c" ) );
			assertEquals( "<", local.encoder.canonicalize( "\x3C" ) );
			assertEquals( "<", local.encoder.canonicalize( "\X3C" ) );

			// css escape syntax
			// be careful because some codecs see \0 as null byte
			local.css = getJava( "java.util.ArrayList" ).init();
			local.css.add( getJava( "org.owasp.esapi.codecs.CSSCodec" ).init() );
			local.encoder = createObject( "component", "cfesapi.org.owasp.esapi.reference.DefaultEncoder" ).init( instance.ESAPI, local.css );
			System.out.println( "CSS Decoding" );
			assertEquals( "<", local.encoder.canonicalize( "\3c" ) );// add strings to prevent null byte
			assertEquals( "<", local.encoder.canonicalize( "\03c" ) );
			assertEquals( "<", local.encoder.canonicalize( "\003c" ) );
			assertEquals( "<", local.encoder.canonicalize( "\0003c" ) );
			assertEquals( "<", local.encoder.canonicalize( "\00003c" ) );
			assertEquals( "<", local.encoder.canonicalize( "\3C" ) );
			assertEquals( "<", local.encoder.canonicalize( "\03C" ) );
			assertEquals( "<", local.encoder.canonicalize( "\003C" ) );
			assertEquals( "<", local.encoder.canonicalize( "\0003C" ) );
			assertEquals( "<", local.encoder.canonicalize( "\00003C" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testDoubleEncodingCanonicalization" output="false"
	            hint="Test of canonicalize method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var local = {};
			System.out.println( "doubleEncodingCanonicalization" );
			local.encoder = instance.ESAPI.encoder();

			// note these examples use the strict=false flag on canonicalize to allow
			// full decoding without throwing an IntrusionException. Generally, you
			// should use strict mode as allowing double-encoding is an abomination.
			// double encoding examples
			assertEquals( "<", local.encoder.canonicalize( "&##x26;lt&##59", false ) );//double entity
			assertEquals( "\", local.encoder.canonicalize( "%255c", false ) );//double percent
			assertEquals( "%", local.encoder.canonicalize( "%2525", false ) );//double percent
			// double encoding with multiple schemes example
			assertEquals( "<", local.encoder.canonicalize( "%26lt%3b", false ) );//first entity, then percent
			assertEquals( "&", local.encoder.canonicalize( "&##x25;26", false ) );//first percent, then
			//entity
			// nested encoding examples
			assertEquals( "<", local.encoder.canonicalize( "%253c", false ) );//nested encode % with percent
			assertEquals( "<", local.encoder.canonicalize( "%%33%63", false ) );//nested encode both nibbles
			//with percent
			assertEquals( "<", local.encoder.canonicalize( "%%33c", false ) );// nested encode first nibble
			//with percent
			assertEquals( "<", local.encoder.canonicalize( "%3%63", false ) );//nested encode second nibble
			//with percent
			assertEquals( "<", local.encoder.canonicalize( "&&##108;t;", false ) );//nested encode l with
			//entity
			assertEquals( "<", local.encoder.canonicalize( "%2&##x35;3c", false ) );//triple percent,
			//percent, 5 with entity
			// nested encoding with multiple schemes examples
			assertEquals( "<", local.encoder.canonicalize( "&%6ct;", false ) );// nested encode l with
			//percent
			assertEquals( "<", local.encoder.canonicalize( "%&##x33;c", false ) );//nested encode 3 with
			//entity
			// multiple encoding tests
			assertEquals( "% & <script> <script>", local.encoder.canonicalize( "%25 %2526 %26##X3c;script&##x3e; &##37;3Cscript%25252525253e", false ) );
			assertEquals( "< < < < < < <", local.encoder.canonicalize( "%26lt; %26lt; &##X25;3c &##x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", false ) );

			// test strict mode with both mixed and multiple encoding
			try {
				assertEquals( "< < < < < < <", local.encoder.canonicalize( "%26lt; %26lt; &##X25;3c &##x25;3c %2526lt%253B %2526lt%253B %2526lt%253B" ) );
			}
			catch(cfesapi.org.owasp.esapi.errors.IntrusionException e) {
				// expected
			}

			try {
				assertEquals( "<script", local.encoder.canonicalize( "%253Cscript" ) );
			}
			catch(cfesapi.org.owasp.esapi.errors.IntrusionException e) {
				// expected
			}
			try {
				assertEquals( "<script", local.encoder.canonicalize( "&##37;3Cscript" ) );
			}
			catch(cfesapi.org.owasp.esapi.errors.IntrusionException e) {
				// expected
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForHTML" output="false"
	            hint="Test of encodeForHTML method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			/* NULL tests not valid for CF
			assertEquals( null, local.encoder.encodeForHTML( null ) );
			*/
			assertEquals( "&lt;script&gt;", local.encoder.encodeForHTML( "<script>" ) );
			assertEquals( "&amp;lt&##x3b;script&amp;gt&##x3b;", local.encoder.encodeForHTML( "&lt;script&gt;" ) );
			assertEquals( "&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.encoder.encodeForHTML( "!@$%()=+{}[]" ) );
			assertEquals( "&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.encoder.encodeForHTML( local.encoder.canonicalize( "&##33;&##64;&##36;&##37;&##40;&##41;&##61;&##43;&##123;&##125;&##91;&##93;" ) ) );
			assertEquals( ",.-_ ", local.encoder.encodeForHTML( ",.-_ " ) );
			assertEquals( "dir&amp;", local.encoder.encodeForHTML( "dir&" ) );
			assertEquals( "one&amp;two", local.encoder.encodeForHTML( "one&two" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForHTMLAttribute" output="false"
	            hint="Test of encodeForHTMLAttribute method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( "&lt;script&gt;", local.encoder.encodeForHTMLAttribute( "<script>" ) );
			assertEquals( ",.-_", local.encoder.encodeForHTMLAttribute( ",.-_" ) );
			assertEquals( " &##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.encoder.encodeForHTMLAttribute( " !@$%()=+{}[]" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForCSS" output="false">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( "\3C script\3E ", local.encoder.encodeForCSS( "<script>" ) );
			assertEquals( " \21 \40 \24 \25 \28 \29 \3D \2B \7B \7D \5B \5D \22 ", local.encoder.encodeForCSS( ' !@$%()=+{}[]"' ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForJavascript" output="false"
	            hint="Test of encodeForJavaScript method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( "\x3Cscript\x3E", local.encoder.encodeForJavaScript( "<script>" ) );
			assertEquals( ",.-_ ", local.encoder.encodeForJavaScript( ",.-_ " ) );
			assertEquals( "\x21\x40\x24\x25\x28\x29\x3D\x2B\x7B\x7D\x5B\x5D", local.encoder.encodeForJavaScript( "!@$%()=+{}[]" ) );
			/* NULL test not valid in CF
			assertEquals( "\0", local.encoder.encodeForJavaScript("\0"));
			*/
			// assertEquals( "\b", local.encoder.encodeForJavaScript( chr( 8 ) ) );
			// assertEquals( "\t", local.encoder.encodeForJavaScript( chr( 9 ) ) );
			// assertEquals( "\n", local.encoder.encodeForJavaScript( chr( 10 ) ) );
			// assertEquals( "\v", local.encoder.encodeForJavaScript( chr( inputBaseN( "0b", 16 ) ) ) );
			// assertEquals( "\f", local.encoder.encodeForJavaScript( chr( 12 ) ) );
			// assertEquals( "\r", local.encoder.encodeForJavaScript( chr( 13 ) ) );
			// assertEquals( "\'", local.encoder.encodeForJavaScript( "'" ) );
			// assertEquals( '\"', local.encoder.encodeForJavaScript( '"' ) );
			// assertEquals( "\\", local.encoder.encodeForJavaScript( "\" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForVBScript" output="false">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( '"<script">', local.encoder.encodeForVBScript( "<script>" ) );
			assertEquals( ' "!"@"$"%"(")"="+"{"}"["]""', local.encoder.encodeForVBScript( ' !@$%()=+{}[]"' ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXPath" output="false"
	            hint="Test of encodeForXPath method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( "&##x27;or 1&##x3d;1", local.encoder.encodeForXPath( "'or 1=1" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForSQL" output="false"
	            hint="Test of encodeForSQL method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			local.MySQLCodec = getJava( "org.owasp.esapi.codecs.MySQLCodec" );

			local.mySQL1 = local.MySQLCodec.init( local.MySQLCodec.ANSI_MODE );
			assertEquals( "Jeff'' or ''1''=''1", local.encoder.encodeForSQL( local.mySQL1, "Jeff' or '1'='1" ), "ANSI_MODE" );

			local.mySQL2 = local.MySQLCodec.init( local.MySQLCodec.MYSQL_MODE );
			assertEquals( "Jeff\' or \'1\'\=\'1", local.encoder.encodeForSQL( local.mySQL2, "Jeff' or '1'='1" ), "MYSQL_MODE" );

			local.oracle = getJava( "org.owasp.esapi.codecs.OracleCodec" ).init();
			assertEquals( "Jeff'' or ''1''=''1", local.encoder.encodeForSQL( local.oracle, "Jeff' or '1'='1" ), "Oracle" );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForLDAP" output="false"
	            hint="Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( "Hi This is a test ##��", local.encoder.encodeForLDAP( "Hi This is a test ##��" ), "No special characters to escape" );
			/* NULL test not valid in CF
			assertEquals( "Hi \00", local.encoder.encodeForLDAP( "Hi " & toUnicode("\u0000") ), "Zeros" );
			*/
			assertEquals( "Hi \28This\29 = is \2a a \5c test ## � � �", local.encoder.encodeForLDAP( "Hi (This) = is * a \ test ## � � �" ), "LDAP Christams Tree" );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForDN" output="false"
	            hint="Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( "Hello�", local.encoder.encodeForDN( "Hello�" ), "No special characters to escape" );
			assertEquals( "\## Hello�", local.encoder.encodeForDN( "## Hello�" ), "leading ##" );
			assertEquals( "\ Hello�", local.encoder.encodeForDN( " Hello�" ), "leading space" );
			assertEquals( "Hello�\ ", local.encoder.encodeForDN( "Hello� " ), "trailing space" );
			assertEquals( "Hello\<\>", local.encoder.encodeForDN( "Hello<>" ), "less than greater than" );
			assertEquals( "\  \ ", local.encoder.encodeForDN( "   " ), "only 3 spaces" );
			assertEquals( '\ Hello\\ \+ \, \"World\" \;\ ', local.encoder.encodeForDN( ' Hello\ + , "World" ; ' ), "Christmas Tree DN" );
		</cfscript>

	</cffunction>

	<!--- NULL test not valid for CF
	    <cffunction access="public" returntype="void" name="testEncodeForXMLNull" output="false">

	        <cfscript>
	            var local = {};
	            local.encoder = instance.ESAPI.encoder();
	            assertEquals( null, local.encoder.encodeForXML( null ) );
	        </cfscript>

	    </cffunction>
	--->

	<cffunction access="public" returntype="void" name="testEncodeForXMLSpace" output="false">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( " ", local.encoder.encodeForXML( " " ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLScript" output="false">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( "&##x3c;script&##x3e;", local.encoder.encodeForXML( "<script>" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLImmune" output="false">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( ",.-_", local.encoder.encodeForXML( ",.-_" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLSymbol" output="false">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( "&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.encoder.encodeForXML( "!@$%()=+{}[]" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLPound" output="false">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( "&##xa3;", local.encoder.encodeForXML( toUnicode( "\u00A3" ) ) );
		</cfscript>

	</cffunction>

	<!--- NULL test not valid for CF
	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributeNull" output="false">

	    <cfscript>
	        var local = {};
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals( null, local.encoder.encodeForXMLAttribute( null ) );
	    </cfscript>

	</cffunction> --->

	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributeSpace" output="false">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( " ", local.encoder.encodeForXMLAttribute( " " ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributeScript" output="false">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( "&##x3c;script&##x3e;", local.encoder.encodeForXMLAttribute( "<script>" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributeImmune" output="false">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( ",.-_", local.encoder.encodeForXMLAttribute( ",.-_" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributeSymbol" output="false">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( " &##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.encoder.encodeForXMLAttribute( " !@$%()=+{}[]" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributePound" output="false">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( "&##xa3;", local.encoder.encodeForXMLAttribute( toUnicode( "\u00A3" ) ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForURL" output="false"
	            hint="Test of encodeForURL method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			assertEquals( "%3Cscript%3E", local.encoder.encodeForURL( "<script>" ) );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testDecodeFromURL" output="false"
	            hint="Test of decodeFromURL method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			try {
				assertEquals( "<script>", local.encoder.decodeFromURL( "%3Cscript%3E" ) );
				assertEquals( "     ", local.encoder.decodeFromURL( "+++++" ) );
			}
			catch(java.lang.Exception e) {
				fail();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testEncodeForBase64" output="false"
	            hint="Test of encodeForBase64 method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			try {
				for(local.i = 0; local.i < 100; local.i++) {
					local.r = instance.ESAPI.randomizer().getRandomString( 20, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_SPECIALS ).getBytes();
					local.encoded = local.encoder.encodeForBase64( local.r, instance.ESAPI.randomizer().getRandomBoolean() );
					local.decoded = local.encoder.decodeFromBase64( local.encoded );
					//assertTrue( Arrays.equals( local.r, local.decoded ) );
					assertEquals( charsetEncode( local.r, "utf-8" ), charsetEncode( local.decoded, "utf-8" ) );
				}
			}
			catch(java.io.IOException e) {
				fail();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="testDecodeFromBase64" output="false"
	            hint="Test of decodeFromBase64 method, of class org.owasp.esapi.Encoder.">

		<cfscript>
			var local = {};
			local.encoder = instance.ESAPI.encoder();
			for(local.i = 0; local.i < 100; local.i++) {
				try {
					local.r = instance.ESAPI.randomizer().getRandomString( 20, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_SPECIALS ).getBytes();
					local.encoded = local.encoder.encodeForBase64( local.r, instance.ESAPI.randomizer().getRandomBoolean() );
					local.decoded = local.encoder.decodeFromBase64( local.encoded );
					//assertTrue( Arrays.equals( local.r, local.decoded ) );
					assertEquals( charsetEncode( local.r, "utf-8" ), charsetEncode( local.decoded, "utf-8" ) );
				}
				catch(java.io.IOException e) {
					fail();
				}
			}
			for(local.i = 0; local.i < 100; local.i++) {
				try {
					local.r = instance.ESAPI.randomizer().getRandomString( 20, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_SPECIALS ).getBytes();
					local.encoded = instance.ESAPI.randomizer().getRandomString( 1, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS ) & local.encoder.encodeForBase64( local.r, instance.ESAPI.randomizer().getRandomBoolean() );
					local.decoded = local.encoder.decodeFromBase64( local.encoded );
					//assertFalse( Arrays.equals( local.r, local.decoded ) );
					assertNotEquals( charsetEncode( local.r, "utf-8" ), charsetEncode( local.decoded, "utf-8" ) );
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
			var local = {};
			local.ret = "";
			for(local.i = 1; local.i <= len( arguments.string ); local.i++) {
				local.thisChr = mid( arguments.string, local.i, 6 );
				if(left( local.thisChr, 2 ) == "\u") {
					local.ret = local.ret & chr( inputBaseN( right( local.thisChr, 4 ), 16 ) );
					local.i = local.i + 5;
				}
				else {
					local.ret = local.ret & left( local.thisChr, 1 );
				}
			}
			return local.ret;
		</cfscript>

	</cffunction>

</cfcomponent>