<cfcomponent extends="cfesapi.test.org.owasp.esapi.TestCase" output="false">

	<cfscript>
		instance.ESAPI = "";

		static.PREFERRED_ENCODING = "UTF-8";
	</cfscript>

	<cffunction access="public" returntype="void" name="setUp" output="false">
		<cfscript>
			structClear(session);
			structClear(request);

			System = createObject("java", "java.lang.System");

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


	<cffunction access="public" returntype="void" name="testCanonicalize" output="false" hint="Test of canonicalize method, of class org.owasp.esapi.Encoder.">
		<cfscript>
			createObject("java", "java.lang.System").out.println("canonicalize");

	        local.list = [];
	        local.list.add( "HTMLEntityCodec" );
		    local.list.add( "PercentCodec" );
			local.local.instance = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultEncoder").init( instance.ESAPI, local.list );

			// Test null paths
			assertEquals( "", local.instance.canonicalize(""));
			assertEquals( "", local.instance.canonicalize("", true));
			assertEquals( "", local.instance.canonicalize("", false));

			// test exception paths
			assertEquals( "%", local.instance.canonicalize("%25", true));
			assertEquals( "%", local.instance.canonicalize("%25", false));

	        assertEquals( "%", local.instance.canonicalize("%25"));
	        assertEquals( "%F", local.instance.canonicalize("%25F"));
	        assertEquals( "<", local.instance.canonicalize("%3c"));
	        assertEquals( "<", local.instance.canonicalize("%3C"));
	        assertEquals( "%X1", local.instance.canonicalize("%X1"));

	        assertEquals( "<", local.instance.canonicalize("&lt"));
	        assertEquals( "<", local.instance.canonicalize("&LT"));
	        assertEquals( "<", local.instance.canonicalize("&lt;"));
	        assertEquals( "<", local.instance.canonicalize("&LT;"));

	        assertEquals( "%", local.instance.canonicalize("&##37;"));
	        assertEquals( "%", local.instance.canonicalize("&##37"));
	        assertEquals( "%b", local.instance.canonicalize("&##37b"));

	        assertEquals( "<", local.instance.canonicalize("&##x3c"));
	        assertEquals( "<", local.instance.canonicalize("&##x3c;"));
	        assertEquals( "<", local.instance.canonicalize("&##x3C"));
	        assertEquals( "<", local.instance.canonicalize("&##X3c"));
	        assertEquals( "<", local.instance.canonicalize("&##X3C"));
	        assertEquals( "<", local.instance.canonicalize("&##X3C;"));

	        // percent encoding
	        assertEquals( "<", local.instance.canonicalize("%3c"));
	        assertEquals( "<", local.instance.canonicalize("%3C"));

	        // html entity encoding
	        assertEquals( "<", local.instance.canonicalize("&##60"));
	        assertEquals( "<", local.instance.canonicalize("&##060"));
	        assertEquals( "<", local.instance.canonicalize("&##0060"));
	        assertEquals( "<", local.instance.canonicalize("&##00060"));
	        assertEquals( "<", local.instance.canonicalize("&##000060"));
	        assertEquals( "<", local.instance.canonicalize("&##0000060"));
	        assertEquals( "<", local.instance.canonicalize("&##60;"));
	        assertEquals( "<", local.instance.canonicalize("&##060;"));
	        assertEquals( "<", local.instance.canonicalize("&##0060;"));
	        assertEquals( "<", local.instance.canonicalize("&##00060;"));
	        assertEquals( "<", local.instance.canonicalize("&##000060;"));
	        assertEquals( "<", local.instance.canonicalize("&##0000060;"));
	        assertEquals( "<", local.instance.canonicalize("&##x3c"));
	        assertEquals( "<", local.instance.canonicalize("&##x03c"));
	        assertEquals( "<", local.instance.canonicalize("&##x003c"));
	        assertEquals( "<", local.instance.canonicalize("&##x0003c"));
	        assertEquals( "<", local.instance.canonicalize("&##x00003c"));
	        assertEquals( "<", local.instance.canonicalize("&##x000003c"));
	        assertEquals( "<", local.instance.canonicalize("&##x3c;"));
	        assertEquals( "<", local.instance.canonicalize("&##x03c;"));
	        assertEquals( "<", local.instance.canonicalize("&##x003c;"));
	        assertEquals( "<", local.instance.canonicalize("&##x0003c;"));
	        assertEquals( "<", local.instance.canonicalize("&##x00003c;"));
	        assertEquals( "<", local.instance.canonicalize("&##x000003c;"));
	        assertEquals( "<", local.instance.canonicalize("&##X3c"));
	        assertEquals( "<", local.instance.canonicalize("&##X03c"));
	        assertEquals( "<", local.instance.canonicalize("&##X003c"));
	        assertEquals( "<", local.instance.canonicalize("&##X0003c"));
	        assertEquals( "<", local.instance.canonicalize("&##X00003c"));
	        assertEquals( "<", local.instance.canonicalize("&##X000003c"));
	        assertEquals( "<", local.instance.canonicalize("&##X3c;"));
	        assertEquals( "<", local.instance.canonicalize("&##X03c;"));
	        assertEquals( "<", local.instance.canonicalize("&##X003c;"));
	        assertEquals( "<", local.instance.canonicalize("&##X0003c;"));
	        assertEquals( "<", local.instance.canonicalize("&##X00003c;"));
	        assertEquals( "<", local.instance.canonicalize("&##X000003c;"));
	        assertEquals( "<", local.instance.canonicalize("&##x3C"));
	        assertEquals( "<", local.instance.canonicalize("&##x03C"));
	        assertEquals( "<", local.instance.canonicalize("&##x003C"));
	        assertEquals( "<", local.instance.canonicalize("&##x0003C"));
	        assertEquals( "<", local.instance.canonicalize("&##x00003C"));
	        assertEquals( "<", local.instance.canonicalize("&##x000003C"));
	        assertEquals( "<", local.instance.canonicalize("&##x3C;"));
	        assertEquals( "<", local.instance.canonicalize("&##x03C;"));
	        assertEquals( "<", local.instance.canonicalize("&##x003C;"));
	        assertEquals( "<", local.instance.canonicalize("&##x0003C;"));
	        assertEquals( "<", local.instance.canonicalize("&##x00003C;"));
	        assertEquals( "<", local.instance.canonicalize("&##x000003C;"));
	        assertEquals( "<", local.instance.canonicalize("&##X3C"));
	        assertEquals( "<", local.instance.canonicalize("&##X03C"));
	        assertEquals( "<", local.instance.canonicalize("&##X003C"));
	        assertEquals( "<", local.instance.canonicalize("&##X0003C"));
	        assertEquals( "<", local.instance.canonicalize("&##X00003C"));
	        assertEquals( "<", local.instance.canonicalize("&##X000003C"));
	        assertEquals( "<", local.instance.canonicalize("&##X3C;"));
	        assertEquals( "<", local.instance.canonicalize("&##X03C;"));
	        assertEquals( "<", local.instance.canonicalize("&##X003C;"));
	        assertEquals( "<", local.instance.canonicalize("&##X0003C;"));
	        assertEquals( "<", local.instance.canonicalize("&##X00003C;"));
	        assertEquals( "<", local.instance.canonicalize("&##X000003C;"));
	        assertEquals( "<", local.instance.canonicalize("&lt"));
	        assertEquals( "<", local.instance.canonicalize("&lT"));
	        assertEquals( "<", local.instance.canonicalize("&Lt"));
	        assertEquals( "<", local.instance.canonicalize("&LT"));
	        assertEquals( "<", local.instance.canonicalize("&lt;"));
	        assertEquals( "<", local.instance.canonicalize("&lT;"));
	        assertEquals( "<", local.instance.canonicalize("&Lt;"));
	        assertEquals( "<", local.instance.canonicalize("&LT;"));

	        assertEquals( '<script>alert("hello");</script>', local.instance.canonicalize("%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E") );
	        assertEquals( '<script>alert("hello");</script>', local.instance.canonicalize("%3Cscript&##x3E;alert%28%22hello&##34%29%3B%3C%2Fscript%3E", false) );

/*
	        // javascript escape syntax
	        local.js = [];
	        local.js.add( "JavaScriptCodec" );
	        local.instance = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultEncoder").init( ESAPI, local.js );
	        createObject("java", "java.lang.System").out.println( "JavaScript Decoding" );

	        assertEquals( "\0", local.instance.canonicalize("\0"));
	        assertEquals( "\b", local.instance.canonicalize("\b"));
	        assertEquals( "\t", local.instance.canonicalize("\\t"));
	        assertEquals( "\n", local.instance.canonicalize("\\n"));
	        assertEquals( ""+(char)0x0b, local.instance.canonicalize("\\v"));
	        assertEquals( "\f", local.instance.canonicalize("\\f"));
	        assertEquals( "\r", local.instance.canonicalize("\\r"));
	        assertEquals( "\'", local.instance.canonicalize("\\'"));
	        assertEquals( "\"", local.instance.canonicalize("\\\""));
	        assertEquals( "\\", local.instance.canonicalize("\\\\"));
	        assertEquals( "<", local.instance.canonicalize("\\<"));

	        assertEquals( "<", local.instance.canonicalize("\\u003c"));
	        assertEquals( "<", local.instance.canonicalize("\\U003c"));
	        assertEquals( "<", local.instance.canonicalize("\\u003C"));
	        assertEquals( "<", local.instance.canonicalize("\\U003C"));
	        assertEquals( "<", local.instance.canonicalize("\\x3c"));
	        assertEquals( "<", local.instance.canonicalize("\\X3c"));
	        assertEquals( "<", local.instance.canonicalize("\\x3C"));
	        assertEquals( "<", local.instance.canonicalize("\\X3C"));

	        // css escape syntax
	        // be careful because some codecs see \0 as null byte
	        local.css = [];
	        local.css.add( "CSSCodec" );
	        local.instance = createObject("component", "cfesapi.org.owasp.esapi.reference.DefaultEncoder").init( ESAPI, local.css );
	        createObject("java", "java.lang.System").out.println( "CSS Decoding" );
	        assertEquals( "<", local.instance.canonicalize("\\3c"));  // add strings to prevent null byte
	        assertEquals( "<", local.instance.canonicalize("\\03c"));
	        assertEquals( "<", local.instance.canonicalize("\\003c"));
	        assertEquals( "<", local.instance.canonicalize("\\0003c"));
	        assertEquals( "<", local.instance.canonicalize("\\00003c"));
	        assertEquals( "<", local.instance.canonicalize("\\3C"));
	        assertEquals( "<", local.instance.canonicalize("\\03C"));
	        assertEquals( "<", local.instance.canonicalize("\\003C"));
	        assertEquals( "<", local.instance.canonicalize("\\0003C"));
	        assertEquals( "<", local.instance.canonicalize("\\00003C"));
	        */
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testDoubleEncodingCanonicalization" output="false" hint="Test of canonicalize method, of class org.owasp.esapi.Encoder.">
		<cfscript>
			createObject("java", "java.lang.System").out.println("doubleEncodingCanonicalization");
			local.instance = instance.ESAPI.encoder();

			// note these examples use the strict=false flag on canonicalize to allow
	        // full decoding without throwing an IntrusionException. Generally, you
	        // should use strict mode as allowing double-encoding is an abomination.

	        // double encoding examples
	        assertEquals( "<", instance.canonicalize("&##x26;lt&##59", false )); //double entity
	        assertEquals( "\", instance.canonicalize("%255c", false)); //double percent
	        assertEquals( "%", instance.canonicalize("%2525", false)); //double percent

	        // double encoding with multiple schemes example
	        assertEquals( "<", instance.canonicalize("%26lt%3b", false)); //first entity, then percent
	        assertEquals( "&", instance.canonicalize("&##x25;26", false)); //first percent, then entity

	        // nested encoding examples
	        assertEquals( "<", instance.canonicalize("%253c", false)); //nested encode % with percent
	        assertEquals( "<", instance.canonicalize("%%33%63", false)); //nested encode both nibbles with percent
	        assertEquals( "<", instance.canonicalize("%%33c", false)); // nested encode first nibble with percent
	        assertEquals( "<", instance.canonicalize("%3%63", false));  //nested encode second nibble with percent
	        assertEquals( "<", instance.canonicalize("&&##108;t;", false)); //nested encode l with entity
	        assertEquals( "<", instance.canonicalize("%2&##x35;3c", false)); //triple percent, percent, 5 with entity

	        // nested encoding with multiple schemes examples
	        assertEquals( "<", instance.canonicalize("&%6ct;", false)); // nested encode l with percent
	        assertEquals( "<", instance.canonicalize("%&##x33;c", false)); //nested encode 3 with entity

	        // multiple encoding tests
	        assertEquals( "% & <script> <script>", instance.canonicalize( "%25 %2526 %26##X3c;script&##x3e; &##37;3Cscript%25252525253e", false ) );
	        assertEquals( "< < < < < < <", instance.canonicalize( "%26lt; %26lt; &##X25;3c &##x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", false ) );

	        // test strict mode with both mixed and multiple encoding
	        try {
	            assertEquals( "< < < < < < <", instance.canonicalize( "%26lt; %26lt; &##X25;3c &##x25;3c %2526lt%253B %2526lt%253B %2526lt%253B" ) );
	        } catch( cfesapi.org.owasp.esapi.errors.IntrusionException e ) {
	            // expected
	        }

	        try {
	            assertEquals( "<script", instance.canonicalize("%253Cscript" ) );
	        } catch( cfesapi.org.owasp.esapi.errors.IntrusionException e ) {
	            // expected
	        }
	        try {
	            assertEquals( "<script", instance.canonicalize("&##37;3Cscript" ) );
	        } catch( cfesapi.org.owasp.esapi.errors.IntrusionException e ) {
	            // expected
	        }
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForHTML" output="false" hint="Test of encodeForHTML method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("encodeForHTML");
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("", local.instance.encodeForHTML(""));
	        // test invalid characters are replaced with spaces
	        assertEquals("a&##xfffd;b&##xfffd;c&##xfffd;d&##xfffd;e&##xfffd;f&##x9;g", local.instance.encodeForHTML("a" & chr(0) & "b" & chr(4) & "c" & chr(128) & "d" & chr(150) & "e" &chr(159) & "f" & chr(9) & "g"));

	        assertEquals("&lt;script&gt;", local.instance.encodeForHTML("<script>"));
	        assertEquals("&amp;lt&##x3b;script&amp;gt&##x3b;", local.instance.encodeForHTML("&lt;script&gt;"));
	        assertEquals("&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.instance.encodeForHTML("!@$%()=+{}[]"));
	        assertEquals("&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.instance.encodeForHTML(local.instance.canonicalize("&##33;&##64;&##36;&##37;&##40;&##41;&##61;&##43;&##123;&##125;&##91;&##93;") ) );
	        assertEquals(",.-_ ", local.instance.encodeForHTML(",.-_ "));
	        assertEquals("dir&amp;", local.instance.encodeForHTML("dir&"));
	        assertEquals("one&amp;two", local.instance.encodeForHTML("one&two"));
	        assertEquals("" & chr(12345) & chr(65533) & chr(1244), "" & chr(12345) & chr(65533) & chr(1244) );
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForHTMLAttribute" output="false" hint="Test of encodeForHTMLAttribute method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("encodeForHTMLAttribute");
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("", local.instance.encodeForHTMLAttribute(""));
	        assertEquals("&lt;script&gt;", local.instance.encodeForHTMLAttribute("<script>"));
	        assertEquals(",.-_", local.instance.encodeForHTMLAttribute(",.-_"));
	        assertEquals("&##x20;&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.instance.encodeForHTMLAttribute(" !@$%()=+{}[]"));
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForCSS" output="false">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("encodeForCSS");
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("", local.instance.encodeForCSS(""));
	        assertEquals("\3c script\3e ", local.instance.encodeForCSS("<script>"));
	        assertEquals("\21 \40 \24 \25 \28 \29 \3d \2b \7b \7d \5b \5d ", local.instance.encodeForCSS("!@$%()=+{}[]"));
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForJavascript" output="false" hint="Test of encodeForJavaScript method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("encodeForJavascript");
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("", local.instance.encodeForJavaScript(""));
	        assertEquals("\x3Cscript\x3E", local.instance.encodeForJavaScript("<script>"));
	        assertEquals(",.\x2D_\x20", local.instance.encodeForJavaScript(",.-_ "));
	        assertEquals("\x21\x40\x24\x25\x28\x29\x3D\x2B\x7B\x7D\x5B\x5D", local.instance.encodeForJavaScript("!@$%()=+{}[]"));
	        // assertEquals( "\0", local.instance.encodeForJavaScript("\0"));
	        // assertEquals( "\b", local.instance.encodeForJavaScript("\b"));
	        // assertEquals( "\t", local.instance.encodeForJavaScript("\t"));
	        // assertEquals( "\n", local.instance.encodeForJavaScript("\n"));
	        // assertEquals( "\v", local.instance.encodeForJavaScript("" + (char)0x0b));
	        // assertEquals( "\f", local.instance.encodeForJavaScript("\f"));
	        // assertEquals( "\r", local.instance.encodeForJavaScript("\r"));
	        // assertEquals( "\'", local.instance.encodeForJavaScript("\'"));
	        // assertEquals( '\"', local.instance.encodeForJavaScript('\"'));
	        // assertEquals( "\\", local.instance.encodeForJavaScript("\\"));
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForVBScript" output="false">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("encodeForVBScript");
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("", local.instance.encodeForVBScript(""));
	        assertEquals( 'chrw(60)&"script"&chrw(62)', local.instance.encodeForVBScript("<script>"));
	        assertEquals( 'x"&chrw(32)&chrw(33)&chrw(64)&chrw(36)&chrw(37)&chrw(40)&chrw(41)&chrw(61)&chrw(43)&chrw(123)&chrw(125)&chrw(91)&chrw(93)', local.instance.encodeForVBScript("x !@$%()=+{}[]"));
	        assertEquals( 'alert"&chrw(40)&chrw(39)&"ESAPI"&chrw(32)&"test"&chrw(33)&chrw(39)&chrw(41)', local.instance.encodeForVBScript("alert('ESAPI test!')" ));
	        assertEquals( 'jeff.williams"&chrw(64)&"aspectsecurity.com', local.instance.encodeForVBScript("jeff.williams@aspectsecurity.com"));
	        assertEquals( 'test"&chrw(32)&chrw(60)&chrw(62)&chrw(32)&"test', local.instance.encodeForVBScript("test <> test" ));
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXPath" output="false" hint="Test of encodeForXPath method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("encodeForXPath");
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("", local.instance.encodeForXPath(""));
	        assertEquals("&##x27;or 1&##x3d;1", local.instance.encodeForXPath("'or 1=1"));
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForSQL" output="false" hint="Test of encodeForSQL method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("encodeForSQL");
	        local.instance = instance.ESAPI.encoder();
			MySQLCodec = javaLoader().create("org.owasp.esapi.codecs.MySQLCodec");
			OracleCodec = javaLoader().create("org.owasp.esapi.codecs.OracleCodec");

	        local.mySQL1 = MySQLCodec.init( MySQLCodec.ANSI_MODE );
	        assertEquals("", local.instance.encodeForSQL(local.mySQL1, ""), "ANSI_MODE");
	        assertEquals("Jeff'' or ''1''=''1", local.instance.encodeForSQL(local.mySQL1, "Jeff' or '1'='1"), "ANSI_MODE");

	        local.mySQL2 = MySQLCodec.init( MySQLCodec.MYSQL_MODE );
	        assertEquals("", local.instance.encodeForSQL(local.mySQL2, ""), "MYSQL_MODE");
	        assertEquals("Jeff\' or \'1\'\=\'1", local.instance.encodeForSQL(local.mySQL2, "Jeff' or '1'='1"), "MYSQL_MODE");

	        local.oracle = OracleCodec.init();
	        assertEquals("", local.instance.encodeForSQL(local.oracle, ""), "Oracle");
	        assertEquals("Jeff'' or ''1''=''1", local.instance.encodeForSQL(local.oracle, "Jeff' or '1'='1"), "Oracle");
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForLDAP" output="false" hint="Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("encodeForLDAP");
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("", local.instance.encodeForLDAP(""));
	        assertEquals("Hi This is a test ##��", local.instance.encodeForLDAP("Hi This is a test ##��"), "No special characters to escape");
	        assertEquals("Hi \00", local.instance.encodeForLDAP("Hi \u0000"), "Zeros");
	        assertEquals("Hi \28This\29 = is \2a a \5c test ## � � �", local.instance.encodeForLDAP("Hi (This) = is * a \ test ## � � �"), "LDAP Christams Tree");
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForDN" output="false" hint="Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("encodeForDN");
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("", local.instance.encodeForDN(""));
	        assertEquals("Hello�", local.instance.encodeForDN("Hello�"), "No special characters to escape");
	        assertEquals("\## Hello�", local.instance.encodeForDN("## Hello�"), "leading ##");
	        assertEquals("\ Hello�", local.instance.encodeForDN(" Hello�"), "leading space");
	        assertEquals("Hello�\ ", local.instance.encodeForDN("Hello� "), "trailing space");
	        assertEquals("Hello\<\>", local.instance.encodeForDN("Hello<>"), "less than greater than");
	        assertEquals("\  \ ", local.instance.encodeForDN("   "), "only 3 spaces");
	        assertEquals('\ Hello\\ \+ \, \"World\" \;\ ', local.instance.encodeForDN(' Hello\ + , "World" ; '), "Christmas Tree DN");
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLNull" output="false">
		<cfscript>
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("", local.instance.encodeForXML(""));
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLSpace" output="false">
		<cfscript>
	        local.instance = instance.ESAPI.encoder();
	        assertEquals(" ", local.instance.encodeForXML(" "));
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLScript" output="false">
		<cfscript>
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("&##x3c;script&##x3e;", local.instance.encodeForXML("<script>"));
    	</cfscript>
	</cffunction>


    <cffunction access="public" returntype="void" name="testEncodeForXMLImmune" output="false">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("encodeForXML");
	        local.instance = instance.ESAPI.encoder();
	        assertEquals(",.-_", local.instance.encodeForXML(",.-_"));
    	</cfscript>
	</cffunction>


    <cffunction access="public" returntype="void" name="testEncodeForXMLSymbol" output="false">
		<cfscript>
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.instance.encodeForXML("!@$%()=+{}[]"));
    	</cfscript>
	</cffunction>


    <cffunction access="public" returntype="void" name="testEncodeForXMLPound" output="false">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("encodeForXML");
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("&##xa3;", local.instance.encodeForXML("\u00A3"));
    	</cfscript>
	</cffunction>


   <cffunction access="public" returntype="void" name="testEncodeForXMLAttributeNull" output="false">
		<cfscript>
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("", local.instance.encodeForXMLAttribute(""));
    	</cfscript>
	</cffunction>


    <cffunction access="public" returntype="void" name="testEncodeForXMLAttributeSpace" output="false">
		<cfscript>
	        local.instance = instance.ESAPI.encoder();
	        assertEquals(" ", local.instance.encodeForXMLAttribute(" "));
    	</cfscript>
	</cffunction>


    <cffunction access="public" returntype="void" name="testEncodeForXMLAttributeScript" output="false">
		<cfscript>
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("&##x3c;script&##x3e;", local.instance.encodeForXMLAttribute("<script>"));
    	</cfscript>
	</cffunction>


    <cffunction access="public" returntype="void" name="testEncodeForXMLAttributeImmune" output="false">
		<cfscript>
	        local.instance = instance.ESAPI.encoder();
	        assertEquals(",.-_", local.instance.encodeForXMLAttribute(",.-_"));
    	</cfscript>
	</cffunction>


    <cffunction access="public" returntype="void" name="testEncodeForXMLAttributeSymbol" output="false">
		<cfscript>
	        local.instance = instance.ESAPI.encoder();
	        assertEquals(" &##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.instance.encodeForXMLAttribute(" !@$%()=+{}[]"));
    	</cfscript>
	</cffunction>


    <cffunction access="public" returntype="void" name="testEncodeForXMLAttributePound" output="false">
		<cfscript>
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("&##xa3;", local.instance.encodeForXMLAttribute("\u00A3"));
    	</cfscript>
	</cffunction>


    <cffunction access="public" returntype="void" name="testEncodeForURL" output="false" hint="Test of encodeForURL method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("encodeForURL");
	        local.instance = instance.ESAPI.encoder();
	        assertEquals("", local.instance.encodeForURL(""));
	        assertEquals("%3Cscript%3E", local.instance.encodeForURL("<script>"));
    	</cfscript>
	</cffunction>


    <cffunction access="public" returntype="void" name="testDecodeFromURL" output="false" hint="Test of decodeFromURL method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        createObject("java", "java.lang.System").out.println("decodeFromURL");
	        local.instance = instance.ESAPI.encoder();
	        try {
	        	assertEquals("", local.instance.decodeFromURL(""));
	            assertEquals("<script>", local.instance.decodeFromURL("%3Cscript%3E"));
	            assertEquals("     ", local.instance.decodeFromURL("+++++") );
	        } catch ( cfesapi.org.owasp.esapi.errors.EncodingException e ) {
	            fail();
	        }
	        try {
	        	local.instance.decodeFromURL( "%3xridiculous" );
	        	fail();
	        } catch( cfesapi.org.owasp.esapi.errors.EncodingException e ) {
	        	// expected
	        }
    	</cfscript>
	</cffunction>


    <cffunction access="public" returntype="void" name="testEncodeForBase64" output="false" hint="Test of encodeForBase64 method, of class org.owasp.esapi.Encoder.">
		<cfscript>
			Arrays = createObject("java", "java.util.Arrays");
			DefaultEncoder = javaLoader().create("org.owasp.esapi.reference.DefaultEncoder");

	        createObject("java", "java.lang.System").out.println("encodeForBase64");
	        local.instance = instance.ESAPI.encoder();

	        try {
	        	assertEquals("", local.instance.encodeForBase64("", false));
	            assertEquals("", local.instance.encodeForBase64("", true));
	            assertEquals("", local.instance.decodeFromBase64(""));
	            for ( local.i=0; local.i < 100; local.i++ ) {
	                local.r = instance.ESAPI.randomizer().getRandomString( 20, DefaultEncoder.CHAR_SPECIALS ).getBytes(static.PREFERRED_ENCODING);
	                local.encoded = local.instance.encodeForBase64( local.r, instance.ESAPI.randomizer().getRandomBoolean() );
	                local.decoded = local.instance.decodeFromBase64( local.encoded );
	                assertEquals( charsetEncode(local.r, 'utf-8'), charsetEncode(local.decoded, 'utf-8') );
	            }
	        } catch ( java.io.IOException e ) {
	            fail();
	        }
    	</cfscript>
	</cffunction>


    <cffunction access="public" returntype="void" name="testDecodeFromBase64" output="false" hint="Test of decodeFromBase64 method, of class org.owasp.esapi.Encoder.">
		<cfscript>
			Arrays = createObject("java", "java.util.Arrays");
			DefaultEncoder = javaLoader().create("org.owasp.esapi.reference.DefaultEncoder");

			createObject("java", "java.lang.System").out.println("decodeFromBase64");
			local.instance = instance.ESAPI.encoder();
			for ( local.i=0; local.i < 100; local.i++ ) {
			    try {
			        local.r = instance.ESAPI.randomizer().getRandomString( 20, DefaultEncoder.CHAR_SPECIALS ).getBytes(static.PREFERRED_ENCODING);
			        local.encoded = local.instance.encodeForBase64( local.r, instance.ESAPI.randomizer().getRandomBoolean() );
			        local.decoded = local.instance.decodeFromBase64( local.encoded );
			        assertTrue( Arrays.equals( local.r, local.decoded ) );
			    } catch ( java.io.IOException e ) {
			        fail();
			 }
			}
			for ( local.i=0; local.i < 100; local.i++ ) {
			    try {
			        local.r = instance.ESAPI.randomizer().getRandomString( 20, DefaultEncoder.CHAR_SPECIALS ).getBytes(static.PREFERRED_ENCODING);
			        local.encoded = instance.ESAPI.randomizer().getRandomString(1, DefaultEncoder.CHAR_ALPHANUMERICS) & local.instance.encodeForBase64( local.r, instance.ESAPI.randomizer().getRandomBoolean() );
			     	local.decoded = local.instance.decodeFromBase64( local.encoded );
			    	assertFalse( Arrays.equals(local.r, local.decoded) );
			    } catch( java.io.UnsupportedEncodingException ex) {
			    	fail();
			    } catch ( IOException e ) {
			    	// expected
			    }
			}
		</cfscript>
	</cffunction>


    <cffunction access="public" returntype="void" name="testWindowsCodec" output="false" hint="Test of WindowsCodec">
		<cfscript>
			Character = createObject("java", "java.lang.Character");
			DefaultEncoder = javaLoader().create("org.owasp.esapi.reference.DefaultEncoder");
			PushbackString = javaLoader().create("org.owasp.esapi.codecs.PushbackString");

	        createObject("java", "java.lang.System").out.println("WindowsCodec");
	        local.instance = instance.ESAPI.encoder();

	        local.win = javaLoader().create("org.owasp.esapi.codecs.WindowsCodec").init();
	        local.immune = Character.toChars(0);
	        assertEquals("", local.instance.encodeForOS(local.win, ""));

	        local.npbs = PushbackString.init("n");
	        //assertEquals("", local.win.decodeCharacter(local.npbs));
	        assertTrue(isNull(local.win.decodeCharacter(local.npbs)));

	        local.epbs = PushbackString.init("");
	        //assertEquals("", local.win.decodeCharacter(local.epbs));
	        assertTrue(isNull(local.win.decodeCharacter(local.epbs)));

	        local.c = Character.valueOf('<');
	        local.cpbs = PushbackString.init(local.win.encodeCharacter(local.immune, local.c));
	        local.decoded = local.win.decodeCharacter(local.cpbs);
	        assertEquals(local.c, local.decoded);

	        local.orig = "c:\jeff";
	        local.enc = local.win.encode(DefaultEncoder.CHAR_ALPHANUMERICS, local.orig);
	        assertEquals(local.orig, local.win.decode(local.enc));
	        assertEquals(local.orig, local.win.decode(local.orig));

			// TODO: Check that these are acceptable for Windows
	        assertEquals("c^:^\jeff", local.instance.encodeForOS(local.win, "c:\jeff"));
	        assertEquals("c^:^\jeff", local.win.encode(local.immune, "c:\jeff"));
	        assertEquals("dir^ ^&^ foo", local.instance.encodeForOS(local.win, "dir & foo"));
	        assertEquals("dir^ ^&^ foo", local.win.encode(local.immune, "dir & foo"));
		</cfscript>
	</cffunction>


    <cffunction access="public" returntype="void" name="testUnixCodec" output="false" hint="Test of UnixCodec">
		<cfscript>
			Character = createObject("java", "java.lang.Character");
			PushbackString = javaLoader().create("org.owasp.esapi.codecs.PushbackString");

	        createObject("java", "java.lang.System").out.println("UnixCodec");
	        local.instance = instance.ESAPI.encoder();

	        local.unix = javaLoader().create("org.owasp.esapi.codecs.UnixCodec").init();
	        local.immune = Character.toChars(0);
	        assertEquals("", local.instance.encodeForOS(local.unix, ""));

	        local.npbs = PushbackString.init("n");
	        //assertEquals("", local.unix.decodeCharacter(local.npbs));
	        assertTrue(isNull(local.unix.decodeCharacter(local.npbs)));

	        local.c = Character.valueOf('<');
	        local.cpbs = PushbackString.init(local.unix.encodeCharacter(local.immune, local.c));
	        local.decoded = local.unix.decodeCharacter(local.cpbs);
	        assertEquals(local.c, local.decoded);

	        local.epbs = PushbackString.init("");
	        //assertEquals("", local.unix.decodeCharacter(local.epbs));
	        assertTrue(isNull(local.unix.decodeCharacter(local.epbs)));

	        local.orig = "/etc/passwd";
	        local.enc = local.unix.encode(local.immune, local.orig);
	        assertEquals(local.orig, local.unix.decode(local.enc));
	        assertEquals(local.orig, local.unix.decode(local.orig));

	     	// TODO: Check that these are acceptable for Unix hosts
	        assertEquals("c\:\\jeff", local.instance.encodeForOS(local.unix, "c:\jeff"));
	        assertEquals("c\:\\jeff", local.unix.encode(local.immune, "c:\jeff"));
	        assertEquals("dir\ \&\ foo", local.instance.encodeForOS(local.unix, "dir & foo"));
	        assertEquals("dir\ \&\ foo", local.unix.encode(local.immune, "dir & foo"));

	        // Unix paths (that must be encoded safely)
	        // TODO: Check that these are acceptable for Unix
	        assertEquals("\/etc\/hosts", local.instance.encodeForOS(local.unix, "/etc/hosts"));
	        assertEquals("\/etc\/hosts\;\ ls\ -l", local.instance.encodeForOS(local.unix, "/etc/hosts; ls -l"));
    	</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testCanonicalizePerformance" output="false">
		<cfscript>
			System = createObject("java", "java.lang.System");

			System.out.println("Canonicalization Performance");
			local.encoder = instance.ESAPI.encoder();
			local.iterations = 100;
			local.normal = "The quick brown fox jumped over the lazy dog";

			local.start = System.currentTimeMillis();
			local.temp = "";		// Trade in 1/2 doz warnings in Eclipse for one (never read)
			for ( local.i=0; local.i< local.iterations; local.i++ ) {
				local.temp = local.normal;
			}
			local.stop = System.currentTimeMillis();
			System.out.println( "Normal: " & (local.stop-local.start) );

			local.start = System.currentTimeMillis();
			for ( local.i=0; local.i< local.iterations; local.i++ ) {
				local.temp = local.encoder.canonicalize( local.normal, false );
			}
			local.stop = System.currentTimeMillis();
			System.out.println( "Normal Loose: " & (local.stop-local.start) );

			local.start = System.currentTimeMillis();
			for ( local.i=0; local.i< local.iterations; local.i++ ) {
				local.temp = local.encoder.canonicalize( local.normal, true );
			}
			local.stop = System.currentTimeMillis();
			System.out.println( "Normal Strict: " & (local.stop-local.start) );

			local.attack = "%2&##x35;2%3525&##x32;\\u0036lt;\r\n\r\n%&##x%%%3333\\u0033;&%23101;";

			local.start = System.currentTimeMillis();
			for ( local.i=0; local.i< local.iterations; local.i++ ) {
				local.temp = local.attack;
			}
			local.stop = System.currentTimeMillis();
			System.out.println( "Attack: " & (local.stop-local.start) );

			local.start = System.currentTimeMillis();
			for ( local.i=0; local.i< local.iterations; local.i++ ) {
				local.temp = local.encoder.canonicalize( local.attack, false );
			}
			local.stop = System.currentTimeMillis();
			System.out.println( "Attack Loose: " & (local.stop-local.start) );

			local.start = System.currentTimeMillis();
			for ( local.i=0; local.i< local.iterations; local.i++ ) {
				try {
					local.temp = local.encoder.canonicalize( local.attack, true );
				} catch( cfesapi.org.owasp.esapi.errors.IntrusionException e ) {
					// expected
				}
			}
			local.stop = System.currentTimeMillis();
			System.out.println( "Attack Strict: " & (local.stop-local.start) );
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="void" name="testConcurrency" output="false">
        <cfset createObject("java", "java.lang.System").out.println("Encoder Concurrency") />
		<cfloop index="i" from="1" to="10">
			<cfthread action="run" name="#i#">
				<cfscript>
					createObject("component", "EncoderConcurrencyMock").init( i ).run();
				</cfscript>
			</cfthread>
		</cfloop>
	</cffunction>


</cfcomponent>
