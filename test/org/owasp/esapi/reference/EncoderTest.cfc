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
<cfcomponent extends="cfesapi.test.org.owasp.esapi.lang.TestCase" output="false">

	<cfscript>
		instance.ESAPI = new cfesapi.org.owasp.esapi.ESAPI();
		
		instance.PREFERRED_ENCODING = "UTF-8";
	</cfscript>
 
	<cffunction access="private" returntype="string" name="toUnicode" output="false" description="Convert Unicode in to string characters">
		<cfargument type="string" name="string" required="true">
		<cfscript>
		 	local.ret = "";
		 	for (local.i=1; local.i <= len(arguments.string); local.i++) {
		 		local.thisChr = mid(arguments.string, local.i, 6);
		 		if (left(local.thisChr, 2) == "\u") {
			 		local.ret = local.ret & chr(inputBaseN(right(local.thisChr, 4), 16));
			 		local.i = local.i+5;
		 		}
				else {
		 			local.ret = local.ret & left(local.thisChr, 1);
		 		}
		 	}
		 	return local.ret;
		 </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testCanonicalize" output="false" hint="Test of canonicalize method, of class org.owasp.esapi.Encoder.">
		<cfscript>
			newJava("java.lang.System").out.println("canonicalize");

	        local.list = [];
	        local.list.add( "HTMLEntityCodec" );
		    local.list.add( "PercentCodec" );
			local.encoder = new cfesapi.org.owasp.esapi.reference.DefaultEncoder( instance.ESAPI, local.list );

			// Test null paths
			assertEquals( "", local.encoder.canonicalize(""));
			assertEquals( "", local.encoder.canonicalize("", true));
			assertEquals( "", local.encoder.canonicalize("", false));
			assertEquals( "", local.encoder.canonicalize("", true, true));
			assertEquals( "", local.encoder.canonicalize("", true, false));
			assertEquals( "", local.encoder.canonicalize("", false, true));
			assertEquals( "", local.encoder.canonicalize("", false, false));

			// test exception paths
			assertEquals( "%", local.encoder.canonicalize("%25", true));
			assertEquals( "%", local.encoder.canonicalize("%25", false));

	        assertEquals( "%", local.encoder.canonicalize("%25"));
	        assertEquals( "%F", local.encoder.canonicalize("%25F"));
	        assertEquals( "<", local.encoder.canonicalize("%3c"));
	        assertEquals( "<", local.encoder.canonicalize("%3C"));
	        assertEquals( "%X1", local.encoder.canonicalize("%X1"));

	        assertEquals( "<", local.encoder.canonicalize("&lt"));
	        assertEquals( "<", local.encoder.canonicalize("&LT"));
	        assertEquals( "<", local.encoder.canonicalize("&lt;"));
	        assertEquals( "<", local.encoder.canonicalize("&LT;"));

	        assertEquals( "%", local.encoder.canonicalize("&##37;"));
	        assertEquals( "%", local.encoder.canonicalize("&##37"));
	        assertEquals( "%b", local.encoder.canonicalize("&##37b"));

	        assertEquals( "<", local.encoder.canonicalize("&##x3c"));
	        assertEquals( "<", local.encoder.canonicalize("&##x3c;"));
	        assertEquals( "<", local.encoder.canonicalize("&##x3C"));
	        assertEquals( "<", local.encoder.canonicalize("&##X3c"));
	        assertEquals( "<", local.encoder.canonicalize("&##X3C"));
	        assertEquals( "<", local.encoder.canonicalize("&##X3C;"));

	        // percent encoding
	        assertEquals( "<", local.encoder.canonicalize("%3c"));
	        assertEquals( "<", local.encoder.canonicalize("%3C"));

	        // html entity encoding
	        assertEquals( "<", local.encoder.canonicalize("&##60"));
	        assertEquals( "<", local.encoder.canonicalize("&##060"));
	        assertEquals( "<", local.encoder.canonicalize("&##0060"));
	        assertEquals( "<", local.encoder.canonicalize("&##00060"));
	        assertEquals( "<", local.encoder.canonicalize("&##000060"));
	        assertEquals( "<", local.encoder.canonicalize("&##0000060"));
	        assertEquals( "<", local.encoder.canonicalize("&##60;"));
	        assertEquals( "<", local.encoder.canonicalize("&##060;"));
	        assertEquals( "<", local.encoder.canonicalize("&##0060;"));
	        assertEquals( "<", local.encoder.canonicalize("&##00060;"));
	        assertEquals( "<", local.encoder.canonicalize("&##000060;"));
	        assertEquals( "<", local.encoder.canonicalize("&##0000060;"));
	        assertEquals( "<", local.encoder.canonicalize("&##x3c"));
	        assertEquals( "<", local.encoder.canonicalize("&##x03c"));
	        assertEquals( "<", local.encoder.canonicalize("&##x003c"));
	        assertEquals( "<", local.encoder.canonicalize("&##x0003c"));
	        assertEquals( "<", local.encoder.canonicalize("&##x00003c"));
	        assertEquals( "<", local.encoder.canonicalize("&##x000003c"));
	        assertEquals( "<", local.encoder.canonicalize("&##x3c;"));
	        assertEquals( "<", local.encoder.canonicalize("&##x03c;"));
	        assertEquals( "<", local.encoder.canonicalize("&##x003c;"));
	        assertEquals( "<", local.encoder.canonicalize("&##x0003c;"));
	        assertEquals( "<", local.encoder.canonicalize("&##x00003c;"));
	        assertEquals( "<", local.encoder.canonicalize("&##x000003c;"));
	        assertEquals( "<", local.encoder.canonicalize("&##X3c"));
	        assertEquals( "<", local.encoder.canonicalize("&##X03c"));
	        assertEquals( "<", local.encoder.canonicalize("&##X003c"));
	        assertEquals( "<", local.encoder.canonicalize("&##X0003c"));
	        assertEquals( "<", local.encoder.canonicalize("&##X00003c"));
	        assertEquals( "<", local.encoder.canonicalize("&##X000003c"));
	        assertEquals( "<", local.encoder.canonicalize("&##X3c;"));
	        assertEquals( "<", local.encoder.canonicalize("&##X03c;"));
	        assertEquals( "<", local.encoder.canonicalize("&##X003c;"));
	        assertEquals( "<", local.encoder.canonicalize("&##X0003c;"));
	        assertEquals( "<", local.encoder.canonicalize("&##X00003c;"));
	        assertEquals( "<", local.encoder.canonicalize("&##X000003c;"));
	        assertEquals( "<", local.encoder.canonicalize("&##x3C"));
	        assertEquals( "<", local.encoder.canonicalize("&##x03C"));
	        assertEquals( "<", local.encoder.canonicalize("&##x003C"));
	        assertEquals( "<", local.encoder.canonicalize("&##x0003C"));
	        assertEquals( "<", local.encoder.canonicalize("&##x00003C"));
	        assertEquals( "<", local.encoder.canonicalize("&##x000003C"));
	        assertEquals( "<", local.encoder.canonicalize("&##x3C;"));
	        assertEquals( "<", local.encoder.canonicalize("&##x03C;"));
	        assertEquals( "<", local.encoder.canonicalize("&##x003C;"));
	        assertEquals( "<", local.encoder.canonicalize("&##x0003C;"));
	        assertEquals( "<", local.encoder.canonicalize("&##x00003C;"));
	        assertEquals( "<", local.encoder.canonicalize("&##x000003C;"));
	        assertEquals( "<", local.encoder.canonicalize("&##X3C"));
	        assertEquals( "<", local.encoder.canonicalize("&##X03C"));
	        assertEquals( "<", local.encoder.canonicalize("&##X003C"));
	        assertEquals( "<", local.encoder.canonicalize("&##X0003C"));
	        assertEquals( "<", local.encoder.canonicalize("&##X00003C"));
	        assertEquals( "<", local.encoder.canonicalize("&##X000003C"));
	        assertEquals( "<", local.encoder.canonicalize("&##X3C;"));
	        assertEquals( "<", local.encoder.canonicalize("&##X03C;"));
	        assertEquals( "<", local.encoder.canonicalize("&##X003C;"));
	        assertEquals( "<", local.encoder.canonicalize("&##X0003C;"));
	        assertEquals( "<", local.encoder.canonicalize("&##X00003C;"));
	        assertEquals( "<", local.encoder.canonicalize("&##X000003C;"));
	        assertEquals( "<", local.encoder.canonicalize("&lt"));
	        assertEquals( "<", local.encoder.canonicalize("&lT"));
	        assertEquals( "<", local.encoder.canonicalize("&Lt"));
	        assertEquals( "<", local.encoder.canonicalize("&LT"));
	        assertEquals( "<", local.encoder.canonicalize("&lt;"));
	        assertEquals( "<", local.encoder.canonicalize("&lT;"));
	        assertEquals( "<", local.encoder.canonicalize("&Lt;"));
	        assertEquals( "<", local.encoder.canonicalize("&LT;"));

	        assertEquals( '<script>alert("hello");</script>', local.encoder.canonicalize("%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E") );
	        assertEquals( '<script>alert("hello");</script>', local.encoder.canonicalize("%3Cscript&##x3E;alert%28%22hello&##34%29%3B%3C%2Fscript%3E", false) );

	        // javascript escape syntax
	        local.js = [];
	        local.js.add( "JavaScriptCodec" );
	        local.encoder = new cfesapi.org.owasp.esapi.reference.DefaultEncoder( instance.ESAPI, local.js );
	        newJava("java.lang.System").out.println( "JavaScript Decoding" );

	        assertEquals( "\0", local.encoder.canonicalize("\0"));
	        assertEquals( "\b", local.encoder.canonicalize("\b"));
	        assertEquals( "\t", local.encoder.canonicalize("\\t"));
	        assertEquals( "\n", local.encoder.canonicalize("\\n"));
	        assertEquals( "" & inputBaseN("0b", 16), local.encoder.canonicalize("\\v"));
	        assertEquals( "\f", local.encoder.canonicalize("\\f"));
	        assertEquals( "\r", local.encoder.canonicalize("\\r"));
	        assertEquals( "\'", local.encoder.canonicalize("\\'"));
	        assertEquals( '\"', local.encoder.canonicalize('\\"'));
	        assertEquals( "\\", local.encoder.canonicalize("\\\\"));
	        assertEquals( "<", local.encoder.canonicalize("\\<"));

	        assertEquals( "<", local.encoder.canonicalize("\\u003c"));
	        assertEquals( "<", local.encoder.canonicalize("\\U003c"));
	        assertEquals( "<", local.encoder.canonicalize("\\u003C"));
	        assertEquals( "<", local.encoder.canonicalize("\\U003C"));
	        assertEquals( "<", local.encoder.canonicalize("\\x3c"));
	        assertEquals( "<", local.encoder.canonicalize("\\X3c"));
	        assertEquals( "<", local.encoder.canonicalize("\\x3C"));
	        assertEquals( "<", local.encoder.canonicalize("\\X3C"));

	        // css escape syntax
	        // be careful because some codecs see \0 as null byte
	        local.css = [];
	        local.css.add( "CSSCodec" );
	        local.encoder = new cfesapi.org.owasp.esapi.reference.DefaultEncoder( instance.ESAPI, local.css );
	        newJava("java.lang.System").out.println( "CSS Decoding" );
	        assertEquals( "<", local.encoder.canonicalize("\\3c"));  // add strings to prevent null byte
	        assertEquals( "<", local.encoder.canonicalize("\\03c"));
	        assertEquals( "<", local.encoder.canonicalize("\\003c"));
	        assertEquals( "<", local.encoder.canonicalize("\\0003c"));
	        assertEquals( "<", local.encoder.canonicalize("\\00003c"));
	        assertEquals( "<", local.encoder.canonicalize("\\3C"));
	        assertEquals( "<", local.encoder.canonicalize("\\03C"));
	        assertEquals( "<", local.encoder.canonicalize("\\003C"));
	        assertEquals( "<", local.encoder.canonicalize("\\0003C"));
	        assertEquals( "<", local.encoder.canonicalize("\\00003C"));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testDoubleEncodingCanonicalization" output="false" hint="Test of canonicalize method, of class org.owasp.esapi.Encoder.">
		<cfscript>
			newJava("java.lang.System").out.println("doubleEncodingCanonicalization");
			local.encoder = instance.ESAPI.encoder();
			
			/* note these examples use the strict=false flag on canonicalize to allow
			full decoding without throwing an IntrusionException. Generally, you
			should use strict mode as allowing double-encoding is an abomination. */
			
			/* double encoding examples */
			assertEquals( "<", local.encoder.canonicalize("&##x26;lt&##59", false )); /* double entity */
			assertEquals( "\", local.encoder.canonicalize("%255c", false)); /* double percent */
			assertEquals( "%", local.encoder.canonicalize("%2525", false)); /* double percent */
			
			/* double encoding with multiple schemes example */
			assertEquals( "<", local.encoder.canonicalize("%26lt%3b", false)); /* first entity, then percent */
			assertEquals( "&", local.encoder.canonicalize("&##x25;26", false)); /* first percent, then entity */
			
			/* enforce multiple and mixed encoding detection */
			try {
				local.encoder.canonicalize("%26lt; %26lt; &##X25;3c &##x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", true, true);
				fail("Multiple and mixed encoding not detected");
			}
			catch (cfesapi.org.owasp.esapi.errors.IntrusionException ie) {
				/* expected */
			}
			
			/* enforce multiple but not mixed encoding detection */
			try {
				local.encoder.canonicalize("%252525253C", true, false);
				fail("Multiple encoding not detected");
			}
			catch (cfesapi.org.owasp.esapi.errors.IntrusionException ie) {
				/* expected */
			}
			
			/* enforce mixed but not multiple encoding detection */
			try {
				local.encoder.canonicalize("%25 %2526 %26##X3c;script&##x3e; &##37;3Cscript%25252525253e", false, true);
				fail("Mixed encoding not detected");
			}
			catch (cfesapi.org.owasp.esapi.errors.IntrusionException ie) {
				/* expected */
			}
			
			/* enforce niether mixed nor multiple encoding detection -should canonicalize but not throw an error */
			assertEquals( "< < < < < < <", local.encoder.canonicalize("%26lt; %26lt; &##X25;3c &##x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", false, false)); /* nested encoding examples */
			assertEquals( "<", local.encoder.canonicalize("%253c", false)); /* nested encode % with percent */
			assertEquals( "<", local.encoder.canonicalize("%%33%63", false)); /* nested encode both nibbles with percent */
			assertEquals( "<", local.encoder.canonicalize("%%33c", false)); /* nested encode first nibble with percent */
			assertEquals( "<", local.encoder.canonicalize("%3%63", false)); /* nested encode second nibble with percent */
			assertEquals( "<", local.encoder.canonicalize("&&##108;t;", false)); /* nested encode l with entity */
			assertEquals( "<", local.encoder.canonicalize("%2&##x35;3c", false)); /* triple percent, percent, 5 with entity */
			
			/* nested encoding with multiple schemes examples */
			assertEquals( "<", local.encoder.canonicalize("&%6ct;", false)); /* nested encode l with percent */
			assertEquals( "<", local.encoder.canonicalize("%&##x33;c", false)); /* nested encode 3 with entity */
			
			/* multiple encoding tests */
			assertEquals( "% & <script> <script>", local.encoder.canonicalize( "%25 %2526 %26##X3c;script&##x3e; &##37;3Cscript%25252525253e", false ) );
			assertEquals( "< < < < < < <", local.encoder.canonicalize( "%26lt; %26lt; &##X25;3c &##x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", false ) );
			
			/* test strict mode with both mixed and multiple encoding */
			try {
				assertEquals( "< < < < < < <", local.encoder.canonicalize( "%26lt; %26lt; &##X25;3c &##x25;3c %2526lt%253B %2526lt%253B %2526lt%253B" ) );
			}
			catch( cfesapi.org.owasp.esapi.errors.IntrusionException e ) {
				/* expected */
			}
			
			try {
				assertEquals( "<script", local.encoder.canonicalize("%253Cscript" ) );
	        }
	        catch( cfesapi.org.owasp.esapi.errors.IntrusionException e ) {
	            /* expected */
	        }
	        
	        try {
	            assertEquals( "<script", local.encoder.canonicalize("&##37;3Cscript" ) );
	        }
	        catch( cfesapi.org.owasp.esapi.errors.IntrusionException e ) {
	            /* expected */
	        }
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForHTML" output="false" hint="Test of encodeForHTML method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        newJava("java.lang.System").out.println("encodeForHTML");
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("", local.encoder.encodeForHTML(""));
	        // test invalid characters are replaced with spaces
	        assertEquals("a&##xfffd;b&##xfffd;c&##xfffd;d&##xfffd;e&##xfffd;f&##x9;g", local.encoder.encodeForHTML("a" & chr(1) & "b" & chr(4) & "c" & chr(128) & "d" & chr(150) & "e" &chr(159) & "f" & chr(9) & "g"));

	        assertEquals("&lt;script&gt;", local.encoder.encodeForHTML("<script>"));
	        assertEquals("&amp;lt&##x3b;script&amp;gt&##x3b;", local.encoder.encodeForHTML("&lt;script&gt;"));
	        assertEquals("&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.encoder.encodeForHTML("!@$%()=+{}[]"));
	        assertEquals("&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.encoder.encodeForHTML(local.encoder.canonicalize("&##33;&##64;&##36;&##37;&##40;&##41;&##61;&##43;&##123;&##125;&##91;&##93;") ) );
	        assertEquals(",.-_ ", local.encoder.encodeForHTML(",.-_ "));
	        assertEquals("dir&amp;", local.encoder.encodeForHTML("dir&"));
	        assertEquals("one&amp;two", local.encoder.encodeForHTML("one&two"));
	        assertEquals("" & chr(12345) & chr(65533) & chr(1244), "" & chr(12345) & chr(65533) & chr(1244) );
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForHTMLAttribute" output="false" hint="Test of encodeForHTMLAttribute method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        newJava("java.lang.System").out.println("encodeForHTMLAttribute");
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("", local.encoder.encodeForHTMLAttribute(""));
	        assertEquals("&lt;script&gt;", local.encoder.encodeForHTMLAttribute("<script>"));
	        assertEquals(",.-_", local.encoder.encodeForHTMLAttribute(",.-_"));
	        assertEquals("&##x20;&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.encoder.encodeForHTMLAttribute(" !@$%()=+{}[]"));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForCSS" output="false">
		<cfscript>
	        newJava("java.lang.System").out.println("encodeForCSS");
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("", local.encoder.encodeForCSS(""));
	        assertEquals("\3c script\3e ", local.encoder.encodeForCSS("<script>"));
	        assertEquals("\21 \40 \24 \25 \28 \29 \3d \2b \7b \7d \5b \5d ", local.encoder.encodeForCSS("!@$%()=+{}[]"));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForJavascript" output="false" hint="Test of encodeForJavaScript method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        newJava("java.lang.System").out.println("encodeForJavascript");
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("", local.encoder.encodeForJavaScript(""));
	        assertEquals("\x3Cscript\x3E", local.encoder.encodeForJavaScript("<script>"));
	        assertEquals(",.\x2D_\x20", local.encoder.encodeForJavaScript(",.-_ "));
	        assertEquals("\x21\x40\x24\x25\x28\x29\x3D\x2B\x7B\x7D\x5B\x5D", local.encoder.encodeForJavaScript("!@$%()=+{}[]"));
	        // assertEquals( "\0", local.encoder.encodeForJavaScript("\0"));
	        // assertEquals( "\b", local.encoder.encodeForJavaScript("\b"));
	        // assertEquals( "\t", local.encoder.encodeForJavaScript("\t"));
	        // assertEquals( "\n", local.encoder.encodeForJavaScript("\n"));
	        // assertEquals( "\v", local.encoder.encodeForJavaScript("" + (char)0x0b));
	        // assertEquals( "\f", local.encoder.encodeForJavaScript("\f"));
	        // assertEquals( "\r", local.encoder.encodeForJavaScript("\r"));
	        // assertEquals( "\'", local.encoder.encodeForJavaScript("\'"));
	        // assertEquals( '\"', local.encoder.encodeForJavaScript('\"'));
	        // assertEquals( "\\", local.encoder.encodeForJavaScript("\\"));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForVBScript" output="false">
		<cfscript>
	        newJava("java.lang.System").out.println("encodeForVBScript");
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("", local.encoder.encodeForVBScript(""));
	        assertEquals( 'chrw(60)&"script"&chrw(62)', local.encoder.encodeForVBScript("<script>"));
	        assertEquals( 'x"&chrw(32)&chrw(33)&chrw(64)&chrw(36)&chrw(37)&chrw(40)&chrw(41)&chrw(61)&chrw(43)&chrw(123)&chrw(125)&chrw(91)&chrw(93)', local.encoder.encodeForVBScript("x !@$%()=+{}[]"));
	        assertEquals( 'alert"&chrw(40)&chrw(39)&"ESAPI"&chrw(32)&"test"&chrw(33)&chrw(39)&chrw(41)', local.encoder.encodeForVBScript("alert('ESAPI test!')" ));
	        assertEquals( 'jeff.williams"&chrw(64)&"aspectsecurity.com', local.encoder.encodeForVBScript("jeff.williams@aspectsecurity.com"));
	        assertEquals( 'test"&chrw(32)&chrw(60)&chrw(62)&chrw(32)&"test', local.encoder.encodeForVBScript("test <> test" ));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXPath" output="false" hint="Test of encodeForXPath method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        newJava("java.lang.System").out.println("encodeForXPath");
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("", local.encoder.encodeForXPath(""));
	        assertEquals("&##x27;or 1&##x3d;1", local.encoder.encodeForXPath("'or 1=1"));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForSQL" output="false" hint="Test of encodeForSQL method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        newJava("java.lang.System").out.println("encodeForSQL");
	        local.encoder = instance.ESAPI.encoder();

	        local.mySQL1 = newJava("org.owasp.esapi.codecs.MySQLCodec").init( newJava("org.owasp.esapi.codecs.MySQLCodec").ANSI_MODE );
	        assertEquals("", local.encoder.encodeForSQL(local.mySQL1, ""), "ANSI_MODE");
	        assertEquals("Jeff'' or ''1''=''1", local.encoder.encodeForSQL(local.mySQL1, "Jeff' or '1'='1"), "ANSI_MODE");

	        local.mySQL2 = newJava("org.owasp.esapi.codecs.MySQLCodec").init( newJava("org.owasp.esapi.codecs.MySQLCodec").MYSQL_MODE );
	        assertEquals("", local.encoder.encodeForSQL(local.mySQL2, ""), "MYSQL_MODE");
	        assertEquals("Jeff\' or \'1\'\=\'1", local.encoder.encodeForSQL(local.mySQL2, "Jeff' or '1'='1"), "MYSQL_MODE");

	        local.oracle = newJava("org.owasp.esapi.codecs.OracleCodec").init();
	        assertEquals("", local.encoder.encodeForSQL(local.oracle, ""), "Oracle");
	        assertEquals("Jeff'' or ''1''=''1", local.encoder.encodeForSQL(local.oracle, "Jeff' or '1'='1"), "Oracle");
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testMySQLANSIModeQuoteInjection" output="false">
		<cfscript>
	        local.encoder = instance.ESAPI.encoder();
	        local.c = newJava("org.owasp.esapi.codecs.MySQLCodec").init(newJava("org.owasp.esapi.codecs.MySQLCodec").ANSI_MODE);
	        assertEquals(" or 1=1 -- -", local.encoder.encodeForSQL(c, '" or 1=1 -- -'), "MySQL Ansi Quote Injection Bug");
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForLDAP" output="false" hint="Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        newJava("java.lang.System").out.println("encodeForLDAP");
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("", local.encoder.encodeForLDAP(""));
	        assertEquals("Hi This is a test ##��", local.encoder.encodeForLDAP("Hi This is a test ##��"), "No special characters to escape");
	        // nulls are not valid CF tests: assertEquals("Hi \00", local.encoder.encodeForLDAP("Hi " & toUnicode("\u0000")), "Zeros");
	        assertEquals("Hi \28This\29 = is \2a a \5c test ## � � �", local.encoder.encodeForLDAP("Hi (This) = is * a \ test ## � � �"), "LDAP Christams Tree");
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForDN" output="false" hint="Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        newJava("java.lang.System").out.println("encodeForDN");
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("", local.encoder.encodeForDN(""));
	        assertEquals("Hello�", local.encoder.encodeForDN("Hello�"), "No special characters to escape");
	        assertEquals("\## Hello�", local.encoder.encodeForDN("## Hello�"), "leading ##");
	        assertEquals("\ Hello�", local.encoder.encodeForDN(" Hello�"), "leading space");
	        assertEquals("Hello�\ ", local.encoder.encodeForDN("Hello� "), "trailing space");
	        assertEquals("Hello\<\>", local.encoder.encodeForDN("Hello<>"), "less than greater than");
	        assertEquals("\  \ ", local.encoder.encodeForDN("   "), "only 3 spaces");
	        assertEquals('\ Hello\\ \+ \, \"World\" \;\ ', local.encoder.encodeForDN(' Hello\ + , "World" ; '), "Christmas Tree DN");
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLNull" output="false">
		<cfscript>
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("", local.encoder.encodeForXML(""));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLSpace" output="false">
		<cfscript>
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals(" ", local.encoder.encodeForXML(" "));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLScript" output="false">
		<cfscript>
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("&##x3c;script&##x3e;", local.encoder.encodeForXML("<script>"));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLImmune" output="false">
		<cfscript>
	        newJava("java.lang.System").out.println("encodeForXML");
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals(",.-_", local.encoder.encodeForXML(",.-_"));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLSymbol" output="false">
		<cfscript>
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.encoder.encodeForXML("!@$%()=+{}[]"));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLPound" output="false">
		<cfscript>
	        newJava("java.lang.System").out.println("encodeForXML");
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("&##xa3;", local.encoder.encodeForXML(toUnicode("\u00A3")));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributeNull" output="false">
		<cfscript>
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("", local.encoder.encodeForXMLAttribute(""));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributeSpace" output="false">
		<cfscript>
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals(" ", local.encoder.encodeForXMLAttribute(" "));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributeScript" output="false">
		<cfscript>
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("&##x3c;script&##x3e;", local.encoder.encodeForXMLAttribute("<script>"));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributeImmune" output="false">
		<cfscript>
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals(",.-_", local.encoder.encodeForXMLAttribute(",.-_"));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributeSymbol" output="false">
		<cfscript>
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals(" &##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", local.encoder.encodeForXMLAttribute(" !@$%()=+{}[]"));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForXMLAttributePound" output="false">
		<cfscript>
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("&##xa3;", local.encoder.encodeForXMLAttribute(toUnicode("\u00A3")));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForURL" output="false" hint="Test of encodeForURL method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        newJava("java.lang.System").out.println("encodeForURL");
	        local.encoder = instance.ESAPI.encoder();
	        assertEquals("", local.encoder.encodeForURL(""));
	        assertEquals("%3Cscript%3E", local.encoder.encodeForURL("<script>"));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testDecodeFromURL" output="false" hint="Test of decodeFromURL method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        newJava("java.lang.System").out.println("decodeFromURL");
	        local.encoder = instance.ESAPI.encoder();
	        try {
	        	assertEquals("", local.encoder.decodeFromURL(""));
	            assertEquals("<script>", local.encoder.decodeFromURL("%3Cscript%3E"));
	            assertEquals("     ", local.encoder.decodeFromURL("+++++") );
	        } catch ( cfesapi.org.owasp.esapi.errors.EncodingException e ) {
	            fail();
	        }
	        try {
	        	local.encoder.decodeFromURL( "%3xridiculous" );
	        	fail();
	        } catch( cfesapi.org.owasp.esapi.errors.EncodingException e ) {
	        	// expected
	        }
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testEncodeForBase64" output="false" hint="Test of encodeForBase64 method, of class org.owasp.esapi.Encoder.">
		<cfscript>
	        newJava("java.lang.System").out.println("encodeForBase64");
	        local.encoder = instance.ESAPI.encoder();

	        try {
	        	// null tests are not valid for CF
	        	//assertEquals(null, local.encoder.encodeForBase64(null, false));
	            //assertEquals(null, local.encoder.encodeForBase64(null, true));
	            //assertEquals(null, local.encoder.decodeFromBase64(null));
	            for ( local.i=0; local.i < 100; local.i++ ) {
	                local.r = instance.ESAPI.randomizer().getRandomString( 20, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_SPECIALS ).getBytes(instance.PREFERRED_ENCODING);
	                local.encoded = local.encoder.encodeForBase64( local.r, instance.ESAPI.randomizer().getRandomBoolean() );
	                local.decoded = local.encoder.decodeFromBase64( local.encoded );
	                assertEquals( charsetEncode(local.r, 'utf-8'), charsetEncode(local.decoded, 'utf-8') );
	            }
	        } catch ( java.io.IOException e ) {
	            fail();
	        }
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testDecodeFromBase64" output="false" hint="Test of decodeFromBase64 method, of class org.owasp.esapi.Encoder.">
		<cfscript>
			// using newJava() in assertX() gives syntax error in CFB
			Arrays = newJava("java.util.Arrays");

			newJava("java.lang.System").out.println("decodeFromBase64");
			local.encoder = instance.ESAPI.encoder();
			for ( local.i=0; local.i < 100; local.i++ ) {
			    try {
			        local.r = instance.ESAPI.randomizer().getRandomString( 20, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_SPECIALS ).getBytes(instance.PREFERRED_ENCODING);
			        local.encoded = local.encoder.encodeForBase64( local.r, instance.ESAPI.randomizer().getRandomBoolean() );
			        local.decoded = local.encoder.decodeFromBase64( local.encoded );
			        assertTrue( Arrays.equals( local.r, local.decoded ) );
			    } catch ( java.io.IOException e ) {
			        fail();
			 }
			}
			for ( local.i=0; local.i < 100; local.i++ ) {
			    try {
			        local.r = instance.ESAPI.randomizer().getRandomString( 20, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_SPECIALS ).getBytes(instance.PREFERRED_ENCODING);
			        local.encoded = instance.ESAPI.randomizer().getRandomString(1, newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS) & local.encoder.encodeForBase64( local.r, instance.ESAPI.randomizer().getRandomBoolean() );
			     	local.decoded = local.encoder.decodeFromBase64( local.encoded );
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
	        newJava("java.lang.System").out.println("WindowsCodec");
	        local.encoder = instance.ESAPI.encoder();

	        local.win = newJava("org.owasp.esapi.codecs.WindowsCodec").init();
	        local.immune = newJava("java.lang.Character").toChars(0);
	        assertEquals("", local.encoder.encodeForOS(local.win, ""));

	        local.npbs = newJava("org.owasp.esapi.codecs.PushbackString").init("n");
	        //assertEquals("", local.win.decodeCharacter(local.npbs));
	        assertTrue(isNull(local.win.decodeCharacter(local.npbs)));

	        local.epbs = newJava("org.owasp.esapi.codecs.PushbackString").init("");
	        //assertEquals("", local.win.decodeCharacter(local.epbs));
	        assertTrue(isNull(local.win.decodeCharacter(local.epbs)));

	        local.c = newJava("java.lang.Character").valueOf('<');
	        local.cpbs = newJava("org.owasp.esapi.codecs.PushbackString").init(local.win.encodeCharacter(local.immune, local.c));
	        local.decoded = local.win.decodeCharacter(local.cpbs);
	        assertEquals(local.c, local.decoded);

	        local.orig = "c:\jeff";
	        local.enc = local.win.encode(newJava("org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS, local.orig);
	        assertEquals(local.orig, local.win.decode(local.enc));
	        assertEquals(local.orig, local.win.decode(local.orig));

			// TODO: Check that these are acceptable for Windows
	        assertEquals("c^:^\jeff", local.encoder.encodeForOS(local.win, "c:\jeff"));
	        assertEquals("c^:^\jeff", local.win.encode(local.immune, "c:\jeff"));
	        assertEquals("dir^ ^&^ foo", local.encoder.encodeForOS(local.win, "dir & foo"));
	        assertEquals("dir^ ^&^ foo", local.win.encode(local.immune, "dir & foo"));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testUnixCodec" output="false" hint="Test of UnixCodec">
		<cfscript>
	        newJava("java.lang.System").out.println("UnixCodec");
	        local.encoder = instance.ESAPI.encoder();

	        local.unix = newJava("org.owasp.esapi.codecs.UnixCodec").init();
	        local.immune = newJava("java.lang.Character").toChars(0);
	        assertEquals("", local.encoder.encodeForOS(local.unix, ""));

	        local.npbs = newJava("org.owasp.esapi.codecs.PushbackString").init("n");
	        //assertEquals("", local.unix.decodeCharacter(local.npbs));
	        assertTrue(isNull(local.unix.decodeCharacter(local.npbs)));

	        local.c = newJava("java.lang.Character").valueOf('<');
	        local.cpbs = newJava("org.owasp.esapi.codecs.PushbackString").init(local.unix.encodeCharacter(local.immune, local.c));
	        local.decoded = local.unix.decodeCharacter(local.cpbs);
	        assertEquals(local.c, local.decoded);

	        local.epbs = newJava("org.owasp.esapi.codecs.PushbackString").init("");
	        //assertEquals("", local.unix.decodeCharacter(local.epbs));
	        assertTrue(isNull(local.unix.decodeCharacter(local.epbs)));

	        local.orig = "/etc/passwd";
	        local.enc = local.unix.encode(local.immune, local.orig);
	        assertEquals(local.orig, local.unix.decode(local.enc));
	        assertEquals(local.orig, local.unix.decode(local.orig));

	     	// TODO: Check that these are acceptable for Unix hosts
	        assertEquals("c\:\\jeff", local.encoder.encodeForOS(local.unix, "c:\jeff"));
	        assertEquals("c\:\\jeff", local.unix.encode(local.immune, "c:\jeff"));
	        assertEquals("dir\ \&\ foo", local.encoder.encodeForOS(local.unix, "dir & foo"));
	        assertEquals("dir\ \&\ foo", local.unix.encode(local.immune, "dir & foo"));

	        // Unix paths (that must be encoded safely)
	        // TODO: Check that these are acceptable for Unix
	        assertEquals("\/etc\/hosts", local.encoder.encodeForOS(local.unix, "/etc/hosts"));
	        assertEquals("\/etc\/hosts\;\ ls\ -l", local.encoder.encodeForOS(local.unix, "/etc/hosts; ls -l"));
    	</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testCanonicalizePerformance" output="false">
		<cfscript>
			newJava("java.lang.System").out.println("Canonicalization Performance");
			local.encoder = instance.ESAPI.encoder();
			local.iterations = 100;
			local.normal = "The quick brown fox jumped over the lazy dog";

			local.start = newJava("java.lang.System").currentTimeMillis();
			local.temp = "";		// Trade in 1/2 doz warnings in Eclipse for one (never read)
			for ( local.i=0; local.i< local.iterations; local.i++ ) {
				local.temp = local.normal;
			}
			local.stop = newJava("java.lang.System").currentTimeMillis();
			newJava("java.lang.System").out.println( "Normal: " & (local.stop-local.start) );

			local.start = newJava("java.lang.System").currentTimeMillis();
			for ( local.i=0; local.i< local.iterations; local.i++ ) {
				local.temp = local.encoder.canonicalize( local.normal, false );
			}
			local.stop = newJava("java.lang.System").currentTimeMillis();
			newJava("java.lang.System").out.println( "Normal Loose: " & (local.stop-local.start) );

			local.start = newJava("java.lang.System").currentTimeMillis();
			for ( local.i=0; local.i< local.iterations; local.i++ ) {
				local.temp = local.encoder.canonicalize( local.normal, true );
			}
			local.stop = newJava("java.lang.System").currentTimeMillis();
			newJava("java.lang.System").out.println( "Normal Strict: " & (local.stop-local.start) );

			local.attack = "%2&##x35;2%3525&##x32;" & toUnicode("\u0036") & "lt;\r\n\r\n%&##x%%%3333" & toUnicode('\u0033') & ";&%23101;";

			local.start = newJava("java.lang.System").currentTimeMillis();
			for ( local.i=0; local.i< local.iterations; local.i++ ) {
				local.temp = local.attack;
			}
			local.stop = newJava("java.lang.System").currentTimeMillis();
			newJava("java.lang.System").out.println( "Attack: " & (local.stop-local.start) );

			local.start = newJava("java.lang.System").currentTimeMillis();
			for ( local.i=0; local.i< local.iterations; local.i++ ) {
				local.temp = local.encoder.canonicalize( local.attack, false );
			}
			local.stop = newJava("java.lang.System").currentTimeMillis();
			newJava("java.lang.System").out.println( "Attack Loose: " & (local.stop-local.start) );

			local.start = newJava("java.lang.System").currentTimeMillis();
			for ( local.i=0; local.i< local.iterations; local.i++ ) {
				try {
					local.temp = local.encoder.canonicalize( local.attack, true );
				} catch( cfesapi.org.owasp.esapi.errors.IntrusionException e ) {
					// expected
				}
			}
			local.stop = newJava("java.lang.System").currentTimeMillis();
			newJava("java.lang.System").out.println( "Attack Strict: " & (local.stop-local.start) );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="void" name="testConcurrency" output="false">
		<cfset newJava("java.lang.System").out.println("Encoder Concurrency") />
		<cfloop index="i" from="1" to="10">
			<cfthread action="run" name="#i#">
				<cfscript>
					new EncoderConcurrencyMock( i ).run();
				</cfscript> 
			</cfthread>
		</cfloop>
	</cffunction>


</cfcomponent>
