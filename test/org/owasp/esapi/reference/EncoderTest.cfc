/*
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
import "org.owasp.esapi.reference.Encoder";
import "org.owasp.esapi.util.Utils";

/**
 * The Class EncoderTest.
 */
component extends="esapi4cf.test.org.owasp.esapi.util.TestCase" {
	pageEncoding "utf-8";

	variables.PREFERRED_ENCODING = "UTF-8";

	variables.testForNull = false;
	if (server.coldfusion.productName == "Railo" || server.coldfusion.productName == "Lucee") {
		variables.testForNull = true;
	}

	public void function testCanonicalize() {
		variables.System.out.println("canonicalize");

        var list = [];
        list.add( "HTMLEntityCodec" );
	    list.add( "PercentCodec" );
		var instance = new Encoder( variables.ESAPI, list );

		// Test null paths
		if (variables.testForNull) {
			assertEquals( "", instance.canonicalize(javaCast("null", "")));
			assertEquals( "", instance.canonicalize(javaCast("null", ""), true));
			assertEquals( "", instance.canonicalize(javaCast("null", ""), false));
			assertEquals( "", instance.canonicalize(javaCast("null", ""), true, true));
			assertEquals( "", instance.canonicalize(javaCast("null", ""), true, false));
			assertEquals( "", instance.canonicalize(javaCast("null", ""), false, true));
			assertEquals( "", instance.canonicalize(javaCast("null", ""), false, false));
		}

		// test exception paths
		assertEquals( "%", instance.canonicalize("%25", true));
		assertEquals( "%", instance.canonicalize("%25", false));

        assertEquals( "%", instance.canonicalize("%25"));
        assertEquals( "%F", instance.canonicalize("%25F"));
        assertEquals( "<", instance.canonicalize("%3c"));
        assertEquals( "<", instance.canonicalize("%3C"));
        assertEquals( "%X1", instance.canonicalize("%X1"));

        assertEquals( "<", instance.canonicalize("&lt"));
        assertEquals( "<", instance.canonicalize("&LT"));
        assertEquals( "<", instance.canonicalize("&lt;"));
        assertEquals( "<", instance.canonicalize("&LT;"));

        assertEquals( "%", instance.canonicalize("&##37;"));
        assertEquals( "%", instance.canonicalize("&##37"));
        assertEquals( "%b", instance.canonicalize("&##37b"));

        assertEquals( "<", instance.canonicalize("&##x3c"));
        assertEquals( "<", instance.canonicalize("&##x3c;"));
        assertEquals( "<", instance.canonicalize("&##x3C"));
        assertEquals( "<", instance.canonicalize("&##X3c"));
        assertEquals( "<", instance.canonicalize("&##X3C"));
        assertEquals( "<", instance.canonicalize("&##X3C;"));

        // percent encoding
        assertEquals( "<", instance.canonicalize("%3c"));
        assertEquals( "<", instance.canonicalize("%3C"));

        // html entity encoding
        assertEquals( "<", instance.canonicalize("&##60"));
        assertEquals( "<", instance.canonicalize("&##060"));
        assertEquals( "<", instance.canonicalize("&##0060"));
        assertEquals( "<", instance.canonicalize("&##00060"));
        assertEquals( "<", instance.canonicalize("&##000060"));
        assertEquals( "<", instance.canonicalize("&##0000060"));
        assertEquals( "<", instance.canonicalize("&##60;"));
        assertEquals( "<", instance.canonicalize("&##060;"));
        assertEquals( "<", instance.canonicalize("&##0060;"));
        assertEquals( "<", instance.canonicalize("&##00060;"));
        assertEquals( "<", instance.canonicalize("&##000060;"));
        assertEquals( "<", instance.canonicalize("&##0000060;"));
        assertEquals( "<", instance.canonicalize("&##x3c"));
        assertEquals( "<", instance.canonicalize("&##x03c"));
        assertEquals( "<", instance.canonicalize("&##x003c"));
        assertEquals( "<", instance.canonicalize("&##x0003c"));
        assertEquals( "<", instance.canonicalize("&##x00003c"));
        assertEquals( "<", instance.canonicalize("&##x000003c"));
        assertEquals( "<", instance.canonicalize("&##x3c;"));
        assertEquals( "<", instance.canonicalize("&##x03c;"));
        assertEquals( "<", instance.canonicalize("&##x003c;"));
        assertEquals( "<", instance.canonicalize("&##x0003c;"));
        assertEquals( "<", instance.canonicalize("&##x00003c;"));
        assertEquals( "<", instance.canonicalize("&##x000003c;"));
        assertEquals( "<", instance.canonicalize("&##X3c"));
        assertEquals( "<", instance.canonicalize("&##X03c"));
        assertEquals( "<", instance.canonicalize("&##X003c"));
        assertEquals( "<", instance.canonicalize("&##X0003c"));
        assertEquals( "<", instance.canonicalize("&##X00003c"));
        assertEquals( "<", instance.canonicalize("&##X000003c"));
        assertEquals( "<", instance.canonicalize("&##X3c;"));
        assertEquals( "<", instance.canonicalize("&##X03c;"));
        assertEquals( "<", instance.canonicalize("&##X003c;"));
        assertEquals( "<", instance.canonicalize("&##X0003c;"));
        assertEquals( "<", instance.canonicalize("&##X00003c;"));
        assertEquals( "<", instance.canonicalize("&##X000003c;"));
        assertEquals( "<", instance.canonicalize("&##x3C"));
        assertEquals( "<", instance.canonicalize("&##x03C"));
        assertEquals( "<", instance.canonicalize("&##x003C"));
        assertEquals( "<", instance.canonicalize("&##x0003C"));
        assertEquals( "<", instance.canonicalize("&##x00003C"));
        assertEquals( "<", instance.canonicalize("&##x000003C"));
        assertEquals( "<", instance.canonicalize("&##x3C;"));
        assertEquals( "<", instance.canonicalize("&##x03C;"));
        assertEquals( "<", instance.canonicalize("&##x003C;"));
        assertEquals( "<", instance.canonicalize("&##x0003C;"));
        assertEquals( "<", instance.canonicalize("&##x00003C;"));
        assertEquals( "<", instance.canonicalize("&##x000003C;"));
        assertEquals( "<", instance.canonicalize("&##X3C"));
        assertEquals( "<", instance.canonicalize("&##X03C"));
        assertEquals( "<", instance.canonicalize("&##X003C"));
        assertEquals( "<", instance.canonicalize("&##X0003C"));
        assertEquals( "<", instance.canonicalize("&##X00003C"));
        assertEquals( "<", instance.canonicalize("&##X000003C"));
        assertEquals( "<", instance.canonicalize("&##X3C;"));
        assertEquals( "<", instance.canonicalize("&##X03C;"));
        assertEquals( "<", instance.canonicalize("&##X003C;"));
        assertEquals( "<", instance.canonicalize("&##X0003C;"));
        assertEquals( "<", instance.canonicalize("&##X00003C;"));
        assertEquals( "<", instance.canonicalize("&##X000003C;"));
        assertEquals( "<", instance.canonicalize("&lt"));
        assertEquals( "<", instance.canonicalize("&lT"));
        assertEquals( "<", instance.canonicalize("&Lt"));
        assertEquals( "<", instance.canonicalize("&LT"));
        assertEquals( "<", instance.canonicalize("&lt;"));
        assertEquals( "<", instance.canonicalize("&lT;"));
        assertEquals( "<", instance.canonicalize("&Lt;"));
        assertEquals( "<", instance.canonicalize("&LT;"));

        assertEquals( '<script>alert("hello");</script>', instance.canonicalize("%3Cscript%3Ealert%28%22hello%22%29%3B%3C%2Fscript%3E") );
        assertEquals( '<script>alert("hello");</script>', instance.canonicalize("%3Cscript&##x3E;alert%28%22hello&##34%29%3B%3C%2Fscript%3E", false) );

        // javascript escape syntax
        var js = [];
        js.add( "JavaScriptCodec" );
        var instance = new Encoder( variables.ESAPI, js );
        variables.System.out.println( "JavaScript Decoding" );

        assertEquals( 0, asc(instance.canonicalize("\0")));
        assertEquals( chr(8), instance.canonicalize("\b"));
        assertEquals( chr(9), instance.canonicalize("\t"));
        assertEquals( chr(10), instance.canonicalize("\n"));
        assertEquals( chr(11), instance.canonicalize("\v"));
        assertEquals( chr(12), instance.canonicalize("\f"));
        assertEquals( chr(13), instance.canonicalize("\r"));
        assertEquals( "'", instance.canonicalize("\'"));
        assertEquals( '"', instance.canonicalize('\"'));
        assertEquals( "\", instance.canonicalize("\\"));
        assertEquals( "<", instance.canonicalize("\<"));

        assertEquals( "<", instance.canonicalize("\u003c"));
        assertEquals( "<", instance.canonicalize("\U003c"));
        assertEquals( "<", instance.canonicalize("\u003C"));
        assertEquals( "<", instance.canonicalize("\U003C"));
        assertEquals( "<", instance.canonicalize("\x3c"));
        assertEquals( "<", instance.canonicalize("\X3c"));
        assertEquals( "<", instance.canonicalize("\x3C"));
        assertEquals( "<", instance.canonicalize("\X3C"));

        // css escape syntax
        // be careful because some codecs see \0 as null byte
        var css = [];
        css.add( "CSSCodec" );
        var instance = new Encoder( variables.ESAPI, css );
        variables.System.out.println( "CSS Decoding" );
        assertEquals( "<", instance.canonicalize("\3c"));  // add strings to prevent null byte
        assertEquals( "<", instance.canonicalize("\03c"));
        assertEquals( "<", instance.canonicalize("\003c"));
        assertEquals( "<", instance.canonicalize("\0003c"));
        assertEquals( "<", instance.canonicalize("\00003c"));
        assertEquals( "<", instance.canonicalize("\3C"));
        assertEquals( "<", instance.canonicalize("\03C"));
        assertEquals( "<", instance.canonicalize("\003C"));
        assertEquals( "<", instance.canonicalize("\0003C"));
        assertEquals( "<", instance.canonicalize("\00003C"));
	}


    /**
     * Test of canonicalize method, of class org.owasp.esapi.Encoder.
     *
     * @throws EncodingException
     */
    public void function testDoubleEncodingCanonicalization() {
        variables.System.out.println("doubleEncodingCanonicalization");
        var instance = variables.ESAPI.encoder();

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

		//enforce multiple and mixed encoding detection
		try {
			instance.canonicalize("%26lt; %26lt; &##X25;3c &##x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", true, true);
			fail("Multiple and mixed encoding not detected");
		} catch (org.owasp.esapi.errors.IntrusionException ie) {}

		//enforce multiple but not mixed encoding detection
		try {
			instance.canonicalize("%252525253C", true, false);
			fail("Multiple encoding not detected");
		} catch (org.owasp.esapi.errors.IntrusionException ie) {}

		//enforce mixed but not multiple encoding detection
		try {
			instance.canonicalize("%25 %2526 %26##X3c;script&##x3e; &##37;3Cscript%25252525253e", false, true);
			fail("Mixed encoding not detected");
		} catch (org.owasp.esapi.errors.IntrusionException ie) {}

		//enforce niether mixed nor multiple encoding detection -should canonicalize but not throw an error
		assertEquals( "< < < < < < <", instance.canonicalize("%26lt; %26lt; &##X25;3c &##x25;3c %2526lt%253B %2526lt%253B %2526lt%253B", false, false));

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
        } catch( org.owasp.esapi.errors.IntrusionException e ) {
            // expected
        }

        try {
            assertEquals( "<script", instance.canonicalize("%253Cscript" ) );
        } catch( org.owasp.esapi.errors.IntrusionException e ) {
            // expected
        }
        try {
            assertEquals( "<script", instance.canonicalize("&##37;3Cscript" ) );
        } catch( org.owasp.esapi.errors.IntrusionException e ) {
            // expected
        }
    }

    /**
	 * Test of encodeForHTML method, of class org.owasp.esapi.Encoder.
     *
     * @throws Exception
     */
	public void function testEncodeForHTML() {
        variables.System.out.println("encodeForHTML");
        var instance = variables.ESAPI.encoder();
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForHTML(javaCast("null", "")));
        }
        // test invalid characters are replaced with spaces
        assertEquals("ab&##xfffd;c&##xfffd;d&##xfffd;e&##xfffd;f&##x9;g", instance.encodeForHTML("a" & chr(0) & "b" & chr(4) & "c" & chr(128) & "d" & chr(150) & "e" &chr(159) & "f" & chr(9) & "g"));

        assertEquals("&lt;script&gt;", instance.encodeForHTML("<script>"));
        assertEquals("&amp;lt&##x3b;script&amp;gt&##x3b;", instance.encodeForHTML("&lt;script&gt;"));
        assertEquals("&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", instance.encodeForHTML("!@$%()=+{}[]"));
        assertEquals("&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", instance.encodeForHTML(instance.canonicalize("&##33;&##64;&##36;&##37;&##40;&##41;&##61;&##43;&##123;&##125;&##91;&##93;") ) );
        assertEquals(",.-_ ", instance.encodeForHTML(",.-_ "));
        assertEquals("dir&amp;", instance.encodeForHTML("dir&"));
        assertEquals("one&amp;two", instance.encodeForHTML("one&two"));
        assertEquals("" & chr(12345) & chr(65533) & chr(1244), "" & chr(12345) & chr(65533) & chr(1244) );
    }

    /**
	 * Test of encodeForHTMLAttribute method, of class org.owasp.esapi.Encoder.
	 */
	public void function testEncodeForHTMLAttribute() {
        variables.System.out.println("encodeForHTMLAttribute");
        var instance = variables.ESAPI.encoder();
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForHTMLAttribute(javaCast("null", "")));
        }
        assertEquals("&lt;script&gt;", instance.encodeForHTMLAttribute("<script>"));
        assertEquals(",.-_", instance.encodeForHTMLAttribute(",.-_"));
        assertEquals("&##x20;&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", instance.encodeForHTMLAttribute(" !@$%()=+{}[]"));
    }


    /**
     *
     */
	public void function testEncodeForCSS() {
        variables.System.out.println("encodeForCSS");
        var instance = variables.ESAPI.encoder();
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForCSS(javaCast("null", "")));
        }
        assertEquals("\3c script\3e ", instance.encodeForCSS("<script>"));
        assertEquals("\21 \40 \24 \25 \28 \29 \3d \2b \7b \7d \5b \5d ", instance.encodeForCSS("!@$%()=+{}[]"));
    }



    /**
	 * Test of encodeForJavaScript method, of class org.owasp.esapi.Encoder.
	 */
	public void function testEncodeForJavascript() {
        variables.System.out.println("encodeForJavascript");
        var instance = variables.ESAPI.encoder();
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForJavaScript(javaCast("null", "")));
        }
        assertEquals("\x3Cscript\x3E", instance.encodeForJavaScript("<script>"));
        assertEquals(",.\x2D_\x20", instance.encodeForJavaScript(",.-_ "));
        assertEquals("\x21\x40\x24\x25\x28\x29\x3D\x2B\x7B\x7D\x5B\x5D", instance.encodeForJavaScript("!@$%()=+{}[]"));
        // assertEquals( 0, asc(instance.encodeForJavaScript(chr(0))));
        // assertEquals( "\b", instance.encodeForJavaScript(chr(8)));
        // assertEquals( "\t", instance.encodeForJavaScript(chr(9)));
        // assertEquals( "\n", instance.encodeForJavaScript(chr(10)));
        // assertEquals( "\v", instance.encodeForJavaScript(chr(inputBaseN("0b", 16))));
        // assertEquals( "\f", instance.encodeForJavaScript(chr(12)));
        // assertEquals( "\r", instance.encodeForJavaScript(chr(13)));
        // assertEquals( "\'", instance.encodeForJavaScript("'"));
        // assertEquals( '\"', instance.encodeForJavaScript('"'));
        // assertEquals( "\\", instance.encodeForJavaScript("\"));
    }

	public void function testEncodeForVBScript() {
        variables.System.out.println("encodeForVBScript");
        var instance = variables.ESAPI.encoder();
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForVBScript(javaCast("null", "")));
        }
        assertEquals( 'chrw(60)&"script"&chrw(62)', instance.encodeForVBScript("<script>"));
        assertEquals( 'x"&chrw(32)&chrw(33)&chrw(64)&chrw(36)&chrw(37)&chrw(40)&chrw(41)&chrw(61)&chrw(43)&chrw(123)&chrw(125)&chrw(91)&chrw(93)', instance.encodeForVBScript("x !@$%()=+{}[]"));
        assertEquals( 'alert"&chrw(40)&chrw(39)&"ESAPI"&chrw(32)&"test"&chrw(33)&chrw(39)&chrw(41)', instance.encodeForVBScript("alert('ESAPI test!')" ));
        assertEquals( 'jeff.williams"&chrw(64)&"aspectsecurity.com', instance.encodeForVBScript("jeff.williams@aspectsecurity.com"));
        assertEquals( 'test"&chrw(32)&chrw(60)&chrw(62)&chrw(32)&"test', instance.encodeForVBScript("test <> test" ));
    }

    /**
	 * Test of encodeForXPath method, of class org.owasp.esapi.Encoder.
	 */
	public void function testEncodeForXPath() {
        variables.System.out.println("encodeForXPath");
        var instance = variables.ESAPI.encoder();
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForXPath(javaCast("null", "")));
        }
        assertEquals("&##x27;or 1&##x3d;1", instance.encodeForXPath("'or 1=1"));
    }



    /**
	 * Test of encodeForSQL method, of class org.owasp.esapi.Encoder.
	 */
	public void function testEncodeForSQL() {
        variables.System.out.println("encodeForSQL");
        var instance = variables.ESAPI.encoder();
		var MySQLCodec = createObject("java", "org.owasp.esapi.codecs.MySQLCodec");

        var mySQL1 = MySQLCodec.init( MySQLCodec.ANSI_MODE );
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForSQL(mySQL1, javaCast("null", "")), "ANSI_MODE");
        }
        assertEquals("Jeff'' or ''1''=''1", instance.encodeForSQL(mySQL1, "Jeff' or '1'='1"), "ANSI_MODE");

        var mySQL2 = MySQLCodec.init( MySQLCodec.MYSQL_MODE );
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForSQL(mySQL2, javaCast("null", "")), "MYSQL_MODE");
        }
        assertEquals("Jeff\' or \'1\'\=\'1", instance.encodeForSQL(mySQL2, "Jeff' or '1'='1"), "MYSQL_MODE");

        var oracle = createObject("java", "org.owasp.esapi.codecs.OracleCodec").init();
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForSQL(oracle, javaCast("null", "")), "Oracle");
        }
        assertEquals("Jeff'' or ''1''=''1", instance.encodeForSQL(oracle, "Jeff' or '1'='1"), "Oracle");
    }

    public void function testMySQLANSIModeQuoteInjection() {
    	var MySQLCodec = createObject("java", "org.owasp.esapi.codecs.MySQLCodec");
        var instance = variables.ESAPI.encoder();
        var c = MySQLCodec.init(MySQLCodec.ANSI_MODE);
        assertEquals(" or 1=1 -- -", instance.encodeForSQL(c, '" or 1=1 -- -'), "MySQL Ansi Quote Injection Bug");
    }


    /**
	 * Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.
	 */
    public void function testEncodeForLDAP() {
        variables.System.out.println("encodeForLDAP");
        var instance = variables.ESAPI.encoder();
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForLDAP(javaCast("null", "")));
        }
        assertEquals("Hi This is a test ##��", instance.encodeForLDAP("Hi This is a test ##��"), "No special characters to escape");
        assertEquals("Hi ", instance.encodeForLDAP("Hi " & new Utils().toUnicode("\u0000")), "Zeros");
        assertEquals("Hi \28This\29 = is \2a a \5c test ## � � �", instance.encodeForLDAP("Hi (This) = is * a \ test ## � � �"), "LDAP Christams Tree");
    }

    /**
	 * Test of encodeForLDAP method, of class org.owasp.esapi.Encoder.
	 */
	public void function testEncodeForDN() {
        variables.System.out.println("encodeForDN");
        var instance = variables.ESAPI.encoder();
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForDN(javaCast("null", "")));
        }
        assertEquals("Hello�", instance.encodeForDN("Hello�"), "No special characters to escape");
        assertEquals("\## Hello�", instance.encodeForDN("## Hello�"), "leading ##");
        assertEquals("\ Hello�", instance.encodeForDN(" Hello�"), "leading space");
        assertEquals("Hello�\ ", instance.encodeForDN("Hello� "), "trailing space");
        assertEquals("Hello\<\>", instance.encodeForDN("Hello<>"), "less than greater than");
        assertEquals("\  \ ", instance.encodeForDN("   "), "only 3 spaces");
        assertEquals('\ Hello\\ \+ \, \"World\" \;\ ', instance.encodeForDN(' Hello\ + , "World" ; '), "Christmas Tree DN");
    }

	public void function testEncodeForXMLNull() {
        var instance = variables.ESAPI.encoder();
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForXML(javaCast("null", "")));
        }
    }

	public void function testEncodeForXMLSpace() {
        var instance = variables.ESAPI.encoder();
        assertEquals(" ", instance.encodeForXML(" "));
    }

    public void function testEncodeForXMLScript() {
        var instance = variables.ESAPI.encoder();
        assertEquals("&##x3c;script&##x3e;", instance.encodeForXML("<script>"));
    }

    public void function testEncodeForXMLImmune() {
        variables.System.out.println("encodeForXML");
        var instance = variables.ESAPI.encoder();
        assertEquals(",.-_", instance.encodeForXML(",.-_"));
    }

    public void function testEncodeForXMLSymbol() {
        var instance = variables.ESAPI.encoder();
        assertEquals("&##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", instance.encodeForXML("!@$%()=+{}[]"));
    }

    public void function testEncodeForXMLPound() {
        variables.System.out.println("encodeForXML");
        var instance = variables.ESAPI.encoder();
        assertEquals("&##xa3;", instance.encodeForXML(new Utils().toUnicode("\u00A3")));
    }

    public void function testEncodeForXMLAttributeNull() {
        var instance = variables.ESAPI.encoder();
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForXMLAttribute(javaCast("null", "")));
        }
    }

    public void function testEncodeForXMLAttributeSpace() {
        var instance = variables.ESAPI.encoder();
        assertEquals(" ", instance.encodeForXMLAttribute(" "));
    }

    public void function testEncodeForXMLAttributeScript() {
        var instance = variables.ESAPI.encoder();
        assertEquals("&##x3c;script&##x3e;", instance.encodeForXMLAttribute("<script>"));
    }

    public void function testEncodeForXMLAttributeImmune() {
        var instance = variables.ESAPI.encoder();
        assertEquals(",.-_", instance.encodeForXMLAttribute(",.-_"));
    }

    public void function testEncodeForXMLAttributeSymbol() {
        var instance = variables.ESAPI.encoder();
        assertEquals(" &##x21;&##x40;&##x24;&##x25;&##x28;&##x29;&##x3d;&##x2b;&##x7b;&##x7d;&##x5b;&##x5d;", instance.encodeForXMLAttribute(" !@$%()=+{}[]"));
    }

    public void function testEncodeForXMLAttributePound() {
        var instance = variables.ESAPI.encoder();
        assertEquals("&##xa3;", instance.encodeForXMLAttribute(new Utils().toUnicode("\u00A3")));
    }

    /**
	 * Test of encodeForURL method, of class org.owasp.esapi.Encoder.
     *
     * @throws Exception
     */
    public void function testEncodeForURL() {
        variables.System.out.println("encodeForURL");
        var instance = variables.ESAPI.encoder();
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForURL(javaCast("null", "")));
        }
        assertEquals("%3Cscript%3E", instance.encodeForURL("<script>"));
    }

    /**
	 * Test of decodeFromURL method, of class org.owasp.esapi.Encoder.
     *
     * @throws Exception
     */
    public void function testDecodeFromURL() {
        variables.System.out.println("decodeFromURL");
        var instance = variables.ESAPI.encoder();
        try {
        	if (variables.testForNull) {
        		assertEquals("", instance.decodeFromURL(javaCast("null", "")));
        	}
            assertEquals("<script>", instance.decodeFromURL("%3Cscript%3E"));
            assertEquals("     ", instance.decodeFromURL("+++++") );
        } catch ( java.lang.Exception e ) {
            fail("");
        }
        try {
        	instance.decodeFromURL( "%3xridiculous" );
        	fail("");
        } catch( java.lang.Exception e ) {
        	// expected
        }
    }

    /**
	 * Test of encodeForBase64 method, of class org.owasp.esapi.Encoder.
	 */
    public void function testEncodeForBase64() {
        variables.System.out.println("encodeForBase64");

        var instance = variables.ESAPI.encoder();
		var Arrays = createObject("java", "java.util.Arrays");

        try {
        	if (variables.testForNull) {
	        	assertEquals("", instance.encodeForBase64(javaCast("null", ""), false));
	            assertEquals("", instance.encodeForBase64(javaCast("null", ""), true));
	            assertEquals("", instance.decodeFromBase64(javaCast("null", "")));
	        }
            for ( var i=0; i < 100; i++ ) {
                var r = variables.ESAPI.randomizer().getRandomString( 20, instance.CHAR_SPECIALS ).getBytes(variables.PREFERRED_ENCODING);
                var encoded = instance.encodeForBase64( r, variables.ESAPI.randomizer().getRandomBoolean() );
                var decoded = instance.decodeFromBase64( encoded );
                assertTrue( Arrays.equals( r, decoded ) );
            }
        } catch ( java.io.IOException e ) {
            fail("");
        }
    }

    /**
	 * Test of decodeFromBase64 method, of class org.owasp.esapi.Encoder.
	 */
    public void function testDecodeFromBase64() {
        variables.System.out.println("decodeFromBase64");

        var instance = variables.ESAPI.encoder();
		var Arrays = createObject("java", "java.util.Arrays");
        for ( var i=0; i < 100; i++ ) {
            try {
                var r = variables.ESAPI.randomizer().getRandomString( 20, instance.CHAR_SPECIALS ).getBytes(variables.PREFERRED_ENCODING);
                var encoded = instance.encodeForBase64( r, variables.ESAPI.randomizer().getRandomBoolean() );
                var decoded = instance.decodeFromBase64( encoded );
                assertTrue( Arrays.equals( r, decoded ) );
            } catch ( java.io.IOException e ) {
                fail("");
	        }
        }
        for ( var i=0; i < 100; i++ ) {
            try {
                var r = variables.ESAPI.randomizer().getRandomString( 20, instance.CHAR_SPECIALS ).getBytes(variables.PREFERRED_ENCODING);
                var encoded = variables.ESAPI.randomizer().getRandomString(1, instance.CHAR_ALPHANUMERICS) & instance.encodeForBase64( r, variables.ESAPI.randomizer().getRandomBoolean() );
	            var decoded = instance.decodeFromBase64( encoded );
	            assertFalse( Arrays.equals(r, decoded) );
            } catch( java.io.UnsupportedEncodingException ex) {
            	fail("");
            } catch ( java.io.IOException e ) {
            	// expected
            }
        }
    }


    /**
	 * Test of WindowsCodec
	 */
    public void function testWindowsCodec() {
        variables.System.out.println("WindowsCodec");
        var instance = variables.ESAPI.encoder();
        var PushbackString = createObject("java", "org.owasp.esapi.codecs.PushbackString");

        var win = createObject("java", "org.owasp.esapi.codecs.WindowsCodec").init();
        var immune = chr(0).getBytes();
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForOS(win, javaCast("null", "")));
        }

        var npbs = PushbackString.init("n");
        assertTrue(isNull(win.decodeCharacter(npbs)));

        var epbs = PushbackString.init("");
        assertTrue(isNull(win.decodeCharacter(epbs)));

        var c = createObject("java", "java.lang.Character").valueOf('<');
        var cpbs = PushbackString.init(win.encodeCharacter(javaCast("char[]", immune), c));
        var decoded = win.decodeCharacter(cpbs);
        assertEquals(c, decoded);

        var orig = "c:\jeff";
        var enc = win.encode(instance.CHAR_ALPHANUMERICS, orig);
        assertEquals(orig, win.decode(enc));
        assertEquals(orig, win.decode(orig));

     // TODO: Check that these are acceptable for Windows
        assertEquals("c^:^\jeff", instance.encodeForOS(win, "c:\jeff"));
        assertEquals("c^:^\jeff", win.encode(immune, "c:\jeff"));
        assertEquals("dir^ ^&^ foo", instance.encodeForOS(win, "dir & foo"));
        assertEquals("dir^ ^&^ foo", win.encode(immune, "dir & foo"));
    }

    /**
	 * Test of UnixCodec
	 */
    public void function testUnixCodec() {
        variables.System.out.println("UnixCodec");
        var instance = variables.ESAPI.encoder();
        var PushbackString = createObject("java", "org.owasp.esapi.codecs.PushbackString");

        var unix = createObject("java", "org.owasp.esapi.codecs.UnixCodec").init();
        var immune = chr(0).getBytes();
        if (variables.testForNull) {
        	assertEquals("", instance.encodeForOS(unix, javaCast("null", "")));
        }

        var npbs = PushbackString.init("n");
        assertTrue(isNull(unix.decodeCharacter(npbs)));

        var c = createObject("java", "java.lang.Character").valueOf('<');
        var cpbs = PushbackString.init(unix.encodeCharacter(javaCast("char[]", immune), c));
        var decoded = unix.decodeCharacter(cpbs);
        assertEquals(c, decoded);

        var epbs = PushbackString.init("");
        assertTrue(isNull(unix.decodeCharacter(epbs)));

        var orig = "/etc/passwd";
        var enc = unix.encode(immune, orig);
        assertEquals(orig, unix.decode(enc));
        assertEquals(orig, unix.decode(orig));

     // TODO: Check that these are acceptable for Unix hosts
        assertEquals("c\:\\jeff", instance.encodeForOS(unix, "c:\jeff"));
        assertEquals("c\:\\jeff", unix.encode(immune, "c:\jeff"));
        assertEquals("dir\ \&\ foo", instance.encodeForOS(unix, "dir & foo"));
        assertEquals("dir\ \&\ foo", unix.encode(immune, "dir & foo"));

        // Unix paths (that must be encoded safely)
        // TODO: Check that these are acceptable for Unix
        assertEquals("\/etc\/hosts", instance.encodeForOS(unix, "/etc/hosts"));
        assertEquals("\/etc\/hosts\;\ ls\ -l", instance.encodeForOS(unix, "/etc/hosts; ls -l"));
    }

    public void function testCanonicalizePerformance() {
        variables.System.out.println("Canonicalization Performance");
    	var encoder = variables.ESAPI.encoder();
    	var iterations = 100;
    	var normal = "The quick brown fox jumped over the lazy dog";

    	var start = variables.System.currentTimeMillis();
    	var temp = javaCast("null", "");		// Trade in 1/2 doz warnings in Eclipse for one (never read)
        for ( var i=0; i< iterations; i++ ) {
        	temp = normal;
        }
    	var stop = variables.System.currentTimeMillis();
        variables.System.out.println( "Normal: " & (stop-start) );

    	start = variables.System.currentTimeMillis();
        for ( var i=0; i< iterations; i++ ) {
        	temp = encoder.canonicalize( normal, false );
        }
    	stop = variables.System.currentTimeMillis();
        variables.System.out.println( "Normal Loose: " & (stop-start) );

    	start = variables.System.currentTimeMillis();
        for ( var i=0; i< iterations; i++ ) {
        	temp = encoder.canonicalize( normal, true );
        }
    	stop = variables.System.currentTimeMillis();
        variables.System.out.println( "Normal Strict: " & (stop-start) );

    	var attack = "%2&##x35;2%3525&##x32;\u0036lt;\r\n\r\n%&##x%%%3333\u0033;&%23101;";

    	start = variables.System.currentTimeMillis();
        for ( var i=0; i< iterations; i++ ) {
        	temp = attack;
        }
    	stop = variables.System.currentTimeMillis();
        variables.System.out.println( "Attack: " & (stop-start) );

    	start = variables.System.currentTimeMillis();
        for ( var i=0; i< iterations; i++ ) {
        	temp = encoder.canonicalize( attack, false );
        }
    	stop = variables.System.currentTimeMillis();
        variables.System.out.println( "Attack Loose: " & (stop-start) );

    	start = variables.System.currentTimeMillis();
        for ( var i=0; i< iterations; i++ ) {
        	try {
        		temp = encoder.canonicalize( attack, true );
        	} catch( org.owasp.esapi.errors.IntrusionException e ) {
        		// expected
        	}
        }
    	stop = variables.System.currentTimeMillis();
        variables.System.out.println( "Attack Strict: " & (stop-start) );
    }


    public void function testConcurrency() {
        variables.System.out.println("Encoder Concurrency");

        var threadName = getMetaData().name & "-testConcurrency";

		for (var i = 0; i < 10; i++) {
			thread action="run" name="#threadName#_#i#" {
				// EncoderConcurrencyMock
				thread.returnValue = false;
				// run each thread for no more than 5s
				while (thread.elapsedTime < 5000) {
					var nonce = variables.ESAPI.randomizer().getRandomString(20, variables.ESAPI.encoder().CHAR_SPECIALS);
					var result = variables.ESAPI.encoder().encodeForJavaScript(nonce);
					// randomize the threads
					sleep(variables.ESAPI.randomizer().getRandomInteger(100, 500));

					if (!result.equals(variables.ESAPI.encoder().encodeForJavaScript(nonce))) {
						break;
					}
				}
				thread.returnValue = true;
			}
		}
		// join threads and loop results for any failures
		thread action="join" name="#structKeyList(cfthread)#";

		for (var key in cfthread) {
			if (structKeyExists(cfthread[key], "error")) {
				assertTrue(cfthread[key].returnValue, cfthread[key].error.message);
			}
			else {
				assertTrue(cfthread[key].returnValue);
			}
		}
	}

}

