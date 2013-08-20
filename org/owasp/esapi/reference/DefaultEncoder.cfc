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
<cfcomponent implements="org.owasp.esapi.Encoder" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Encoder interface. This implementation takes a whitelist approach to encoding, meaning that everything not specifically identified in a list of 'immune' characters is encoded. Several methods follow the approach in the Microsoft AntiXSS Library. The Encoder performs two key functions The canonicalization algorithm is complex, as it has to be able to recognize encoded characters that might affect downstream interpreters without being told what encodings are possible. The stream is read one character at a time. If an encoded character is encountered, it is canonicalized and pushed back onto the stream. If the next character is encoded, then a intrusion exception is thrown for the double-encoding which is assumed to be an attack. The encoding methods also attempt to prevent double encoding, by canonicalizing strings that are passed to them for encoding. Currently the implementation supports: HTML Entity Encoding (including non-terminated), Percent Encoding, Backslash Encoding">

	<cfscript>
		// Codecs
		variables.codecs = [];
		variables.htmlCodec = newJava( "org.owasp.esapi.codecs.HTMLEntityCodec" ).init();
		variables.xmlCodec = newJava( "org.owasp.esapi.codecs.XMLEntityCodec" ).init();
		variables.percentCodec = newJava( "org.owasp.esapi.codecs.PercentCodec" ).init();
		variables.javaScriptCodec = newJava( "org.owasp.esapi.codecs.JavaScriptCodec" ).init();
		variables.vbScriptCodec = newJava( "org.owasp.esapi.codecs.VBScriptCodec" ).init();
		variables.cssCodec = newJava( "org.owasp.esapi.codecs.CSSCodec" ).init();

		/** The logger. */
		variables.logger = "";

		/** Character sets that define characters immune from encoding in various formats */
		variables.IMMUNE_HTML = [',', '.', '-', '_', ' '];
		variables.IMMUNE_HTMLATTR = [',', '.', '-', '_'];
		variables.IMMUNE_CSS = [' '];// TODO: check
		variables.IMMUNE_JAVASCRIPT = [',', '.', '-', '_', ' '];
		variables.IMMUNE_VBSCRIPT = [' '];// TODO: check
		variables.IMMUNE_XML = [',', '.', '-', '_', ' '];
		variables.IMMUNE_SQL = [' '];
		variables.IMMUNE_OS = ['-'];
		variables.IMMUNE_XMLATTR = [',', '.', '-', '_'];
		variables.IMMUNE_XPATH = [',', '.', '-', '_', ' '];
	</cfscript>
 
	<cffunction access="public" returntype="org.owasp.esapi.Encoder" name="init" output="false" hint="Instantiates a new DefaultEncoder">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI">
		<cfargument type="Array" name="codecs" hint="A list of codecs to use by the Encoder class">
		<cfscript>
			// CF8 requires 'var' at the top
			var i = 0;
			var o = "";
			
			variables.ESAPI = arguments.ESAPI;
			variables.logger = variables.ESAPI.getLogger( "Encoder" );

			if(structKeyExists( arguments, "codecs" )) {

				for(i = 1; i <= arrayLen( arguments.codecs ); i++) {
					o = arguments.codecs[i];
					/* FIXME: this condition fails in Railo - no idea why
					if(!isInstanceOf( o, "org.owasp.esapi.codecs.Codec" )) {
					    throwException( newJava( "java.lang.IllegalArgumentException" ).init( "Codec list must contain only Codec instances" ) );
					} */
					// at least check to ensure its an object since Railo fails the above check
					if(!isObject( o )) {
						throwException( newJava( "java.lang.IllegalArgumentException" ).init( "Codec list must contain only Codec instances" ) );
					}
				}
				variables.codecs = arguments.codecs;
			}
			else {

				// initialize the codec list to use for canonicalization
				variables.codecs.add( variables.htmlCodec );
				variables.codecs.add( variables.percentCodec );
				variables.codecs.add( variables.javaScriptCodec );

				// leave this out because it eats / characters
				// variables.codecs.add( variables.cssCodec );

				// leave this out because it eats " characters
				// variables.codecs.add( variables.vbScriptCodec );
			}

			return this;
		</cfscript> 
	</cffunction>


	<cffunction access="private" returntype="String" name="encode" output="false" hint="Private helper method to encode a single character by a particular codec. Will not encode characters from the base and special white lists. Note: It is strongly recommended that you canonicalize input before calling this method to prevent double-encoding.">
		<cfargument required="true" name="c" hint="character to be encoded">
		<cfargument required="true" name="codec" hint="codec to be used to encode c">
		<cfargument required="true" type="Array" name="baseImmune" hint="white list of base characters that are okay">
		<cfargument required="true" type="Array" name="specialImmune" hint="white list of special characters that are okay">
		<cfscript>
			if(isContained( arguments.baseImmune, arguments.c ) || isContained( arguments.specialImmune, arguments.c )) {
				return "" & arguments.c;
			}
			else {
				return arguments.codec.encodeCharacter( newJava( "java.lang.Character" ).init( arguments.c ) );
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="canonicalize" output="false">
		<cfargument required="true" type="String" name="input">
		<cfargument required="false" type="boolean" name="strict" default="true">
		<cfscript>
			// CF8 requires 'var' at the top
			var working = "";
			var codecFound = "";
			var mixedCount = "";
			var foundCount = "";
			var clean = "";
			var i = "";
			var codec = "";
			var old = "";
			
			if(arguments.input == "") {
				return "";
			}

			working = arguments.input;
			codecFound = "";
			mixedCount = 1;
			foundCount = 0;
			clean = false;
			while(!clean) {
				clean = true;

				// try each codec and keep track of which ones work
				i = variables.codecs.iterator();
				while(i.hasNext()) {
					codec = i.next();
					old = working;
					working = codec.decode( working );
					if(!old.equals( working )) {
						if(isObject( codecFound ) && !codecFound.equals( codec )) {
							mixedCount++;
						}
						codecFound = codec;
						if(clean) {
							foundCount++;
						}
						clean = false;
					}
				}
			}

			// do strict tests and handle if any mixed, multiple, nested encoding were found
			if(foundCount >= 2 && mixedCount > 1) {
				if(arguments.strict) {
					throwException( createObject( "component", "org.owasp.esapi.errors.IntrusionException" ).init( variables.ESAPI, "Input validation failure", "Multiple (" & foundCount & "x) and mixed encoding (" & mixedCount & "x) detected in " & arguments.input ) );
				}
				else {
					variables.logger.warning( getSecurity( "SECURITY_FAILURE" ), false, "Multiple (" & foundCount & "x) and mixed encoding (" & mixedCount & "x) detected in " & arguments.input );
				}
			}
			else if(foundCount >= 2) {
				if(arguments.strict) {
					throwException( createObject( "component", "org.owasp.esapi.errors.IntrusionException" ).init( variables.ESAPI, "Input validation failure", "Multiple (" & foundCount & "x) encoding detected in " & arguments.input ) );
				}
				else {
					variables.logger.warning( getSecurity( "SECURITY_FAILURE" ), false, "Multiple (" & foundCount & "x) encoding detected in " & arguments.input );
				}
			}
			else if(mixedCount > 1) {
				if(arguments.strict) {
					throwException( createObject( "component", "org.owasp.esapi.errors.IntrusionException" ).init( variables.ESAPI, "Input validation failure", "Mixed encoding (" & mixedCount & "x) detected in " & arguments.input ) );
				}
				else {
					variables.logger.warning( getSecurity( "SECURITY_FAILURE" ), false, "Mixed encoding (" & mixedCount & "x) detected in " & arguments.input );
				}
			}
			return working;
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForHTML" output="false">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			// CF8 requires 'var' at the top
			var sb = "";
			var i = "";
			var c = "";
			
			if(arguments.input == "")
				return "";

			if(this.ESAPI4JVERSION == 2) {
				return variables.htmlCodec.encode( variables.IMMUNE_HTML, arguments.input );
			}
			else if(this.ESAPI4JVERSION == 1) {
				sb = newJava( "java.lang.StringBuffer" ).init();
				for(i = 0; i < arguments.input.length(); i++) {
					c = asc( arguments.input.charAt( i ) );
					if(c == 9 || c == 13 || c == 10) {
						sb.append( chr( c ) );
					}
					else if(c <= inputBaseN( "1f", 16 ) || (c >= inputBaseN( "7f", 16 ) && c <= inputBaseN( "9f", 16 ))) {
						variables.logger.warning( getSecurity( "SECURITY_FAILURE" ), false, "Attempt to HTML entity encode illegal character: " & chr( c ) & " (skipping)" );
						sb.append( " " );
					}
					else {
						sb.append( encode( chr( c ), variables.htmlCodec, newJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, variables.IMMUNE_HTML ) );
					}
				}
				return sb.toString();
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForHTMLAttribute" output="false">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			// CF8 requires 'var' at the top
			var sb = "";
			var i = "";
			var c = "";
			
			if(arguments.input == "")
				return "";

			if(this.ESAPI4JVERSION == 2) {
				return variables.htmlCodec.encode( variables.IMMUNE_HTMLATTR, arguments.input );
			}
			else if(this.ESAPI4JVERSION == 1) {
				sb = newJava( "java.lang.StringBuffer" ).init();
				for(i = 0; i < len( arguments.input ); i++) {
					c = javaCast( "string", arguments.input ).charAt( i );
					sb.append( encode( c, variables.htmlCodec, newJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, variables.IMMUNE_HTMLATTR ) );
				}
				return sb.toString();
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForCSS" output="false">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			// CF8 requires 'var' at the top
			var sb = "";
			var i = "";
			var c = "";
			
			if(arguments.input == "")
				return "";

			if(this.ESAPI4JVERSION == 2) {
				return variables.cssCodec.encode( variables.IMMUNE_CSS, arguments.input );
			}
			else if(this.ESAPI4JVERSION == 1) {
				sb = newJava( "java.lang.StringBuffer" ).init();
				for(i = 0; i < arguments.input.length(); i++) {
					c = arguments.input.charAt( i );
					if(c != 0) {
						sb.append( encode( c, variables.cssCodec, newJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, variables.IMMUNE_CSS ) );
					}
				}
				return sb.toString();
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForJavaScript" output="false">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			// CF8 requires 'var' at the top
			var sb = "";
			var i = "";
			var c = "";
			
			if(arguments.input == "")
				return "";

			if(this.ESAPI4JVERSION == 2) {
				return variables.javaScriptCodec.encode( variables.IMMUNE_JAVASCRIPT, arguments.input );
			}
			else if(this.ESAPI4JVERSION == 1) {
				sb = newJava( "java.lang.StringBuffer" ).init();
				for(i = 0; i < arguments.input.length(); i++) {
					c = arguments.input.charAt( i );
					sb.append( encode( c, variables.javaScriptCodec, newJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, variables.IMMUNE_JAVASCRIPT ) );
				}
				return sb.toString();
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForVBScript" output="false">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			// CF8 requires 'var' at the top
			var sb = "";
			var i = "";
			var c = "";
			
			if(arguments.input == "")
				return "";

			if(this.ESAPI4JVERSION == 2) {
				return variables.vbScriptCodec.encode( variables.IMMUNE_VBSCRIPT, arguments.input );
			}
			else if(this.ESAPI4JVERSION == 1) {
				sb = newJava( "java.lang.StringBuffer" ).init();
				for(i = 0; i < arguments.input.length(); i++) {
					c = arguments.input.charAt( i );
					sb.append( encode( c, variables.vbScriptCodec, newJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, variables.IMMUNE_VBSCRIPT ) );
				}
				return sb.toString();
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForSQL" output="false">
		<cfargument required="true" name="codec">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			// CF8 requires 'var' at the top
			var sb = "";
			var i = "";
			var c = "";
			
			if(arguments.input == "")
				return "";

			if(this.ESAPI4JVERSION == 2) {
				return arguments.codec.encode( variables.IMMUNE_SQL, arguments.input );
			}
			else if(this.ESAPI4JVERSION == 1) {
				sb = newJava( "java.lang.StringBuffer" ).init();
				for(i = 0; i < len( arguments.input ); i++) {
					c = javaCast( "string", arguments.input ).charAt( i );
					sb.append( encode( c, arguments.codec, newJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, variables.IMMUNE_SQL ) );
				}
				return sb.toString();
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForOS" output="false">
		<cfargument required="true" name="codec">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			// CF8 requires 'var' at the top
			var sb = "";
			var i = "";
			var c = "";
			
			if(arguments.input == "")
				return "";

			if(this.ESAPI4JVERSION == 2) {
				return arguments.codec.encode( variables.IMMUNE_OS, arguments.input );
			}
			else if(this.ESAPI4JVERSION == 1) {
				sb = newJava( "java.lang.StringBuffer" ).init();
				for(i = 0; i < arguments.input.length(); i++) {
					c = arguments.input.charAt( i );
					sb.append( encode( c, arguments.codec, newJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, variables.IMMUNE_OS ) );
				}
				return sb.toString();
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForLDAP" output="false">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			// CF8 requires 'var' at the top
			var sb = "";
			var i = "";
			var c = "";
			
			// TODO: replace with LDAP codec
			sb = newJava( "java.lang.StringBuffer" ).init();
			for(i = 0; i < arguments.input.length(); i++) {
				c = arguments.input.charAt( i );

				switch(c.toString()) {
					case '\':
						sb.append( "\5c" );
						break;
					case '*':
						sb.append( "\2a" );
						break;
					case '(':
						sb.append( "\28" );
						break;
					case ')':
						sb.append( "\29" );
						break;
					case chr( 0 ):
						sb.append( "\00" );
						break;
					default:
						sb.append( c );
				}

			}
			return sb.toString();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForDN" output="false">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			// CF8 requires 'var' at the top
			var sb = "";
			var i = "";
			var c = "";
			
			// TODO: replace with DN codec
			sb = newJava( "java.lang.StringBuffer" ).init();
			if((arguments.input.length() > 0) && ((arguments.input.charAt( 0 ) == ' ') || (arguments.input.charAt( 0 ) == chr( 35 )))) {
				sb.append( '\' );// add the leading backslash if needed
			}
			for(i = 0; i < arguments.input.length(); i++) {
				c = arguments.input.charAt( i );

				switch(c.toString()) {
					case '\':
						sb.append( "\\" );
						break;
					case ',':
						sb.append( "\," );
						break;
					case '+':
						sb.append( "\+" );
						break;
					case '"':
						sb.append( '\"' );
						break;
					case '<':
						sb.append( "\<" );
						break;
					case '>':
						sb.append( "\>" );
						break;
					case ';':
						sb.append( "\;" );
						break;
					default:
						sb.append( c );
				}

			}
			// add the trailing backslash if needed
			if((arguments.input.length() > 1) && (arguments.input.charAt( arguments.input.length() - 1 ) == " ")) {
				sb.insert( sb.length() - 1, "\" );
			}
			return sb.toString();
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForXPath" output="false">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			// CF8 requires 'var' at the top
			var sb = "";
			var i = "";
			var c = "";
			
			if(arguments.input == "")
				return "";

			if(this.ESAPI4JVERSION == 2) {
				return variables.htmlCodec.encode( variables.IMMUNE_XPATH, arguments.input );
			}
			else if(this.ESAPI4JVERSION == 1) {
				sb = newJava( "java.lang.StringBuffer" ).init();
				for(i = 0; i < arguments.input.length(); i++) {
					c = arguments.input.charAt( i );
					sb.append( encode( c, variables.htmlCodec, newJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, variables.IMMUNE_XPATH ) );
				}
				return sb.toString();
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForXML" output="false">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			if(arguments.input == "") {
				return "";
			}
			return variables.xmlCodec.encode( variables.IMMUNE_XML, arguments.input );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForXMLAttribute" output="false">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			if(arguments.input == "") {
				return "";
			}
			return variables.xmlCodec.encode( variables.IMMUNE_XMLATTR, arguments.input );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForURL" output="false">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			try {
				return newJava( "java.net.URLEncoder" ).encode( javaCast( "string", arguments.input ), variables.ESAPI.securityConfiguration().getCharacterEncoding() );
			}
			catch(java.io.UnsupportedEncodingException ex) {
				throwException( createObject( "component", "org.owasp.esapi.errors.EncodingException" ).init( variables.ESAPI, "Encoding failure", "Encoding not supported", ex ) );
			}
			catch(java.lang.Exception e) {
				throwException( createObject( "component", "org.owasp.esapi.errors.EncodingException" ).init( variables.ESAPI, "Encoding failure", "Problem URL decoding input", e ) );
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="decodeFromURL" output="false">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			var canonical = this.canonicalize( arguments.input );
			try {
				return newJava( "java.net.URLDecoder" ).decode( canonical, variables.ESAPI.securityConfiguration().getCharacterEncoding() );
			}
			catch(java.io.UnsupportedEncodingException ex) {
				throwException( createObject( "component", "org.owasp.esapi.errors.EncodingException" ).init( variables.ESAPI, "Decoding failed", "Encoding not supported", ex ) );
			}
			catch(java.lang.Exception e) {
				throwException( createObject( "component", "org.owasp.esapi.errors.EncodingException" ).init( variables.ESAPI, "Decoding failed", "Problem URL decoding input", e ) );
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForBase64" output="false">
		<cfargument required="true" type="binary" name="input">
		<cfargument required="true" type="boolean" name="wrap">
		<cfscript>
			var options = 0;
			if(!arguments.wrap) {
				options = newJava( "org.owasp.esapi.codecs.Base64" ).DONT_BREAK_LINES;
			}
			return newJava( "org.owasp.esapi.codecs.Base64" ).encodeBytes( arguments.input, options );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="binary" name="decodeFromBase64" output="false">
		<cfargument required="true" type="String" name="input">
		<cfscript>
			return newJava( "org.owasp.esapi.codecs.Base64" ).decode( arguments.input );
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="boolean" name="isContained" output="false" hint="isContained is a helper method which determines if c is contained in the character array haystack.">
		<cfargument required="true" type="Array" name="haystack" hint="a character array containing a set of characters to be searched">
		<cfargument required="true" name="c" hint="a character to be searched for">
		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			
			for(i = 1; i <= arrayLen( arguments.haystack ); i++) {
				if(arguments.c == arguments.haystack[i])
					return true;
			}
			return false;

			// If sorted arrays are guaranteed, this is faster
			// return( Arrays.binarySearch(array, element) >= 0 );
		</cfscript> 
	</cffunction>


</cfcomponent>
