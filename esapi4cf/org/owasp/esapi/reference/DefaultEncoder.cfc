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
<cfcomponent implements="esapi4cf.org.owasp.esapi.Encoder" extends="esapi4cf.org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the Encoder interface. This implementation takes a whitelist approach to encoding, meaning that everything not specifically identified in a list of 'immune' characters is encoded. Several methods follow the approach in the Microsoft AntiXSS Library. The Encoder performs two key functions The canonicalization algorithm is complex, as it has to be able to recognize encoded characters that might affect downstream interpreters without being told what encodings are possible. The stream is read one character at a time. If an encoded character is encountered, it is canonicalized and pushed back onto the stream. If the next character is encoded, then a intrusion exception is thrown for the double-encoding which is assumed to be an attack. The encoding methods also attempt to prevent double encoding, by canonicalizing strings that are passed to them for encoding. Currently the implementation supports: HTML Entity Encoding (including non-terminated), Percent Encoding, Backslash Encoding">

	<cfscript>
		// Codecs
		instance.codecs = [];
		instance.htmlCodec = getJava( "org.owasp.esapi.codecs.HTMLEntityCodec" ).init();
		instance.xmlCodec = getJava( "org.owasp.esapi.codecs.XMLEntityCodec" ).init();
		instance.percentCodec = getJava( "org.owasp.esapi.codecs.PercentCodec" ).init();
		instance.javaScriptCodec = getJava( "org.owasp.esapi.codecs.JavaScriptCodec" ).init();
		instance.vbScriptCodec = getJava( "org.owasp.esapi.codecs.VBScriptCodec" ).init();
		instance.cssCodec = getJava( "org.owasp.esapi.codecs.CSSCodec" ).init();

		/** The logger. */
		instance.logger = "";

		/** Character sets that define characters immune from encoding in various formats */
		instance.IMMUNE_HTML = [',', '.', '-', '_', ' '];
		instance.IMMUNE_HTMLATTR = [',', '.', '-', '_'];
		instance.IMMUNE_CSS = [' '];// TODO: check
		instance.IMMUNE_JAVASCRIPT = [',', '.', '-', '_', ' '];
		instance.IMMUNE_VBSCRIPT = [' '];// TODO: check
		instance.IMMUNE_XML = [',', '.', '-', '_', ' '];
		instance.IMMUNE_SQL = [' '];
		instance.IMMUNE_OS = ['-'];
		instance.IMMUNE_XMLATTR = [',', '.', '-', '_'];
		instance.IMMUNE_XPATH = [',', '.', '-', '_', ' '];
	</cfscript>

	<cffunction access="public" returntype="esapi4cf.org.owasp.esapi.Encoder" name="init" output="false"
	            hint="Instantiates a new DefaultEncoder">
		<cfargument required="true" type="esapi4cf.org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument type="Array" name="codecs" hint="A list of codecs to use by the Encoder class"/>

		<cfscript>
			var local = {};
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger( "Encoder" );

			if(structKeyExists( arguments, "codecs" )) {

				for(local.i = 1; local.i <= arrayLen( arguments.codecs ); local.i++) {
					local.o = arguments.codecs[local.i];
					/* FIXME: this condition fails in Railo - no idea why
					if(!isInstanceOf( local.o, "org.owasp.esapi.codecs.Codec" )) {
					    throwException( getJava( "java.lang.IllegalArgumentException" ).init( "Codec list must contain only Codec instances" ) );
					} */
					// at least check to ensure its an object since Railo fails the above check
					if(!isObject( local.o )) {
						throwException( getJava( "java.lang.IllegalArgumentException" ).init( "Codec list must contain only Codec instances" ) );
					}
				}
				instance.codecs = arguments.codecs;
			}
			else {

				// initialize the codec list to use for canonicalization
				instance.codecs.add( instance.htmlCodec );
				instance.codecs.add( instance.percentCodec );
				instance.codecs.add( instance.javaScriptCodec );

				// leave this out because it eats / characters
				// instance.codecs.add( instance.cssCodec );
				// leave this out because it eats " characters
				// instance.codecs.add( instance.vbScriptCodec );
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="encode" output="false"
	            hint="Private helper method to encode a single character by a particular codec. Will not encode characters from the base and special white lists. Note: It is strongly recommended that you canonicalize input before calling this method to prevent double-encoding.">
		<cfargument required="true" name="c" hint="character to be encoded"/>
		<cfargument required="true" name="codec" hint="codec to be used to encode c"/>
		<cfargument required="true" type="Array" name="baseImmune" hint="white list of base characters that are okay"/>
		<cfargument required="true" type="Array" name="specialImmune" hint="white list of special characters that are okay"/>

		<cfscript>
			if(isContained( arguments.baseImmune, arguments.c ) || isContained( arguments.specialImmune, arguments.c )) {
				return "" & arguments.c;
			}
			else {
				return arguments.codec.encodeCharacter( getJava( "java.lang.Character" ).init( arguments.c ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="canonicalize" output="false">
		<cfargument required="true" type="String" name="input"/>
		<cfargument required="false" type="boolean" name="strict" default="true"/>

		<cfscript>
			var local = {};
			if(arguments.input == "") {
				return "";
			}

			local.working = arguments.input;
			local.codecFound = "";
			local.mixedCount = 1;
			local.foundCount = 0;
			local.clean = false;
			while(!local.clean) {
				local.clean = true;

				// try each codec and keep track of which ones work
				local.i = instance.codecs.iterator();
				while(local.i.hasNext()) {
					local.codec = local.i.next();
					local.old = local.working;
					local.working = local.codec.decode( local.working );
					if(!local.old.equals( local.working )) {
						if(isObject( local.codecFound ) && !local.codecFound.equals( local.codec )) {
							local.mixedCount++;
						}
						local.codecFound = local.codec;
						if(local.clean) {
							local.foundCount++;
						}
						local.clean = false;
					}
				}
			}

			// do strict tests and handle if any mixed, multiple, nested encoding were found
			if(local.foundCount >= 2 && local.mixedCount > 1) {
				if(arguments.strict) {
					throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.IntrusionException" ).init( instance.ESAPI, "Input validation failure", "Multiple (" & local.foundCount & "x) and mixed encoding (" & local.mixedCount & "x) detected in " & arguments.input ) );
				}
				else {
					instance.logger.warning( getSecurity( "SECURITY_FAILURE" ), false, "Multiple (" & local.foundCount & "x) and mixed encoding (" & local.mixedCount & "x) detected in " & arguments.input );
				}
			}
			else if(local.foundCount >= 2) {
				if(arguments.strict) {
					throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.IntrusionException" ).init( instance.ESAPI, "Input validation failure", "Multiple (" & local.foundCount & "x) encoding detected in " & arguments.input ) );
				}
				else {
					instance.logger.warning( getSecurity( "SECURITY_FAILURE" ), false, "Multiple (" & local.foundCount & "x) encoding detected in " & arguments.input );
				}
			}
			else if(local.mixedCount > 1) {
				if(arguments.strict) {
					throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.IntrusionException" ).init( instance.ESAPI, "Input validation failure", "Mixed encoding (" & local.mixedCount & "x) detected in " & arguments.input ) );
				}
				else {
					instance.logger.warning( getSecurity( "SECURITY_FAILURE" ), false, "Mixed encoding (" & local.mixedCount & "x) detected in " & arguments.input );
				}
			}
			return local.working;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForHTML" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			var local = {};
			if(arguments.input == "")
				return "";

			// ESAPI 2.0_rc10
			if(isInstanceOf( instance.htmlCodec, "org.owasp.esapi.codecs.Codec" )) {
				return instance.htmlCodec.encode( instance.IMMUNE_HTML, arguments.input );
			}
			// ESAPI 1.4.4
			else {
				local.sb = getJava( "java.lang.StringBuffer" ).init();
				for(local.i = 0; local.i < arguments.input.length(); local.i++) {
					local.c = asc( arguments.input.charAt( local.i ) );
					if(local.c == 9 || local.c == 13 || local.c == 10) {
						local.sb.append( chr( local.c ) );
					}
					else if(local.c <= inputBaseN( "1f", 16 ) || (local.c >= inputBaseN( "7f", 16 ) && local.c <= inputBaseN( "9f", 16 ))) {
						instance.logger.warning( getSecurity( "SECURITY_FAILURE" ), false, "Attempt to HTML entity encode illegal character: " & chr( local.c ) & " (skipping)" );
						local.sb.append( " " );
					}
					else {
						local.sb.append( encode( chr( local.c ), instance.htmlCodec, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, instance.IMMUNE_HTML ) );
					}
				}
				return local.sb.toString();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForHTMLAttribute" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			var local = {};
			if(arguments.input == "")
				return "";
			// ESAPI 2.0_rc10
			if(isInstanceOf( instance.htmlCodec, "org.owasp.esapi.codecs.Codec" )) {
				return instance.htmlCodec.encode( instance.IMMUNE_HTMLATTR, arguments.input );
			}
			// ESAPI 1.4.4
			else {
				local.sb = getJava( "java.lang.StringBuffer" ).init();
				for(local.i = 0; local.i < len( arguments.input ); local.i++) {
					local.c = javaCast( "string", arguments.input ).charAt( local.i );
					local.sb.append( encode( local.c, instance.htmlCodec, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, instance.IMMUNE_HTMLATTR ) );
				}
				return local.sb.toString();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForCSS" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			var local = {};
			if(arguments.input == "")
				return "";

			// ESAPI 2.0_rc10
			if(isInstanceOf( instance.cssCodec, "org.owasp.esapi.codecs.Codec" )) {
				return instance.cssCodec.encode( instance.IMMUNE_CSS, arguments.input );
			}
			// ESAPI 1.4.4
			else {
				local.sb = getJava( "java.lang.StringBuffer" ).init();
				for(local.i = 0; local.i < arguments.input.length(); local.i++) {
					local.c = arguments.input.charAt( local.i );
					if(local.c != 0) {
						local.sb.append( encode( local.c, instance.cssCodec, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, instance.IMMUNE_CSS ) );
					}
				}
				return local.sb.toString();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForJavaScript" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			var local = {};
			if(arguments.input == "")
				return "";

			// ESAPI 2.0_rc10
			if(isInstanceOf( instance.javaScriptCodec, "org.owasp.esapi.codecs.Codec" )) {
				return instance.javaScriptCodec.encode( instance.IMMUNE_JAVASCRIPT, arguments.input );
			}
			// ESAPI 1.4.4
			else {
				local.sb = getJava( "java.lang.StringBuffer" ).init();
				for(local.i = 0; local.i < arguments.input.length(); local.i++) {
					local.c = arguments.input.charAt( local.i );
					local.sb.append( encode( local.c, instance.javaScriptCodec, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, instance.IMMUNE_JAVASCRIPT ) );
				}
				return local.sb.toString();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForVBScript" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			var local = {};
			if(arguments.input == "")
				return "";
			// ESAPI 2.0_rc10
			if(isInstanceOf( instance.vbScriptCodec, "org.owasp.esapi.codecs.Codec" )) {
				return instance.vbScriptCodec.encode( instance.IMMUNE_VBSCRIPT, arguments.input );
			}
			// ESAPI 1.4.4
			else {
				local.sb = getJava( "java.lang.StringBuffer" ).init();
				for(local.i = 0; local.i < arguments.input.length(); local.i++) {
					local.c = arguments.input.charAt( local.i );
					local.sb.append( encode( local.c, instance.vbScriptCodec, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, instance.IMMUNE_VBSCRIPT ) );
				}
				return local.sb.toString();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForSQL" output="false">
		<cfargument required="true" name="codec"/>
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			var local = {};
			if(arguments.input == "")
				return "";
			// ESAPI 2.0_rc10
			if(isInstanceOf( arguments.codec, "org.owasp.esapi.codecs.Codec" )) {
				return arguments.codec.encode( instance.IMMUNE_SQL, arguments.input );
			}
			// ESAPI 1.4.4
			else {
				local.sb = getJava( "java.lang.StringBuffer" ).init();
				for(local.i = 0; local.i < len( arguments.input ); local.i++) {
					local.c = javaCast( "string", arguments.input ).charAt( local.i );
					local.sb.append( encode( local.c, arguments.codec, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, instance.IMMUNE_SQL ) );
				}
				return local.sb.toString();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForOS" output="false">
		<cfargument required="true" name="codec"/>
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			var local = {};
			if(arguments.input == "")
				return "";
			// ESAPI 2.0_rc10
			if(isInstanceOf( arguments.codec, "org.owasp.esapi.codecs.Codec" )) {
				return arguments.codec.encode( instance.IMMUNE_OS, arguments.input );
			}
			// ESAPI 1.4.4
			else {
				local.sb = getJava( "java.lang.StringBuffer" ).init();
				for(local.i = 0; local.i < arguments.input.length(); local.i++) {
					local.c = arguments.input.charAt( local.i );
					local.sb.append( encode( local.c, arguments.codec, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, instance.IMMUNE_OS ) );
				}
				return local.sb.toString();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForLDAP" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			var local = {};
			// TODO: replace with LDAP codec
			local.sb = getJava( "java.lang.StringBuffer" ).init();
			for(local.i = 0; local.i < arguments.input.length(); local.i++) {
				local.c = arguments.input.charAt( local.i );

				switch(local.c.toString()) {
					case '\':
						local.sb.append( "\5c" );
						break;
					case '*':
						local.sb.append( "\2a" );
						break;
					case '(':
						local.sb.append( "\28" );
						break;
					case ')':
						local.sb.append( "\29" );
						break;
					case chr( 0 ):
						local.sb.append( "\00" );
						break;
					default:
						local.sb.append( local.c );
				}

			}
			return local.sb.toString();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForDN" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			var local = {};
			// TODO: replace with DN codec
			local.sb = getJava( "java.lang.StringBuffer" ).init();
			if((arguments.input.length() > 0) && ((arguments.input.charAt( 0 ) == ' ') || (arguments.input.charAt( 0 ) == chr( 35 )))) {
				local.sb.append( '\' );// add the leading backslash if needed
			}
			for(local.i = 0; local.i < arguments.input.length(); local.i++) {
				local.c = arguments.input.charAt( local.i );

				switch(local.c.toString()) {
					case '\':
						local.sb.append( "\\" );
						break;
					case ',':
						local.sb.append( "\," );
						break;
					case '+':
						local.sb.append( "\+" );
						break;
					case '"':
						local.sb.append( '\"' );
						break;
					case '<':
						local.sb.append( "\<" );
						break;
					case '>':
						local.sb.append( "\>" );
						break;
					case ';':
						local.sb.append( "\;" );
						break;
					default:
						local.sb.append( local.c );
				}

			}
			// add the trailing backslash if needed
			if((arguments.input.length() > 1) && (arguments.input.charAt( arguments.input.length() - 1 ) == ' ')) {
				local.sb.insert( local.sb.length() - 1, '\' );
			}
			return local.sb.toString();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForXPath" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			var local = {};
			if(arguments.input == "")
				return "";
			// ESAPI 2.0_rc10
			if(isInstanceOf( instance.htmlCodec, "org.owasp.esapi.codecs.Codec" )) {
				return instance.htmlCodec.encode( instance.IMMUNE_XPATH, arguments.input );
			}
			// ESAPI 1.4.4
			else {
				local.sb = getJava( "java.lang.StringBuffer" ).init();
				for(local.i = 0; local.i < arguments.input.length(); local.i++) {
					local.c = arguments.input.charAt( local.i );
					local.sb.append( encode( local.c, instance.htmlCodec, getJava( "org.owasp.esapi.reference.DefaultEncoder" ).CHAR_ALPHANUMERICS, instance.IMMUNE_XPATH ) );
				}
				return local.sb.toString();
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForXML" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if(arguments.input == "") {
				return "";
			}
			return instance.xmlCodec.encode( instance.IMMUNE_XML, arguments.input );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForXMLAttribute" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			if(arguments.input == "") {
				return "";
			}
			return instance.xmlCodec.encode( instance.IMMUNE_XMLATTR, arguments.input );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForURL" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			try {
				return getJava( "java.net.URLEncoder" ).encode( javaCast( "string", arguments.input ), instance.ESAPI.securityConfiguration().getCharacterEncoding() );
			}
			catch(java.io.UnsupportedEncodingException ex) {
				throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.EncodingException" ).init( instance.ESAPI, "Encoding failure", "Encoding not supported", ex ) );
			}
			catch(java.lang.Exception e) {
				throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.EncodingException" ).init( instance.ESAPI, "Encoding failure", "Problem URL decoding input", e ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="decodeFromURL" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			var local = {};
			local.canonical = this.canonicalize( arguments.input );
			try {
				return getJava( "java.net.URLDecoder" ).decode( local.canonical, instance.ESAPI.securityConfiguration().getCharacterEncoding() );
			}
			catch(java.io.UnsupportedEncodingException ex) {
				throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.EncodingException" ).init( instance.ESAPI, "Decoding failed", "Encoding not supported", ex ) );
			}
			catch(java.lang.Exception e) {
				throwException( createObject( "component", "esapi4cf.org.owasp.esapi.errors.EncodingException" ).init( instance.ESAPI, "Decoding failed", "Problem URL decoding input", e ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForBase64" output="false">
		<cfargument required="true" type="binary" name="input"/>
		<cfargument required="true" type="boolean" name="wrap"/>

		<cfscript>
			var local = {};
			local.options = 0;
			if(!arguments.wrap) {
				local.options = getJava( "org.owasp.esapi.codecs.Base64" ).DONT_BREAK_LINES;
			}
			return getJava( "org.owasp.esapi.codecs.Base64" ).encodeBytes( arguments.input, local.options );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="binary" name="decodeFromBase64" output="false">
		<cfargument required="true" type="String" name="input"/>

		<cfscript>
			return getJava( "org.owasp.esapi.codecs.Base64" ).decode( arguments.input );
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isContained" output="false"
	            hint="isContained is a helper method which determines if c is contained in the character array haystack.">
		<cfargument required="true" type="Array" name="haystack" hint="a character array containing a set of characters to be searched"/>
		<cfargument required="true" name="c" hint="a character to be searched for"/>

		<cfscript>
			var local = {};

			for(local.i = 1; local.i <= arrayLen( arguments.haystack ); local.i++) {
				if(arguments.c == arguments.haystack[local.i])
					return true;
			}
			return false;

			// If sorted arrays are guaranteed, this is faster
			// return( Arrays.binarySearch(array, element) >= 0 );
		</cfscript>

	</cffunction>

</cfcomponent>