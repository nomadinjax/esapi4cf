<cfcomponent extends="cfesapi.org.owasp.esapi.util.Object" implements="cfesapi.org.owasp.esapi.Encoder" output="false" hint="Reference implementation of the Encoder interface. This implementation takes a whitelist approach to encoding, meaning that everything not specifically identified in a list of 'immune' characters is encoded.">

	<cfscript>
		instance.ESAPI = "";

		instance.codecs = [];

		instance.logger = "";

		/* Character sets that define characters (in addition to alphanumerics) that are immune from encoding in various formats */
		static.IMMUNE_HTML = [ ',', '.', '-', '_', ' ' ];
		static.IMMUNE_HTMLATTR = [ ',', '.', '-', '_' ];
		static.IMMUNE_CSS = [];
		static.IMMUNE_JAVASCRIPT = [ ',', '.', '_' ];
		static.IMMUNE_VBSCRIPT = [ ',', '.', '_' ];
		static.IMMUNE_XML = [ ',', '.', '-', '_', ' ' ];
		static.IMMUNE_SQL = [ ' ' ];
		static.IMMUNE_OS = [ '-' ];
		static.IMMUNE_XMLATTR = [ ',', '.', '-', '_' ];
		static.IMMUNE_XPATH = [ ',', '.', '-', '_', ' ' ];
	</cfscript>

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Encoder" name="init" output="false" hint="Instantiates a new DefaultEncoder">
		<cfargument type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI" required="true">
		<cfargument type="Array" name="codecNames" required="false">
		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger("Encoder");

			if (structKeyExists(arguments, "codecNames")) {
				for ( local.clazz in codecNames ) {
					try {
						if (!structKeyExists(variables, local.clazz)) {
							local.path = local.clazz;
							if ( local.path.indexOf( "." ) == -1 ) {
								local.path = "org.owasp.esapi.codecs." & local.clazz;
							}
							variables[local.clazz] = createObject("java", local.path);
						}
						instance.codecs.add(variables[local.clazz].init());
					} catch ( java.lang.Exception e ) {
						instance.logger.warning( createObject("java", "org.owasp.esapi.Logger").EVENT_FAILURE, "Codec " & local.clazz & " listed in ESAPI.properties not on classpath" );
					}
				}
			}
			else {
				instance.codecs.add( createObject("java", "org.owasp.esapi.codecs.HTMLEntityCodec").init() );
				instance.codecs.add( createObject("java", "org.owasp.esapi.codecs.PercentCodec").init() );
				instance.codecs.add( createObject("java", "org.owasp.esapi.codecs.JavaScriptCodec").init() );
			}

			return this;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="canonicalize" output="false">
		<cfargument type="String" name="input" required="true">
		<cfargument type="boolean" name="strict" required="false" default="#!instance.ESAPI.securityConfiguration().getDisableIntrusionDetection()#">
		<cfscript>
			local.working = arguments.input;
			local.codecFound = "";
			local.mixedCount = 1;
			local.foundCount = 0;
			local.clean = false;
			while( !local.clean ) {
			    local.clean = true;

			    // try each codec and keep track of which ones work
			    local.i = instance.codecs.iterator();
			    while ( local.i.hasNext() ) {
			        local.codec = local.i.next();
			        local.old = local.working;
			        local.working = local.codec.decode( local.working );
			        if ( !local.old.equals( local.working ) ) {
			            if ( local.codecFound != "" && local.codecFound != local.codec ) {
			                local.mixedCount++;
			            }
			            local.codecFound = local.codec;
			            if ( local.clean ) {
			                local.foundCount++;
			            }
			            local.clean = false;
			        }
			    }
			}

			// do strict tests and handle if any mixed, multiple, nested encoding were found
			if ( local.foundCount >= 2 && local.mixedCount > 1 ) {
			    if ( arguments.strict ) {
                	cfex = createObject('component', 'cfesapi.org.owasp.esapi.errors.IntrusionException').init(instance.ESAPI, "Input validation failure", "Multiple ("& local.foundCount &"x) and mixed encoding ("& local.mixedCount &"x) detected in " & arguments.input );
            		throw(message=cfex.getMessage(), type=cfex.getType());
			    } else {
			        instance.logger.warning( createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Multiple ("& local.foundCount &"x) and mixed encoding ("& local.mixedCount &"x) detected in " & arguments.input );
			    }
			}
			else if ( local.foundCount >= 2 ) {
			    if ( arguments.strict ) {
                	cfex = createObject('component', 'cfesapi.org.owasp.esapi.errors.IntrusionException').init(instance.ESAPI, "Input validation failure", "Multiple ("& local.foundCount &"x) encoding detected in " & arguments.input );
            		throw(message=cfex.getMessage(), type=cfex.getType());
			    } else {
			        instance.logger.warning( createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Multiple ("& local.foundCount &"x) encoding detected in " & arguments.input );
			    }
			}
			else if ( local.mixedCount > 1 ) {
			    if ( arguments.strict ) {
	                cfex = createObject('component', 'cfesapi.org.owasp.esapi.errors.IntrusionException').init(instance.ESAPI, "Input validation failure", "Mixed encoding ("& local.mixedCount &"x) detected in " & arguments.input );
            		throw(message=cfex.getMessage(), type=cfex.getType());
			    } else {
			        instance.logger.warning( createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Mixed encoding ("& local.mixedCount &"x) detected in " & arguments.input );
			    }
			}
			return local.working;
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForHTML" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
		    return createObject("java", "org.owasp.esapi.codecs.HTMLEntityCodec").init().encode( static.IMMUNE_HTML, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="decodeForHTML" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			return createObject("java", "org.owasp.esapi.codecs.HTMLEntityCodec").init().decode(arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForHTMLAttribute" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
		    return createObject("java", "org.owasp.esapi.codecs.HTMLEntityCodec").init().encode( static.IMMUNE_HTMLATTR, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForCSS" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
	    	return createObject("java", "org.owasp.esapi.codecs.CSSCodec").init().encode( static.IMMUNE_CSS, arguments.input);
	    </cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForJavaScript" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
	    	return createObject("java", "org.owasp.esapi.codecs.JavaScriptCodec").init().encode(static.IMMUNE_JAVASCRIPT, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForVBScript" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			return createObject("java", "org.owasp.esapi.codecs.VBScriptCodec").init().encode(static.IMMUNE_VBSCRIPT, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForSQL" output="false">
		<cfargument type="any" name="codec" required="true" hint="org.owasp.esapi.codecs.Codec">
		<cfargument type="String" name="input" required="true">
		<cfscript>
		    return arguments.codec.encode(static.IMMUNE_SQL, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForOS" output="false">
		<cfargument type="any" name="codec" required="true" hint="org.owasp.esapi.codecs.Codec">
		<cfargument type="String" name="input" required="true">
		<cfscript>
		    return arguments.codec.encode( static.IMMUNE_OS, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForLDAP" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			// TODO: replace with LDAP codec
		    local.sb = createObject("java", "java.lang.StringBuilder").init();
			for (local.i = 0; local.i < input.length(); local.i++) {
				local.c = input.charAt(local.i);
				switch (local.c) {
				case '\':
					local.sb.append("\5c");
					break;
				case '*':
					local.sb.append("\2a");
					break;
				case '(':
					local.sb.append("\28");
					break;
				case ')':
					local.sb.append("\29");
					break;
				case '\0':
					local.sb.append("\00");
					break;
				default:
					local.sb.append(c);
				}
			}
			return local.sb.toString();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForDN" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			if( !len(arguments.input) ) {
		    	return "";
		    }
			// TODO: replace with DN codec
		    local.sb = createObject("java", "java.lang.StringBuilder").init();
			if ((arguments.input.length() > 0) && ((arguments.input.charAt(0) == ' ') || (arguments.input.charAt(0) == chr(35)))) {
				local.sb.append('\'); // add the leading backslash if needed
			}
			for (local.i = 0; local.i < arguments.input.length(); local.i++) {
				local.c = arguments.input.charAt(local.i);
				switch (local.c) {
				case '\':
					local.sb.append("\\");
					break;
				case ',':
					local.sb.append("\,");
					break;
				case '+':
					local.sb.append("\+");
					break;
				case '"':
					local.sb.append('\"');
					break;
				case '<':
					local.sb.append("\<");
					break;
				case '>':
					local.sb.append("\>");
					break;
				case ';':
					local.sb.append("\;");
					break;
				default:
					local.sb.append(local.c);
				}
			}
			// add the trailing backslash if needed
			if ((arguments.input.length() > 1) && (arguments.input.charAt(arguments.input.length() - 1) == ' ')) {
				local.sb.insert(local.sb.length() - 1, '\');
			}
			return local.sb.toString();
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForXPath" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
	    	return createObject("java", "org.owasp.esapi.codecs.HTMLEntityCodec").init().encode( static.IMMUNE_XPATH, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForXML" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
	    	return createObject("java", "org.owasp.esapi.codecs.XMLEntityCodec").init().encode( static.IMMUNE_XML, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForXMLAttribute" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
	    	return createObject("java", "org.owasp.esapi.codecs.XMLEntityCodec").init().encode( static.IMMUNE_XMLATTR, arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForURL" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
	    	try {
				return createObject("java", "java.net.URLEncoder").encode(arguments.input, instance.ESAPI.securityConfiguration().getCharacterEncoding());
			} catch (java.io.UnsupportedEncodingException ex) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncodingException").init(instance.ESAPI, "Encoding failure", "Character encoding not supported", ex);
           		throw(message=cfex.getMessage(), type=cfex.getType());
			} catch (java.lang.Exception e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncodingException").init(instance.ESAPI, "Encoding failure", "Problem URL encoding input", e);
           		throw(message=cfex.getMessage(), type=cfex.getType());
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="decodeFromURL" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
	    	local.canonical = canonicalize(arguments.input);
			try {
				return createObject("java", "java.net.URLDecoder").decode(local.canonical, instance.ESAPI.securityConfiguration().getCharacterEncoding());
			} catch (java.io.UnsupportedEncodingException ex) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncodingException").init(instance.ESAPI, "Decoding failed", "Character encoding not supported", ex);
				throw(message=cfex.getMessage(), type=cfex.getType());
			} catch (java.lang.Exception e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncodingException").init(instance.ESAPI, "Decoding failed", "Problem URL decoding input", e);
				throw(message=cfex.getMessage(), type=cfex.getType());
			}
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForBase64" output="false">
		<cfargument type="any" name="input" required="true" hint="binary">
		<cfargument type="boolean" name="wrap" required="true">
		<cfscript>
			if ( !len(arguments.input) ) {
				return toBase64("");
			}
			/* not sure we want to use the Base64.cfc - performance?
			local.Base64 = createObject("component", "cfesapi.org.owasp.esapi.codecs.Base64").init(instance.ESAPI);
			local.options = 0;
			if ( !arguments.wrap ) {
				local.options |= local.Base64.DONT_BREAK_LINES;
			}
			return local.Base64.encodeBytes(arguments.input, local.options);
			*/
			return toBase64(arguments.input);
		</cfscript>
	</cffunction>


	<cffunction access="public" returntype="binary" name="decodeFromBase64" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			if ( !len(arguments.input) ) {
				return toBinary(toBase64(""));
			}
			/* not sure we want to use the Base64.cfc - performance?
			return createObject("component", "cfesapi.org.owasp.esapi.codecs.Base64").init(instance.ESAPI).decode( arguments.input );
			*/
			try {
				return toBinary(arguments.input);
			} catch (Expression e) {	// input was not Base64, so make it so
				return toBinary(toBase64(arguments.input));
			}
		</cfscript>
	</cffunction>


</cfcomponent>
