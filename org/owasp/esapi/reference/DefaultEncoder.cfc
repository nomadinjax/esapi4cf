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
<cfcomponent extends="cfesapi.org.owasp.esapi.lang.Object" implements="cfesapi.org.owasp.esapi.Encoder" output="false" hint="Reference implementation of the Encoder interface. This implementation takes a whitelist approach to encoding, meaning that everything not specifically identified in a list of 'immune' characters is encoded.">

	<cfscript>
		instance.ESAPI = "";

		instance.codecs = [];

		instance.logger = "";

		/* Character sets that define characters (in addition to alphanumerics) that are immune from encoding in various formats */
		instance.IMMUNE_HTML = [ ',', '.', '-', '_', ' ' ];
		instance.IMMUNE_HTMLATTR = [ ',', '.', '-', '_' ];
		instance.IMMUNE_CSS = [];
		instance.IMMUNE_JAVASCRIPT = [ ',', '.', '_' ];
		instance.IMMUNE_VBSCRIPT = [ ',', '.', '_' ];
		instance.IMMUNE_XML = [ ',', '.', '-', '_', ' ' ];
		instance.IMMUNE_SQL = [ ' ' ];
		instance.IMMUNE_OS = [ '-' ];
		instance.IMMUNE_XMLATTR = [ ',', '.', '-', '_' ];
		instance.IMMUNE_XPATH = [ ',', '.', '-', '_', ' ' ];
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
		<cfargument type="boolean" name="restrictMultiple" required="false">
		<cfargument type="boolean" name="restrictMixed" required="false">
		<cfscript>
			// if only 1 argument was passed, assume default 2 optional arguments
			// we can't use cfargument default otherwise the next condition below would never be true
			if (!structKeyExists(arguments, "restrictMultiple")) {
				return canonicalize(arguments.input, !instance.ESAPI.securityConfiguration().getAllowMultipleEncoding(), !instance.ESAPI.securityConfiguration().getAllowMixedEncoding());
			}
			// if 3rd argument is missing, assume old arguments of "String input, boolean strict" were passed
			else if (!structKeyExists(arguments, "restrictMixed")) {
				return canonicalize(arguments.input, arguments.restrictMultiple, arguments.restrictMultiple);
			}
			
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
			            if ( isObject(local.codecFound) && !local.codecFound.equals(local.codec) ) {
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
			    if ( arguments.restrictMultiple || arguments.restrictMixed ) {
                	cfex = createObject('component', 'cfesapi.org.owasp.esapi.errors.IntrusionException').init(instance.ESAPI, "Input validation failure", "Multiple ("& local.foundCount &"x) and mixed encoding ("& local.mixedCount &"x) detected in " & arguments.input );
            		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			    } else {
			        instance.logger.warning( createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Multiple ("& local.foundCount &"x) and mixed encoding ("& local.mixedCount &"x) detected in " & arguments.input );
			    }
			}
			else if ( local.foundCount >= 2 ) {
			    if ( arguments.restrictMultiple ) {
                	cfex = createObject('component', 'cfesapi.org.owasp.esapi.errors.IntrusionException').init(instance.ESAPI, "Input validation failure", "Multiple ("& local.foundCount &"x) encoding detected in " & arguments.input );
            		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			    } else {
			        instance.logger.warning( createObject("java", "org.owasp.esapi.Logger").SECURITY_FAILURE, "Multiple ("& local.foundCount &"x) encoding detected in " & arguments.input );
			    }
			}
			else if ( local.mixedCount > 1 ) {
			    if ( arguments.restrictMixed ) {
	                cfex = createObject('component', 'cfesapi.org.owasp.esapi.errors.IntrusionException').init(instance.ESAPI, "Input validation failure", "Mixed encoding ("& local.mixedCount &"x) detected in " & arguments.input );
            		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
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
		    return createObject("java", "org.owasp.esapi.codecs.HTMLEntityCodec").init().encode( instance.IMMUNE_HTML, javaCast("string", arguments.input));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="decodeForHTML" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			return createObject("java", "org.owasp.esapi.codecs.HTMLEntityCodec").init().decode(javaCast("string", arguments.input));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForHTMLAttribute" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
		    return createObject("java", "org.owasp.esapi.codecs.HTMLEntityCodec").init().encode( instance.IMMUNE_HTMLATTR, javaCast("string", arguments.input));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForCSS" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
	    	return createObject("java", "org.owasp.esapi.codecs.CSSCodec").init().encode( instance.IMMUNE_CSS, javaCast("string", arguments.input));
	    </cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForJavaScript" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
	    	return createObject("java", "org.owasp.esapi.codecs.JavaScriptCodec").init().encode(instance.IMMUNE_JAVASCRIPT, javaCast("string", arguments.input));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForVBScript" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			return createObject("java", "org.owasp.esapi.codecs.VBScriptCodec").init().encode(instance.IMMUNE_VBSCRIPT, javaCast("string", arguments.input));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForSQL" output="false">
		<cfargument type="any" name="codec" required="true" hint="org.owasp.esapi.codecs.Codec">
		<cfargument type="String" name="input" required="true">
		<cfscript>
		    return arguments.codec.encode(instance.IMMUNE_SQL, javaCast("string", arguments.input));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForOS" output="false">
		<cfargument type="any" name="codec" required="true" hint="org.owasp.esapi.codecs.Codec">
		<cfargument type="String" name="input" required="true">
		<cfscript>
		    return arguments.codec.encode( instance.IMMUNE_OS, javaCast("string", arguments.input));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForLDAP" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			// TODO: replace with LDAP codec
		    local.sb = createObject("java", "java.lang.StringBuilder").init();
			for (local.i = 0; local.i < arguments.input.length(); local.i++) {
				local.c = arguments.input.charAt(local.i);
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
				case chr(0):	// not sure this will ever run
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
	    	return createObject("java", "org.owasp.esapi.codecs.HTMLEntityCodec").init().encode( instance.IMMUNE_XPATH, javaCast("string", arguments.input));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForXML" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
	    	return createObject("java", "org.owasp.esapi.codecs.XMLEntityCodec").init().encode( instance.IMMUNE_XML, javaCast("string", arguments.input));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForXMLAttribute" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
	    	return createObject("java", "org.owasp.esapi.codecs.XMLEntityCodec").init().encode( instance.IMMUNE_XMLATTR, javaCast("string", arguments.input));
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForURL" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
	    	try {
				return createObject("java", "java.net.URLEncoder").encode(javaCast("string", arguments.input), instance.ESAPI.securityConfiguration().getCharacterEncoding());
			} catch (java.io.UnsupportedEncodingException ex) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncodingException").init(instance.ESAPI, "Encoding failure", "Character encoding not supported", ex);
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			} catch (java.lang.Exception e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncodingException").init(instance.ESAPI, "Encoding failure", "Problem URL encoding input", e);
           		throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="decodeFromURL" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
	    	local.canonical = canonicalize(arguments.input);
			try {
				return createObject("java", "java.net.URLDecoder").decode(javaCast("string", local.canonical), instance.ESAPI.securityConfiguration().getCharacterEncoding());
			} catch (java.io.UnsupportedEncodingException ex) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncodingException").init(instance.ESAPI, "Decoding failed", "Character encoding not supported", ex);
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			} catch (java.lang.Exception e) {
				cfex = createObject("component", "cfesapi.org.owasp.esapi.errors.EncodingException").init(instance.ESAPI, "Decoding failed", "Problem URL decoding input", e);
				throw(type=cfex.getType(), message=cfex.getUserMessage(), detail=cfex.getLogMessage());
			}
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForBase64" output="false">
		<cfargument type="any" name="input" required="true" hint="binary">
		<cfargument type="boolean" name="wrap" required="true">
		<cfscript>
			return toBase64(arguments.input);
		</cfscript> 
	</cffunction>


	<cffunction access="public" returntype="binary" name="decodeFromBase64" output="false">
		<cfargument type="String" name="input" required="true">
		<cfscript>
			try {
				return toBinary(arguments.input);
			} catch(Expression e) {	// input was not Base64, so make it so
				return toBinary(toBase64(arguments.input));
			}
		</cfscript> 
	</cffunction>


</cfcomponent>
