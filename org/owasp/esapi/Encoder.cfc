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
<cfinterface hint="The Encoder interface contains a number of methods for decoding input and encoding output so that it will be safe for a variety of interpreters. To prevent double-encoding, all encoding methods should first check to see that the input does not already contain encoded characters. There are a few methods related to decoding that are used for canonicalization purposes. See the Validator class for more information as the Validators rely heavily on these decoders for canonicalizing data before validating it. All of the methods must use a 'whitelist' or 'positive' security model. For the encoding methods, this means that all characters should be encoded, except for a specific list of 'immune' characters that are known to be safe. For the decoding methods, all encoded characters should be decoded and if any doubly encoded characters (using the same encoding scheme or two different encoding schemes) should be rejected. ">
	<!--- Railo 4/CF10 throw error: The name [canonicalize] is already used by a built in Function

	    <cffunction access="public" returntype="String" name="canonicalize" output="false"
	    hint="This method performs canonicalization on data received to ensure that it has been reduced to its most basic form before validation. For example, URL-encoded data received from ordinary 'application/x-www-url-encoded' forms so that it may be validated properly. Canonicalization is simply the operation of reducing a possibly encoded string down to its simplest form. This is important, because attackers frequently use encoding to change their input in a way that will bypass validation filters, but still be interpreted properly by the target of the attack. Note that data encoded more than once is not something that a normal user would generate and should be regarded as an attack. For input that comes from an HTTP servlet request, there are generally two types of encoding to be concerned with. The first is 'applicaton/x-www-url-encoded' which is what is typically used in most forms and URI's where characters are encoded in a %xy format. The other type of common character encoding is HTML entity encoding, which uses several formats: &lt;, &##117;, and &##x3a;. Note that all of these formats may possibly render properly in a browser without the trailing semicolon. Double-encoding is a particularly thorny problem, as applying ordinary decoders may introduce encoded characters, even characters encoded with a different encoding scheme. For example %26lt; is a < character which has been entity encoded and then the first character has been url-encoded. Implementations should throw an IntrusionException when double-encoded characters are detected. Note that there is also 'multipart/form' encoding, which allows files and other binary data to be transmitted. Each part of a multipart form can itself be encoded according to a 'Content-Transfer-Encoding' header. See the HTTPUtilties.getSafeFileUploads() method. For more information on form encoding, please refer to the W3C specifications.">
	    <cfargument required="true" type="String" name="input" hint="the text to canonicalize"/>
	    <cfargument required="false" type="boolean" name="strict" hint="true if checking for double encoding is desired, false otherwise"/>
	    </cffunction>
	--->
	<!--- Railo 4/CF10 throw error: The name [encodeForCSS] is already used by a built in Function

	    <cffunction access="public" returntype="String" name="encodeForCSS" output="false"
	    hint="Encode data for use in Cascading Style Sheets (CSS) content.">
	    <cfargument required="true" type="String" name="input" hint="the text to encode for CSS"/>
	    </cffunction>
	--->
	<!--- Railo 4/CF10 throw error: The name [encodeForHTML] is already used by a built in Function

	    <cffunction access="public" returntype="String" name="encodeForHTML" output="false"
	    hint="Encode data for use in HTML using HTML entity encoding Note that the following characters: 00�08, 0B�0C, 0E�1F, and 7F�9F cannot be used in HTML.">
	    <cfargument required="true" type="String" name="input" hint="the text to encode for HTML"/>
	    </cffunction>
	--->
	<!--- Railo 4/CF10 throw error: The name [encodeForHTMLAttribute] is already used by a built in Function

	    <cffunction access="public" returntype="String" name="encodeForHTMLAttribute" output="false"
	    hint="Encode data for use in HTML attributes.">
	    <cfargument required="true" type="String" name="input" hint="the text to encode for an HTML attribute"/>
	    </cffunction>
	--->
	<!--- Railo 4/CF10 throw error: The name [encodeForJavaScript] is already used by a built in Function

	    <cffunction access="public" returntype="String" name="encodeForJavaScript" output="false"
	    hint="Encode data for insertion inside a data value in JavaScript. Putting user data directly inside a script is quite dangerous. Great care must be taken to prevent putting user data directly into script code itself, as no amount of encoding will prevent attacks there.">
	    <cfargument required="true" type="String" name="input" hint="the text to encode for JavaScript"/>
	    </cffunction>
	--->

	<cffunction access="public" returntype="String" name="encodeForVBScript" output="false"
	            hint="Encode data for insertion inside a data value in a Visual Basic script. Putting user data directly inside a script is quite dangerous. Great care must be taken to prevent putting user data directly into script code itself, as no amount of encoding will prevent attacks there. This method is not recommended as VBScript is only supported by Internet Explorer">
		<cfargument required="true" type="String" name="input" hint="the text to encode for VBScript"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForSQL" output="false"
	            hint="Encode input for use in a SQL query, according to the selected codec (appropriate codecs include the MySQLCodec and OracleCodec). his method is not recommended. The use of the PreparedStatement interface is the preferred approach. However, if for some reason this is impossible, then this method is provided as a weaker alternative. The best approach is to make sure any single-quotes are double-quoted. Another possible approach is to use the {escape} syntax described in the JDBC specification in section 1.5.6. However, this syntax does not work with all drivers, and requires modification of all queries.">
		<cfargument required="true" name="codec" hint="a Codec that declares which database 'input' is being encoded for (ie. MySQL, Oracle, etc.)"/>
		<cfargument required="true" type="String" name="input" hint="the text to encode for SQL"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="encodeForOS" output="false"
	            hint="Encode for an operating system command shell according to the selected codec (appropriate codecs include the WindowsCodec and UnixCodec).">
		<cfargument required="true" name="codec" hint="a Codec that declares which operating system 'input' is being encoded for (ie. Windows, Unix, etc.)"/>
		<cfargument required="true" type="String" name="input" hint="the text to encode for the command shell"/>

	</cffunction>

	<!--- Railo 4/CF10 throw error: The name [encodeForLDAP] is already used by a built in Function

	    <cffunction access="public" returntype="String" name="encodeForLDAP" output="false"
	    hint="Encode data for use in LDAP queries.">
	    <cfargument required="true" type="String" name="input" hint="the text to encode for LDAP"/>
	    </cffunction>
	--->
	<!--- Railo 4/CF10 throw error: The name [encodeForDN] is already used by a built in Function

	    <cffunction access="public" returntype="String" name="encodeForDN" output="false"
	    hint="Encode data for use in an LDAP distinguished name.">
	    <cfargument required="true" type="String" name="input" hint="the text to encode for an LDAP distinguished name"/>
	    </cffunction>
	--->
	<!--- Railo 4/CF10 throw error: The name [encodeForXPath] is already used by a built in Function

	    <cffunction access="public" returntype="String" name="encodeForXPath" output="false"
	    hint="Encode data for use in an XPath query. NB: The reference implementation encodes almost everything and may over-encode. The difficulty with XPath encoding is that XPath has no built in mechanism for escaping characters. It is possible to use XQuery in a parameterized way to prevent injection. For more information, refer to this article which specifies the following list of characters as the most dangerous: ^&""*';<>(). This paper suggests disallowing ' and "" in queries.">
	    <cfargument required="true" type="String" name="input" hint="the text to encode for XPath"/>
	    </cffunction>
	--->
	<!--- Railo 4/CF10 throw error: The name [encodeForXML] is already used by a built in Function

	    <cffunction access="public" returntype="String" name="encodeForXML" output="false"
	    hint="Encode data for use in an XML element. The implementation should follow the XML Encoding Standard from the W3C. The use of a real XML parser is strongly encouraged. However, in the hopefully rare case that you need to make sure that data is safe for inclusion in an XML document and cannot use a parse, this method provides a safe mechanism to do so.">
	    <cfargument required="true" type="String" name="input" hint="the text to encode for XML"/>
	    </cffunction>
	--->
	<!--- Railo 4/CF10 throw error: The name [encodeForXMLAttribute] is already used by a built in Function

	    <cffunction access="public" returntype="String" name="encodeForXMLAttribute" output="false"
	    hint="Encode data for use in an XML attribute. The implementation should follow the XML Encoding Standard from the W3C. The use of a real XML parser is highly encouraged. However, in the hopefully rare case that you need to make sure that data is safe for inclusion in an XML document and cannot use a parse, this method provides a safe mechanism to do so.">
	    <cfargument required="true" type="String" name="input" hint="the text to encode for use as an XML attribute"/>
	    </cffunction>
	--->
	<!--- Railo 4/CF10 throw error: The name [encodeForURL] is already used by a built in Function

	    <cffunction access="public" returntype="String" name="encodeForURL" output="false"
	    hint="Encode for use in a URL. This method performs URL encoding on the entire string.">
	    <cfargument required="true" type="String" name="input" hint="the text to encode for use in a URL"/>
	    </cffunction>
	--->
	<!--- Railo 4/CF10 throw error: The name [decodeFromURL] is already used by a built in Function

	    <cffunction access="public" returntype="String" name="decodeFromURL" output="false"
	    hint="Decode from URL. Implementations should first canonicalize and detect any double-encoding. If this check passes, then the data is decoded using URL decoding.">
	    <cfargument required="true" type="String" name="input" hint="the text to decode from an encoded URL"/>
	    </cffunction>
	--->

	<cffunction access="public" returntype="String" name="encodeForBase64" output="false"
	            hint="Encode for Base64.">
		<cfargument required="true" type="binary" name="input" hint="the text to encode for Base64"/>
		<cfargument required="true" type="boolean" name="wrap" hint="the encoder will wrap lines every 64 characters of output"/>

	</cffunction>

	<cffunction access="public" returntype="binary" name="decodeFromBase64" output="false"
	            hint="Decode data encoded with BASE-64 encoding.">
		<cfargument required="true" type="String" name="input" hint="the Base64 text to decode"/>

	</cffunction>

</cfinterface>