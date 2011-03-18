<cfinterface hint="The Encoder interface contains a number of methods for decoding input and encoding output so that it will be safe for a variety of interpreters. To prevent double-encoding, callers should make sure input does not already contain encoded characters by calling canonicalize. Validator implementations should call canonicalize on user input 'before' validating to prevent encoded attacks. All of the methods must use a 'whitelist' or 'positive' security model. For the encoding methods, this means that all characters should be encoded, except for a specific list of 'immune' characters that are known to be safe. The Encoder performs two key functions, encoding and decoding. These functions rely on a set of codecs that can be found in the org.owasp.esapi.codecs package.">

	<cffunction access="public" returntype="String" name="canonicalize" output="false" hint="Canonicalization is simply the operation of reducing a possibly encoded string down to its simplest form. This is important, because attackers frequently use encoding to change their input in a way that will bypass validation filters, but still be interpreted properly by the target of the attack. Note that data encoded more than once is not something that a normal user would generate and should be regarded as an attack. Everyone says you shouldn't do validation without canonicalizing the data first. This is easier said than done. The canonicalize method can be used to simplify just about any input down to its most basic form. Note that canonicalize doesn't handle Unicode issues, it focuses on higher level encoding and escaping schemes.">
		<cfargument type="String" name="input" required="true" hint="the text to canonicalize">
		<cfargument type="boolean" name="strict" required="false" hint="true if checking for double encoding is desired, false otherwise">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForCSS" output="false" hint="Encode data for use in Cascading Style Sheets (CSS) content.">
		<cfargument type="String" name="input" required="true" hint="the text to encode for CSS">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForHTML" output="false" hint="Encode data for use in HTML using HTML entity encoding">
		<cfargument type="String" name="input" required="true" hint="the text to encode for HTML">
	</cffunction>


	<cffunction access="public" returntype="String" name="decodeForHTML" output="false" hint="Decodes HTML entities.">
		<cfargument type="String" name="input" required="true" hint="the String to decode">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForHTMLAttribute" output="false" hint="Encode data for use in HTML attributes.">
		<cfargument type="String" name="input" required="true" hint="the text to encode for an HTML attribute">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForJavaScript" output="false" hint="Encode data for insertion inside a data value or function argument in JavaScript. Including user data directly inside a script is quite dangerous. Great care must be taken to prevent including user data directly into script code itself, as no amount of encoding will prevent attacks there. Please note there are some JavaScript functions that can never safely receive untrusted data as input &ndash; even if the user input is encoded.">
		<cfargument type="String" name="input" required="true" hint="the text to encode for JavaScript">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForVBScript" output="false" hint="Encode data for insertion inside a data value in a Visual Basic script. Putting user data directly inside a script is quite dangerous. Great care must be taken to prevent putting user data directly into script code itself, as no amount of encoding will prevent attacks there. This method is not recommended as VBScript is only supported by Internet Explorer">
		<cfargument type="String" name="input" required="true" hint="the text to encode for VBScript">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForSQL" output="false" hint="Encode input for use in a SQL query, according to the selected codec (appropriate codecs include the MySQLCodec and OracleCodec). This method is not recommended. The use of the PreparedStatement interface is the preferred approach. However, if for some reason this is impossible, then this method is provided as a weaker alternative. The best approach is to make sure any single-quotes are double-quoted. Another possible approach is to use the {escape} syntax described in the JDBC specification in section 1.5.6. However, this syntax does not work with all drivers, and requires modification of all queries.">
		<cfargument type="any" name="codec" required="true" hint="org.owasp.esapi.codecs.Codec: a Codec that declares which database 'input' is being encoded for (ie. MySQL, Oracle, etc.)">
		<cfargument type="String" name="input" required="true" hint="the text to encode for SQL">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForOS" output="false" hint="Encode for an operating system command shell according to the selected codec (appropriate codecs include the WindowsCodec and UnixCodec). Please note the following recommendations before choosing to use this method: 1) It is strongly recommended that applications avoid making direct OS system calls if possible as such calls are not portable, and they are potentially unsafe. Please use language provided features if at all possible, rather than native OS calls to implement the desired feature. 2) If an OS call cannot be avoided, then it is recommended that the program to be invoked be invoked directly (e.g., System.exec('nameofcommand' + 'parameterstocommand');) as this avoids the use of the command shell. The 'parameterstocommand' should of course be validated before passing them to the OS command. 3) If you must use this method, then we recommend validating all user supplied input passed to the command shell as well, in addition to using this method in order to make the command shell invocation safe.">
		<cfargument type="any" name="codec" required="true" hint="org.owasp.esapi.codecs.Codec: a Codec that declares which operating system 'input' is being encoded for (ie. Windows, Unix, etc.)">
		<cfargument type="String" name="input" required="true" hint="the text to encode for the command shell">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForLDAP" output="false" hint="Encode data for use in LDAP queries.">
		<cfargument type="String" name="input" required="true" hint="the text to encode for LDAP">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForDN" output="false" hint="Encode data for use in an LDAP distinguished name.">
		<cfargument type="String" name="input" required="true" hint="the text to encode for an LDAP distinguished name">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForXPath" output="false" hint="Encode data for use in an XPath query. NB: The reference implementation encodes almost everything and may over-encode. The difficulty with XPath encoding is that XPath has no built in mechanism for escaping characters. It is possible to use XQuery in a parameterized way to prevent injection. ">
		<cfargument type="String" name="input" required="true" hint="the text to encode for XPath">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForXML" output="false" hint="Encode data for use in an XML element. The implementation should follow the XML Encoding Standard from the W3C. The use of a real XML parser is strongly encouraged. However, in the hopefully rare case that you need to make sure that data is safe for inclusion in an XML document and cannot use a parse, this method provides a safe mechanism to do so.">
		<cfargument type="String" name="input" required="true" hint="the text to encode for XML">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForXMLAttribute" output="false" hint="Encode data for use in an XML attribute. The implementation should follow the XML Encoding Standard from the W3C. The use of a real XML parser is highly encouraged. However, in the hopefully rare case that you need to make sure that data is safe for inclusion in an XML document and cannot use a parse, this method provides a safe mechanism to do so.">
		<cfargument type="String" name="input" required="true" hint="the text to encode for use as an XML attribute">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForURL" output="false" hint="Encode for use in a URL. This method performs URL encoding on the entire string.">
		<cfargument type="String" name="input" required="true" hint="the text to encode for use in a URL">
	</cffunction>


	<cffunction access="public" returntype="String" name="decodeFromURL" output="false" hint="Decode from URL. Implementations should first canonicalize and detect any double-encoding. If this check passes, then the data is decoded using URL decoding.">
		<cfargument type="String" name="input" required="true" hint="the text to decode from an encoded URL">
	</cffunction>


	<cffunction access="public" returntype="String" name="encodeForBase64" output="false" hint="Encode for Base64.">
		<cfargument type="any" name="input" required="true" hint="binary: the text to encode for Base64">
		<cfargument type="boolean" name="wrap" required="true" hint="the encoder will wrap lines every 64 characters of output">
	</cffunction>


	<cffunction access="public" returntype="binary" name="decodeFromBase64" output="false" hint="Decode data encoded with BASE-64 encoding.">
		<cfargument type="String" name="input" required="true" hint="the Base64 text to decode">
	</cffunction>

</cfinterface>
