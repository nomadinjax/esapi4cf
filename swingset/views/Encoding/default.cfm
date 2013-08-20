<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> | 
<b><a href="#buildURL('Encoding')#">Tutorial</a></b> | 
<a href="#buildURL('Encoding.lab')#">Lab : Encoding</a> |
<a href="#buildURL('Encoding.solution')#">Solution</a> |
<a href="#buildURL('XSS.lab')#">Lab : XSS</a> | 
<a href="#buildURL('XSS.solution')#">Solution</a> |
<a href="#buildURL('Canonicalize.lab')#">Lab : Canonicalize</a> | 
<a href="#buildURL('Canonicalize.solution')#">Solution</a>
</div>
<div id="header"></div>
<p>
<hr>

<h2 align="center">Tutorial</h2>

Encoding, closely related to Escaping is a powerful mechanism to help protect against many types of attack, especially injection attacks and Cross-site Scripting (XSS). Essentially, encoding involves translating special characters into some equivalent that is no longer significant in the target interpreter. So, for example, using HTML entity encoding before sending untrusted data into a browser will protect against many forms of Cross-site Scripting (XSS).<br /><br />
Considerations:<br /><br />
<span style="font-weight:bold">What interpreter?</span><br />
To encode properly, you need to know what interpreters the data might end up in. For example, if the data is going into a SQL interpreter, you should consider encoding based on syntax of the SQL engine you are using.<br /><br />
<span style="font-weight:bold">What characters? Complete?</span><br />
You want to make sure that you encode all the characters that might cause a problem, so the best approach is to use a positive encoding scheme, where all characters except a minimal known good set are encoded.<br /><br />
<span style="font-weight:bold">What encoding scheme?</span><br />
There are dozens of ways to encode characters and many interpreters allow multiple forms of a single significant character. For a browser, HTML entity encoding is a good way to prevent script injection, but URL encoding or Unicode encoding (%xx) will not prevent scripts from running. Be sure to use the appropriate encoding scheme for the target interpreter.<br /><br />
<span style="font-weight:bold">Double encoding and decoding?</span><br />
Be careful not to double encode your data. In some cases, doubly encoding data can inadvertently introduce special characters in the final output. Also, be aware that some processors may automatically undo your encoding. There is some evidence that XML processors are decoding HTML entity encoding, thus reintroducing potential XSS problems.
<br /><br />
<h4>Using ESAPI for encoding & decoding: </h4>
ESAPI's Encoder interface contains a number of methods for decoding input and encoding output.
<p class="newsItem">
<code>
//sample usage of ESAPI's Encoder interface<br/>
application.ESAPI.encoder().encodeForHTML(input)
</code>
</p>

<ul>
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##canonicalize">String canonicalize(String input)</a></b> This method performs canonicalization on data received to ensure that it has been reduced to its most basic form before validation.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##canonicalize">String canonicalize(String input, boolean strict)</a></b> This method performs canonicalization on data received to ensure that it has been reduced to its most basic form before validation.</li><br />
    <li><b><a href="../apiref/org/owasp/esapi/Encoder.html##decodeFromBase64">decodeFromBase64(String input)</a></b> Decode data encoded with BASE-64 encoding.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##decodeFromURL">decodeFromURL(String input)</a></b> Decode from URL.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##encodeForBase64">encodeForBase64(byte[] input, boolean wrap)</a></b> Encode for Base64.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##encodeForCSS">encodeForCSS(String input)</a></b> Encode data for use in Cascading Style Sheets (CSS) content.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##encodeForDN">encodeForDN(String input)</a></b> Encode data for use in an LDAP distinguished name.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##encodeForHTML">encodeForHTML(String input)</a></b> Encode data for use in HTML using HTML entity encoding.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##encodeForHTMLAttribute">encodeForHTMLAttribute(String input)</a></b> Encode data for use in HTML attributes.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##encodeForJavaScript">encodeForJavaScript(String input)</a></b>  Encode data for insertion inside a data value in JavaScript.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##encodeForLDAP">encodeForLDAP(String input)</a></b> Encode data for use in LDAP queries.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##encodeForOS">encodeForOS(Codec codec, String input)</a></b> Encode for an operating system command shell according to the selected codec (appropriate codecs include the WindowsCodec and UnixCodec).</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##encodeForSQL">encodeForSQL(Codec codec, String input)</a></b> Encode input for use in a SQL query, according to the selected codec (appropriate codecs include the MySQLCodec and OracleCodec).</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##encodeForURL">encodeForURL(String input)</a></b> Encode for use in a URL.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##encodeForVBScript">encodeForVBScript(String input)</a></b> Encode data for insertion inside a data value in a Visual Basic script.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##encodeForXML">encodeForXML(String input)</a></b> Encode data for use in an XML element.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##encodeForXMLAttribute">encodeForXMLAtribute(String input)</a></b> Encode data for use in an XML attribute.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##encodeForXPath">encodeForXPath(String input)</a></b> Encode data for use in an XPath query.</li><br />
	<li><b><a href="../apiref/org/owasp/esapi/Encoder.html##normalize">normalize(String input)</a></b> Reduce all non-ascii characters to their ASCII form so that simpler validation rules can be applied.</li><br />
</ul>

</cfoutput>