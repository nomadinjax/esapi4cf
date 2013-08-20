<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> | 
<a href="#buildURL('Encoding')#">Tutorial</a> | 
<a href="#buildURL('Encoding.lab')#">Lab : Encoding</a> |
<b><a href="#buildURL('Encoding.solution')#">Solution</a></b> |
<a href="#buildURL('XSS.lab')#">Lab : XSS</a> | 
<a href="#buildURL('XSS.solution')#">Solution</a> |
<a href="#buildURL('Canonicalize.lab')#">Lab : Canonicalize</a> | 
<a href="#buildURL('Canonicalize.solution')#">Solution</a>
</div>
<div id="header"></div>
<p>
<cfparam name="form.input" default="encode 'this' <b>string</b> null #chr(0)# byte">
<cfscript>
	OracleCodec = createObject("java", "org.owasp.esapi.codecs.OracleCodec");
	MySQLCodec = createObject("java", "org.owasp.esapi.codecs.MySQLCodec");

	oracle = OracleCodec.init();
	mysqlansi = MySQLCodec.init( MySQLCodec.ANSI_MODE);
	mysql = MySQLCodec.init( MySQLCodec.MYSQL_MODE);
</cfscript>

<h2>HTML Encoding Solution</h2>
<h4>CFM Location: #getCurrentTemplateWebPath()#</h4>

<p>Enter whatever input you want. Click submit and the table below will be populated using different Encoding methods.</br></p>

<form action="#buildURL('Encoding.solution')#" method="POST">	
	<textarea style="width:400px; height:150px" name="input">#form.input#</textarea><br>
	<input type="submit" value="submit">
</form>

<div style="overflow-x:scroll;">
<table border="1">
<tr><th>Input</th><th>Encoded output</th></tr>
<tr><td>Unencoded</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(form.input)#</pre></td></tr>
<tr><td>HTML Body (encodeForHTML)</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForHTML(form.input))#</pre></p></td></tr>
<tr><td>HTML Attribute (encodeForHTMLAttribute)</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForHTMLAttribute(form.input))#</pre></p></td></tr>
<tr><td>Javascript (encodeForJavascript)</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForJavaScript(form.input))#</pre></p></td></tr>
<tr><td>VBScript (encodeForVBScript)</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForVBScript(form.input))#</pre></p></td></tr>
<tr><td>CSS (encodeForCSS)</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForCSS(form.input))#</pre></p></td></tr>
<tr><td>URL (encodeForURL)</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForURL(form.input))#</pre></p></td></tr>
<tr><td>Base 64 (encodeForBase64)</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForBase64(form.input.getBytes(), false))#</pre></p></td></tr>
<tr><td>LDAP (encodeForLDAP)</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForLDAP(form.input))#</pre></p></td></tr>
<tr><td>Oracle (encodeForSQL) - discouraged use &lt;cfqueryparam&gt;</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForSQL(oracle, form.input))#</pre></p></td></tr>
<tr><td>MySQL (encodeForSQL) - discouraged use &lt;cfqueryparam&gt;</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForSQL(mysql, form.input))#</pre></p></td></tr>
<tr><td>MySQLAnsi (encodeForSQL) - discouraged use &lt;cfqueryparam&gt;</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForSQL(mysqlansi, form.input))#</pre></p></td></tr>
<tr><td>XML (encodeForXML)</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForXML(form.input))#</pre></p></td></tr>
<tr><td>XML Attribute (encodeForXMLAttribute)</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForXMLAttribute(form.input))#</pre></p></td></tr>
<tr><td>LDAP Distinguished Name (encodeForDN)</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForDN(form.input))#</pre></p></td></tr>
<tr><td>XPath Query (encodeForXPath)</td><td><p><pre>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForXPath(form.input))#</pre></p></td></tr>
</table>
</div>

<h2>Quick Reference</h2>

<p>Important: The characters below are what is produced by the ESAPI codecs. These
represent the most standard ways of encoding for the listed interpreters. However,
there are many other <i>legal</i> encoding formats. For example, the ESAPI default
is to use decimal HTML entities if there is not a named entity, but hexidecimal entities
(e.g. &amp;##x26;) are completely legal. ESAPI follows the principle of being liberal
in what it accepts (for canonicalization) and strict in what it emits.

<div style="overflow-x:scroll;"> 
<table width="100%">
<tr align="center" bgcolor="yellow">
<th width="10%">int</th>
<th width="10%">char</th>
<th width="10%">html body</th>
<th width="10%">html attr</th>
<th width="10%">javascript</th>
<th width="10%">vbscript</th>
<th width="10%">css</th>
<th width="10%">url</th>
<th width="10%">oracle</th>
<th width="10%">mysql</th>
<th width="10%">mysqlansi</th>
<th width="10%">xml</th>
<th width="10%">xml attr</th>
<th width="10%">ldap</th>
<th width="10%">ldap dn</th>
<th width="10%">xpath</th>
</tr>
</div>

<cfloop index="i" from="0" to="1024">
<cfset c = "" & chr(i)>
<cftry>
<tr bgcolor="##e0e0e0" align="center">
	<td bgcolor="yellow">#i#</td>
	<td bgcolor="yellow">#c#</td>
	<td>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForHTML(c))#</td>
	<td>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForHTMLAttribute(c))#</td>
	<td>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForJavaScript(c))#</td>
	<td>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForVBScript(c))#</td>
	<td>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForCSS(c))#</td>
	<td>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForURL(c))#</td>
	<td>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForSQL(oracle, c))#</td>
	<td>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForSQL(mysql, c))#</td>
	<td>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForSQL(mysqlansi, c))#</td>
	<td>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForXML(c))#</td>
	<td>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForXMLAttribute(c))#</td>
	<td>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForLDAP(c))#</td>
	<td>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForDN(c))#</td>
	<td>#application.ESAPI.encoder().encodeForHTML(application.ESAPI.encoder().encodeForXPath(c))#</td>
</tr>
<cfcatch type="Exception">
	<cfdump var="#cfcatch#">
</cfcatch>
</cftry>
</cfloop>
</table>
</cfoutput>