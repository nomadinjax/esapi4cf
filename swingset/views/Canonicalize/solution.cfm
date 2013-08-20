<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> | 
<a href="#buildURL('Encoding')#">Tutorial</a> | 
<a href="#buildURL('Encoding.lab')#">Lab : Encoding</a> |
<a href="#buildURL('Encoding.solution')#">Solution</a> |
<a href="#buildURL('XSS.lab')#">Lab : XSS</a> | 
<a href="#buildURL('XSS.solution')#">Solution</a> |
<a href="#buildURL('Canonicalize.lab')#">Lab : Canonicalize</a> | 
<b><a href="#buildURL('Canonicalize.solution')#">Solution</a></b>
</div>
<div id="header"></div>
<p>
<hr>

<cfparam name="rc.input" default="%2&##x35;2%3525&##x32;\\u0036lt;\r\n\r\n%&##x%%%3333\\u0033;&%23101;">
<cfscript>
	canonical = "";
	// do it in strict mode just to get the warnings
	userMessage = "";
	logMessage = "";
	
	try {
		canonical = application.ESAPI.encoder().canonicalize(rc.input, true);
	}
	catch( org.owasp.esapi.errors.IntrusionException e ) {
		userMessage = e.message;
		logMessage = e.detail;
	}	

	// now redo it in non-strict mode to get the real answer
	canonical = application.ESAPI.encoder().canonicalize(rc.input, false);
</cfscript>

<h2 align="center">Canonicalize Solution</h2>
<h4>CFM Location : #getCurrentTemplateWebPath()#</h4>

<form action="#buildURL('Canonicalize.solution')#" method="POST">
	<table>
	<tr><td>Original</td><td>Decoded</td></tr>
	<tr><td>
		<textarea style="width:300px; height:150px" name="input">#application.ESAPI.encoder().encodeForHTML(rc.input)#</textarea>
	</td><td>
		<textarea style="width:300px; height:150px">#application.ESAPI.encoder().encodeForHTML(canonical)#</textarea>
	</td></tr></table>
	<input type="submit" value="submit">
</form>
<p>User Message: <font color="red">#application.ESAPI.encoder().encodeForHTML(userMessage)#</font></p>
<p>Log Message: <font color="red">#application.ESAPI.encoder().encodeForHTML(logMessage)#</font></p><hr>
<p>
<h2 align="center">Quick Reference</h2>

<table border=0 width="100%">
<tr align="center">
<td bgcolor="yellow">int</td><td>hex</td><td>char</td><td bgcolor="black">&nbsp;</td>
<td bgcolor="yellow">int</td><td>hex</td><td>char</td><td bgcolor="black">&nbsp;</td>
<td bgcolor="yellow">int</td><td>hex</td><td>char</td><td bgcolor="black">&nbsp;</td>
<td bgcolor="yellow">int</td><td>hex</td><td>char</td>
<cfset pc = createObject("java", "org.owasp.esapi.codecs.PercentCodec").init()>
<cfloop index="i" from="1" to="64">

<cfset value = i>
<tr align="center">
<td bgcolor="yellow">#value#</td>
<td>#pc.toHex( chr(value) )#</td>
<td>#chr(value)#</td>
<td bgcolor="black">&nbsp;</td>

<cfset value += 64>
<td bgcolor="yellow">#value#</td>
<td>#pc.toHex( chr(value) )#</td>
<td>#chr(value)#</td>
<td bgcolor="black">&nbsp;</td>

<cfset value += 64>
<td bgcolor="yellow">#value#</td>
<td>#pc.toHex( chr(value) )#</td>
<td>#chr(value)#</td>
<td bgcolor="black">&nbsp;</td>

<cfset value += 64>
<td bgcolor="yellow">#value#</td>
<td>#pc.toHex( chr(value) )#</td>
<td>#chr(value)#</td>
</tr>
</cfloop>
</table>

</cfoutput>