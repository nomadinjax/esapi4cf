<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> | 
<a href="#buildURL('Encoding')#">Tutorial</a> | 
<a href="#buildURL('Encoding.lab')#">Lab : Encoding</a> |
<a href="#buildURL('Encoding.solution')#">Solution</a> |
<a href="#buildURL('XSS.lab')#">Lab : XSS</a> | 
<a href="#buildURL('XSS.solution')#">Solution</a> |
<b><a href="#buildURL('Canonicalize.lab')#">Lab : Canonicalize</a></b> | 
<a href="#buildURL('Canonicalize.solution')#">Solution</a>
</div>
<div id="header"></div>
<p>
<hr>

<cfparam name="rc.input" default="%2&##x35;2%3525&##x32;\\u0036lt;\r\n\r\n%&##x%%%3333\\u0033;&%23101;">
<cfscript>
	canonical = "";
	userMessage = "";
	logMessage = "";
</cfscript>

<h2 align="center">Canonicalize Exercise</h2>
<h4>CFM Location : #getCurrentTemplateWebPath()#</h4>
<p>Canonicalization deals with the way in which systems convert data from one form to another. Canonical means the simplest or most standard form of something. Canonicalization is the process of converting something from one representation to the simplest form</p>
<h4>Enter encoded data</h4>
<p>Your goal is to canonicalize the input to see the string decoded, and to display the IntrusionException's user and log messages if necessary. <br />

(For more information on the user and log messages of ESAPI's Exception classes, c.f. the <a href="#buildURL('ErrorHandling')#">ErrorHandling Tutorial</a>)</p>

<form action="#buildURL('Canonicalize.lab')#" method="POST">
	<table>
	<tr><td>Original</td><td>Decoded</td></tr>
	<tr><td>
		<textarea style="width:300px; height:150px" name="input">#ESAPI().encoder().encodeForHTML(rc.input)#</textarea>
	</td><td>
		<textarea style="width:300px; height:150px">#ESAPI().encoder().encodeForHTML(canonical)#</textarea>
	</td></tr></table>
	<input type="submit" value="submit">
</form>
<!-- <p>The User Message and Log Message can be obtained by the IntrusionException, thrown by ESAPI.encoder().canonicalize()</p> -->
<p>User Message: <font color="red">#ESAPI().encoder().encodeForHTML(userMessage)#</font></p>
<p>Log Message: <font color="red">#ESAPI().encoder().encodeForHTML(logMessage)#</font></p><hr>

</cfoutput>
