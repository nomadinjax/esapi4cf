<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> | 
<a href="#buildURL('Encoding')#">Tutorial</a> | 
<b><a href="#buildURL('Encoding.lab')#">Lab : Encoding</a></b> |
<a href="#buildURL('Encoding.solution')#">Solution</a> |
<a href="#buildURL('XSS.lab')#">Lab : XSS</a> | 
<a href="#buildURL('XSS.solution')#">Solution</a> |
<a href="#buildURL('Canonicalize.lab')#">Lab : Canonicalize</a> | 
<a href="#buildURL('Canonicalize.solution')#">Solution</a>
</div>
<div id="header"></div>
<p>

<cfparam name="form.input" default="encode this string">

<h2>HTML Encoding Exercise</h2>
<h4>CFM Location: #getCurrentTemplateWebPath()#</h4>
<p>Enter some javascript in the following text box. E.g.</p>
<code>
		<b>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</b>
</code>
<p>Your goal is to html encode the input so the script is not executed.</p>
<form action="#buildURL('Encoding.lab')#" method="POST">	
	<textarea style="width:400px; height:150px" name="input">#form.input#</textarea>
	<input type="submit" value="submit"><br></td>
</form>

<!-- TODO HTML Encode the Output -->
<p>Output : #form.input#</p>

</cfoutput>