<cfparam name="form.input" default="">

<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> | 
<a href="#buildURL('ValidateUserInput')#">Tutorial</a> | 
<a href="#buildURL('ValidateUserInput.lab')#">Lab : Validate User Input</a> | 
<a href="#buildURL('ValidateUserInput.solution')#">Solution</a> |
<b><a href="#buildURL('RichContent.lab')#">Lab : Rich Content</a></b> | 
<a href="#buildURL('RichContent.solution')#">Solution</a>
</div>
<div id="header"></div>
<p>
<hr>

<h2>Rich Content Lab</h2>
<h4>CFM Location: #getCurrentTemplateWebPath()#</h4>
<p>One method many people use to safeguard their application from a XSS attack is to filter out the &lt;script&gt; tag.  While this may seem like it would prevent an attack involving javascript, it does contain some flaws.
One way to bypass this filtering is to input &lt;scr&lt;script&gt;ipt&gt;.  When &lt;script&gt; is removed, the two halves of the other &lt;script&gt; tag will come together, forming an attack.  Try this below and see what happens.<br /><br />
</p>
<p>Your goal here is to use ESAPI.validator().getValidSafeHtml to prevent the Cross Site Scripting Attack.</p>



<cfscript>
	input = form.input;
	if ( input == "" ) input = "<p>test <b>this</b> <script>alert(document.cookie)</script><i>right</i> now</p>";
	markup = input.replaceAll("<script>", "");
	// TODO: Check if the text entered is valid safe html
</cfscript>

<hr><br><h2>Exercise: Enter Rich HTML Markup</h2>
 
<form action="#buildURL('RichContent.lab')#" method="POST">
	<table width="100%" border="1"><tr><th width="50%">Enter whatever markup you want</th><th>Safe HTML rendered</th></tr>
	<tr><td><textarea style="width:400px; height:150px" name="input">#input#</textarea>
	<input type="submit" value="render"><br></td>
	<td>#markup#</td></tr></table>
</form>

</cfoutput>