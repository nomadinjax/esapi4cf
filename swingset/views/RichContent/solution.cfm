<cfparam name="form.input" default="">

<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> | 
<a href="#buildURL('ValidateUserInput')#">Tutorial</a> | 
<a href="#buildURL('ValidateUserInput.lab')#">Lab : Validate User Input</a> | 
<a href="#buildURL('ValidateUserInput.solution')#">Solution</a> |
<a href="#buildURL('RichContent.lab')#">Lab : Rich Content</a> | 
<b><a href="#buildURL('RichContent.solution')#">Solution</a></b>
</div>
<div id="header"></div>
<p>
<hr>

<cfscript>
input = "<p>test <b>this</b> <script>alert(document.cookie)</script><i>right</i> now</p>";
markup = "testing";
if( form.input != "" )
	input = form.input;
try{
	markup = application.ESAPI.validator().getValidSafeHTML("input", input, 2500, false);
}
catch(org.owasp.esapi.errors.ValidationException e){
	application.ESAPI.logger().error(application.ESAPILogger.EVENT_FAILURE, false, e.message);
}
</cfscript>

<h2>Rich Content Solution</h2>
<h4>CFM Location: #getCurrentTemplateWebPath()#</h4>

<p>The input is validated using application.ESAPI.validator().getValidSafeHTML()</p>

<form action="#buildURL('RichContent.solution')#" method="POST">
	<table width="100%" border="1">
	<tr><th width="50%">Enter whatever markup you want</th><th>Safe HTML rendered</th><th>HTML encoded</th></tr>
	<tr><td><textarea style="width:400px; height:150px" name="input">#input#</textarea><input type="submit" value="render"><br></td><td>#markup#</td><td>#application.ESAPI.encoder().encodeForHTML(markup)#</td></tr>
	</table>
</form>

</cfoutput>