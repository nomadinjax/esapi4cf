<cfparam name="form.input" default="">
<cfparam name="form.output" default="">

<cfscript>
	output = "";
	input = form.input;
	err = "";
	if(form.output!=""){
		output = ESAPI().currentRequest().getAttribute("output").toString();
	}
	if ( input == "" ) input = "type input here";
	
	// TODO 1: Canonicalize the input string
	// TODO 2: Validate the string checking that it is a safe string	
</cfscript>
<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> | 
<a href="#buildURL('ValidateUserInput')#">Tutorial</a> | 
<b><a href="#buildURL('ValidateUserInput.lab')#">Lab : Validate User Input</a></b> | 
<a href="#buildURL('ValidateUserInput.solution')#">Solution</a> |
<a href="#buildURL('RichContent.lab')#">Lab : Rich Content</a> | 
<a href="#buildURL('RichContent.solution')#">Solution</a>

</div>
<div id="header"></div>
<p>
<hr>


<h2 align="center">Validate User Input Exercise</h2>
<h4>CFM Location: #getCurrentTemplateWebPath()#</h4>
<form action="#buildURL('ValidateUserInput.lab')#" method="POST">
	<p>Enter malicious data in the textbox</p>
	<p class="newsItem">
	<code>
		EXAMPLE: <b>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</b>
	</code>
	</p>
	<p>Your goal is to canonicalize the input to remove any encoding. Then validate the input using ESAPI.validator().getValidInput. <br/>
		ESAPI.validator().getValidInput uses a regular expression set with the property Validator.SafeString in the file validation.properties.
		Then display the output encoded for html. The validation.properties is located in the <i>.esapi</i> folder. 		 
	</p>
	<textarea style="width:300px; height:100px" name="input">#input#</textarea>
	<br /><br /><input type="submit" value="Submit">
</form>

<!--  TODO 3: Encode the output for HTML -->
<h4>Unvalidated output: </h4>#output#
</cfoutput>