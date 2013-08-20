<cfparam name="form.type" default="">
<cfparam name="form.input" default="">

<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> |
<a href="#buildURL('ValidateUserInput')#">Tutorial</a> |
<a href="#buildURL('ValidateUserInput.lab')#">Lab : Validate User Input</a> |
<b><a href="#buildURL('ValidateUserInput.solution')#">Solution</a></b> |
<a href="#buildURL('RichContent.lab')#">Lab : Rich Content</a> |
<a href="#buildURL('RichContent.solution')#">Solution</a>
</div>
<div id="header"></div>
<p>
<hr>

<cfscript>
	type = form.type;
	if (type == "")
		type = "SafeString";
	input = form.input;
	if (input == "")
		input = "type input here";

	writeOutput(" >>>>>");
	inputBytes = input.getBytes("UTF-8");
	for (i = 1; i <= arrayLen(inputBytes); i++)
		writeOutput(" " & inputBytes[i]);
	writeOutput("<br>");

	canonical = "";
	try {
		canonical = application.ESAPI.encoder().canonicalize(input, false);
		application.ESAPI.validator().getValidInput(
				"Swingset Validation Secure Exercise", input, type,
				200, false);
	} catch (org.owasp.esapi.errors.ValidationException e) {
		input = "Validation attack detected";
		application.ESAPI.currentRequest().setAttribute("userMessage", e.message);
		application.ESAPI.currentRequest().setAttribute("logMessage", e.detail);
	} catch (org.owasp.esapi.errors.IntrusionException ie) {
		input = "double encoding attack detected";
		application.ESAPI.currentRequest().setAttribute("userMessage", ie.message);
		application.ESAPI.currentRequest().setAttribute("logMessage", ie.detail);
	} catch (java.lang.Exception e) {
		input = "exception thrown";
		application.ESAPI.currentRequest().setAttribute("logMessage", e.message);
	}
</cfscript>

<h2 align="center">Validate User Input Solution</h2>
<h4>CFM Location: #getCurrentTemplateWebPath()#</h4>

<!-- <p>1. The input is canonicalized using the ESAPI.encoder().canonicalize() to remove any encoded characters.</p> -->
<p>1. The input is canonicalized and validated using
	ESAPI.validator().getValidInput() which compares the string against a
	regular expression in validation.properties</p>
<p>2. The output is encoded for html using
	ESAPI.encoder().encodeForHTML() to prevent XSS.</p>
<p class="newsItem">
<code>
	EXAMPLE: <br/>
	<b>%252%35252\u0036lt;<br/>
	%&##x%%%3333\u0033;&%23101;</b>
</code>
</p>
<p>Note: The "Type/Regex" field accepts any of the values defined in
	the .esapi/validation.properties file be one of the following Regular
	Expressions.</p>
<p>
	SafeString : [A-Za-z0-9]{0,1024}$<br /> Email :
	^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\\.[a-zA-Z]{2,4}$<br /> IPAddress :
	^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$<br />
	URL :
	^(ht|f)tp(s?)\\:\\/\\/[0-9a-zA-Z]([-.\\w]*[0-9a-zA-Z])*(:(0-9)*)*(\\/?)([a-zA-Z0-9\\-\\.\\?\\,\\:\\'\\/\\\\\\+=&amp;%\\$##_]*)?$<br />
	CreditCard : ^(\\d{4}[- ]?){3}\\d{4}$<br /> SSN :
	^(?!000)([0-6]\\d{2}|7([0-6]\\d|7[012]))([
	-]?)(?!00)\\d\\d\\3(?!0000)\\d{4}$<br />
</p>
<form action="#buildURL('ValidateUserInput.solution')#" method="POST">
	Type/Regex: <input name="type"
		value="#application.ESAPI.encoder().encodeForHTMLAttribute(type)#"><br>
	<textarea style="width: 400px; height: 150px" name="input">#application.ESAPI.encoder().encodeForHTML(input)#</textarea>
	<br> <input type="submit" value="submit">
</form>

<p>
	Canonical output:
	#application.ESAPI.encoder().encodeForHTML(canonical)#</p>

</cfoutput>