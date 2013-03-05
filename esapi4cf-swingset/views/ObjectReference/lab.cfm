<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> |
<a href="#buildURL('AccessControl')#">Tutorial</a> |
<a href="#buildURL('AccessControl.lab')#">Lab : Forced Browsing</a> |
<a href="#buildURL('AccessControl.solution')#">Solution</a> |
<b><a href="#buildURL('ObjectReference.lab')#">Lab : Direct Object Reference</a></b> |
<a href="#buildURL('ObjectReference.solution')#">Solution</a>
</div>
<div id="header"></div>
<p>
<hr>

<cfscript>
	found = false;
	quote = "Change the URL to access other files...";
	if (ESAPI().currentRequest().getAttribute("user") != "") {
		found = true;
		quote = ESAPI().currentRequest().getAttribute("user").toString();
	}
	href = buildURL(action='ObjectReference.lab', queryString='&user=');
	thisSession = ESAPI().currentRequest().getSession();
</cfscript>

<h2>Lab: Insecure Object Reference</h2>
<h4>CFM Location : #getCurrentTemplateWebPath()#</h4>
<p>
	Below is a list of users which have been put in session attributes in
	the following Action Class:<br /> <b><i>Java
			Resources:src/org.owasp.esapi.swingset.actions.ObjectReferenceLab.java</i>
	</b>
</p>

<p>
	Changing the user parameter in the url to any of the users name will
	retrieve the users message. <br /> E.g. in the url <i>https://localhost:8443/SwingSet/main?function=ObjectReference&lab&user=admin</i><br />
	Change 'admin' to 'matrix'.
</p>

<p>Your goal is to use
	org.owasp.esapi.reference.RandomAccessReferenceMap to change the
	references from Direct to Indirect references.</p>

<table width="30%" border="1">
	<tr>
		<th width="50%">List of Users</th>
	</tr>
	<!--- <tr><td><a href="#href##thisSession.getAttribute("do0")#">#thisSession.getAttribute("do0")#</a></td></tr> --->
	<!--- <tr><td><a href="#href##thisSession.getAttribute("do1")#">#thisSession.getAttribute("do1")#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##thisSession.getAttribute("do2")#">#thisSession.getAttribute("do2")#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##thisSession.getAttribute("do3")#">#thisSession.getAttribute("do3")#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##thisSession.getAttribute("do4")#">#thisSession.getAttribute("do4")#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##thisSession.getAttribute("do5")#">#thisSession.getAttribute("do5")#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##thisSession.getAttribute("do6")#">#thisSession.getAttribute("do6")#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##thisSession.getAttribute("do7")#">#thisSession.getAttribute("do7")#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##thisSession.getAttribute("do8")#">#thisSession.getAttribute("do8")#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##thisSession.getAttribute("do9")#">#thisSession.getAttribute("do9")#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##thisSession.getAttribute("do10")#">#thisSession.getAttribute("do10")#</a></td></tr> --->

	<tr><td><a href="#href##thisSession.getAttribute("do0")#">#thisSession.getAttribute("do0")#</a></td></tr>
	<tr><td><a href="#href##thisSession.getAttribute("do1")#">#thisSession.getAttribute("do1")#</a></td></tr> 
	<tr><td><a href="#href##thisSession.getAttribute("do2")#">#thisSession.getAttribute("do2")#</a></td></tr> 
	<tr><td><a href="#href##thisSession.getAttribute("do3")#">#thisSession.getAttribute("do3")#</a></td></tr> 
	<tr><td><a href="#href##thisSession.getAttribute("do4")#">#thisSession.getAttribute("do4")#</a></td></tr> 
	<tr><td><a href="#href##thisSession.getAttribute("do5")#">#thisSession.getAttribute("do5")#</a></td></tr> 
	<tr><td><a href="#href##thisSession.getAttribute("do6")#">#thisSession.getAttribute("do6")#</a></td></tr> 
	<tr><td><a href="#href##thisSession.getAttribute("do7")#">#thisSession.getAttribute("do7")#</a></td></tr> 
	<tr><td><a href="#href##thisSession.getAttribute("do8")#">#thisSession.getAttribute("do8")#</a></td></tr> 
	<tr><td><a href="#href##thisSession.getAttribute("do9")#">#thisSession.getAttribute("do9")#</a></td></tr> 
	<tr><td><a href="#href##thisSession.getAttribute("do10")#">#thisSession.getAttribute("do10")#</a></td></tr>
</table>
<br />

<cfif found>
User's message:
<br />
<p style="color: red">
</cfif>#quote#</p>
<br />
</cfoutput>