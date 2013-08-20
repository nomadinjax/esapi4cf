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
	if (structKeyExists(rc, "user") ) {
		found = true;
		quote = rc.user;
	}
	href = buildURL(action='ObjectReference.lab', queryString='&user=');
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
	retrieve the users message. <br /> E.g. in the url <i>#buildURL(action='ObjectReference.lab', queryString='user=admin')#</i><br />
	Change 'admin' to 'matrix'.
</p>

<p>Your goal is to use
	org.owasp.esapi.reference.RandomAccessReferenceMap to change the
	references from Direct to Indirect references.</p>

<table width="30%" border="1">
	<tr>
		<th width="50%">List of Users</th>
	</tr>
	<!--- <tr><td><a href="#href##session["do0"]#">#session["do0"]#</a></td></tr> --->
	<!--- <tr><td><a href="#href##session["do1"]#">#session["do1"]#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##session["do2"]#">#session["do2"]#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##session["do3"]#">#session["do3"]#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##session["do4"]#">#session["do4"]#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##session["do5"]#">#session["do5"]#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##session["do6"]#">#session["do6"]#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##session["do7"]#">#session["do7"]#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##session["do8"]#">#session["do8"]#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##session["do9"]#">#session["do9"]#</a></td></tr>  --->
	<!--- <tr><td><a href="#href##session["do10"]#">#session["do10"]#</a></td></tr> --->

	<tr><td><a href="#href##session["do0"]#">#session["do0"]#</a></td></tr>
	<tr><td><a href="#href##session["do1"]#">#session["do1"]#</a></td></tr> 
	<tr><td><a href="#href##session["do2"]#">#session["do2"]#</a></td></tr> 
	<tr><td><a href="#href##session["do3"]#">#session["do3"]#</a></td></tr> 
	<tr><td><a href="#href##session["do4"]#">#session["do4"]#</a></td></tr> 
	<tr><td><a href="#href##session["do5"]#">#session["do5"]#</a></td></tr> 
	<tr><td><a href="#href##session["do6"]#">#session["do6"]#</a></td></tr> 
	<tr><td><a href="#href##session["do7"]#">#session["do7"]#</a></td></tr> 
	<tr><td><a href="#href##session["do8"]#">#session["do8"]#</a></td></tr> 
	<tr><td><a href="#href##session["do9"]#">#session["do9"]#</a></td></tr> 
	<tr><td><a href="#href##session["do10"]#">#session["do10"]#</a></td></tr>
</table>
<br />

<cfif found>
User's message:
<br />
<p style="color: red">
</cfif>#quote#</p>
<br />
</cfoutput>