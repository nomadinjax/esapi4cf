<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> | 
<a href="#buildURL('AccessControl')#">Tutorial</a> | 
<a href="#buildURL('AccessControl.lab')#">Lab : Forced Browsing</a>| 
<a href="#buildURL('AccessControl.solution')#">Solution</a> |
<a href="#buildURL('ObjectReference.lab')#">Lab : Direct Object Reference</a> | 
<b><a href="#buildURL('ObjectReference.solution')#">Solution</a></b>
</div>
<div id="header"></div>
<p>
<hr>

<cfscript>
	href = buildURL(action='ObjectReference.solution', queryString='showItem=');
	output = "Click a link or change the URL to change this message.";
	
	thisSession = ESAPI().currentRequest().getSession();
	
	dir0 = session["ind0"];
	dir1 = session["ind1"];
	dir2 = session["ind2"];
	dir3 = session["ind3"];
	dir4 = session["ind4"];
	dir5 = session["ind5"];
	dir6 = session["ind6"];
</cfscript>
<h2>Solution: Insecure Object Reference</h2>
<h4>CFM Location : #getCurrentTemplateWebPath()#</h4>
<p>Below is a list of users which have been put in session attributes in the following Action Class:<br/>
	<b><i>Java Resources:src/org.owasp.esapi.swingset.actions.ObjectReferenceSolution.java</i></b><br/><br/>
   The references are created using org.owasp.esapi.reference.RandomAccessReferenceMap. 
	</p>

<table width="100%" border="1">
<tr><th width="50%">Links with indirect references</th><th>The direct reference</th></tr>
<tr><td><a href="#href##session["ind0"]#">#session["ind0"]#</a></td><td>#session[dir0]#</td></tr>
<tr><td><a href="#href##session["ind1"]#">#session["ind1"]#</a></td><td>#session[dir1]#</td></tr>
<tr><td><a href="#href##session["ind2"]#">#session["ind2"]#</a></td><td>#session[dir2]#</td></tr>
<tr><td><a href="#href##session["ind3"]#">#session["ind3"]#</a></td><td>#session[dir3]#</td></tr>
<tr><td><a href="#href##session["ind4"]#">#session["ind4"]#</a></td><td>#session[dir4]#</td></tr>
<tr><td><a href="#href##session["ind5"]#">#session["ind5"]#</a></td><td>#session[dir5]#</td></tr>
<tr><td><a href="#href##session["ind6"]#">#session["ind6"]#</a></td><td>#session[dir6]#</td></tr>
</table>
<cfscript>
if( structKeyExists(rc, "output") )
	output = rc.output;

if( structKeyExists(rc, "showItem") ){
	show = rc.showItem;
	if(session[show] != ""){
		output = session[show].toString();
	}
	else 
		output = '<p style="color: red; display:inline">Invalid item.</p>  See the value? :)';
}
</cfscript>
Message: #output#
<br /><br />
Click <a href="#buildURL(action='ObjectReference.solution', queryString='refresh')#">here</a> to get new object mapping.
</cfoutput>