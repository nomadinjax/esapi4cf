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
	
	dir0 = thisSession.getAttribute("ind0");
	dir1 = thisSession.getAttribute("ind1");
	dir2 = thisSession.getAttribute("ind2");
	dir3 = thisSession.getAttribute("ind3");
	dir4 = thisSession.getAttribute("ind4");
	dir5 = thisSession.getAttribute("ind5");
	dir6 = thisSession.getAttribute("ind6");
</cfscript>
<h2>Solution: Insecure Object Reference</h2>
<h4>CFM Location : #getCurrentTemplateWebPath()#</h4>
<p>Below is a list of users which have been put in session attributes in the following Action Class:<br/>
	<b><i>Java Resources:src/org.owasp.esapi.swingset.actions.ObjectReferenceSolution.java</i></b><br/><br/>
   The references are created using org.owasp.esapi.reference.RandomAccessReferenceMap. 
	</p>

<table width="100%" border="1">
<tr><th width="50%">Links with indirect references</th><th>The direct reference</th></tr>
<tr><td><a href="#href##thisSession.getAttribute("ind0")#">#thisSession.getAttribute("ind0")#</a></td><td>#thisSession.getAttribute(dir0)#</td></tr>
<tr><td><a href="#href##thisSession.getAttribute("ind1")#">#thisSession.getAttribute("ind1")#</a></td><td>#thisSession.getAttribute(dir1)#</td></tr>
<tr><td><a href="#href##thisSession.getAttribute("ind2")#">#thisSession.getAttribute("ind2")#</a></td><td>#thisSession.getAttribute(dir2)#</td></tr>
<tr><td><a href="#href##thisSession.getAttribute("ind3")#">#thisSession.getAttribute("ind3")#</a></td><td>#thisSession.getAttribute(dir3)#</td></tr>
<tr><td><a href="#href##thisSession.getAttribute("ind4")#">#thisSession.getAttribute("ind4")#</a></td><td>#thisSession.getAttribute(dir4)#</td></tr>
<tr><td><a href="#href##thisSession.getAttribute("ind5")#">#thisSession.getAttribute("ind5")#</a></td><td>#thisSession.getAttribute(dir5)#</td></tr>
<tr><td><a href="#href##thisSession.getAttribute("ind6")#">#thisSession.getAttribute("ind6")#</a></td><td>#thisSession.getAttribute(dir6)#</td></tr>
</table>
<cfscript>
if( ESAPI().currentRequest().getAttribute("output") != null)
	output = ESAPI().currentRequest().getAttribute("output").toString();

if( form.showItem != null ){
	show = form.showItem;
	if(thisSession.getAttribute(show) != null){
		output = thisSession.getAttribute(show).toString();
	}
	else 
		output = '<p style="color: red; display:inline">Invalid item.</p>  See the value? :)';
}
</cfscript>
Message: #output#
<br /><br />
Click <a href="#buildURL(action='ObjectReference&solution', queryString='refresh')#">here</a> to get new object mapping.
</cfoutput>