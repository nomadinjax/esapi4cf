<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> |
<a href="#buildURL('SessionManagement')#">Tutorial</a> |
<a href="#buildURL('SessionFixation.lab')#">Lab : Session Fixation</a>|
<b><a href="#buildURL('SessionFixation.solution')#">Solution</a></b> |
<a href="#buildURL('CSRF.lab')#">Lab : Cross Site Request Forgery</a> |
<a href="#buildURL('CSRF.solution')#">Solution</a>
</div>
<div id="header"></div>
<p>
<hr>


<h2 align="center">Exercise: Session Fixation</h2>

<h4>CFM Location: #getCurrentTemplateWebPath()#</h4>

<p>You have seen have seen how Session Fixation can be used to steal a users session.</p>

<p>Try the previous exercise with <a href="/SwingSet/#buildURL('InsecureLogin.solution')#" target="_blank">LoginServletSolution</a></p>

<p>The source code of the solution is located at :<br/><br/>
Java Resources:org.owasp.esapi.swingset.login\LoginServletSolution.java</p>
<p>A call to ESAPI.httpUtilities().changeSessionIdentifier() changes the session id in the login process.  </p>
</p>
</cfoutput>