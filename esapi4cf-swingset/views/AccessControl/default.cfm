<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> |
<b><a href="#buildURL('AccessControl')#">Tutorial</a></b> |
<a href="#buildURL('AccessControl.lab')#">Lab : Forced Browsing</a>|
<a href="#buildURL('AccessControl.solution')#">Solution</a> |
<a href="#buildURL('ObjectReference.lab')#">Lab : Direct Object Reference</a> |
<a href="#buildURL('ObjectReference.solution')#">Solution</a>
</div>
<div id="header"></div>
<p>
<hr>

<h2 align="center">Tutorial</h2>
<p>The AccessController interface defines a set of methods that can be used in a wide variety of applications to enforce access control. In most applications, access control must be performed in multiple different locations across the various application layers. This class provides access control for URLs, business functions, data, services, and files. </p>


<p>For Forced Browsing lab we need first to set the following url access rules in the .esapi\fbac-policies\URLAccessRules.txt file.</p>
<p class="newsItem">
<code>
## URL Access Rules<br />
##<br />
/SwingSet/admin_solution.jsp    | any    | allow  |<br />
/SwingSet/admin_solution.jsp    | admin    | allow  |<br />
</code>
</p>

<p>In the Forced Browsing lab, the following ESAPI function is used:</p>

<p class="newsItem">
<code>
boolean isAuthorizedForURL(String url)
<br />Checks if an account is authorized to access the referenced URL.
<br />Returns true, if is authorized for URL
</code>
<p>Once you click on the test url. The requested jsp calls the ESAPI's isAuthorizedForURL function. It displays the success and failure messages depending upon the boolean value returned by the function.</p>
<p>The jsp also displays the boolean value returned by calling ESAPI.accessController().isAuthorizedForURL(request.getRequestURI());
and the log message in case of authorization failure.</p>
<h4>ESAPI's AccessController Interface includes:</h4>
<ul>
	<li><b><a href="../apiref/esapi4cf/org/owasp/esapi/AccessController.html##assertAuthorizedForData()">assertAuthorizedForData(java.lang.String key)</a></b> Checks if the current user is authorized to access the referenced data. This method simply returns if access is authorized.</li><br />
	<li><b><a href="../apiref/esapi4cf/org/owasp/esapi/AccessController.html##assertAuthorizedForData()">assertAuthorizedForData(java.lang.String action, java.lang.Object data) </a></b> Checks if the current user is authorized to access the referenced data.</li><br />
    <li><b><a href="../apiref/esapi4cf/org/owasp/esapi/AccessController.html##assertAuthorizedForFile()">assertAuthorizedForFile(java.lang.String filepath)</a></b>Checks if an account is authorized to access the referenced file.</li><br />
	<li><b><a href="../apiref/esapi4cf/org/owasp/esapi/AccessController.html##assertAuthorizedForFunction()">assertAuthorizedForFunction(java.lang.String functionName)</a></b>Checks if an account is authorized to access the referenced function.</li><br />
	<li><b><a href="../apiref/esapi4cf/org/owasp/esapi/AccessController.html##assertAuthorizedForService()">assertAuthorizedForService(java.lang.String serviceName) </a></b>   Checks if an account is authorized to access the referenced service.</li><br />
	<li><b><a href="../apiref/esapi4cf/org/owasp/esapi/AccessController.html##assertAuthorizedForURL()">assertAuthorizedForURL(java.lang.String url) </a></b>Checks if an account is authorized to access the referenced URL.</li><br />
	<li><b><a href="../apiref/esapi4cf/org/owasp/esapi/AccessController.html##isAuthorizedForData()">boolean isAuthorizedForData(java.lang.String key) </a></b>Checks if an account is authorized to access the referenced data, represented as a String.</li><br />
	<li><b><a href="../apiref/esapi4cf/org/owasp/esapi/AccessController.html##isAuthorizedForData()">boolean isAuthorizedForData(java.lang.String action, java.lang.Object data) </a></b>Checks if an account is authorized to access the referenced data, represented as an Object.</li><br />
	<li><b><a href="../apiref/esapi4cf/org/owasp/esapi/AccessController.html##isAuthorizedForFile()">boolean isAuthorizedForFile(java.lang.String filepath) </a></b>Checks if an account is authorized to access the referenced file.</li><br />
	<li><b><a href="../apiref/esapi4cf/org/owasp/esapi/AccessController.html##isAuthorizedForFunction()">boolean isAuthorizedForFunction(java.lang.String functionName) </a></b>Checks if an account is authorized to access the referenced function.</li><br />
	<li><b><a href="../apiref/esapi4cf/org/owasp/esapi/AccessController.html##isAuthorizedForService()">boolean isAuthorizedForService(java.lang.String serviceName) </a></b>Checks if an account is authorized to access the referenced service.</li><br />
	<li><b><a href="../apiref/esapi4cf/org/owasp/esapi/AccessController.html##isAuthorizedForURL()">boolean isAuthorizedForURL(java.lang.String url)</a></b>Checks if an account is authorized to access the referenced URL.</li><br />
</ul>
</cfoutput>