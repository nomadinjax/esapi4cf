<hr>
<cfset message = ESAPI().currentRequest().getAttribute( "message" )>
<cfif ( ESAPI().currentRequest().getAttribute("userMessage") NEQ "" OR ESAPI().currentRequest().getAttribute("logMessage") NEQ "")>
	<cfoutput>
		<p>User Message: <font color="red">#ESAPI().encoder().encodeForHTML(ESAPI().currentRequest().getAttribute("userMessage").toString())#</font></p>
		<p>Log Message: <font color="red">#ESAPI().encoder().encodeForHTML(ESAPI().currentRequest().getAttribute("logMessage").toString())#</font></p><hr>
	</cfoutput>
</cfif>
<p><center><a href="http://www.owasp.org/index.php/ESAPI">OWASP Enterprise Security API Project</a> <!--  (c) 2008 --></center></p>
<!-- <p><center><a href="index.cfm?action=About">About SwingSet</a></center></p> -->
<!--  <span id="copyright">Design by <a href="http://www.sitecreative.net" target="_blank" title="Opens link to SiteCreative.net in a New Window">SiteCreative</a></span> -->
	</div> <!-- end holder div -->
</div> <!-- end container div -->
</body>
</html>