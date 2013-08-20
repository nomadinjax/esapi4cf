<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> |
<a href="#buildURL('SessionManagement')#">Tutorial</a> |
<a href="#buildURL('SessionFixation.lab')#">Lab : Session Fixation</a>|
<a href="#buildURL('SessionFixation.solution')#">Solution</a> |
<a href="#buildURL('CSRF.lab')#">Lab : Cross Site Request Forgery</a> |
<b><a href="#buildURL('CSRF.solution')#">Solution</a></b>
</div>
<div id="header"></div>
<p>
<hr>

<h2>Cross Site Request Forgery Solution</h2>

<h4>CFM Location: #getCurrentTemplateWebPath()#</h4>

<p>The CSRF Token is added to the link using ESAPI.httpUtilities().addCSRFToken()<br/><br/>
A CSRF token can be re-generated once per session or once per request using ESAPI.authenticator().getCurrentUser().resetCSRFToken().<br/> <br/>
Note: A user has to be logged in to use this utility.</p>

	<cfset user = "">
	<cftry>
		<cfset user = application.ESAPI.authenticator().login(application.ESAPI.currentRequest(), application.ESAPI.currentResponse())>
		<cfset transferFundsHref = buildURL('TransferFunds.solution')>
		<a href="#application.ESAPI.httpUtilities().addCSRFToken(transferFundsHref)#" target="_blank">Transfer Funds</a>
		<cfcatch type="org.owasp.esapi.errors.AuthenticationException">
			<cfset application.ESAPI.currentRequest().setAttribute("userMessage", cfcatch.message )>
			<cfset application.ESAPI.currentRequest().setAttribute("logMessage", cfcatch.detail )>
			<cfset cfcatch.printStackTrace()>
		</cfcatch>
		<cfcatch type="org.owasp.esapi.errors.AuthenticationCredentialsException">
			<cfset application.ESAPI.currentRequest().setAttribute("userMessage", cfcatch.message )>
			<cfset application.ESAPI.currentRequest().setAttribute("logMessage", cfcatch.detail )>
			<cfset cfcatch.printStackTrace()>
		</cfcatch>
		<cfcatch type="java.lang.Exception">
			<cfset application.ESAPI.currentRequest().setAttribute("userMessage", cfcatch.message)>
			<cfset cfcatch.printStackTrace()>
		</cfcatch>
	</cftry>
	<cfif user EQ "" OR user.isAnonymous()>
		<H2>Please login</H2>
		<form action="#buildURL('CSRF.solution')#" method="POST">
			<table>
				<tr>
					<td>Username:</td><td><input name="username"></td>
				</tr>
				<tr>
					<td>Password:</td><td><input type="password" name="password" autocomplete="off"></td>
				</tr>
				<tr>
					<td>Remember me on this computer:</td>
					<td><input type="checkbox" name="remember"></td>
				</tr>
			</table>
			<input type="submit" value="login"><br>
		</form>
	</cfif>
</cfoutput>