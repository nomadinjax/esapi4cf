<cfoutput>
<div id="navigation">
<a href="#buildURL('')#">Home</a> |
<a href="#buildURL('SessionManagement')#">Tutorial</a> |
<a href="#buildURL('SessionFixation.lab')#">Lab : Session Fixation</a>|
<a href="#buildURL('SessionFixation.solution')#">Solution</a> |
<b><a href="#buildURL('CSRF.lab')#">Lab : Cross Site Request Forgery</a></b> |
<a href="#buildURL('CSRF.solution')#">Solution</a>
</div>
<div id="header"></div>
<p>
<hr>

<h2>Cross Site Request Forgery Lab</h2>

<h4>CFM Location: #getCurrentTemplateWebPath()#</h4>

<p>CSRF is an attack which forces an end user to execute unwanted actions on a web application in which he/she is currently authenticated. With a little help of social engineering (like sending a link via email/chat), an attacker may force the users of a web application to execute actions of the attacker's choosing. A successful CSRF exploit can compromise end user data and operation in case of normal user. If the targeted end user is the administrator account, this can compromise the entire web application. </p>
<p>After logging in, click on the link at the bottom to go to a dummy funds transfer page. <br/>
Your goal is to protect the funds transfer page against a CSRF Attack.
Add a CSRF Token to the link provided below and Validate the CSRF Token on the Funds Transfer Page.
</p>

	<cfset user = "">
	<cftry>
		<cfset user = ESAPI().authenticator().login(ESAPI().currentRequest(), ESAPI().currentResponse())>
		<cfset transferFundsHref = buildURL('TransferFunds&lab')>

		<!-- TODO : Add a CSRF Token to this URL -->
		<a href='<%=transferFundsHref%>' target="_blank">Transfer Funds</a>

		<cfcatch type="esapi4cf.org.owasp.esapi.errors.AuthenticationException">
			<cfset ESAPI().currentRequest().setAttribute("userMessage", cfcatch.message )>
			<cfset ESAPI().currentRequest().setAttribute("logMessage", cfcatch.detail )>
			<cfset cfcatch.printStackTrace()>
		</cfcatch>
		<cfcatch type="esapi4cf.org.owasp.esapi.errors.AuthenticationCredentialsException">
			<cfset ESAPI().currentRequest().setAttribute("userMessage", cfcatch.message )>
			<cfset ESAPI().currentRequest().setAttribute("logMessage", cfcatch.detail )>
			<cfset cfcatch.printStackTrace()>
		</cfcatch>
		<cfcatch type="java.lang.Exception">
			<cfset ESAPI().currentRequest().setAttribute("userMessage", cfcatch.message)>
			<cfset cfcatch.printStackTrace()>
		</cfcatch>
	</cftry>

	<cfif user EQ "" OR user.isAnonymous()>
		<h4>Please login</h4>
		<p>If you do not have a user account created, you can do so from <a href="#buildURL('Login.solution')#" target="_blank">Authentication Chapter Solution</a></p>
		<form action="#buildURL('CSRF.lab')#" method="POST">
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