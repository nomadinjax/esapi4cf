<cfparam name="form.create_username" default="">

<cfoutput>
<div id="navigation">
	<a href="#buildURL('')#">Home</a> |
	<a href="#buildURL('Login')#">Tutorial</a> |
	<b><a href="#buildURL('Login.lab')#">Lab : Authenticator Functions</a></b> |
	<a href="#buildURL('Login.solution')#">Solution</a>
</div>

<div id="header"></div>
<p>
<hr>

<h2>Authenticator Methods Lab</h2>

<h4>CFM Location : #getCurrentTemplateWebPath()#</h4>

<p>The goal of this exercise is to create an ESAPI user account and then log in using that user.</p>
<p>Additionally, generate a Logout link for users who are logged in.</p>

<p>Use the form below and the functions detailed in the tutorial to implement this.</p>

<p>After creating a user you should see a users.txt file in your .esapi folder.</p>

<cfset user = ""/>

<cftry>
	<cfif form.create_username NEQ "">
		<!--- TODO 1: Use ESAPI to Create a User Account --->
		User Created : #form.create_username#
	<cfelse>
		<cfset user = ESAPI().authenticator().login(ESAPI().currentRequest(), ESAPI().currentResponse())>
		<!--- TODO 2: Login using ESAPI --->
		<cfif user NEQ "">
			<cfif form.remember NEQ "">
				<cfset ESAPI().httpUtilities().setRememberToken(form.password, 8000, "", "") />
			</cfif>
			Current User:
			#user.getAccountName()#<br>
			Last Successful Login:
			#user.getLastLoginTime()#<br>
			Last Failed Login:
			#user.getLastFailedLoginTime()#<br>
			Failed Login Count:
			#user.getFailedLoginCount()#<br>
			Current Roles:
			#user.getRoles()#<br>
			Last Host Name:
			#user.getLastHostAddress()#<br>
			Current Cookies:
			<br />
			<cfset cookies = ESAPI().httpUtilities().getCurrentRequest().getCookies()/>
			<cfloop index="i" array="#cookies#">
				&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; #cookies[i].getName()#=#cookies[i].getValue()#<br />
			</cfloop>
			Browser Cookies:
			<script>document.write(document.cookie)</script>
			<br>
			<br>
			<a href="index.cfm?action=Logout.lab">logout</a>
		</cfif>
	</cfif>
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
		<cfset ESAPI().currentRequest().setAttribute("userMessage", "there was a problem..." )>
		<cfset ESAPI().currentRequest().setAttribute("userMessage", cfcatch.message)>
		<cfset cfcatch.printStackTrace()>
	</cfcatch>
</cftry>

<cfif user EQ "" OR user.isAnonymous()>
	<h2>Create User</h2>
	<form action="#buildURL('Login.lab')#" method="POST">
		<table>
			<tr>
				<td>Username:</td>
				<td><input name="create_username">
				</td>
			</tr>
			<tr>
				<td>Password:</td>
				<td><input type="password" name="create_password1"
					autocomplete="off">
				</td>
			</tr>
			<tr>
				<td>Confirm Password:</td>
				<td><input type="password" name="create_password2"
					autocomplete="off">
				</td>
			</tr>
		</table>
		<input type="submit" value="Create User"><br>
	</form>

	<h2>Login</h2>
	<form action="#buildURL('Login.lab')#" method="POST">
		<table>
			<tr>
				<td>Username:</td>
				<td><input name="username">
				</td>
			</tr>
			<tr>
				<td>Password:</td>
				<td><input type="password" name="password" autocomplete="off">
				</td>
			</tr>
			<tr>
				<td>Remember me on this computer:</td>
				<td><input type="checkbox" name="remember">
				</td>
			</tr>
		</table>
		<input type="submit" value="login"><br>
	</form>
</cfif>
</cfoutput>