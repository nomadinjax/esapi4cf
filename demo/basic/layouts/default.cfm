<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfparam name="rc.container" default="">
<cfscript>
	encoder = application.ESAPI.encoder();
	currentUser = application.ESAPI.authenticator().getCurrentUser();
</cfscript>
<cfoutput>
<!DOCTYPE html>
<html lang="en" class="no-js">
<head>
<meta charset="utf-8"/>
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"/>
<title>Basic App :: ESAPI4CF</title>
<meta name="description" content=""/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.1.1/css/bootstrap.min.css">
</head>
<body>

<nav class="navbar navbar-default" role="navigation">
	<div class="container">

		<div class="navbar-header">
			<button type="button" class="navbar-toggle" data-toggle="collapse" data-target="##navbar-topmenu">
				<span class="sr-only">Toggle navigation</span>
				<span class="icon-bar"></span>
				<span class="icon-bar"></span>
				<span class="icon-bar"></span>
			</button>
			<a class="navbar-brand" href="#buildURL('')#">ESAPI4CF Basic App</a>
		</div>

		<div class="collapse navbar-collapse" id="navbar-topmenu">
			<ul class="nav navbar-nav">
				<li class="dropdown">
					<a href="##" class="dropdown-toggle" data-toggle="dropdown">Modules <b class="caret"></b></a>
					<ul class="dropdown-menu">
						<li><a href="#buildURL('accessController')#">AccessController</a></li>
						<li><a href="#buildURL('authenticator')#">Authenticator / User</a></li>
						<li><a href="#buildURL('encoder')#">Encoder</a></li>
						<li><a href="#buildURL('encryptor')#">Encryptor</a></li>
						<li><a href="#buildURL('executor')#">Executor</a></li>
						<li><a href="#buildURL('httpUtilities')#">HTTPUtilities</a></li>
						<li><a href="#buildURL('intrusionDetector')#">IntrusionDetector</a></li>
						<li><a href="#buildURL('logger')#">Logger</a></li>
						<li><a href="#buildURL('randomizer')#">Randomizer</a></li>
						<li><a href="#buildURL('securityConfiguration')#">SecurityConfiguration</a></li>
						<li><a href="#buildURL('validator')#">Validator / ValidationErrorList</a></li>
					</ul>
				</li>
				<li class="dropdown">
					<a href="##" class="dropdown-toggle" id="modules" data-toggle="dropdown">Filters <b class="caret"></b></a>
					<ul class="dropdown-menu">
						<li><a href="#buildURL('safeRequest')#">SafeRequest</a></li>
						<li><a href="#buildURL('safeResponse')#">SafeResponse</a></li>
						<li><a href="#buildURL('safeSession')#">SafeSession</a></li>
					</ul>
				</li>
				<li class="dropdown">
					<a href="##" class="dropdown-toggle" data-toggle="dropdown">Extras <b class="caret"></b></a>
					<ul class="dropdown-menu">
						<li><a href="#buildURL('accessReferenceMap')#">AccessReferenceMap</a></li>
						<li><a href="#buildURL('encryptedProperties')#">EncryptedProperties</a></li>
						<li><a href="#buildURL('safeFile')#">SafeFile</a></li>
					</ul>
				</li>
			</ul>
			<ul class="nav navbar-nav navbar-right">
				<cfif currentUser.isLoggedIn()>
					<li class="dropdown">
						<a href="##" class="dropdown-toggle" id="loggedInAs" data-toggle="dropdown"><span class="glyphicon glyphicon-user"></span> #encoder.encodeForHTML(currentUser.getAccountName())# <b class="caret"></b></a>
						<ul class="dropdown-menu">
							<li><a href="#buildURL('account.profile')#">My Profile</a></li>
							<li><a href="#buildURL('account.changePassword')#" data-toggle="modal" data-target="##changePasswordModal">Change Password</a></li>
							<li><a href="#buildURL('account.settings')#">Settings</a></li>
							<li class="divider"></li>
							<li><a href="#buildURL(action=rc.action, queryString='logout=1')#">Logout</a></li>
						</ul>
					</li>
				<cfelse>
					<li><a href="#buildURL(action='main.login', queryString='x=' & encryptQueryString('redirect=' & encoder.encodeForURL(request.action)))#">Login</a></li>
				</cfif>
			</ul>
		</div>

	</div>
</nav>

<div class="container#rc.container#">
	#trim(body)#

	<footer>
		<hr />
		<p><a href="https://github.com/damonmiller/esapi4cf">OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)</a></p>
		<p>This application is part of the Open Web Application Security Project (OWASP) Enterprise Security API (ESAPI) project. For details, please see <a href="https://owasp.org/index.php/ESAPI">https://owasp.org/index.php/ESAPI</a>.</p>
		<p><copy>Copyright &copy; 2011-2014, The OWASP Foundation</copy></p>
		<p>The ESAPI is published by OWASP under the <a href="http://en.wikipedia.org/wiki/BSD_license">BSD license</a>. You should read and accept the LICENSE before you use, modify, and/or redistribute this software.</p>
	</footer>
</div>

<script src="//code.jquery.com/jquery-2.1.0.min.js"></script>
<script src="//netdna.bootstrapcdn.com/bootstrap/3.1.1/js/bootstrap.min.js"></script>
</body>
</html>
</cfoutput>