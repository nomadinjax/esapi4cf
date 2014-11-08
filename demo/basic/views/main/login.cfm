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
<cfparam name="rc.redirect" default="main">
<cfscript>
	encoder = application.ESAPI.encoder();
</cfscript>
<cfoutput>
<div class="row">
	<div class="col-lg-6 col-lg-offset-3">
		<form role="form" class="form-vertical" method="POST" action="#buildURL(encoder.encodeForHTMLAttribute(rc.redirect))#">
			<fieldset>
				<legend>Sign In Form</legend>
				<p>username: <span class="label label-info">admin</span></p>
				<p>password: <span class="label label-info">Admin123</span></p>
				<cfif structKeyExists(rc, "message")>
					<div class="alert alert-danger" id="alertMessage">#encoder.encodeForHTML(rc.message)#</div>
				</cfif>
				<div class="form-group">
					<label for="accountName">Account Name</label>
					<!--- turn off autocomplete - this is a username field!!! --->
					<input type="text" class="form-control" id="accountName" name="username" required="required" autocomplete="off" />
				</div>
				<div class="form-group">
					<label for="password">Password</label>
					<!--- turn off autocomplete - this is a password field!!! --->
					<input type="password" class="form-control" id="password" name="password" required="required" autocomplete="off"/>
				</div>
				<button type="submit" class="btn btn-primary" id="loginButton" autocomplete="off">Sign In</button>
			</fieldset>
		</form>
	</div>
</div>
</cfoutput>