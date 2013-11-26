<cfparam name="url.x" default="">
<cfparam name="form.username" default="admin">
<cfparam name="form.password" default="Admin123">
<cfscript>
	encoder = application.ESAPI.encoder();

	urlX.redirect = "./";
	try {
		urlX = application.ESAPI.httpUtilities().decryptQueryString(url.x);
	}
	catch (org.owasp.esapi.errors.EncryptionException e) {}
	catch(expression e) {}
</cfscript>
<cfoutput>
<!DOCTYPE html>
<html lang="en" class="no-js">
<head>
<meta charset="utf-8"/>
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"/>
<title>Sample App :: ESAPI4CF</title>
<meta name="description" content=""/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.0.2/css/bootstrap.min.css"/>
</head>
<body>
<div class="container">
	<div class="row">
		<div class="col-lg-6 col-lg-offset-3">
			<form role="form" class="form-vertical" method="POST" action="#encoder.encodeForHTMLAttribute(urlX.redirect)#">
				<fieldset>
					<legend>Sign In Form</legend>
					<p><span class="label label-warning">NOTE:</span> This sample application currently works in ColdFuson 8, ColdFusion 9, and Railo 4.1.  ColdFusion 10 does not authenticate due to <a href="https://github.com/damonmiller/esapi4cf/issues/39">Issue 39</a>.</p>
					<p>username: <span class="label label-info">admin</span></p>
					<p>password: <span class="label label-info">Admin123</span></p>
					<cfif structKeyExists(urlX, "message")>
						<div class="alert alert-danger">#encoder.encodeForHTML(urlX.message)#</div>
					</cfif>
					<div class="form-group">
						<label for="accountName">Account Name</label>
						<input type="text" class="form-control" id="accountName" name="username" required="required" autocomplete="off" />
					</div>
					<div class="form-group">
						<label for="password">Password</label>
						<input type="password" class="form-control" id="password" name="password" required="required" autocomplete="off"/>
					</div>
					<button type="submit" class="btn btn-primary">Sign In</button>
				</fieldset>
			</form>
		</div>
	</div>
</div>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
<script src="//netdna.bootstrapcdn.com/bootstrap/3.0.2/js/bootstrap.min.js"></script>
</body>
</html>
</cfoutput>