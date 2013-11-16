<cfparam name="url.x" default="">
<cfparam name="form.username" default="admin">
<cfparam name="form.password" default="admin123">
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
			<title>
				Authentication Tutorial :: ESAPI4CF
			</title>
			<meta name="description" content=""/>
			<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
			<link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.0.0/css/bootstrap.min.css"/>
		</head>
		<body>
			<div class="container">
				<div class="row">
					<div class="col-sm-3">
						<form role="form" class="form-vertical" method="POST" action="#encoder.encodeForHTMLAttribute(urlX.redirect)#">
							<fieldset>
								<legend>
									Sign In Form
								</legend>
								<cfif structKeyExists(urlX, "message")>
									<div class="alert alert-danger">
										#encoder.encodeForHTML(urlX.message)#
									</div>
								</cfif>
								<div class="form-group">
									<label for="accountName">
										Account Name
									</label>
									<input type="text" class="form-control" id="accountName" name="username"
									       required="required" value="#encoder.encodeForHTMLAttribute(form.username)#"/>
								</div>
								<div class="form-group">
									<label for="password">
										Password
									</label>
									<input type="password" class="form-control" id="password" name="password"
									       required="required" value="#encoder.encodeForHTMLAttribute(form.password)#"/>
								</div>
								<button type="submit" class="btn btn-primary">
									Sign In
								</button>
							</fieldset>
						</form>
					</div>
				</div>
			</div>
		</body>
	</html>
</cfoutput>