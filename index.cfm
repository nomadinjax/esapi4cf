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
<cfscript>
	ESAPI = createObject("component", "org.owasp.esapi.ESAPI");

	serverVersion = "CF " & server.coldfusion.ProductVersion;
	if(structKeyExists(server, "railo")) {
		serverVersion = "Railo " & server.railo.version;
	}
</cfscript>

<cfoutput>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>#ESAPI.ESAPINAME# #ESAPI.VERSION# [#serverVersion#]</title>
<link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.1.1/css/bootstrap.min.css">
</head>
<body>

<div class="container">

	<div class="page-header">
		<h1>#ESAPI.ESAPINAME# <small>ESAPI for ColdFusion/CFML</small></h1>
	</div>

	<div class="row">
		<div class="col-md-8">
			<h2>Documentation</h2>
			<p>Please refer to the <a href="http://damonmiller.github.io/esapi4cf/">#ESAPI.ESAPINAME# GitHub.io pages</a> for more information.</p>
			<h2>API References</h2>
			<p>Please refer to the <a href="http://damonmiller.github.io/esapi4cf/">#ESAPI.ESAPINAME# GitHub.io pages</a> for more information.</p>
		</div>
		<div class="col-md-4">
			<div class="panel panel-success">
				<div class="panel-heading"><h4>Under The Hood</h4></div>
				<div class="panel-body">
					<ul class="list-unstyled">
						<li><strong>CFML Server:</strong> #serverVersion#</li>
						<li><strong>#ESAPI.ESAPINAME# Version:</strong> #ESAPI.VERSION#</li>
						<li><strong>ESAPI4J Version:</strong> #ESAPI.ESAPI4JVERSION#</li>
					</ul>
				</div>
			</div>
		</div>
	</div>

	<h2>Tutorials</h2>
	<p>Please refer to the <a href="http://damonmiller.github.io/esapi4cf/">#ESAPI.ESAPINAME# GitHub.io pages</a> for more information.</p>

	<h2>Demo</h2>
	<dl>
		<dt><a href="demo/">Demo Application</a></dt>
		<dd>This app contains the sample code referenced by the <a href="http://damonmiller.github.io/esapi4cf/tutorials/Introduction.html">#ESAPI.ESAPINAME# tutorials</a>.</dd>
	</dl>

	<h2>Tests</h2>
	<dl>
		<dt><a href="test/unit/TestSuite.cfm">Unit Tests</a></dt>
		<dd>The ESAPI Unit Tests ported into ColdFusion/CFML using MXUnit (not included).</dd>
	</dl>
	<!---<form class="form-inline" role="form" method="get" action="test/automation/TestSuite.cfm">
		<fieldset>
			<legend>Automation Tests</legend>
			<div class="form-group">
				<label class="control-label" for="engine">CFML Engine</label>
				<select class="form-control" id="engine" name="engine">
					<option value="railo">Railo</option>
				</select>
			</div>
			<div class="form-group">
				<label class="control-label" for="browser">Browser</label>
				<select class="form-control" id="browser" name="browser">
					<option value="chrome">Chrome</option>
				</select>
			</div>
			<button type="submit" class="btn btn-primary">Run Test</button>
		</fieldset>
	</form>--->

	<h2>Utilities</h2>
	<dl>
		<dt><a href="utilities/DefaultEncryptedProperties.cfm">Encrypted Properties files</a></dt>
		<dd>Loads encrypted properties file based on the location passed in args then prompts the user to input key-value pairs.</dd>
		<dt><a href="utilities/FileBasedAuthenticator.cfm">Fail safe main program to add or update an account in an emergency</a></dt>
		<dd>WARNING: this method does not perform the level of validation and checks generally required in ESAPI, and can therefore be used to create a username and password that do not comply with the username and password strength requirements.</dd>
	</dl>

</div>

<script src="//code.jquery.com/jquery-2.1.0.min.js"></script>
<script src="//netdna.bootstrapcdn.com/bootstrap/3.1.1/js/bootstrap.min.js"></script>
</body>
</html>
</cfoutput>