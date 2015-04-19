<!---
/*
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfscript>
	// NOTE: maintain this list with each release
	versionData = {};
	versionData["lucee4"] = {
		jvm: "1.8.0_45",
		engine: "4.5.1.000",
		display: "Lucee 4.5.x"
	};
	versionData["railo4"] = {
		jvm: "1.8.0_45",
		engine: "4.2.1.008",
		display: "Railo 4.2.x"
	};
	versionData["coldfusion11"] = {
		jvm: "1.8.0_45",
		engine: "11,0,05,293506",
		display: "ColdFusion 11.x"
	};
	/*versionData["coldfusion10"] = {
		jvm: "1.8.0_25",
		engine: "10,0,13,287689",
		display: "ColdFusion 10.x"
	};*/

	Version = application.ESAPI.versionData();
	thisVersion = Version.getCFMLEngine() & listFirst(Version.getCFMLVersion(), ",.");

	rc.pageTitle = Version.getESAPI4CFName() & " " & Version.getESAPI4CFVersion() & " [" & Version.getCFMLEngine() & " " & Version.getCFMLVersion() & "]";
	rc.showTitle = false;

	boolean function isVersionSufficient(required string minVersion, required string currentVersion) {
		var minVersionParsed = listChangeDelims(arguments.minVersion, "", ",._");
		var currentVersionParsed = listChangeDelims(arguments.currentVersion, "", ",._");
		if (minVersionParsed > currentVersionParsed) return false;
		return true;
	}
</cfscript>
<cfoutput>
	<div class="page-header" style="border: 0 none;"></div>

	<div class="row">
		<div class="col-md-8">

			<div class="jumbotron">
				<h1>#Version.getESAPI4CFName()#</h1>
				<p>Enterprise Security API for ColdFusion, Railo, and Lucee Applications</p>
			</div>

		</div>
		<div class="col-md-4">

			<div class="panel panel-success">
				<div class="panel-heading"><h4>Under The Hood...</h4></div>
				<div class="panel-body">
					<ul class="list-group">
						<li class="list-group-item"><strong>#Version.getESAPI4CFName()# Version:</strong> #Version.getESAPI4CFVersion()#</li>
						<cfif isVersionSufficient(Version.getESAPI4JVersion(), 2)>
							<li class="list-group-item"><strong>ESAPI4J Version:</strong> #Version.getESAPI4JVersion()#</li>
						<cfelse>
							<li class="list-group-item list-group-item-danger"><strong>ESAPI4J Version:</strong> #Version.getESAPI4JVersion()#  <span class="glyphicon glyphicon-exclamation-sign" title="This ESAPI4J version is not supported by #Version.getESAPI4CFName()#"></span></li>
						</cfif>
						<cfif not structKeyExists(versionData, thisVersion)>
							<li class="list-group-item list-group-item-danger"><strong>CFML Server:</strong> #Version.getCFMLEngine()# #Version.getCFMLVersion()# <span class="glyphicon glyphicon-exclamation-sign" title="This CFML Server is not supported by #Version.getESAPI4CFName()#"></span></li>
						<cfelseif isVersionSufficient(versionData[thisVersion].engine, Version.getCFMLVersion())>
							<li class="list-group-item"><strong>CFML Server:</strong> #Version.getCFMLEngine()# #Version.getCFMLVersion()#</li>
						<cfelse>
							<li class="list-group-item list-group-item-danger"><strong>CFML Server:</strong> #Version.getCFMLEngine()# #Version.getCFMLVersion()# <span class="glyphicon glyphicon-exclamation-sign" title="Recommend updating server to #versionData[thisVersion].engine#"></span></li>
						</cfif>
						<cfif not structKeyExists(versionData, thisVersion)>
							<li class="list-group-item"><strong>JVM Version:</strong> #Version.getJVMVersion()#</li>
						<cfelseif isVersionSufficient(versionData[thisVersion].jvm, Version.getJVMVersion())>
							<li class="list-group-item"><strong>JVM Version:</strong> #Version.getJVMVersion()#</li>
						<cfelse>
							<li class="list-group-item list-group-item-danger"><strong>JVM Version:</strong> #Version.getJVMVersion()# <span class="glyphicon glyphicon-exclamation-sign" title="Recommend updating JVM to #versionData[thisVersion].jvm#"></span></li>
						</cfif>
					</ul>
				</div>
			</div>
		</div>

	</div>

	<div class="row">
		<div class="col-md-3">
			<h2>Documentation</h2>
			<p>Compatibility information, setup, tutorials, API reference, and links to latest download are available here: <a href="https://damonmiller.github.io/esapi4cf/">http://damonmiller.github.io/esapi4cf/</a></p>
		</div>
		<div class="col-md-3">
			<h2>Release Notes</h2>
			<p>Information on bug fixes and improvements for each release are available here: <a href="https://github.com/damonmiller/esapi4cf/releases">https://github.com/damonmiller/esapi4cf/releases</a></p>
		</div>
		<div class="col-md-3">
			<h2>Issues</h2>
			<p>You can find known issues or report new issues here: <a href="https://github.com/damonmiller/esapi4cf/issues">https://github.com/damonmiller/esapi4cf/issues</a></p>
		</div>
		<div class="col-md-3">
			<h2>Tests</h2>
			<p>The #Version.getESAPI4CFName()# TestBox runner is included and can be run locally for you here: <a href="../test/runner.cfm">Click Here</a>.</p>
			<p><em>Compatible with:</em> <small class="label label-info">#versionData["lucee4"].display#</small> <small class="label label-info">#versionData["coldfusion11"].display#</small></p>
		</div>
	</div>

	<!---<div class="page-header">
		<h2>Demos</h2>
	</div>
	<div class="row">
		<div class="col-md-3">
			<h3><a href="demo/views/something/default.cfm">...something...</a></h3>
			<p>...something...</p>
			<p><em>Compatible with:</em> <span class="label label-info">#versionData["lucee4"].display#</span></p>
		</div>
	</div>--->

	<div class="page-header">
		<h2>Utilities</h2>
	</div>
	<div class="row">
		<div class="col-md-4">
			<h3><a href="../utilities/secretKeyGenerator.cfm">Secret Key Generator</a></h3>
			<p>Generates a new strongly random secret key and salt that can be copy and pasted in the #Version.getESAPI4CFName()# init configuration.</p>
			<p><em>Compatible with:</em> <small class="label label-info">#versionData["lucee4"].display#</small> <small class="label label-info">#versionData["coldfusion11"].display#</small></p>
		</div>
		<!---<div class="col-md-4">
			<h3><small class="label label-danger">TODO</small> <a href="../utilities/DefaultEncryptedProperties.cfm">Encrypted Properties</a></h3>
			<p>Loads encrypted properties file based on the location passed in args then prompts the user to input key-value pairs.</p>
		</div>
		<div class="col-md-4">
			<h3><small class="label label-danger">TODO</small> <a href="../utilities/FileBasedAuthenticator.cfm">User Management</a></h3>
			<p>Fail safe main program to add or update an account in an emergency. WARNING: this method does not perform the level of validation and checks generally required in #Version.getESAPI4CFName()#, and can therefore be used to create a username and password that do not comply with the username and password strength requirements.</p>
		</div>--->
	</div>

</cfoutput>