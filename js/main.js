!function($) {
	$(function() {
		
		function getContext(folder) {
			var pathName = window.location.pathname.split("/");
			var context = pathName.slice(0, $.inArray(folder, pathName) + 1);
			return context.join("/");
		}
		
		// this will generate the same navbar on every page for consistency
		function createTopNav() {
			var context = getContext("esapi4cf");
			var navbar = $('<div class="container"/>');
			var navbarHeader = $('<div class="navbar-header"><button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-ex1-collapse"><span class="icon-bar"/><span class="icon-bar"/><span class="icon-bar"/></button><a class="navbar-brand" href="#">OWASP ESAPI4CF</a></div>');
			var navbarCollapse = $('<div class="collapse navbar-collapse navbar-ex1-collapse"/>');
			var navbarNavLeft = $(
				'<ul class="nav navbar-nav">'
					+ '<li><a href="' + context + '/index.html">Home</a></li>'
					+ '<li class="dropdown"><a href="#" class="dropdown-toggle" data-toggle="dropdown">API Reference <b class="caret"></b></a>'
						+ '<ul class="dropdown-menu">'
							+ '<li><a href="' + context + '/apiref/1/">ESAPI4CF 1.0</a></li>'
						+ '</ul>'
					+ '</li>'
					+ '<li class="dropdown">'
						+ '<a href="#" class="dropdown-toggle" data-toggle="dropdown">Tutorials <b class="caret"></b></a>'
						+ '<ul class="dropdown-menu">'
							+ '<li><a href="' + context + '/tutorials/Introduction.html">Introduction</a></li>'
							+ '<li><a href="' + context + '/tutorials/Setup.html"><span class="label label-warning">WIP</span> Setup</a></li>'
							+ '<li><a href="' + context + '/tutorials/Login.html"><span class="label label-warning">WIP</span> Authentication</a></li>'
							+ '<li><a href="' + context + '/tutorials/SessionManagement.html"><span class="label label-danger">TODO</span> Session Management</a></li>'
							+ '<li><a href="' + context + '/tutorials/AccessControl.html"><span class="label label-danger">TODO</span> Access Control</a></li>'
							+ '<li><a href="' + context + '/tutorials/ValidateUserInput.html"><span class="label label-danger">TODO</span> Input Validation</a></li>'
							+ '<li><a href="' + context + '/tutorials/Encoding.html"><span class="label label-danger">TODO</span> Output Encoding/Escaping</a></li>'
							+ '<li><a href="' + context + '/tutorials/Encryption.html"><span class="label label-danger">TODO</span> Cryptography</a></li>'
							+ '<li><a href="' + context + '/tutorials/Logging.html"><span class="label label-danger">TODO</span> Error Handling and Logging</a></li>'
							+ '<li><a href="' + context + '/tutorials/DataProtection.html"><span class="label label-danger">TODO</span> Data Protection</a></li>'
							+ '<li><a href="' + context + '/tutorials/HttpSecurity.html"><span class="label label-danger">TODO</span> Http Security</a></li>'
						+ '</ul>'
					+ '</li>'
				+ '</ul>'
			);
			var navbarNavRight = $(
				'<ul class="nav navbar-nav navbar-right">'
					+ '<li class="dropdown">'
						+ '<a href="#" class="dropdown-toggle" data-toggle="dropdown">Links/Download <b class="caret"></b></a>'
						+ '<ul class="dropdown-menu">'
							+ '<li><a href="https://github.com/damonmiller/esapi4cf">View on GitHub</a></li>'
							+ '<li class="divider"></li>'
							+ '<li class="dropdown-header">Download Latest</li>'
							+ '<li><a href="https://github.com/damonmiller/esapi4cf/zipball/master">.zip file</a></li>'
							+ '<li><a href="https://github.com/damonmiller/esapi4cf/tarball/master">.tar.gz file</a></li>'
						+ '</ul>'
					+ '</li>'
				+ '</ul>'
			);
			
			// put it all together
			navbarCollapse.append(navbarNavLeft);
			navbarCollapse.append(navbarNavRight);
			navbar.append(navbarHeader);
			navbar.append(navbarCollapse);
			
			return navbar;
		}
		
		$("#bannerNav").append(createTopNav());
		
	});
}(window.jQuery);
