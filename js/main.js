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
						+ '<a href="#" class="dropdown-toggle" data-toggle="dropdown">Swingset <b class="caret"></b></a>'
						+ '<ul class="dropdown-menu">'
							+ '<li class="dropdown-header"><strong class="text-danger">ALL CHAPTERS WORK IN PROGRESS</strong></li>'
							+ '<li><a href="' + context + '/swingset/Introduction.html">Introduction</a></li>'
							+ '<li class="divider"></li>'
							+ '<li class="dropdown-header">Chapters</li>'
							+ '<li><a href="' + context + '/swingset/Login.html">1. Authentication</a></li>'
							+ '<li><a href="' + context + '/swingset/SessionManagement.html">2. Session Management</a></li>'
							+ '<li><a href="' + context + '/swingset/AccessControl.html">3. Access Control</a></li>'
							+ '<li><a href="' + context + '/swingset/ValidateUserInput.html">4. Input Validation</a></li>'
							+ '<li><a href="' + context + '/swingset/Encoding.html">5. Output Encoding/Escaping</a></li>'
							+ '<li><a href="' + context + '/swingset/Encryption.html">6. Cryptography</a></li>'
							+ '<li><a href="' + context + '/swingset/Logging.html">7. Error Handling and Logging</a></li>'
							+ '<li><a href="' + context + '/swingset/DataProtection.html">8. Data Protection</a></li>'
							+ '<li><a href="' + context + '/swingset/HttpSecurity.html">9. Http Security</a></li>'
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
