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
<title>Sample App :: ESAPI4CF</title>
<meta name="description" content=""/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.0.2/css/bootstrap.min.css"/>
</head>
<body>
<div class="container">

	<nav class="navbar navbar-default" role="navigation">
		<a class="navbar-brand" href="##">ESAPI4CF Sample Application</a>
		<ul class="nav navbar-nav navbar-right">
			<li class="dropdown">
				<a href="##" class="dropdown-toggle" data-toggle="dropdown">Logged in as #encoder.encodeForHTML(currentUser.getAccountName())# (#encoder.encodeForHTML(arrayToList(currentUser.getRoles(), "/"))#) <b class="caret"></b></a>
				<ul class="dropdown-menu">
					<!--- <li><a href="##" data-toggle="modal" data-target="##changePasswordModal">Change Password</a></li>
					<li class="divider"></li> --->
					<li><a href="index.cfm?logout=1">Logout</a></li>
				</ul>
			</li>
		</ul>
	</nav>

	<div class="row">
		<div class="col-lg-12">
			<div class="page-header">
				<h3>Current User Profile</h3>
			</div>
			<div class="form-horizontal">
				<div class="form-group">
					<label class="col-lg-2 control-label">Account ID</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.getAccountID())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Accout Name</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.getAccountName())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Screen Name</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.getScreenName())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Roles</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(arrayToList(currentUser.getRoles()))#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">CSRF Token</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.getCSRFToken())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Last Host Address</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.getLastHostAddress())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Failed Login Count</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.getFailedLoginCount())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Last Failed Login Time</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.getLastFailedLoginTime())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Last Login Time</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.getLastLoginTime())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Expiration Time</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.getExpirationTime())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Last Password Change Time</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.getLastPasswordChangeTime())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Is Anonymous?</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.isAnonymous())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Is Enabled?</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.isEnabled())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Is Expired?</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.isExpired())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Is Locked?</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.isLocked())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Is Logged In?</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.isLoggedIn())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Is Session Absolute Timeout?</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.isSessionAbsoluteTimeout())#</span>
					</div>
				</div>
				<div class="form-group">
					<label class="col-lg-2 control-label">Is Session Idle Timeout?</label>
					<div class="col-lg-10">
						<span class="form-control">#encoder.encodeForHTML(currentUser.isSessionTimeout())#</span>
					</div>
				</div>
			</div>
		</div>
	</div>

	<!--- Change Password Modal --->
	<form class="form-horizontal" id="changePasswordForm">
		<div class="modal fade" id="changePasswordModal">
			<div class="modal-dialog">
				<div class="modal-content">
					<div class="modal-header">
						<button type="button" class="close" data-dismiss="modal">&times;</button>
						<h4 class="modal-title" id="myModalLabel">Change Password</h4>
					</div>
					<div class="modal-body">
						<div class="alert alert-danger" style="display: none;"></div>
						<div class="form-group">
							<label class="col-lg-4 control-label">Current Password</label>
							<div class="col-lg-8">
								<input type="password" class="form-control" name="currentPassword" required="required" />
							</div>
						</div>
						<div class="form-group">
							<label class="col-lg-4 control-label">New Password</label>
							<div class="col-lg-8">
								<input type="password" class="form-control" name="newPassword1" required="required" />
							</div>
						</div>
						<div class="form-group">
							<label class="col-lg-4 control-label">Verify Password</label>
							<div class="col-lg-8">
								<input type="password" class="form-control" name="newPassword2" required="required" />
							</div>
						</div>
					</div>
					<div class="modal-footer">
						<button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
						<button type="submit" class="btn btn-primary">Change Password</button>
					</div>
				</div>
			</div>
		</div>
	</form>

</div>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
<script src="//netdna.bootstrapcdn.com/bootstrap/3.0.2/js/bootstrap.min.js"></script>
<script>
+function ($) { "use strict";
	$(function() {
		$(document).on("submit", "##changePasswordForm", function() {
			$.post("changePassword.cfm", $(this).serialize(), function(data, textStatus, xhr) {
				if (!!data) {
					$(".alert-danger").html("").append("<dl><dt>" + data.message + "</dt><dd>" + data.detail + "</dd></dl>").show(400);
				}
				else {
					$(".alert-danger").hide(400).html("");
				}
			}, "json");
			return false;
		});
	});
}(jQuery);
</script>
</body>
</html>
</cfoutput>