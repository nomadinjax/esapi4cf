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
	encoder = application.ESAPI.encoder();
	currentUser = application.ESAPI.authenticator().getCurrentUser();
</cfscript>
<cfoutput>
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
</cfoutput>