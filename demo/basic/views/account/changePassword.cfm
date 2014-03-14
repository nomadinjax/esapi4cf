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
<cfoutput>
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
</cfoutput>