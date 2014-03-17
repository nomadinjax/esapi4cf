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
	Locale = createObject("java", "java.util.Locale");
</cfscript>
<cfoutput>
<div class="row">
	<div class="col-lg-12">
		<div class="page-header">
			<h3>Current User Profile</h3>
		</div>
		<form class="form-horizontal" method="POST" action="#buildURL('account.settings')#">
			<div class="form-group">
				<label class="col-md-2 control-label" for="localeSetting">Locale</label>
				<div class="col-md-10">
					<select class="form-control" id="localeSetting" name="localeSetting">
						<option value="en_US" #iif(currentUser.getLocaleData().toString() EQ 'en_US', de('selected="selected"'), de(''))#>#Locale.init("en", "US").getDisplayName()#</option>
						<option value="en_CA" #iif(currentUser.getLocaleData().toString() EQ 'en_CA', de('selected="selected"'), de(''))#>#Locale.init("en", "CA").getDisplayName()#</option>
					</select>
				</div>
			</div>
			<div class="form-group">
				<div class="col-md-offset-2 col-md-10">
					<button type="submit" class="btn btn-primary">Save</button>
				</div>
			</div>
		</form>
	</div>
</div>
</cfoutput>