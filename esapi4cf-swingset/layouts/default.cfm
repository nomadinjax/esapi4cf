<cfscript>
	title = "ESAPI SwingSet Interactive - " & listFirst(rc.action, ".");
	pageHeader = "ESAPI Swingset Interactive - " & listFirst(rc.action, ".");

	secure = iif(listLast(rc.action, ".") EQ "solution", true, false);
	if ( secure ) {
		title &= ": Solution with ESAPI";
		pageHeader &= ": Solution with ESAPI";
	}

	insecure = iif(listLast(rc.action, ".") EQ "lab", true, false);
	if ( insecure ) {
		title &= ": Lab";
		pageHeader &= ": Lab";
	}
</cfscript>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8" />
<cfoutput><title>#title#</title></cfoutput>
<link rel="stylesheet" href="style/style.css" />
</head>

<cfif ( !insecure && !secure )> <body>
<cfelseif ( insecure ) > <body bgcolor="#EECCCC">
<cfelseif ( secure ) > <body bgcolor="#BBDDBB">
</cfif>
<div id="container">
	<div id="holder">
		<div id="logo"><img src="style/images/owasp-logo_130x55.png" width="130" height="55" alt="owasp_logo" title="owasp_logo"></div>
<cfoutput><h2>#pageHeader#</h2>
#trim(body)#</cfoutput>
<cfinclude template="_footer.cfm">