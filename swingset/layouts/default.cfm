<cfscript>
	action = ESAPI().currentRequest().getAttribute("action");
	title = "ESAPI SwingSet Interactive - " & action;
	querystring = ESAPI().currentRequest().getQueryString();
	pageHeader = "ESAPI Swingset Interactive - " & action;

	i1 = querystring.indexOf("&solution");
	secure = ( i1 != -1 );
	if ( secure ) {
		querystring = querystring.substring( 0, i1 );
		title &= ": Solution with ESAPI";
		pageHeader &= ": Solution with ESAPI";
	}

	i2 = querystring.indexOf("&lab");
	insecure = ( i2 != -1 );
	if ( insecure ) {
		querystring = querystring.substring( 0, i2 );
		title &= ": Lab";
		pageHeader &= ": Lab";
	}
</cfscript>
<!doctype html>
<html>
<head>
<cfoutput><title>#title#</title></cfoutput>
<link rel="stylesheet" type="text/css" href="style/style.css" />
</head>

<cfif ( !insecure && !secure )> <body> </cfif>
<cfif ( insecure ) > <body bgcolor="#EECCCC"> </cfif>
<cfif ( secure ) > <body bgcolor="#BBDDBB"> </cfif>
<div id="container">
	<div id="holder">
		<div id="logo"><img src="style/images/owasp-logo_130x55.png" width="130" height="55" alt="owasp_logo" title="owasp_logo"></div>
<cfoutput><h2>#pageHeader#</h2>
#trim(body)#</cfoutput>
<cfinclude template="_footer.cfm">