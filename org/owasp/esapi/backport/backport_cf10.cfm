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

<!--- NOTE: only include functions added to ColdFusion 10 --->

<!--- https://github.com/misterdai/cfbackport/blob/master/cf10.cfm#SessionInvalidate --->
<cffunction access="private" returntype="void" name="sessionInvalidate" output="false" hint="CF10 Backport">
	<cfscript>
		var sessionTracker = createObject("java", "coldfusion.runtime.SessionTracker");
		var sessionId = session.sessionid;

		// Fire onSessionEnd
		var appEvents = application.getEventInvoker();
		var args = [];
		args[1] = application;
		args[2] = session;
		appEvents.onSessionEnd(args);

		// Make sure that session is empty
		structClear(session);

		// Clean up the session
		sessionTracker.cleanUp(application.applicationName, sessionId);
	</cfscript>
</cffunction>

<!--- https://github.com/misterdai/cfbackport/blob/master/cf10.cfm#CallStackGet --->
<cffunction access="private" returntype="Array" name="callStackGet" output="false">
	<cfscript>
		var st = createObject("java", "java.lang.Throwable").getStackTrace();
		var op = [];
		var elCount = arrayLen(st);
		var i = 0;
		var info = {};
		for (i = 1; i <= elCount; i = i + 1) {
			if (listFindNoCase("runPage,runFunction", st[i].getMethodName())) {
				info = {};
				info["Template"] = st[i].getFileName();
				if (st[i].getMethodName() == "runFunction") {
					info["Function"] = ReReplace(st[i].getClassName(), "^.+\$func", "");
				} else {
					info["Function"] = "";
				}
				info["LineNumber"] = st[i].getLineNumber();
				arrayAppend(op, duplicate(info));
			}
		}
		// Remove the entry for this function
		arrayDeleteAt(op, 1);
		return op;
	</cfscript>
</cffunction>