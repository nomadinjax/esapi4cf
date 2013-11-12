<!---
	Based upon https://github.com/misterdai/cfbackport/blob/master/cf10.cfm
--->
<!--- TODO: implement this
<cffunction access="private" returntype="void" name="sessionInvalidate" output="false">
	<cfscript>
		var lc = {};
		lc.sessionId = session.cfid & "_" & session.cftoken;

		// Fire onSessionEnd
		lc.appEvents = application.getEventInvoker();
		lc.args = arrayNew(1);
		lc.args[1] = application;
		lc.args[2] = session;
		lc.appEvents.onSessionEnd(lc.args);

		// Make sure that session is empty
		structClear(session);

		// Clean up the session
		lc.sessionTracker = newJava("coldfusion.runtime.SessionTracker");
		lc.sessionTracker.cleanUp(application.applicationName, lc.sessionId);
	</cfscript>
</cffunction>
--->