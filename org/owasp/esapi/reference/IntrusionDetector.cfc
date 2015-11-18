/*
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */

/**
 * Reference implementation of the IntrusionDetector interface. This
 * implementation monitors EnterpriseSecurityExceptions to see if any user
 * exceeds a configurable threshold in a configurable time period. For example,
 * it can monitor to see if a user exceeds 10 input validation issues in a 1
 * minute period. Or if there are more than 3 authentication problems in a 10
 * second period. More complex implementations are certainly possible, such as
 * one that establishes a baseline of expected behavior, and then detects
 * deviations from that baseline. This implementation stores state in the
 * user's session, so that it will be properly cleaned up when the session is
 * terminated. State is not otherwise persisted, so attacks that span sessions
 * will not be detectable.
 */
component implements="org.owasp.esapi.IntrusionDetector" extends="org.owasp.esapi.util.Object" {

	variables.ESAPI = "";

	/** The logger. */
	variables.logger = "";

    public org.owasp.esapi.IntrusionDetector function init(required org.owasp.esapi.ESAPI ESAPI) {
    	variables.ESAPI = arguments.ESAPI;
    	variables.logger = variables.ESAPI.getLogger(getMetaData(this).fullName);

    	return this;
	}

	/**
     *
     * @param e
     */
	public void function addException(required exception) {
		if (variables.ESAPI.securityConfiguration().getDisableIntrusionDetection()) return;

        if (isInstanceOf(arguments.exception, "org.owasp.esapi.errors.EnterpriseSecurityException")) {
            variables.logger.warning(variables.logger.SECURITY_FAILURE, arguments.exception.getLogMessage(), arguments.exception);
        }
        else {
            variables.logger.warning(variables.logger.SECURITY_FAILURE, arguments.exception.getMessage(), arguments.exception);
        }

        // add the exception to the current user, which may trigger a detector
		var user = variables.ESAPI.authenticator().getCurrentUser();
        var eventName = getMetaData(arguments.exception).name;

        if (isInstanceOf(arguments.exception, "org.owasp.esapi.errors.IntrusionException")) {
            return;
        }

        // add the exception to the user's store, handle IntrusionException if thrown
		try {
			addSecurityEvent(user, eventName);
		}
		catch (org.owasp.esapi.errors.IntrusionException ex) {
            var quota = variables.ESAPI.securityConfiguration().getQuota(eventName);
            var i = quota.actions.iterator();
            while (i.hasNext()) {
                var action = i.next();
                var message = "User exceeded quota of " & quota.count & " per " & quota.interval & " seconds for event " & eventName & ". Taking actions " & arrayToList(quota.actions);
                takeSecurityAction( action, message );
            }
		}
	}

    public void function addEvent(required string eventName, required string logMessage) {
    	if (variables.ESAPI.securityConfiguration().getDisableIntrusionDetection()) return;

        variables.logger.warning( variables.Logger.SECURITY_FAILURE, "Security event " & arguments.eventName & " received : " & arguments.logMessage );

        // add the event to the current user, which may trigger a detector
        var user = variables.ESAPI.authenticator().getCurrentUser();
        try {
            addSecurityEvent(user, "event." & arguments.eventName);
        } catch( org.owasp.esapi.errors.IntrusionException ex ) {
            var quota = variables.ESAPI.securityConfiguration().getQuota("event." & arguments.eventName);
            var i = quota.actions.iterator();
            while ( i.hasNext() ) {
                var action = i.next();
                var message = "User exceeded quota of " & quota.count & " per "& quota.interval &" seconds for event " & arguments.eventName & ". Taking actions " & arrayToList(quota.actions);
                takeSecurityAction( action, message );
            }
        }
    }

    /**
     * Take a specified security action.  In this implementation, acceptable
     * actions are: log, disable, logout.
     *
     * @param action
     * 		the action to take (log, disable, logout)
     * @param message
     * 		the message to log if the action is "log"
     */
    private void function takeSecurityAction( required string action, required string message ) {
    	if (variables.ESAPI.securityConfiguration().getDisableIntrusionDetection()) return;

        if ( arguments.action == "log" ) {
            variables.logger.fatal( variables.Logger.SECURITY_FAILURE, "INTRUSION - " & arguments.message );
        }
        var user = variables.ESAPI.authenticator().getCurrentUser();
        if (user.isAnonymous())
        	return;
        if ( arguments.action == "disable" ) {
            user.disable();
        }
        if ( arguments.action == "logout" ) {
            user.logout();
        }
    }

	 /**
	 * Adds a security event to the user.  These events are used to check that the user has not
	 * reached the security thresholds set in the properties file.
	 *
	 * @param user
	 * 			The user that caused the event.
	 * @param eventName
	 * 			The name of the event that occurred.
	 */
	private void function addSecurityEvent(required org.owasp.esapi.User user, required string eventName) {
		if (variables.ESAPI.securityConfiguration().getDisableIntrusionDetection()) return;

		if ( arguments.user.isAnonymous() ) return;

		var eventMap = arguments.user.getEventMap();

		// if there is a threshold, then track this event
		var threshold = variables.ESAPI.securityConfiguration().getQuota(arguments.eventName);
		if (!isNull(threshold)) {
			var event = "";
			if (structKeyExists(eventMap, arguments.eventName)) {
				event = eventMap[arguments.eventName];
			}
			else {
				event = new org.owasp.esapi.beans.Event(variables.ESAPI, arguments.eventName);
				eventMap[arguments.eventName] = event;
			}
			// increment
			event.increment(threshold.count, threshold.interval);
		}
	}

}
