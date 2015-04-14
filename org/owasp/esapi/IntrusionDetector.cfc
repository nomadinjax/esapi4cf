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
 * The IntrusionDetector interface is intended to track security relevant events and identify attack behavior. The
 * implementation can use as much state as necessary to detect attacks, but note that storing too much state will burden
 * your system.
 * <P>
 * The interface is currently designed to accept exceptions as well as custom events. Implementations can use this
 * stream of information to detect both normal and abnormal behavior.
 */
interface {

    /**
     * Adds the exception to the IntrusionDetector.  This method should immediately log the exception so that developers throwing an
     * IntrusionException do not have to remember to log every error.  The implementation should store the exception somewhere for the current user
     * in order to check if the User has reached the threshold for any Enterprise Security Exceptions.  The User object is the recommended location for storing
     * the current user's security exceptions.  If the User has reached any security thresholds, the appropriate security action can be taken and logged.
     *
     * @param exception
     * 		the exception thrown
     *
     * @throws IntrusionException
     * 		the intrusion exception
     */
    public void function addException(required exception);

    /**
     * Adds the event to the IntrusionDetector.  This method should immediately log the event.  The implementation should store the event somewhere for the current user
     * in order to check if the User has reached the threshold for any Enterprise Security Exceptions.  The User object is the recommended location for storing
     * the current user's security event.  If the User has reached any security thresholds, the appropriate security action can be taken and logged.
     *
     * @param eventName
     * 		the event to add
     * @param logMessage
     * 		the message to log with the event
     *
     * @throws IntrusionException
     * 		the intrusion exception
     */
    public void function addEvent(required string eventName, required string logMessage);

}