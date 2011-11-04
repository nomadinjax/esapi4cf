/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Damon Miller
 * @created 2011
 */
component UnitTestSecurityConfiguration extends="cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration" {

	public cfesapi.org.owasp.esapi.SecurityConfiguration function init(required cfesapi.org.owasp.esapi.ESAPI ESAPI, required cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration cfg) {
		super.init(arguments.ESAPI, arguments.cfg.getESAPIProperties());
	
		return this;
	}
	
	/**
     * {@inheritDoc}
     */
	
	public void function setApplicationName(required String v) {
		getESAPIProperties().setProperty(this.APPLICATION_NAME, arguments.v);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setLogImplementation(required String v) {
		getESAPIProperties().setProperty(this.LOG_IMPLEMENTATION, arguments.v);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setAuthenticationImplementation(required String v) {
		getESAPIProperties().setProperty(this.AUTHENTICATION_IMPLEMENTATION, arguments.v);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setEncoderImplementation(required String v) {
		getESAPIProperties().setProperty(this.ENCODER_IMPLEMENTATION, arguments.v);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setAccessControlImplementation(required String v) {
		getESAPIProperties().setProperty(this.ACCESS_CONTROL_IMPLEMENTATION, arguments.v);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setEncryptionImplementation(required String v) {
		getESAPIProperties().setProperty(this.ENCRYPTION_IMPLEMENTATION, arguments.v);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setIntrusionDetectionImplementation(required String v) {
		getESAPIProperties().setProperty(this.INTRUSION_DETECTION_IMPLEMENTATION, arguments.v);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setRandomizerImplementation(required String v) {
		getESAPIProperties().setProperty(this.RANDOMIZER_IMPLEMENTATION, arguments.v);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setExecutorImplementation(required String v) {
		getESAPIProperties().setProperty(this.EXECUTOR_IMPLEMENTATION, arguments.v);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setHTTPUtilitiesImplementation(required String v) {
		getESAPIProperties().setProperty(this.HTTP_UTILITIES_IMPLEMENTATION, arguments.v);
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public void function setValidationImplementation(required String v) {
		getESAPIProperties().setProperty(this.VALIDATOR_IMPLEMENTATION, arguments.v);
	}
	
}