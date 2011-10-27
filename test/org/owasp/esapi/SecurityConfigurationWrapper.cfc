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
/**
 * Simple wrapper implementation of {@link SecurityConfiguration}. 
 * This allows for easy subclassing and property fixups for unit tests.
 *
 * Note that there are some compilers have issues with Override
 * attributes on methods implementing a interface method with some
 * compilers. Technically Override on such methods is a 1.6 feature so
 * they are commented out here.
 */
component SecurityConfigurationWrapper implements="cfesapi.org.owasp.esapi.SecurityConfiguration" {

	instance.wrapped = "";

	/**
	 * Constructor wrapping the given configuration.
	 * @param wrapped The configuration to wrap.
	 */
	
	public SecurityConfigurationWrapper function init(required cfesapi.org.owasp.esapi.SecurityConfiguration wrapped) {
		instance.wrapped = arguments.wrapped;
		
		return this;
	}
	
	/**
	 * Access the wrapped configuration.
	 * @return The wrapped configuration.
	 */
	
	public SecurityConfiguration function getWrappedSecurityConfiguration() {
		return instance.wrapped;
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getApplicationName() {
		return instance.wrapped.getApplicationName();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getLogImplementation() {
		return instance.wrapped.getLogImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getAuthenticationImplementation() {
		return instance.wrapped.getAuthenticationImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getEncoderImplementation() {
		return instance.wrapped.getEncoderImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getAccessControlImplementation() {
		return instance.wrapped.getAccessControlImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getIntrusionDetectionImplementation() {
		return instance.wrapped.getIntrusionDetectionImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getRandomizerImplementation() {
		return instance.wrapped.getRandomizerImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getEncryptionImplementation() {
		return instance.wrapped.getEncryptionImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getValidationImplementation() {
		return instance.wrapped.getValidationImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public function getValidationPattern(required String key) {
		return instance.wrapped.getValidationPattern(arguments.key);
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getExecutorImplementation() {
		return instance.wrapped.getExecutorImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getHTTPUtilitiesImplementation() {
		return instance.wrapped.getHTTPUtilitiesImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public binary function getMasterKey() {
		return instance.wrapped.getMasterKey();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public function getUploadDirectory() {
		return instance.wrapped.getUploadDirectory();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public function getUploadTempDirectory() {
		return instance.wrapped.getUploadTempDirectory();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public numeric function getEncryptionKeyLength() {
		return instance.wrapped.getEncryptionKeyLength();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public binary function getMasterSalt() {
		return instance.wrapped.getMasterSalt();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public Array function getAllowedExecutables() {
		return instance.wrapped.getAllowedExecutables();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public Array function getAllowedFileExtensions() {
		return instance.wrapped.getAllowedFileExtensions();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public numeric function getAllowedFileUploadSize() {
		return instance.wrapped.getAllowedFileUploadSize();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getPasswordParameterName() {
		return instance.wrapped.getPasswordParameterName();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getUsernameParameterName() {
		return instance.wrapped.getUsernameParameterName();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getEncryptionAlgorithm() {
		return instance.wrapped.getEncryptionAlgorithm();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getCipherTransformation() {
		return instance.wrapped.getCipherTransformation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function setCipherTransformation(required String cipherXform) {
		return instance.wrapped.setCipherTransformation(arguments.cipherXform);
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public boolean function useMACforCipherText() {
		return instance.wrapped.useMACforCipherText();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public boolean function overwritePlainText() {
		return instance.wrapped.overwritePlainText();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getIVType() {
		return instance.wrapped.getIVType();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getFixedIV() {
		return instance.wrapped.getFixedIV();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getHashAlgorithm() {
		return instance.wrapped.getHashAlgorithm();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public numeric function getHashIterations() {
		return instance.wrapped.getHashIterations();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getCharacterEncoding() {
		return instance.wrapped.getCharacterEncoding();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public boolean function getAllowMultipleEncoding() {
		return instance.wrapped.getAllowMultipleEncoding();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public boolean function getAllowMixedEncoding() {
		return instance.wrapped.getAllowMixedEncoding();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public Array function getDefaultCanonicalizationCodecs() {
		return instance.wrapped.getDefaultCanonicalizationCodecs();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getDigitalSignatureAlgorithm() {
		return instance.wrapped.getDigitalSignatureAlgorithm();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public numeric function getDigitalSignatureKeyLength() {
		return instance.wrapped.getDigitalSignatureKeyLength();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getRandomAlgorithm() {
		return instance.wrapped.getRandomAlgorithm();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public numeric function getAllowedLoginAttempts() {
		return instance.wrapped.getAllowedLoginAttempts();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public numeric function getMaxOldPasswordHashes() {
		return instance.wrapped.getMaxOldPasswordHashes();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public function getQuota(required String eventName) {
		return instance.wrapped.getQuota(arguments.eventName);
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public function getResourceFile(required String filename) {
		return instance.wrapped.getResourceFile(arguments.filename);
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public boolean function getForceHttpOnlySession() {
		return instance.wrapped.getForceHttpOnlySession();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public boolean function getForceSecureSession() {
		return instance.wrapped.getForceSecureSession();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public boolean function getForceHttpOnlyCookies() {
		return instance.wrapped.getForceHttpOnlyCookies();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public boolean function getForceSecureCookies() {
		return instance.wrapped.getForceSecureCookies();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public numeric function getMaxHttpHeaderSize() {
		return instance.wrapped.getMaxHttpHeaderSize();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public function getResourceStream(required String filename) throws IOException {
		return instance.wrapped.getResourceStream(arguments.filename);
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public void function setResourceDirectory(required String dir) {
		instance.wrapped.setResourceDirectory(arguments.dir);
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getResponseContentType() {
		return instance.wrapped.getResponseContentType();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getHttpSessionIdName() {
		return instance.wrapped.getHttpSessionIdName();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public numeric function getRememberTokenDuration() {
		return instance.wrapped.getRememberTokenDuration();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public numeric function getSessionIdleTimeoutLength() {
		return instance.wrapped.getSessionIdleTimeoutLength();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public numeric function getSessionAbsoluteTimeoutLength() {
		return instance.wrapped.getSessionAbsoluteTimeoutLength();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public boolean function getLogEncodingRequired() {
		return instance.wrapped.getLogEncodingRequired();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public boolean function getLogApplicationName() {
		return instance.wrapped.getLogApplicationName();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public boolean function getLogServerIP() {
		return instance.wrapped.getLogServerIP();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public numeric function getLogLevel() {
		return instance.wrapped.getLogLevel();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getLogFileName() {
		return instance.wrapped.getLogFileName();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public numeric function getMaxLogFileSize() {
		return instance.wrapped.getMaxLogFileSize();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public function getWorkingDirectory() {
		return instance.wrapped.getWorkingDirectory();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public Array function getAdditionalAllowedCipherModes() {
		return instance.wrapped.getAdditionalAllowedCipherModes();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public Array function getCombinedCipherModes() {
		return instance.wrapped.getCombinedCipherModes();
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public String function getPreferredJCEProvider() {
		return instance.wrapped.getPreferredJCEProvider();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public boolean function getDisableIntrusionDetection() {
		return instance.wrapped.getDisableIntrusionDetection();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	
	public String function getKDFPseudoRandomFunction() {
		return instance.wrapped.getKDFPseudoRandomFunction();
	}
	
	/**
	 * {@inheritDoc}
	 */
	
	public boolean function getLenientDatesAccepted() {
		return instance.wrapped.getLenientDatesAccepted();
	}
	
}