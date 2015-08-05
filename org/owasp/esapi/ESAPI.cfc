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
import "org.owasp.esapi.errors.ConfigurationException";

component extends="org.owasp.esapi.util.Object" {

	variables.factory = {};
	variables.configuration = {};
	variables.Adapter = {};

	/**
	 * Main constructor for the ESAPI library.
	 *
	 * @param configuration Parameters to override the default ESAPI configuration. You are required to pass in your own MasterKey and MasterSalt.
	 */
	public ESAPI function init(struct configuration) {
		if (structKeyExists(arguments, "configuration")) {
			variables.configuration = arguments.configuration;
		}

		// default to file based adapter
		variables.Adapter = new org.owasp.esapi.reference.FileBasedAdapter(this);

		return this;
	}

	public Version function versionData() {
		if (!structKeyExists(variables.factory, "Version")) {
        	variables.factory["Version"] = new org.owasp.esapi.Version();
        }
        return variables.factory["Version"];
	}

    /**
	 * Clears the current User, HttpRequest, and HttpResponse associated with the current thread. This method
	 * MUST be called as some containers do not properly clear threadlocal variables when the execution of
	 * a thread is complete. The suggested approach is to put this call in a finally block inside a filter.
	 * The advantages of having identity everywhere are worth the risk here.
	 */
	public void function clearCurrent() {
		authenticator().clearCurrent();
		httpUtilities().clearCurrent();
	}

	/**
	 * Get the current HTTP Servlet Request being processed.
	 * @return the current HTTP Servlet Request.
	 */
	public function currentRequest() {
		return httpUtilities().getCurrentRequest();
	}

	/**
	 * Get the current HTTP Servlet Response being generated.
	 * @return the current HTTP Servlet Response.
	 */
	public function currentResponse() {
		return httpUtilities().getCurrentResponse();
	}

	/**
	 * @return the current ESAPI AccessController object being used to maintain the access control rules for this application.
	 */
	public AccessController function accessController() {
		if (!structKeyExists(variables.factory, "AccessController")) {
        	variables.factory["AccessController"] = createObject(securityConfiguration().getAccessControlImplementation()).init(this);
        }
        return variables.factory["AccessController"];
	}

	/**
	 * @return the current ESAPI Authenticator object being used to authenticate users for this application.
	 */
	public Authenticator function authenticator() {
		if (!structKeyExists(variables.factory, "Authenticator")) {
        	variables.factory["Authenticator"] = createObject(securityConfiguration().getAuthenticationImplementation()).init(this);
        }
        return variables.factory["Authenticator"];
	}

	/**
	 * @return the current ESAPI Encoder object being used to encode and decode data for this application.
	 */
	public Encoder function encoder() {
        if (!structKeyExists(variables.factory, "Encoder")) {
        	variables.factory["Encoder"] = createObject(securityConfiguration().getEncoderImplementation()).init(this);
        }
        return variables.factory["Encoder"];
	}

	/**
	 * @return the current ESAPI Encryptor object being used to encrypt and decrypt data for this application.
	 */
	public Encryptor function encryptor() {
		if (!structKeyExists(variables.factory, "Encryptor")) {
        	variables.factory["Encryptor"] = createObject(securityConfiguration().getEncryptionImplementation()).init(this);
        }
        return variables.factory["Encryptor"];
	}

	/**
	 * @return the current ESAPI Executor object being used to safely execute OS commands for this application.
	 */
	/*public Executor function executor() {
        return ObjFactory.make( securityConfiguration().getExecutorImplementation(), "Executor" );
	}*/

	/**
	 * @return the current ESAPI HTTPUtilities object being used to safely access HTTP requests and responses
	 * for this application.
	 */
	public HTTPUtilities function httpUtilities() {
		if (!structKeyExists(variables.factory, "HTTPUtilities")) {
        	variables.factory["HTTPUtilities"] = createObject(securityConfiguration().getHTTPUtilitiesImplementation()).init(this);
        }
        return variables.factory["HTTPUtilities"];
	}

	/**
	 * @return the current ESAPI IntrusionDetector being used to monitor for intrusions in this application.
	 */
	public IntrusionDetector function intrusionDetector() {
		if (!structKeyExists(variables.factory, "IntrusionDetector")) {
        	variables.factory["IntrusionDetector"] = createObject(securityConfiguration().getIntrusionDetectionImplementation()).init(this);
        }
        return variables.factory["IntrusionDetector"];
	}

	/**
	 * Get the current LogFactory being used by ESAPI. If there isn't one yet, it will create one, and then
	 * return this same LogFactory from then on.
	 * @return The current LogFactory being used by ESAPI.
	 */
	private LogFactory function logFactory() {
		if (!structKeyExists(variables.factory, "LogFactory")) {
        	variables.factory["LogFactory"] = createObject(securityConfiguration().getLogImplementation()).init(this);
        }
        return variables.factory["LogFactory"];
	}

	/**
	 * @param moduleName The module to associate the logger with.
	 * @return The current Logger associated with the specified module.
	 */
	public Logger function getLogger(required string moduleName) {
		return logFactory().getLogger(arguments.moduleName);
	}

	/**
	 * @return The default Logger.
	 */
	public Logger function log() {
        return logFactory().getLogger(getMetaData(this).fullName);
    }

	/**
	 * @return the current ESAPI Randomizer being used to generate random numbers in this application.
	 */
	public Randomizer function randomizer() {
		if (!structKeyExists(variables.factory, "Randomizer")) {
        	variables.factory["Randomizer"] = createObject(securityConfiguration().getRandomizerImplementation()).init(this);
        }
        return variables.factory["Randomizer"];
	}

	private ResourceFactory function resourceFactory() {
		if (!structKeyExists(variables.factory, "ResourceFactory")) {
        	variables.factory["ResourceFactory"] = createObject(securityConfiguration().getResourceImplementation()).init(this);
        }
        return variables.factory["ResourceFactory"];
	}

	/**
	 * @param moduleName The module to associate the logger with.
	 * @return The current Logger associated with the specified module.
	 */
	public Resource function getResource(string baseName, Locale) {
		return resourceFactory().getResource(argumentCollection=arguments);
	}

	/**
	 * @return the current ESAPI SecurityConfiguration being used to manage the security configuration for
	 * ESAPI for this application.
	 */
	public SecurityConfiguration function securityConfiguration() {
		if (!structKeyExists(variables.factory, "SecurityConfiguration")) {
        	variables.factory["SecurityConfiguration"] = new org.owasp.esapi.reference.SecurityConfiguration(this, variables.configuration);
        }
        return variables.factory["SecurityConfiguration"];
	}

	/**
	 * @return the current ESAPI Validator being used to validate data in this application.
	 */
	public Validator function validator() {
		if (!structKeyExists(variables.factory, "Validator")) {
        	variables.factory["Validator"] = createObject(securityConfiguration().getValidationImplementation()).init(this);
        }
        return variables.factory["Validator"];
	}

	/**
	 * Returns the implemented component containing the access to data.
	 */
	public Adapter function getAdapter() {
		// FIXME: CF11 not sure why isInstanceOf() returns false when should be true
		//if (structKeyExists(variables, "Adapter") && isInstanceOf(variables.Adapter, "org.owasp.esapi.Adapter")) {
		if (structKeyExists(variables, "Adapter")) {
			var implements = structKeyList(getMetaData(variables.Adapter).implements);
			if (implements == "org.owasp.esapi.Adapter") {
				return variables.Adapter;
			}
		}
		raiseException(new ConfigurationException("ESAPI Configuration Error: Either no Adapter object has been defined or it does not implement the Adapter interface."));
	}

	/**
	 * Set the component which contains the access to your data.
	 *
	 * @param Adapter
	 */
	public void function setAdapter(required Adapter adapter) {
		variables.Adapter = arguments.Adapter;
	}

}
