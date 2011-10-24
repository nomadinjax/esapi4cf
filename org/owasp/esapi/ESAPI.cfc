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
 * ESAPI locator class is provided to make it easy to gain access to the current ESAPI classes in use.
 * Use the set methods to override the reference implementations with instances of any custom ESAPI implementations.
 */
component ESAPI extends="cfesapi.org.owasp.esapi.lang.Object" {

	instance.securityConfigurationImplName = createObject("java", "java.lang.System").getProperty("cfesapi.org.owasp.esapi.SecurityConfiguration", "cfesapi.org.owasp.esapi.reference.DefaultSecurityConfiguration");

    /**
	 * Clears the current User, HttpRequest, and HttpResponse associated with the current thread. This method
	 * MUST be called as some containers do not properly clear threadlocal variables when the execution of
	 * a thread is complete. The suggested approach is to put this call in a finally block inside a filter.
	 * <pre>
		public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException {
			try {
				HttpServletRequest request = (HttpServletRequest) req;
				HttpServletResponse response = (HttpServletResponse) resp;
				ESAPI.httpUtilities().setCurrentHTTP(request, response);
				ESAPI.authenticator().login();
				chain.doFilter(request, response);
			} catch (Exception e) {
				logger.error( Logger.SECURITY_FAILURE, "Error in ESAPI security filter: " & e.getMessage(), e );
			} finally {
				// VERY IMPORTANT
				// clear out ThreadLocal variables
				ESAPI.clearCurrent();
			}
		}
	 * </pre>
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
	public cfesapi.org.owasp.esapi.HttpServletRequest function currentRequest() {
		return httpUtilities().getCurrentRequest();
	}
	
	/**
	 * Get the current HTTP Servlet Response being generated.
	 * @return the current HTTP Servlet Response.
	 */
	public cfesapi.org.owasp.esapi.HttpServletResponse function currentResponse() {
		return httpUtilities().getCurrentResponse();
	}
	
	/**
	 * @return the current ESAPI AccessController object being used to maintain the access control rules for this application. 
	 */
	public cfesapi.org.owasp.esapi.AccessController function accessController() {
        return make( securityConfiguration().getAccessControlImplementation(), "AccessController" );
	}

	/**
	 * @return the current ESAPI Authenticator object being used to authenticate users for this application. 
	 */
	public cfesapi.org.owasp.esapi.Authenticator function authenticator() {
        return make( securityConfiguration().getAuthenticationImplementation(), "Authenticator" );
	}

	/**
	 * @return the current ESAPI Encoder object being used to encode and decode data for this application. 
	 */
	public cfesapi.org.owasp.esapi.Encoder function encoder() {
        return make( securityConfiguration().getEncoderImplementation(), "Encoder" );
	}

	/**
	 * @return the current ESAPI Encryptor object being used to encrypt and decrypt data for this application. 
	 */
	public cfesapi.org.owasp.esapi.Encryptor function encryptor() {
        return make( securityConfiguration().getEncryptionImplementation(), "Encryptor" );
	}

	/**
	 * @return the current ESAPI Executor object being used to safely execute OS commands for this application. 
	 */
	public cfesapi.org.owasp.esapi.Executor function executor() {
        return make( securityConfiguration().getExecutorImplementation(), "Executor" );
	}

	/**
	 * @return the current ESAPI HTTPUtilities object being used to safely access HTTP requests and responses 
	 * for this application. 
	 */
	public cfesapi.org.owasp.esapi.HTTPUtilities function httpUtilities() {
        return make( securityConfiguration().getHTTPUtilitiesImplementation(), "HTTPUtilities" );
	}

	/**
	 * @return the current ESAPI IntrusionDetector being used to monitor for intrusions in this application. 
	 */
	public cfesapi.org.owasp.esapi.IntrusionDetector function intrusionDetector() {
        return make( securityConfiguration().getIntrusionDetectionImplementation(), "IntrusionDetector" );
	}

	/**
	 * Get the current LogFactory being used by ESAPI. If there isn't one yet, it will create one, and then 
	 * return this same LogFactory from then on.
	 * @return The current LogFactory being used by ESAPI.
	 */
	private cfesapi.org.owasp.esapi.LogFactory function logFactory() {
        return make( securityConfiguration().getLogImplementation(), "LogFactory" );
	}
	
	/**
	 * @param moduleName The module to associate the logger with.
	 * @return The current Logger associated with the specified module.
	 */
	public cfesapi.org.owasp.esapi.Logger function getLogger(required String moduleName) {
		return logFactory().getLogger(arguments.moduleName);
	}
	
	/**
	 * @return The default Logger.
	 */
	public cfesapi.org.owasp.esapi.Logger function log() {
        return logFactory().getLogger("DefaultLogger");
    }
	
	/**
	 * @return the current ESAPI Randomizer being used to generate random numbers in this application. 
	 */
	public cfesapi.org.owasp.esapi.Randomizer function randomizer() {
        return make( securityConfiguration().getRandomizerImplementation(), "Randomizer" );
	}

    instance.overrideConfig = "";

	/**
	 * @return the current ESAPI SecurityConfiguration being used to manage the security configuration for 
	 * ESAPI for this application. 
	 */
	public cfesapi.org.owasp.esapi.SecurityConfiguration function securityConfiguration() {
		// copy the volatile into a non-volatile to prevent TOCTTOU race condition
		local.override = instance.overrideConfig;
		if ( isObject(local.override) ) {
			return local.override;
        }

        return make( instance.securityConfigurationImplName, "SecurityConfiguration" );
	}

	/**
	 * @return the current ESAPI Validator being used to validate data in this application. 
	 */
	public cfesapi.org.owasp.esapi.Validator function validator() {
        return make( securityConfiguration().getValidationImplementation(), "Validator" );
	}

    // TODO: This should probably use the SecurityManager or some value within the current
    // securityConfiguration to determine if this method is allowed to be called. This could
    // allow for unit tests internal to ESAPI to modify the configuration for the purpose of
    // testing stuff, and allow developers to allow this in development environments but make
    // it so the securityConfiguration implementation *cannot* be modified in production environments.
    //
    // The purpose of this method is to replace the functionality provided by the setSecurityConfiguration
    // method that is no longer on this class, and allow the context configuration of the ESAPI
    // to be modified at Runtime.
    public String function initialize( required String impl ) {
        local.oldImpl = instance.securityConfigurationImplName;
        instance.securityConfigurationImplName = arguments.impl;
        return local.oldImpl;
    }

    /**
     * Overrides the current security configuration with a new implementation. This is meant
     * to be used as a temporary means to alter the behavior of the ESAPI and should *NEVER*
     * be used in a production environment as it will affect the behavior and configuration of
     * the ESAPI *GLOBALLY*.
     *
     * To clear an overridden Configuration, simple call this method with null for the config
     * parameter.
     *
     * @param config
     * @return
     */
    public void function override( required config ) {
        instance.overrideConfig = arguments.config;
    }
    
    instance.make = {};
    
    /**
	 * Create an object based on the <code>className</code> parameter.
	 * 
	 * @param className	The name of the class to construct. Should be a fully qualified name and
	 * 					generally the same as type <code>T</code>
	 * @param typeName	A type name used in error messages / exceptions.
	 * @return	An object of type <code>className</code>, which is cast to type <code>T</code>.
	 * @throws	ConfigurationException thrown if class name not found in class path, or does not
	 * 			have a public, no-argument constructor, or is not a concrete class, or if it is
	 * 			not a sub-type of <code>T</code> (or <code>T</code> itself). Usually this is
	 * 			caused by a misconfiguration of the class names specified in the ESAPI.properties
	 * 			file. Also thrown if the CTOR of the specified <code>className</code> throws
	 * 			an <code>Exception</code> of some type.
	 */
	//@SuppressWarnings({ "unchecked" })	// Added because of Eclipse warnings, but ClassCastException IS caught.
	private function make(required String className, required String typeName) {
		local.obj = "";
		local.errMsg = "";
		try {
			if (isNull(arguments.className) || "" == arguments.className ) {
				throwError( IllegalArgumentException.init("Classname cannot be null or empty.") );
			}
			if (isNull(arguments.typeName) || "" == arguments.typeName ) {
				// No big deal...just use "[unknown?]" for this as it's only for an err msg.
				arguments.typeName = "[unknown?]";	// CHECKME: Any better suggestions?
			}
			
			if ( structKeyExists(instance.make, arguments.typeName) ) {
				local.obj = instance.make[arguments.typeName];
			}
			else {
	            try {
	                local.obj = createObject("component", arguments.className).init(this);
	            } catch (expression e) {
	                // This is a no-error exception, if this is caught we will continue on assuming the implementation was
	                // not meant to be used as a singleton.
	                local.obj = createObject("component", arguments.className);
	            } catch (SecurityException e) {
	                // The class is meant to be singleton, however, the SecurityManager restricts us from calling the
	                // getInstance method on the class, thus this is a configuration issue and a ConfigurationException
	                // is thrown
	                throwError( new cfesapi.org.owasp.esapi.errors.ConfigurationException( "The SecurityManager has restricted the object factory from getting a reference to the singleton implementation of the class [" & arguments.className & "]", e ) );
	            }
            	instance.make[arguments.typeName] = local.obj;
            }

			return local.obj;		// Eclipse warning here if @SupressWarnings omitted.
			
            // Issue 66 - Removed System.out calls as we are throwing an exception in each of these cases
            // anyhow.
		} catch( IllegalArgumentException ex ) {
			local.errMsg = ex.toString() & " " & arguments.typeName & " type name cannot be null or empty.";
			throwError( new cfesapi.org.owasp.esapi.errors.ConfigurationException(local.errMsg, ex) );
		}catch ( ClassNotFoundException ex ) {
			local.errMsg = ex.toString() & " " & arguments.typeName & " class (" & arguments.className & ") must be in class path.";
			throwError( new cfesapi.org.owasp.esapi.errors.ConfigurationException(local.errMsg, ex) );
		} catch( InstantiationException ex ) {
			local.errMsg = ex.toString() & " " & arguments.typeName & " class (" & arguments.className & ") must be concrete.";
			throwError( new cfesapi.org.owasp.esapi.errors.ConfigurationException(local.errMsg, ex) );
		} catch( IllegalAccessException ex ) {
			local.errMsg = ex.toString() & " " & arguments.typeName & " class (" & arguments.className & ") must have a public, no-arg constructor.";
			throwError( new cfesapi.org.owasp.esapi.errors.ConfigurationException(local.errMsg, ex) );
		} catch( ClassCastException ex ) {
			local.errMsg = ex.toString() & " " & arguments.typeName & " class (" & arguments.className & ") must be a subtype of T in ObjFactory<T>";
			throwError( new cfesapi.org.owasp.esapi.errors.ConfigurationException(local.errMsg, ex) );
		} catch( Exception ex ) {
			// Because we are using reflection, we want to catch any checked or unchecked Exceptions and
			// re-throw them in a way we can handle them. Because using reflection to construct the object,
			// we can't have the compiler notify us of uncaught exceptions. For example, JavaEncryptor()
			// CTOR can throw [well, now it can] an EncryptionException if something goes wrong. That case
			// is taken care of here.
			//
			// CHECKME: Should we first catch RuntimeExceptions so we just let unchecked Exceptions go through
			//		    unaltered???
			//
			local.errMsg = ex.toString() & " " & arguments.typeName & " class (" & arguments.className & ") CTOR threw exception.";
			throwError( new ConfigurationException(local.errMsg, ex) );
		}
		// DISCUSS: Should we also catch ExceptionInInitializerError here? See Google Issue #61 comments.
	}
}
