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
 * The class Exception and its subclasses are a form of Throwable that indicates conditions that a reasonable application might want to catch.
 */
component Exception extends="Object" {

	instance.exception = {};
	instance.stackTrace = [];
	instance.type = "";

	/**
	 * Constructs a new exception with the specified detail message and cause.
	 * Note that the detail message associated with cause is not automatically incorporated in this exception's detail message.
	 *
	 * @param message the detail message (which is saved for later retrieval by the Throwable.getMessage() method).
	 * @param cause the cause (which is saved for later retrieval by the Throwable.getCause() method). (A null value is permitted, and indicates that the cause is nonexistent or unknown.)
	 */
	
	public Exception function init(String message, cause) {
		if(structKeyExists(arguments, "message")) {
			if(structKeyExists(arguments, "cause")) {
				// ADOBE CF exceptions extend java.lang.Exception
				if(isInstanceOf(arguments.cause, "java.lang.Throwable")) {
					local.cause = arguments.cause;
				}
				// RAILO CF exceptions do not extend java.lang.Exception
				// ? is there a better way ? I hope so...
				else if(isStruct(arguments.cause)) {
					local.cause = createObject("java", "java.lang.Throwable").init(arguments.cause.message);
				}
				instance.exception = createObject("java", "java.lang.Exception").init(arguments.message, local.cause);
			}
			else {
				instance.exception = createObject("java", "java.lang.Exception").init(arguments.message);
			}
		}
		else {
			instance.exception = createObject("java", "java.lang.Exception").init();
		}
	
		setType();
		// RAILO ERROR: setStackTrace(instance.exception.tagContext);
		setStackTrace(instance.exception.getStackTrace());
	
		return this;
	}
	
	/**
	 * Returns the cause of this throwable or null if the cause is nonexistent or unknown. (The cause is the throwable that caused this throwable to get thrown.)
	 * This implementation returns the cause that was supplied via one of the constructors requiring a Throwable, or that was set after creation with the initCause(Throwable) method. While it is typically unnecessary to override this method, a subclass can override it to return a cause set by some other means. This is appropriate for a "legacy chained throwable" that predates the addition of chained exceptions to Throwable. Note that it is not necessary to override any of the PrintStackTrace methods, all of which invoke the getCause method to determine the cause of a throwable.
	 *
	 * @return the cause of this throwable or null if the cause is nonexistent or unknown.
	 */
	
	public function getCause() {
		return instance.exception.getCause();
	}
	
	/**
	 * Creates a localized description of this throwable. Subclasses may override this method in order to produce a locale-specific message. For subclasses that do not override this method, the default implementation returns the same result as getMessage().
	 *
	 * @return The localized description of this throwable.
	 */
	
	public String function getLocalizedMessage() {
		return instance.exception.getLocalizedMessage();
	}
	
	/**
	 * Returns the detail message string of this throwable.
	 *
	 * @return the detail message string of this Throwable instance (which may be null).
	 */
	
	public String function getMessage() {
		return instance.exception.getMessage();
	}
	
	/**
	 * Provides programmatic access to the stack trace information printed by printStackTrace(). Returns an array of stack trace elements, each representing one stack frame. The zeroth element of the array (assuming the array's length is non-zero) represents the top of the stack, which is the last method invocation in the sequence. Typically, this is the point at which this throwable was created and thrown. The last element of the array (assuming the array's length is non-zero) represents the bottom of the stack, which is the first method invocation in the sequence.
	 * Some virtual machines may, under some circumstances, omit one or more stack frames from the stack trace. In the extreme case, a virtual machine that has no stack trace information concerning this throwable is permitted to return a zero-length array from this method. Generally speaking, the array returned by this method will contain one element for every frame that would be printed by printStackTrace.
	 *
	 * @return an array of stack trace elements representing the stack trace pertaining to this throwable.
	 */
	
	public Array function getStackTrace() {
		//return instance.exception.getStackTrace();
		return instance.stackTrace;
	}
	
	/**
	 *
	 */
	
	public String function getType() {
		return instance.type;
	}
	
	/** 
	 * Initializes the cause of this throwable to the specified value. (The cause is the throwable that caused this throwable to get thrown.)
	 * This method can be called at most once. It is generally called from within the constructor, or immediately after creating the throwable. If this throwable was created with Throwable(Throwable) or Throwable(String,Throwable), this method cannot be called even once.
	 * 
	 * @param cause the cause (which is saved for later retrieval by the getCause() method). (A null value is permitted, and indicates that the cause is nonexistent or unknown.)
	 *
	 * @return a reference to this Throwable instance.
	 */
	
	public Exception function initCause(required cause) {
		return instance.exception.initCause(arguments.cause);
	}
	
	/**
	 * Prints this throwable and its backtrace to the standard error stream. This method prints a stack trace for this Throwable object on the error output stream that is the value of the field System.err. The first line of output contains the result of the toString() method for this object. Remaining lines represent data previously recorded by the method fillInStackTrace().
	 */
	
	public void function printStackTrace() {
		return instance.exception.printStackTrace();
	}
	
	/**
	 * Sets the stack trace elements that will be returned by getStackTrace() and printed by printStackTrace() and related methods. This method, which is designed for use by RPC frameworks and other advanced systems, allows the client to override the default stack trace that is either generated by fillInStackTrace() when a throwable is constructed or deserialized when a throwable is read from a serialization stream.
	 *
	 * @param stackTrace the stack trace elements to be associated with this Throwable. The specified array is copied by this call; changes in the specified array after the method invocation returns will have no affect on this Throwable's stack trace.
	 */
	
	public void function setStackTrace(required Array stackTrace) {
		//instance.exception.setStackTrace(arguments.stackTrace);
		local.stackTrace = duplicate(arguments.stackTrace);
	
		// drop indexes that contain "cfesapi\org\owasp\esapi\errors"
		while(arrayLen(local.stackTrace)) {
			local.item = local.stackTrace[1];
			if( !findNoCase("cfesapi\org\owasp\esapi\errors", local.item.getFileName()) ) {
				break;
			}
			arrayDeleteAt(local.stackTrace, 1);
		}
		// 1st index should now be the actual caller object
		instance.stackTrace = local.stackTrace;
	}
	
	private void function setType() {
		instance.type = getMetaData().name;
		// full path is missing when cfesapi is virtual directory
		if(listLen(instance.type, ".") EQ 1) {
			instance.type = "cfesapi.org.owasp.esapi.errors." & instance.type;
		}
	}
	
	/**
	 * Returns a short description of this throwable. The result is the concatenation of:
	 *     the name of the class of this object
	 *     ": " (a colon and a space)
	 *     the result of invoking this object's getLocalizedMessage() method
	 * If getLocalizedMessage returns null, then just the class name is returned.
	 *
	 * @return a string representation of this throwable.
	 */
	
	public String function toString() {
		return instance.exception.toString();
	}
	
}