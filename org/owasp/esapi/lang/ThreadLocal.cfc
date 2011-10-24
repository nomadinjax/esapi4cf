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
 * This allows a singleton to store a request specific variable so it will not be shared.
 * The variable will be stored in the request scope and available only throughout the current request.
 */
component extends="cfesapi.org.owasp.esapi.lang.Object" {

	instance.threadId = "";

	private void function resetThreadId() {
		instance.threadId = "ThreadLocal_" & createUUID();
	}
	
	private String function getThreadId() {
		if(instance.threadId == "") {
			resetThreadId();
		}
		return instance.threadId;
	}
	
	/**
	 * Returns the current thread's "initial value" for this
	 * thread-local variable.  This method will be invoked the first
	 * time a thread accesses the variable with the {@link #get}
	 * method, unless the thread previously invoked the {@link #set}
	 * method, in which case the <tt>initialValue</tt> method will not
	 * be invoked for the thread.  Normally, this method is invoked at
	 * most once per thread, but it may be invoked again in case of
	 * subsequent invocations of {@link #remove} followed by {@link #get}.
	 *
	 * <p>This implementation simply returns <tt>null</tt>; if the
	 * programmer desires thread-local variables to have an initial
	 * value other than <tt>null</tt>, <tt>ThreadLocal</tt> must be
	 * subclassed, and this method overridden.  Typically, an
	 * anonymous inner class will be used.
	 *
	 * @return the initial value for this thread-local
	 */
	
	public function initialValue() {
		return "";
	}
	
	/**
	 * Returns the value in the current thread's copy of this
	 * thread-local variable.  If the variable has no value for the
	 * current thread, it is first initialized to the value returned
	 * by an invocation of the {@link #initialValue} method.
	 *
	 * @return the current thread's value of this thread-local
	 */
	
	public function get() {
		local.threadId = getThreadId();
		if(structKeyExists(request, local.threadId)) {
			return request[local.threadId];
		}
		return setInitialValue();
	}
	
	/**
	 * Variant of set() to establish initialValue. Used instead
	 * of set() in case user has overridden the set() method.
	 *
	 * @return the initial value
	 */
	
	private function setInitialValue() {
		local.threadId = getThreadId();
		local.value = initialValue();
		request[local.threadId] = local.value;
		return local.value;
	}
	
	/**
	 * Sets the current thread's copy of this thread-local variable
	 * to the specified value.  Most subclasses will have no need to
	 * override this method, relying solely on the {@link #initialValue}
	 * method to set the values of thread-locals.
	 *
	 * @param value the value to be stored in the current thread's copy of
	 *        this thread-local.
	 */
	
	public void function set(required value) {
		local.threadId = getThreadId();
		request[local.threadId] = arguments.value;
	}
	
	/**
	 * Removes the current thread's value for this thread-local
	 * variable.  If this thread-local variable is subsequently
	 * {@linkplain #get read} by the current thread, its value will be
	 * reinitialized by invoking its {@link #initialValue} method,
	 * unless its value is {@linkplain #set set} by the current thread
	 * in the interim.  This may result in multiple invocations of the
	 * <tt>initialValue</tt> method in the current thread.
	 *
	 * @since 1.5
	 */
	
	public void function remove() {
		local.threadId = getThreadId();
		structDelete(request, local.threadId);
		
		// reset the Thread ID so we never use this request variable again
		resetThreadId();
	}
	
}