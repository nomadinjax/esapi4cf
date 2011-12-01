<!--- /**
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
 */ --->
<cfcomponent displayname="ThreadLocal" extends="cfesapi.org.owasp.esapi.lang.Object" output="false" hint="This allows a singleton to store a request specific variable so it will not be shared. The variable will be stored in the request scope and available only throughout the current request.">

	<cfscript>
		instance.threadId = "";
	</cfscript>

	<cffunction access="private" returntype="void" name="resetThreadId" output="false">

		<cfscript>
			instance.threadId = "ThreadLocal_" & createUUID();
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="getThreadId" output="false">

		<cfscript>
			if(instance.threadId == "") {
				resetThreadId();
			}
			return instance.threadId;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="initialValue" output="false" hint="Returns the current thread's 'initial value' for this thread-local variable.  This method will be invoked the first time a thread accesses the variable with the {@link ##get} method, unless the thread previously invoked the {@link ##set} method, in which case the initialValue method will not be invoked for the thread.  Normally, this method is invoked at most once per thread, but it may be invoked again in case of subsequent invocations of {@link ##remove} followed by {@link ##get}. This implementation simply returns null; if the programmer desires thread-local variables to have an initial value other than null, ThreadLocal must be subclassed, and this method overridden.  Typically, an anonymous inner class will be used.">

		<cfscript>
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="get" output="false" hint="Returns the current thread's 'initial value' for this thread-local variable.  This method will be invoked the first time a thread accesses the variable with the {@link ##get} method, unless the thread previously invoked the {@link ##set} method, in which case the initialValue method will not be invoked for the thread.  Normally, this method is invoked at most once per thread, but it may be invoked again in case of subsequent invocations of {@link ##remove} followed by {@link ##get}. This implementation simply returns null; if the programmer desires thread-local variables to have an initial value other than null, ThreadLocal must be subclassed, and this method overridden.  Typically, an anonymous inner class will be used.">
		<cfset var local = {}/>

		<cfscript>
			local.threadId = getThreadId();
			if(structKeyExists(request, local.threadId)) {
				return request[local.threadId];
			}
			return setInitialValue();
		</cfscript>

	</cffunction>

	<cffunction access="private" name="setInitialValue" output="false" hint="Variant of set() to establish initialValue. Used instead of set() in case user has overridden the set() method.">
		<cfset var local = {}/>

		<cfscript>
			local.threadId = getThreadId();
			local.value = initialValue();
			request[local.threadId] = local.value;
			return local.value;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="set" output="false"
	            hint="Sets the current thread's copy of this thread-local variable to the specified value.  Most subclasses will have no need to override this method, relying solely on the {@link ##initialValue} method to set the values of thread-locals.">
		<cfargument required="true" name="value" hint="the value to be stored in the current thread's copy of this thread-local."/>

		<cfset var local = {}/>

		<cfscript>
			local.threadId = getThreadId();
			request[local.threadId] = arguments.value;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="remove" output="false"
	            hint="Removes the current thread's value for this thread-local variable.  If this thread-local variable is subsequently {@linkplain ##get read} by the current thread, its value will be reinitialized by invoking its {@link ##initialValue} method, unless its value is {@linkplain ##set set} by the current thread in the interim.  This may result in multiple invocations of the initialValue method in the current thread.">
		<cfset var local = {}/>

		<cfscript>
			local.threadId = getThreadId();
			structDelete(request, local.threadId);

			// reset the Thread ID so we never use this request variable again
			resetThreadId();
		</cfscript>

	</cffunction>

</cfcomponent>