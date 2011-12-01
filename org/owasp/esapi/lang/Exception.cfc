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
<cfcomponent displayname="Exception" extends="Object" output="false" hint="The class Exception and its subclasses are a form of Throwable that indicates conditions that a reasonable application might want to catch.">

	<cfscript>
		instance.exception = {};
		instance.stackTrace = [];
		instance.type = "";
	</cfscript>

	<cffunction access="public" returntype="Exception" name="init" output="false"
	            hint="Constructs a new exception with the specified detail message and cause. Note that the detail message associated with cause is not automatically incorporated in this exception's detail message.">
		<cfargument type="String" name="message" hint="the detail message (which is saved for later retrieval by the Throwable.getMessage() method)."/>
		<cfargument name="cause" hint="the cause (which is saved for later retrieval by the Throwable.getCause() method). (A null value is permitted, and indicates that the cause is nonexistent or unknown.)"/>

		<cfset var local = {}/>

		<cfscript>
			if(structKeyExists(arguments, "message")) {
				if(structKeyExists(arguments, "cause")) {
					// ADOBE CF exceptions extend java.lang.Exception
					if(isInstanceOf(arguments.cause, "java.lang.Throwable")) {
						local.cause = arguments.cause;
					}
					// RAILO CF exceptions do not extend java.lang.Exception
					// ? is there a better way ? I hope so...
					else if(isStruct(arguments.cause)) {
						local.cause = newJava("java.lang.Exception").init(arguments.cause.message);
					}
					instance.exception = newJava("java.lang.Exception").init(arguments.message, local.cause);
				}
				else {
					instance.exception = newJava("java.lang.Exception").init(arguments.message);
				}
			}
			else {
				instance.exception = newJava("java.lang.Exception").init();
			}

			setType();
			// RAILO ERROR: setStackTrace(instance.exception.tagContext);
			setStackTrace(instance.exception.getStackTrace());

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getCause" output="false" hint="Returns the cause of this throwable or null if the cause is nonexistent or unknown. (The cause is the throwable that caused this throwable to get thrown.) This implementation returns the cause that was supplied via one of the constructors requiring a Throwable, or that was set after creation with the initCause(Throwable) method. While it is typically unnecessary to override this method, a subclass can override it to return a cause set by some other means. This is appropriate for a 'legacy chained throwable' that predates the addition of chained exceptions to Throwable. Note that it is not necessary to override any of the PrintStackTrace methods, all of which invoke the getCause method to determine the cause of a throwable.">

		<cfscript>
			return instance.exception.getCause();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getLocalizedMessage" output="false"
	            hint="Creates a localized description of this throwable. Subclasses may override this method in order to produce a locale-specific message. For subclasses that do not override this method, the default implementation returns the same result as getMessage().">

		<cfscript>
			return instance.exception.getLocalizedMessage();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getMessage" output="false"
	            hint="Returns the detail message string of this throwable.">

		<cfscript>
			return instance.exception.getMessage();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Array" name="getStackTrace" output="false"
	            hint="Provides programmatic access to the stack trace information printed by printStackTrace(). Returns an array of stack trace elements, each representing one stack frame. The zeroth element of the array (assuming the array's length is non-zero) represents the top of the stack, which is the last method invocation in the sequence. Typically, this is the point at which this throwable was created and thrown. The last element of the array (assuming the array's length is non-zero) represents the bottom of the stack, which is the first method invocation in the sequence. Some virtual machines may, under some circumstances, omit one or more stack frames from the stack trace. In the extreme case, a virtual machine that has no stack trace information concerning this throwable is permitted to return a zero-length array from this method. Generally speaking, the array returned by this method will contain one element for every frame that would be printed by printStackTrace.">

		<cfscript>
			//return instance.exception.getStackTrace();
			return instance.stackTrace;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getType" output="false">

		<cfscript>
			return instance.type;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="Exception" name="initCause" output="false"
	            hint="Initializes the cause of this throwable to the specified value. (The cause is the throwable that caused this throwable to get thrown.) This method can be called at most once. It is generally called from within the constructor, or immediately after creating the throwable. If this throwable was created with Throwable(Throwable) or Throwable(String,Throwable), this method cannot be called even once.">
		<cfargument required="true" name="cause" hint="the cause (which is saved for later retrieval by the getCause() method). (A null value is permitted, and indicates that the cause is nonexistent or unknown.)"/>

		<cfscript>
			return instance.exception.initCause(arguments.cause);
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="printStackTrace" output="false"
	            hint="Prints this throwable and its backtrace to the standard error stream. This method prints a stack trace for this Throwable object on the error output stream that is the value of the field System.err. The first line of output contains the result of the toString() method for this object. Remaining lines represent data previously recorded by the method fillInStackTrace().">

		<cfscript>
			return instance.exception.printStackTrace();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="setStackTrace" output="false"
	            hint="Sets the stack trace elements that will be returned by getStackTrace() and printed by printStackTrace() and related methods. This method, which is designed for use by RPC frameworks and other advanced systems, allows the client to override the default stack trace that is either generated by fillInStackTrace() when a throwable is constructed or deserialized when a throwable is read from a serialization stream.">
		<cfargument required="true" type="Array" name="stackTrace" hint="the stack trace elements to be associated with this Throwable. The specified array is copied by this call; changes in the specified array after the method invocation returns will have no affect on this Throwable's stack trace."/>

		<cfset var local = {}/>

		<cfscript>
			//instance.exception.setStackTrace(arguments.stackTrace);
			local.stackTrace = duplicate(arguments.stackTrace);

			// drop indexes that contain "cfesapi\org\owasp\esapi\errors"
			while(arrayLen(local.stackTrace)) {
				local.item = local.stackTrace[1];
				if(!findNoCase("cfesapi\org\owasp\esapi\errors", local.item.getFileName())) {
					break;
				}
				arrayDeleteAt(local.stackTrace, 1);
			}
			// 1st index should now be the actual caller object
			instance.stackTrace = local.stackTrace;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="void" name="setType" output="false">

		<cfscript>
			instance.type = getMetaData().name;
			// full path is missing when cfesapi is virtual directory
			if(listLen(instance.type, ".") EQ 1) {
				instance.type = "cfesapi.org.owasp.esapi.errors." & instance.type;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="toESAPIString" output="false"
	            hint="Returns a short description of this throwable. The result is the concatenation of: 1) the name of the class of this object, 2) ': ' (a colon and a space), 3) the result of invoking this object's getLocalizedMessage() method. If getLocalizedMessage returns null, then just the class name is returned.">

		<cfscript>
			return instance.exception.toString();
		</cfscript>

	</cffunction>

</cfcomponent>