<!---
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
--->
<cfcomponent implements="org.owasp.esapi.AccessReferenceMap" extends="org.owasp.esapi.util.Object" output="false" hint="Reference implementation of the AccessReferenceMap interface. This implementation generates random 6 character alphanumeric strings for indirect references. It is possible to use simple integers as indirect references, but the random string approach provides a certain level of protection from CSRF attacks, because an attacker would have difficulty guessing the indirect reference.">

	<cfscript>
		variables.ESAPI = "";

		/** The itod (indirect to direct) */
		variables.itod = {};

		/** The dtoi (direct to indirect) */
		variables.dtoi = {};

		/** The random. */
		variables.random = "";
	</cfscript>

	<cffunction access="public" returntype="org.owasp.esapi.AccessReferenceMap" name="init" output="false"
	            hint="This AccessReferenceMap implementation uses short random strings to create a layer of indirection. Other possible implementations would use simple integers as indirect references.">
		<cfargument required="true" type="org.owasp.esapi.ESAPI" name="ESAPI"/>
		<cfargument type="Array" name="directReferences" hint="Instantiates a new access reference map with a set of direct references."/>

		<cfscript>
			variables.ESAPI = arguments.ESAPI;
			variables.random = variables.ESAPI.randomizer();

			if(structKeyExists(arguments, "directReferences")) {
				this.update(arguments.directReferences);
			}

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" name="iterator" output="false">

		<cfscript>
			var sorted = createObject("java", "java.util.TreeSet").init(variables.dtoi.keySet());
			return sorted.iterator();
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="addDirectReference" output="false">
		<cfargument required="true" name="direct"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var indirect = "";

			if(structKeyExists(variables.dtoi, arguments.direct)) {
				return variables.dtoi[arguments.direct];
			}
			indirect = getUniqueRandomReference();
			variables.itod[indirect] = arguments.direct;
			variables.dtoi[arguments.direct] = indirect;
			return indirect;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="String" name="getUniqueRandomReference" output="false"
	            hint="Create a new random reference that is guaranteed to be unique.">

		<cfscript>
			var candidate = "";
			do {
				candidate = variables.random.getRandomString(6, createObject("java", "org.owasp.esapi.reference.DefaultEncoder").CHAR_ALPHANUMERICS);
			}while(structKeyExists(variables.itod, candidate));
			return candidate;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="removeDirectReference" output="false">
		<cfargument required="true" name="direct"/>

		<cfscript>
			var indirect = "";
			if(structKeyExists(variables.dtoi, arguments.direct)) {
				indirect = variables.dtoi[arguments.direct];
			}
			if(isDefined("indirect") && !isNull(indirect)) {
				variables.itod.remove(indirect);
				variables.dtoi.remove(arguments.direct);
				return indirect;
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="update" output="false">
		<cfargument required="true" type="Array" name="directReferences"/>

		<cfscript>
			// CF8 requires 'var' at the top
			var i = "";
			var direct = "";
			var indirect = "";

			var dtoi_old = duplicate(variables.dtoi);
			variables.dtoi.clear();
			variables.itod.clear();

			i = arguments.directReferences.iterator();
			while(i.hasNext()) {
				direct = i.next();
				indirect = "";

				if(structKeyExists(dtoi_old, direct)) {
					// get the old indirect reference
					indirect = dtoi_old[direct];
				}

				// if the old reference is null, then create a new one that doesn't
				// collide with any existing indirect references
				if(!len(indirect)) {
					indirect = getUniqueRandomReference();
				}

				variables.itod[indirect] = direct;
				variables.dtoi[direct] = indirect;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="String" name="getIndirectReference" output="false">
		<cfargument required="true" name="directReference"/>

		<cfscript>
			if(variables.dtoi.containsKey(arguments.directReference)) {
				return variables.dtoi.get(arguments.directReference);
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="public" name="getDirectReference" output="false">
		<cfargument required="true" type="String" name="indirectReference"/>

		<cfscript>
			if(variables.itod.containsKey(arguments.indirectReference)) {
				return variables.itod.get(arguments.indirectReference);
			}
			throwException(createObject("component", "org.owasp.esapi.errors.AccessControlException").init(variables.ESAPI, "Access denied", "Request for invalid indirect reference: " & arguments.indirectReference));
		</cfscript>

	</cffunction>

</cfcomponent>