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
<cfinterface hint="This interface represents the abstract notion of a principal, which can be used to represent any entity, such as an individual, a corporation, and a login id.">

	<cffunction access="public" returntype="boolean" name="equalsESAPI" output="false"
	            hint="Compares this principal to the specified object. Returns true if the object passed in matches the principal represented by the implementation of this interface.">
		<cfargument required="true" name="another" hint="principal to compare with."/>
	
	</cffunction>
	
	<cffunction access="public" returntype="String" name="toStringESAPI" output="false"
	            hint="Returns a string representation of this principal."/>

	<cffunction access="public" returntype="numeric" name="hashCodeESAPI" output="false"
	            hint="Returns a hashcode for this principal."/>

	<cffunction access="public" returntype="String" name="getName" output="false"
	            hint="Returns the name of this principal."/>

</cfinterface>