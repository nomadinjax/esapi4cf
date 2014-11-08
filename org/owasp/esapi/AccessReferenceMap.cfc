<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfinterface hint="The AccessReferenceMap interface is used to map from a set of internal direct object references to a set of indirect references that are safe to disclose publicly. This can be used to help protect database keys, filenames, and other types of direct object references. As a rule, developers should not expose their direct object references as it enables attackers to attempt to manipulate them. Indirect references are handled as strings, to facilitate their use in HTML. Implementations can generate simple integers or more complicated random character strings as indirect references. Implementations should probably add a constructor that takes a list of direct references. Note that in addition to defeating all forms of parameter tampering attacks, there is a side benefit of the AccessReferenceMap. Using random strings as indirect object references, as opposed to simple integers makes it impossible for an attacker to guess valid identifiers. So if per-user AccessReferenceMaps are used, then request forgery (CSRF) attacks will also be prevented.">

	<cffunction access="public" name="iterator" output="false" hint="Get an iterator through the direct object references. No guarantee is made as to the order of items returned.">
	</cffunction>

	<cffunction access="public" returntype="String" name="getIndirectReference" output="false"
	            hint="Get a safe indirect reference to use in place of a potentially sensitive direct object reference. Developers should use this call when building URL's, form fields, hidden fields, etc... to help protect their private implementation information.">
		<cfargument required="true" name="directReference" hint="the direct reference"/>

	</cffunction>

	<cffunction access="public" name="getDirectReference" output="false" hint="Get the original direct object reference from an indirect reference. Developers should use this when they get an indirect reference from a request to translate it back into the real direct reference. If an invalid indirect reference is requested, then an AccessControlException is thrown.">
		<cfargument required="true" type="String" name="indirectReference" hint="the indirect reference"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="addDirectReference" output="false"
	            hint="Adds a direct reference to the AccessReferenceMap, then generates and returns an associated indirect reference.">
		<cfargument required="true" name="direct" hint="the direct reference"/>

	</cffunction>

	<cffunction access="public" returntype="String" name="removeDirectReference" output="false"
	            hint="Removes a direct reference and its associated indirect reference from the AccessReferenceMap.">
		<cfargument required="true" name="direct" hint="the direct reference to remove"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="update" output="false"
	            hint="Updates the access reference map with a new set of direct references, maintaining any existing indirect references associated with items that are in the new list. New indirect references could be generated every time, but that might mess up anything that previously used an indirect reference, such as a URL parameter.">
		<cfargument required="true" type="Array" name="directReferences" hint="a Set of direct references to add"/>

	</cffunction>

</cfinterface>