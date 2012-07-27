<!---
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 --->
<!---
 * Reference implementation of the AccessController interface. This reference
 * implementation uses a simple model for specifying a set of access control
 * rules. Many organizations will want to create their own implementation of the
 * methods provided in the AccessController interface.
 * <P>
 * This reference implementation uses a simple scheme for specifying the rules.
 * The first step is to create a namespace for the resources being accessed. For
 * files and URL's, this is easy as they already have a namespace. Be extremely
 * careful about canonicalizing when relying on information from the user in an
 * access control decision.
 * <P>
 * For functions, data, and services, you will have to come up with your own
 * namespace for the resources being accessed. You might simply define a flat
 * namespace with a list of category names. For example, you might specify
 * 'FunctionA', 'FunctionB', and 'FunctionC'. Or you can create a richer
 * namespace with a hierarchical structure, such as:
 * <P>
 * /functions
 * <ul>
 * <li>purchasing</li>
 * <li>shipping</li>
 * <li>inventory</li>
 * </ul>
 * /admin
 * <ul>
 * <li>createUser</li>
 * <li>deleteUser</li>
 * </ul>
 * Once you've defined your namespace, you have to work out the rules that
 * govern access to the different parts of the namespace. This implementation
 * allows you to attach a simple access control list (ACL) to any part of the
 * namespace tree. The ACL lists a set of roles that are either allowed or
 * denied access to a part of the tree. You specify these rules in a textfile
 * with a simple format.
 * <P>
 * There is a single configuration file supporting each of the five methods in
 * the AccessController interface. These files are located in the ESAPI
 * resources directory as specified when the JVM was started. The use of a
 * default deny rule is STRONGLY recommended. The file format is as follows:
 *
 * <pre>
 * path          | role,role   | allow/deny | comment
 * ------------------------------------------------------------------------------------
 * /banking/*    | user,admin  | allow      | authenticated users can access /banking
 * /admin        | admin       | allow      | only admin role can access /admin
 * /             | any         | deny       | default deny rule
 * </pre>
 *
 * To find the matching rules, this implementation follows the general approach
 * used in Java EE when matching HTTP requests to servlets in web.xml. The
 * four mapping rules are used in the following order:
 * <ul>
 * <li>exact match, e.g. /access/login</li>
 * <li>longest path prefix match, beginning / and ending /*, e.g. /access/* or /*</li>
 * <li>extension match, beginning *., e.g. *.css</li>
 * <li>default rule, specified by the single character pattern /</li>
 * </ul>
 *
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 * @since June 1, 2007
 * @see org.owasp.esapi.AccessController
 --->
<cfcomponent implements="cfesapi.org.owasp.esapi.AccessController" extends="cfesapi.org.owasp.esapi.util.Object" output="false">

	<!---
	import java.io.File;
	import java.io.FileInputStream;
	import java.io.IOException;
	import java.io.InputStream;
	import java.util.ArrayList;
	import java.util.Arrays;
	import java.util.HashMap;
	import java.util.HashSet;
	import java.util.Iterator;
	import java.util.List;
	import java.util.Map;
	import java.util.Set;

	import org.owasp.esapi.ESAPI;
	import org.owasp.esapi.Logger;
	import org.owasp.esapi.User;
	import org.owasp.esapi.errors.AccessControlException;
	import org.owasp.esapi.errors.EncodingException;
	import org.owasp.esapi.errors.IntrusionException;
	--->

	<cfscript>
		instance.ESAPI = "";

		/** The url map. */
		instance.urlMap = {};

		/** The function map. */
		instance.functionMap = {};

		/** The data map. */
		instance.dataMap = {};

		/** The file map. */
		instance.fileMap = {};

		/** The service map. */
		instance.serviceMap = {};

		/** A rule containing "deny". */
		instance.deny = createObject( "component", "FileBasedAccessController$Rule" ).init();

		/** The logger. */
		instance.logger = "";
	</cfscript>

	<cffunction access="public" returntype="FileBasedAccessController" name="init" output="false">
		<cfargument required="true" type="cfesapi.org.owasp.esapi.ESAPI" name="ESAPI"/>

		<cfscript>
			instance.ESAPI = arguments.ESAPI;
			instance.logger = instance.ESAPI.getLogger( "AccessController" );

			return this;
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForURL" output="false">
		<cfargument required="true" type="String" name="url"/>

		<cfscript>
			try {
				assertAuthorizedForURL( arguments.url );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForFunction" output="false">
		<cfargument required="true" type="String" name="functionName"/>

		<cfscript>
			try {
				assertAuthorizedForFunction( arguments.functionName );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForData" output="false">
		<cfargument required="true" type="String" name="action"/>
		<cfargument name="data"/>

		<cfscript>
			try {
				assertAuthorizedForData( argumentCollection=arguments );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForFile" output="false">
		<cfargument required="true" type="String" name="filepath"/>

		<cfscript>
			try {
				assertAuthorizedForFile( arguments.filepath );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForService" output="false">
		<cfargument required="true" type="String" name="serviceName"/>

		<cfscript>
			try {
				assertAuthorizedForService( arguments.serviceName );
				return true;
			}
			catch(cfesapi.org.owasp.esapi.errors.AccessControlException e) {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForURL" output="false">
		<cfargument required="true" type="String" name="url"/>

		<cfscript>
			if(instance.urlMap.isEmpty()) {
				instance.urlMap = loadRules( "URLAccessRules.txt" );
			}
			if(!matchRuleByPath( instance.urlMap, arguments.url )) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AccessControlException" ).init( instance.ESAPI, "Not authorized for URL", "Not authorized for URL: " & arguments.url ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForFunction" output="false">
		<cfargument required="true" type="String" name="functionName"/>

		<cfscript>
			if(instance.functionMap.isEmpty()) {
				instance.functionMap = loadRules( "FunctionAccessRules.txt" );
			}
			if(!matchRuleByPath( instance.functionMap, arguments.functionName )) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AccessControlException" ).init( instance.ESAPI, "Not authorized for function", "Not authorized for function: " & arguments.functionName ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForData" output="false">
		<cfargument required="true" type="String" name="action"/>
		<cfargument name="data"/>

		<cfscript>
			if(instance.dataMap.isEmpty()) {
				instance.dataMap = loadDataRules( "DataAccessRules.txt" );
			}

			if(structKeyExists( arguments, "data" )) {
				if(!matchRuleByAction( instance.dataMap, arguments.data, arguments.action )) {
					throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AccessControlException" ).init( instance.ESAPI, "Not authorized for data", "Not authorized for data: " & arguments.data.getClass().getName() ) );
				}
			}
			else if(!matchRuleByPath( instance.dataMap, arguments.action )) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AccessControlException" ).init( instance.ESAPI, "Not authorized for function", "Not authorized for data: " & arguments.action ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForFile" output="false">
		<cfargument required="true" type="String" name="filepath"/>

		<cfscript>
			if(instance.fileMap.isEmpty()) {
				instance.fileMap = loadRules( "FileAccessRules.txt" );
			}
			if(!matchRuleByPath( instance.fileMap, arguments.filepath.replaceAll( "\\", "/" ) )) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AccessControlException" ).init( instance.ESAPI, "Not authorized for file", "Not authorized for file: " & arguments.filepath ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForService" output="false">
		<cfargument required="true" type="String" name="serviceName"/>

		<cfscript>
			if(instance.serviceMap.isEmpty()) {
				instance.serviceMap = loadRules( "ServiceAccessRules.txt" );
			}
			if(!matchRuleByPath( instance.serviceMap, arguments.serviceName )) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.AccessControlException" ).init( instance.ESAPI, "Not authorized for service", "Not authorized for service: " & arguments.serviceName ) );
			}
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="matchRuleByPath" output="false"
	            hint="Checks to see if the current user has access to the specified data, File, Object, etc. If the User has access, as specified by the map parameter, this method returns true.  If the User does not have access or an exception is thrown, false is returned.">
		<cfargument required="true" type="Struct" name="map" hint="the map containing access rules"/>
		<cfargument required="true" type="String" name="path" hint="the path of the requested File, URL, Object, etc."/>

		<cfscript>
			var local = {};

			// get users roles
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			local.roles = local.user.getRoles();
			// search for the first rule that matches the path and rules
			local.rule = searchForRuleByPath( arguments.map, local.roles, arguments.path );
			return local.rule.allow;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="matchRuleByAction" output="false"
	            hint="Checks to see if the current user has access to the specified Class and action. If the User has access, as specified by the map parameter, this method returns true. If the User does not have access or an exception is thrown, false is returned.">
		<cfargument required="true" type="Struct" name="map" hint="the map containing access rules"/>
		<cfargument required="true" name="clazz" hint="the Class being requested for access"/>
		<cfargument required="true" type="String" name="action" hint="the action the User has asked to perform"/>

		<cfscript>
			var local = {};

			// get users roles
			local.user = instance.ESAPI.authenticator().getCurrentUser();
			local.roles = local.user.getRoles();
			// search for the first rule that matches the path and rules
			local.rule = searchForRuleByAction( arguments.map, local.roles, arguments.clazz, arguments.action );
			return isObject( local.rule );
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="FileBasedAccessController$Rule" name="searchForRuleByPath" output="false"
	            hint="Search for rule. Four mapping rules are used in order: - exact match, e.g. /access/login - longest path prefix match, beginning / and ending /*, e.g. /access/* or /* - extension match, beginning *., e.g. *.css - default servlet, specified by the single character pattern /">
		<cfargument required="true" type="Struct" name="map" hint="the map containing access rules"/>
		<cfargument required="true" type="Array" name="roles" hint="the roles of the User being checked for access"/>
		<cfargument required="true" type="String" name="path" hint="the File, URL, Object, etc. being checked for access"/>

		<cfscript>
			var local = {};

			local.canonical = "";
			try {
				local.canonical = instance.ESAPI.encoder().canonicalize( arguments.path );
			}
			catch(cfesapi.org.owasp.esapi.errors.EncodingException e) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Failed to canonicalize input: " & arguments.path );
			}

			local.part = local.canonical;
			if(local.part == "") {
				local.part = "";
			}

			while(local.part.endsWith( "/" )) {
				local.part = local.part.substring( 0, local.part.length() - 1 );
			}

			if(local.part.indexOf( ".." ) != -1) {
				throwException( createObject( "component", "cfesapi.org.owasp.esapi.errors.IntrusionException" ).init( "Attempt to manipulate access control path", "Attempt to manipulate access control path: " & arguments.path ) );
			}

			// extract extension if any
			local.extension = "";
			local.extIndex = local.part.lastIndexOf( "." );
			if(local.extIndex != -1) {
				local.extension = local.part.substring( local.extIndex + 1 );
			}

			// Check for exact match - ignore any ending slash
			if(structKeyExists( arguments.map, local.part )) {
				local.rule = arguments.map.get( local.part );
			}

			// Check for ending with /*
			if(!structKeyExists( local, "rule" ))
				if(structKeyExists( arguments.map, local.part & "/*" ))
					local.rule = arguments.map.get( local.part & "/*" );

			// Check for matching extension rule *.ext
			if(!structKeyExists( local, "rule" ))
				if(structKeyExists( arguments.map, "*." & local.extension ))
					local.rule = arguments.map.get( "*." & local.extension );

			// if rule found and user's roles match rules' roles, return the rule
			if(structKeyExists( local, "rule" ) && overlapByRoles( local.rule.roles, arguments.roles )) {
				return local.rule;
			}

			// rule hasn't been found - if there are no more parts, return a deny
			local.slash = local.part.lastIndexOf( '/' );
			if(local.slash == -1) {
				return instance.deny;
			}

			// if there are more parts, strip off the last part and recurse
			local.part = local.part.substring( 0, local.part.lastIndexOf( '/' ) );

			// return default deny
			if(local.part.length() <= 1) {
				return instance.deny;
			}

			return searchForRuleByPath( arguments.map, arguments.roles, local.part );
		</cfscript>

	</cffunction>

	<cffunction access="private" name="searchForRuleByAction" output="false" hint="Search for rule. Searches the specified access map to see if any of the roles specified have access to perform the specified action on the specified Class.">
		<cfargument required="true" type="Struct" name="map" hint="the map containing access rules"/>
		<cfargument required="true" type="Array" name="roles" hint="the roles used to determine access level"/>
		<cfargument required="true" name="clazz" hint="the Class being requested for access"/>
		<cfargument required="true" type="String" name="action" hint="the action the User has asked to perform"/>

		<cfscript>
			var local = {};

			// Check for exact match - ignore any ending slash
			if(structKeyExists( arguments.map, arguments.clazz.getClass().getName() )) {
				local.rule = arguments.map.get( arguments.clazz.getClass().getName() );
			}
			if((structKeyExists( local, "rule" )) && (overlapByAction( local.rule.actions, arguments.action )) && (overlapByRoles( local.rule.roles, arguments.roles ))) {
				return local.rule;
			}
			return "";
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="overlapByRoles" output="false"
	            hint="Return true if there is overlap between the two sets.  This method merely checks to see if ruleRoles contains any of the roles listed in userRoles.">
		<cfargument required="true" type="Array" name="ruleRoles" hint="the rule roles"/>
		<cfargument required="true" type="Array" name="userRoles" hint="the user roles"/>

		<cfscript>
			var local = {};

			if(arguments.ruleRoles.contains( "any" )) {
				return true;
			}
			local.i = arguments.userRoles.iterator();
			while(local.i.hasNext()) {
				local.role = local.i.next();
				if(arguments.ruleRoles.contains( local.role )) {
					return true;
				}
			}
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="boolean" name="overlapByAction" output="false"
	            hint="This method merely checks to see if ruleActions contains the action requested.">
		<cfargument required="true" type="Array" name="ruleActions" hint="actions listed for a rule"/>
		<cfargument required="true" type="String" name="action" hint="the action requested that will be searched for in ruleActions"/>

		<cfscript>
			if(arguments.ruleActions.contains( arguments.action ))
				return true;
			return false;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="Array" name="validateRoles" output="false"
	            hint="Checks that the roles passed in contain only letters, numbers, and underscores.  Also checks that roles are no more than 10 characters long.  If a role does not pass validation, it is not included in the list of roles returned by this method.  A log warning is also generated for any invalid roles.">
		<cfargument required="true" type="Array" name="roles" hint="roles to validate according to criteria started above"/>

		<cfscript>
			var local = {};

			local.ret = [];
			for(local.x = 1; local.x <= arrayLen( arguments.roles ); local.x++) {
				local.canonical = "";
				try {
					local.canonical = instance.ESAPI.encoder().canonicalize( trim( arguments.roles[local.x] ) );
				}
				catch(cfesapi.org.owasp.esapi.errors.EncodingException e) {
					instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Failed to canonicalize role " & trim( arguments.roles[local.x] ), e );
				}
				if(!instance.ESAPI.validator().isValidInput( "Validating user roles in FileBasedAccessController", local.canonical, "^[a-zA-Z0-9_]{0,10}$", 200, false ))
					instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Role: " & trim( arguments.roles[local.x] ) & " is invalid, so was not added to the list of roles for this Rule." );
				else
					local.ret.add( local.canonical.trim() );
			}
			return local.ret;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="Struct" name="loadRules" output="false"
	            hint="Loads access rules by storing them in a hashmap.  This method begins reading the File specified by the ruleset parameter, ignoring any lines that begin with '##' characters as comments.  Sections of the access rules file are split by the pipe character ('|').  The method loads all paths, replacing '\' characters with '/' for uniformity then loads the list of comma separated roles. The roles are validated to be sure they are within a length and character set, specified in the validateRoles(String) method.  Then the permissions are stored for each item in the rules list. If the word 'allow' appears on the line, the specified roles are granted access to the data - otherwise, they will be denied access. Each path may only appear once in the access rules file.  Any entry, after the first, containing the same path will be logged and ignored.">
		<cfargument required="true" type="String" name="ruleset" hint="the name of the data that contains access rules"/>

		<cfscript>
			var local = {};

			local.map = {};
			local.is = "";
			try {
				local.is = getJava( "java.io.FileInputStream" ).init( getJava( "java.io.File" ).init( instance.ESAPI.securityConfiguration().getResourceDirectory(), arguments.ruleset ) );
				local.line = instance.ESAPI.validator().safeReadLine( local.is, 500 );
				while(local.line != -1) {
					if(local.line.length() > 0 && local.line.charAt( 0 ) != chr( 35 )) {
						local.rule = createObject( "component", "FileBasedAccessController$Rule" ).init();
						local.parts = local.line.split( "\|" );
						// fix Windows paths
						local.rule.path = local.parts[1].trim().replaceAll( "\\", "/" );

						local.roles = commaSplit( local.parts[2].trim().toLowerCase() );
						local.roles = validateRoles( local.roles );
						for(local.x = 1; local.x <= arrayLen( local.roles ); local.x++)
							local.rule.roles.add( trim(local.roles[ local.x ]) );

						local.action = local.parts[3].trim();
						local.rule.allow = local.action.equalsIgnoreCase( "allow" );
						if(local.map.containsKey( local.rule.path )) {
							instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Problem in access control file. Duplicate rule ignored: " & local.rule );
						}
						else {
							local.map.put( local.rule.path, local.rule );
						}
					}
					local.line = instance.ESAPI.validator().safeReadLine( local.is, 500 );
				}
			}
			catch(java.lang.Exception e) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Problem in access control file : " & arguments.ruleset, e );
			}
			try {
				if(isObject( local.is )) {
					local.is.close();
				}
			}
			catch(java.io.IOException e) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Failure closing access control file : " & arguments.ruleset, e );
			}

			return local.map;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="Struct" name="loadDataRules" output="false"
	            hint="Loads access rules by storing them in a hashmap.  This method begins reading the File specified by the ruleset parameter, ignoring any lines that begin with '##' characters as comments.  Sections of the access rules file are split by the pipe character ('|').  The method then loads all Classes, loads the list of comma separated roles, then the list of comma separated actions. The roles are validated to be sure they are within a length and character set, specified in the validateRoles(String) method. Each path may only appear once in the access rules file.  Any entry, after the first, containing the same path will be logged and ignored.">
		<cfargument required="true" type="String" name="ruleset" hint="the name of the data that contains access rules"/>

		<cfscript>
			var local = {};

			local.map = {};
			local.is = "";

			try {
				local.is = getJava( "java.io.FileInputStream" ).init( getJava( "java.io.File" ).init( instance.ESAPI.securityConfiguration().getResourceDirectory(), arguments.ruleset ) );
				local.line = instance.ESAPI.validator().safeReadLine( local.is, 500 );
				while(local.line != -1) {
					if(local.line.length() > 0 && local.line.charAt( 0 ) != chr( 35 )) {
						local.rule = createObject( "component", "FileBasedAccessController$Rule" ).init();
						local.parts = local.line.split( "\|" );
						local.rule.clazz = local.parts[1].trim();

						local.roles = commaSplit( local.parts[2].trim().toLowerCase() );
						local.roles = validateRoles( local.roles );
						for(local.x = 1; local.x <= arrayLen( local.roles ); local.x++)
							local.rule.roles.add( trim( local.roles[local.x] ) );

						local.action = commaSplit( local.parts[3].trim().toLowerCase() );
						for(local.x = 1; local.x <= arrayLen( local.action ); local.x++)
							local.rule.actions.add( trim( local.action[local.x] ) );

						if(local.map.containsKey( local.rule.path )) {
							instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Problem in access control file. Duplicate rule ignored: " & local.rule.toStringData() );
						}
						else {
							local.map.put( local.rule.clazz, local.rule );
						}
					}
					local.line = instance.ESAPI.validator().safeReadLine( local.is, 500 );
				}
			}
			catch(java.lang.Exception e) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Problem in access control file : " & arguments.ruleset, e );
			}

			try {
				if(isObject( local.is )) {
					local.is.close();
				}
			}
			catch(java.io.IOException e) {
				instance.logger.warning( getSecurity("SECURITY_FAILURE"), false, "Failure closing access control file : " & arguments.ruleset, e );
			}

			return local.map;
		</cfscript>

	</cffunction>

	<cffunction access="private" returntype="Array" name="commaSplit" output="false"
	            hint="This method splits a String by the ',' and returns the result as a List.">
		<cfargument required="true" type="String" name="input" hint="the String to split by ','"/>

		<cfscript>
			var local = {};

			local.array = arguments.input.split( "," );
			return local.array;
		</cfscript>

	</cffunction>

</cfcomponent>