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
 * @author Damon Miller
 * @created 2011
 --->
<!---
 * The AccessController interface defines a set of methods that can be used in a wide variety of applications to
 * enforce access control. In most applications, access control must be performed in multiple different locations across
 * the various application layers. This class provides access control for URLs, business functions, data, services, and
 * files.
 * <P>
 * <img src="doc-files/AccessController.jpg">
 * <P>
 * The implementation of this interface will need to access the current User object (from Authenticator.getCurrentUser())
 * to determine roles or permissions. In addition, the implementation
 * will also need information about the resources that are being accessed. Using the user information and the resource
 * information, the implementation should return an access control decision.
 * <P>
 * Implementers are encouraged to implement the ESAPI access control methods, like assertAuthorizedForFunction() using
 * existing access control mechanisms, such as methods like isUserInRole() or hasPrivilege(). While powerful,
 * methods like isUserInRole() can be confusing for developers, as users may be in multiple roles or possess multiple
 * overlapping privileges. Direct use of these finer grained access control methods encourages the use of complex boolean
 * tests throughout the code, which can easily lead to developer mistakes.
 * <P>
 * The point of the ESAPI access control interface is to centralize access control logic behind easy to use calls like
 * assertAuthorizedForData() so that access control is easy to use and easy to verify. Here is an example of a very
 * straightforward to implement, understand, and verify ESAPI access control check:
 *
 * <pre>
 * try {
 *     ESAPI.accessController().assertAuthorizedForFunction( BUSINESS_FUNCTION );
 *     // execute BUSINESS_FUNCTION
 * } catch (AccessControlException ace) {
 * ... attack in progress
 * }
 * </pre>
 *
 * Note that in the user interface layer, access control checks can be used to control whether particular controls are
 * rendered or not. These checks are supposed to fail when an unauthorized user is logged in, and do not represent
 * attacks. Remember that regardless of how the user interface appears, an attacker can attempt to invoke any business
 * function or access any data in your application. Therefore, access control checks in the user interface should be
 * repeated in both the business logic and data layers.
 *
 * <pre>
 * &lt;% if ( ESAPI.accessController().isAuthorizedForFunction( ADMIN_FUNCTION ) ) { %&gt;
 * &lt;a href=&quot;/doAdminFunction&quot;&gt;ADMIN&lt;/a&gt;
 * &lt;% } else { %&gt;
 * &lt;a href=&quot;/doNormalFunction&quot;&gt;NORMAL&lt;/a&gt;
 * &lt;% } %&gt;
 * </pre>
 *
 * @author Damon Miller
 --->
<cfinterface>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForURL" output="false"
	            hint="Checks if an account is authorized to access the referenced URL. Generally, this method should be invoked in the application's controller or a filter as follows: ESAPI.accessController().isAuthorizedForURL(request.getRequestURI().toString()); The implementation of this method should call assertAuthorizedForURL(String url), and if an AccessControlException is not thrown, this method should return true. This way, if the user is not authorized, false would be returned, and the exception would be logged.">
		<cfargument required="true" type="String" name="url" hint="the URL as returned by request.getRequestURI().toString()"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForFunction" output="false"
	            hint="Checks if an account is authorized to access the referenced function. The implementation of this method should call assertAuthorizedForFunction(String functionName), and if an AccessControlException is not thrown, this method should return true.">
		<cfargument required="true" type="String" name="functionName" hint="the name of the function"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForData" output="false"
	            hint="Checks if an account is authorized to access the referenced data, represented as an Object. The implementation of this method should call assertAuthorizedForData(String action, Object data), and if an AccessControlException is not thrown, this method should return true.">
		<cfargument required="true" type="String" name="action" hint="the action to check for in the configuration file in the resource directory"/>
		<cfargument name="data" hint="the data to check for in the configuration file in the resource directory"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForFile" output="false"
	            hint="Checks if an account is authorized to access the referenced file. The implementation of this method should call assertAuthorizedForFile(String filepath), and if an AccessControlException is not thrown, this method should return true.">
		<cfargument required="true" type="String" name="filepath" hint="the path of the file to be checked, including filename"/>

	</cffunction>

	<cffunction access="public" returntype="boolean" name="isAuthorizedForService" output="false"
	            hint="Checks if an account is authorized to access the referenced service. This can be used in applications that provide access to a variety of back end services. The implementation of this method should call assertAuthorizedForService(String serviceName), and if an AccessControlException is not thrown, this method should return true.">
		<cfargument required="true" type="String" name="serviceName" hint="the service name"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForURL" output="false"
	            hint="Checks if an account is authorized to access the referenced URL. The implementation should allow access to be granted to any part of the URL. Generally, this method should be invoked in the application's controller or a filter as follows: ESAPI.accessController().assertAuthorizedForURL(request.getRequestURI().toString()); This method throws an AccessControlException if access is not authorized, or if the referenced URL does not exist. If the User is authorized, this method simply returns. Specification:  The implementation should do the following: 1) Check to see if the resource exists and if not, throw an AccessControlException. 2) Use available information to make an access control decision. 2a) Ideally, this policy would be data driven. 2b) You can use the current User, roles, data type, data name, time of day, etc. 2c) Access control decisions must deny by default. 3) If access is not permitted, throw an AccessControlException with details.">
		<cfargument required="true" type="String" name="url" hint="the URL as returned by request.getRequestURI().toString()"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForFunction" output="false"
	            hint="Checks if an account is authorized to access the referenced function. The implementation should define the function 'namespace' to be enforced. Choosing something simple like the class name of action classes or menu item names will make this implementation easier to use. This method throws an AccessControlException if access is not authorized, or if the referenced function does not exist. If the User is authorized, this method simply returns. Specification:  The implementation should do the following: 1) Check to see if the function exists and if not, throw an AccessControlException. 2) Use available information to make an access control decision. 2a) Ideally, this policy would be data driven. 2b) You can use the current User, roles, data type, data name, time of day, etc. 2c) Access control decisions must deny by default. 3) If access is not permitted, throw an AccessControlException with details.">
		<cfargument required="true" type="String" name="functionName" hint="the function name"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForData" output="false"
	            hint="Checks if the current user is authorized to access the referenced data.  This method simply returns if access is authorized. It throws an AccessControlException if access is not authorized, or if the referenced data does not exist. Specification:  The implementation should do the following: 1) Check to see if the resource exists and if not, throw an AccessControlException 2) Use available information to make an access control decision. 2a) Ideally, this policy would be data driven. 2b) You can use the current User, roles, data type, data name, time of day, etc. 2c) Access control decisions must deny by default. 3) If access is not permitted, throw an AccessControlException with details.">
		<cfargument required="true" type="String" name="action" hint="the action to check for in the configuration file in the resource directory"/>
		<cfargument name="data" hint="the data to check for in the configuration file in the resource directory"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForFile" output="false"
	            hint="Checks if an account is authorized to access the referenced file. The implementation should validate and canonicalize the input to be sure the filepath is not malicious. This method throws an AccessControlException if access is not authorized, or if the referenced File does not exist. If the User is authorized, this method simply returns. Specification:  The implementation should do the following: 1) Check to see if the File exists and if not, throw an AccessControlException. 2) Use available information to make an access control decision. 2a) Ideally, this policy would be data driven. 2b) You can use the current User, roles, data type, data name, time of day, etc. 2c) Access control decisions must deny by default. 3) If access is not permitted, throw an AccessControlException with details.">
		<cfargument required="true" type="String" name="filepath" hint="Path to the file to be checked"/>

	</cffunction>

	<cffunction access="public" returntype="void" name="assertAuthorizedForService" output="false"
	            hint="Checks if an account is authorized to access the referenced service. This can be used in applications that provide access to a variety of backend services. This method throws an AccessControlException if access is not authorized, or if the referenced service does not exist. If the User is authorized, this method simply returns. Specification:  The implementation should do the following: 1) Check to see if the service exists and if not, throw an AccessControlException. 2) Use available information to make an access control decision. 2a) Ideally, this policy would be data driven. 2b) You can use the current User, roles, data type, data name, time of day, etc. 2c) Access control decisions must deny by default. 3) If access is not permitted, throw an AccessControlException with details.">
		<cfargument required="true" type="String" name="serviceName" hint="the service name"/>

	</cffunction>

</cfinterface>