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
<cfinterface hint="The Authenticator interface defines a set of methods for generating and handling account credentials and session identifiers. The goal of this interface is to encourage developers to protect credentials from disclosure to the maximum extent possible. One possible implementation relies on the use of a thread local variable to store the current user's identity. The application is responsible for calling setCurrentUser() as soon as possible after each HTTP request is received. The value of getCurrentUser() is used in several other places in this API. This eliminates the need to pass a user object to methods throughout the library. For example, all of the logging, access control, and exception calls need access to the currently logged in user. The goal is to minimize the responsibility of the developer for authentication. In this example, the user simply calls authenticate with the current request and the name of the parameters containing the username and password. The implementation should verify the password if necessary, create a session if necessary, and set the user as the current user.">

	<cffunction access="public" returntype="void" name="clearCurrent" output="false" hint="Clears the current User. This allows the thread to be reused safely. This clears all threadlocal variables from the thread. This should ONLY be called after all possible ESAPI operations have concluded. If you clear too early, many calls will fail, including logging, which requires the user identity.">
	</cffunction>


	<cffunction access="public" returntype="org.owasp.esapi.User" name="login" output="false" hint="This method should be called for every HTTP request, to login the current user either from the session of HTTP request. This method will set the current user so that getCurrentUser() will work properly. Authenticates the user's credentials from the HttpServletRequest if necessary, creates a session if necessary, and sets the user as the current user. Specification:  The implementation should do the following: 1) Check if the User is already stored in the session a. If so, check that session absolute and inactivity timeout have not expired b. Step 2 may not be required if 1a has been satisfied 2) Verify User credentials a. It is recommended that you use loginWithUsernameAndPassword(HttpServletRequest, HttpServletResponse) to verify credentials 3) Set the last host of the User (ex.  user.setLastHostAddress(address) ) 4) Verify that the request is secure (ex. over SSL) 5) Verify the User account is allowed to be logged in a. Verify the User is not disabled, expired or locked 6) Assign User to session variable">
		<cfargument required="true" type="org.owasp.esapi.util.HttpServletRequest" name="httpRequest" hint="the current HTTP request">
		<cfargument required="true" type="org.owasp.esapi.util.HttpServletResponse" name="httpResponse" hint="the HTTP response">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="verifyPassword" output="false" hint="Verify that the supplied password matches the password for this user. Password should be stored as a hash. It is recommended you use the hashPassword(password, accountName) method in this class. This method is typically used for 'reauthentication' for the most sensitive functions, such as transactions, changing email address, and changing other account information.">
		<cfargument required="true" type="org.owasp.esapi.User" name="user" hint="the user who requires verification">
		<cfargument required="true" type="String" name="password" hint="the hashed user-supplied password">
	</cffunction>


	<cffunction access="public" returntype="void" name="logout" output="false" hint="Logs out the current user. This is usually done by calling User.logout on the current User.">
	</cffunction>


	<cffunction access="public" returntype="org.owasp.esapi.User" name="createUser" output="false" hint="Creates a new User with the information provided. Implementations should check accountName and password for proper format and strength against brute force attacks ( verifyAccountNameStrength(String), verifyPasswordStrength(String, String)  ). Two copies of the new password are required to encourage user interface designers to include a 're-type password' field in their forms. Implementations should verify that both are the same.">
		<cfargument required="true" type="String" name="accountName" hint="the account name of the new user">
		<cfargument required="true" type="String" name="password1" hint="the password of the new user">
		<cfargument required="true" type="String" name="password2" hint="the password of the new user.  This field is to encourage user interface designers to include two password fields in their forms.">
	</cffunction>


	<cffunction access="public" returntype="String" name="generateStrongPassword" output="false" hint="Generate strong password that takes into account the user's information and old password. Implementations should verify that the new password does not include information such as the username, fragments of the old password, and other information that could be used to weaken the strength of the password.">
		<cfargument required="false" type="org.owasp.esapi.User" name="user" hint="the user whose information to use when generating password">
		<cfargument required="false" type="String" name="oldPassword" hint="the old password to use when verifying strength of new password.  The new password may be checked for fragments of oldPassword.">
	</cffunction>


	<cffunction access="public" returntype="void" name="changePassword" output="false" hint="Changes the password for the specified user. This requires the current password, as well as the password to replace it with. The new password should be checked against old hashes to be sure the new password does not closely resemble or equal any recent passwords for that User. Password strength should also be verified.  This new password must be repeated to ensure that the user has typed it in correctly.">
		<cfargument required="true" type="org.owasp.esapi.User" name="user" hint="the user to change the password for">
		<cfargument required="true" type="String" name="currentPassword" hint="the current password for the specified user">
		<cfargument required="true" type="String" name="newPassword" hint="the new password to use">
		<cfargument required="true" type="String" name="newPassword2" hint="a verification copy of the new password">
	</cffunction>


	<cffunction access="public" name="getUserByAccountId" output="false" hint="Returns the User matching the provided accountId.  If the accoundId is not found, an Anonymous User or null may be returned.">
		<cfargument required="true" type="numeric" name="accountId" hint="the account id">
	</cffunction>


	<cffunction access="public" name="getUserByAccountName" output="false" hint="Returns the User matching the provided accountName.  If the accoundId is not found, an Anonymous User or null may be returned.">
		<cfargument required="true" type="String" name="accountName" hint="the account name">
	</cffunction>


	<cffunction access="public" returntype="Array" name="getUserNames" output="false" hint="Gets a collection containing all the existing user names.">
	</cffunction>


	<cffunction access="public" returntype="org.owasp.esapi.User" name="getCurrentUser" output="false" hint="Returns the currently logged in User.">
	</cffunction>


	<cffunction access="public" returntype="void" name="setCurrentUser" output="false" hint="Sets the currently logged in User.">
		<cfargument required="true" type="org.owasp.esapi.User" name="user">
	</cffunction>


	<cffunction access="public" returntype="String" name="hashPassword" output="false" hint="Returns a string representation of the hashed password, using the accountName as the salt. The salt helps to prevent against 'rainbow' table attacks where the attacker pre-calculates hashes for known strings. This method specifies the use of the user's account name as the 'salt' value. The Encryptor.hash method can be used if a different salt is required.">
		<cfargument required="true" type="String" name="password" hint="the password to hash">
		<cfargument required="true" type="String" name="accountName" hint="the account name to use as the salt">
	</cffunction>


	<cffunction access="public" returntype="void" name="removeUser" output="false" hint="Removes the account of the specified accountName.">
		<cfargument required="true" type="String" name="accountName" hint="the account name to remove">
	</cffunction>


	<cffunction access="public" returntype="void" name="verifyAccountNameStrength" output="false" hint="Ensures that the account name passes site-specific complexity requirements, like minimum length.">
		<cfargument required="true" type="String" name="accountName" hint="the account name">
	</cffunction>


	<cffunction access="public" returntype="void" name="verifyPasswordStrength" output="false" hint="Ensures that the password meets site-specific complexity requirements, like length or number of character sets. This method takes the old password so that the algorithm can analyze the new password to see if it is too similar to the old password. Note that this has to be invoked when the user has entered the old password, as the list of old credentials stored by ESAPI is all hashed.">
		<cfargument required="false" type="String" name="oldPassword" hint="the old password">
		<cfargument required="true" type="String" name="newPassword" hint="the new password">
	</cffunction>


	<cffunction access="public" returntype="boolean" name="exists" output="false" hint="Determine if the account exists.">
		<cfargument required="true" type="String" name="accountName" hint="the account name">
	</cffunction>

</cfinterface>
