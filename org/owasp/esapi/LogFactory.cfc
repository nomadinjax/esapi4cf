<cfinterface hint="The LogFactory interface is intended to allow substitution of various logging packages, while providing a common interface to access them. In the reference implementation, JavaLogFactory.java implements this interface.  JavaLogFactory.java also contains an inner class called JavaLogger which implements Logger.java and uses the Java logging package to log events. ">

	<cffunction access="public" returntype="cfesapi.org.owasp.esapi.Logger" name="getLogger" output="false" hint="Gets the logger associated with the specified module name. The module name is used by the logger to log which module is generating the log events. The implementation of this method should return any preexisting Logger associated with this module name, rather than creating a new Logger. The JavaLogFactory reference implementation meets these requirements.">
		<cfargument type="String" name="moduleName" required="true" hint="The name of the module requesting the logger.">
	</cffunction>

</cfinterface>
