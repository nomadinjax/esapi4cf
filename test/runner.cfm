<cfscript>
	Version = new org.owasp.esapi.ESAPI().versionData();
</cfscript>
<cfoutput><h1>#Version.getESAPI4CFName()# #Version.getESAPI4CFVersion()# [#Version.getCFMLEngine()# #Version.getCFMLVersion()#]</h1></cfoutput>
<cfsetting showdebugoutput="false">
<!--- Executes all tests in the 'test' folder with simple reporter by default --->
<cfparam name="url.reporter" 		default="simple">
<cfparam name="url.directory" 		default="esapi4cf.test.org">
<cfparam name="url.recurse" 		default="true" type="boolean">
<cfparam name="url.bundles" 		default="">
<cfparam name="url.labels" 			default="">
<cfparam name="url.reportpath" 		default="#expandPath( "/esapi4cf/test/results" )#">

<!--- Include the TestBox HTML Runner --->
<cfinclude template="/testbox/system/runners/HTMLRunner.cfm" >