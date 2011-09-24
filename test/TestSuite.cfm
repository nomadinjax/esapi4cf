<cfsetting showdebugoutput="false" requesttimeout="180" />
<cfinvoke component="mxunit.runner.DirectoryTestSuite" method="run" directory="#expandPath('.')#" componentpath="cfesapi.test" recurse="true" returnvariable="results" />
<cfoutput>
	#results.getResultsOutput('html')# 
</cfoutput>
