<cfcomponent output="false" hint="Models a simple threshold as a count and an interval, along with a set of actions to take if the threshold is exceeded. These thresholds are used to define when the accumulation of a particular event has met a set number within the specified time period. Once a threshold value has been met, various actions can be taken at that point.">

	<cfscript>
		/* The name of this threshold. */
		this.name = "";

		/* The count at which this threshold is triggered. */
		this.count = 0;

		/*
		 * The time frame within which 'count' number of actions has to be detected in order to
		 * trigger this threshold.
		 */
		this.interval = 0;

		/*
		 * The list of actions to take if the threshold is met. It is expected that this is a list of Strings, but
		 * your implementation could have this be a list of any type of 'actions' you wish to define.
		 */
		this.actions = [];
	</cfscript>

	<cffunction access="public" returntype="Threshold" name="init" output="false" hint="Constructs a threshold that is composed of its name, its threshold count, the time window for the threshold, and the actions to take if the threshold is triggered.">
		<cfargument type="String" name="name" required="true" hint="The name of this threshold.">
		<cfargument type="numeric" name="count" required="true" hint="The count at which this threshold is triggered.">
		<cfargument type="numeric" name="interval" required="true" hint="The time frame within which 'count' number of actions has to be detected in order to trigger this threshold.">
		<cfargument type="Array" name="actions" required="true" hint="The list of actions to take if the threshold is met.">
		<cfscript>
			this.name = arguments.name;
			this.count = arguments.count;
			this.interval = arguments.interval;
			this.actions = arguments.actions;

			return this;
		</cfscript>
	</cffunction>


</cfcomponent>
