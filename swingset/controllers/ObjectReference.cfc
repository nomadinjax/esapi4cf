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
<cfcomponent output="false">

	<cffunction access="public" returntype="void" name="lab" output="false">
		<cfargument required="true" type="Struct" name="rc"/>
	
		<cfscript>
			map = {};
			map.put("Admin", "My password is abc123.  It's really secure, but it controls EVERYTHING, so don't tell anyone - please.");
			map.put("admin", "So long, and thanks for all the fish<br />So sad that it should come to this<br />We tried to warn you all, but, oh, dear<br />You may not share out intellect<br />Which might explain your disrespect<br />For all the natural wonders that grow around you<br />So long, so long, and thanks for all the fish! The world's about to be destroyed<br />There's no point getting all annoyed<br />Lie back and let the planet dissolve around you<br />Despite those nets of tuna fleets<br />We thought that most of you were sweet<br />Especially tiny tots and your pregnant women<br />So long, so long, so long, so long, so long! So long, so long, so long, so long, so long! So long, so long, and thanks for all the fish!<br /> If I had just one last wish<br />I would like a tasty fish!<br />If we could just change one thing<br />We would all have learnt to sing!<br />Come one and all<br />Man and mammal<br />Side by side<br />In life's great gene pool!<br />So long, so long, so long, so long, so long<br />So long, so long, so long, so long<br />So long, so long and thanks for all the fish! ");
			map.put("Jeff1", "Take the blue pill... trust me!");
			map.put("Jeff2", "The Matrix has you.");
			map.put("Jeff3", "We're two wild and crazy guys!");
			map.put("Kevin1", "Tron, is that you?");
			map.put("Kevin2", "Oh man...when you're on the other side of the screen...it all looks so easy... ");
			map.put("Kevin3", "I should never have written all of those tank programs!");
			map.put("matrix", "Do you want to know what <i>it</i> is?");
			map.put("matrix1", "The Matrix is everywhere. It is all around us. Even now, in this very room. You can see it when you look out your window or when you turn on your television. You can feel it when you go to work... when you go to church... when you pay your taxes. It is the world that has been pulled over your eyes to blind you from the truth.");
			map.put("matrix2", "The Matrix is a system, Neo. That system is our enemy. But when you're inside, you look around, what do you see? Businessmen, teachers, lawyers, carpenters. The very minds of the people we are trying to save. But until we do, these people are still a part of that system and that makes them our enemy. You have to understand, most of these people are not ready to be unplugged. And many of them are so inert, so hopelessly dependent on the system, that they will fight to protect it.");
		
			session["do0"] = "Admin";
			session["do1"] = "admin";
			session["do2"] = "Jeff1";
			session["do3"] = "Jeff2";
			session["do4"] = "Jeff3";
			session["do5"] = "Kevin1";
			session["do6"] = "Kevin2";
			session["do7"] = "Kevin3";
			session["do8"] = "matrix";
			session["do9"] = "matrix1";
			session["do10"] = "matrix2";
		
			if(!structKeyExists(session, "rarm")) {
				session["rarm"] = createObject("component", "org.owasp.esapi.reference.RandomAccessReferenceMap").init(arguments.rc.ESAPI);
			}
			rarm = session["rarm"];
		
			try {
				user = "";
				if(structKeyExists(arguments.rc, "user")) {
					user = arguments.rc.user;
					user = map.get(user);
				
					arguments.rc.user = user;
				}
			}
			catch(Exception e) {
				System.out.println(e);
			}
		</cfscript>
		
	</cffunction>
	
	<cffunction access="public" returntype="void" name="solution" output="false">
		<cfargument required="true" type="Struct" name="rc"/>
	
		<cfscript>
			try {
				//if user selected an in indirect reference to display, send back the direct reference
				if(!structKeyExists(arguments.rc, "showItem")) {
				
					//create a new ReferenceMap and store all direct and indirect references
					//for display to user
					directReference0 = "Oh man...when you're on the other side of the screen...it all looks so easy... ";
					directReference1 = "Tron, is that you?";
					directReference2 = "The Matrix has you.";
					directReference3 = "Take the blue pill... trust me!";
					directReference4 = "The Matrix is everywhere. It is all around us. Even now, in this very room. You can see it when you look out your window or when you turn on your television. You can feel it when you go to work... when you go to church... when you pay your taxes. It is the world that has been pulled over your eyes to blind you from the truth.";
					directReference5 = "The Matrix is a system, Neo. That system is our enemy. But when you're inside, you look around, what do you see? Businessmen, teachers, lawyers, carpenters. The very minds of the people we are trying to save. But until we do, these people are still a part of that system and that makes them our enemy. You have to understand, most of these people are not ready to be unplugged. And many of them are so inert, so hopelessly dependent on the system, that they will fight to protect it.";
					directReference6 = "PC Load Letter? What does that mean?";
				
					rarm = createObject("component", "org.owasp.esapi.reference.RandomAccessReferenceMap").init(arguments.rc.ESAPI);
				
					ind0 = rarm.addDirectReference(directReference0);
					ind1 = rarm.addDirectReference(directReference1);
					ind2 = rarm.addDirectReference(directReference2);
					ind3 = rarm.addDirectReference(directReference3);
					ind4 = rarm.addDirectReference(directReference4);
					ind5 = rarm.addDirectReference(directReference5);
					ind6 = rarm.addDirectReference(directReference6);
				
					session[ind0] = directReference0;
					session[ind1] = directReference1;
					session[ind2] = directReference2;
					session[ind3] = directReference3;
					session[ind4] = directReference4;
					session[ind5] = directReference5;
					session[ind6] = directReference6;
				
					session["ind0"] = ind0;
					session["ind1"] = ind1;
					session["ind2"] = ind2;
					session["ind3"] = ind3;
					session["ind4"] = ind4;
					session["ind5"] = ind5;
					session["ind6"] = ind6;
				}
			}
			catch(Exception e) {
				System.out.println(e);
				System.out.println("hi");
				e.printStackTrace();
			}
		</cfscript>
		
	</cffunction>
	
</cfcomponent>