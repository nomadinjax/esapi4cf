/*
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
component {

	public boolean function isEquals(required object, required another) {
		var System = createObject("java", "java.lang.System");
		var objHash1 = System.identityHashCode(arguments.object);
		var objHash2 = System.identityHashCode(arguments.another);
		if (objHash1 == objHash2) return true;
		return false;
	}

	public string function toUnicode(required string input) {
		var sb = createObject("java", "java.lang.StringBuffer").init();
		var l = len(arguments.input);
		for(var i=1; i<=l; i++) {
			var thisChr = mid(arguments.input, i, 6);
			if(left(thisChr, 2) == "\u") {
				sb.append(chr(inputBaseN(right(thisChr, 4), 16)));
				i = i + 5;
			}
			else {
				sb.append(left(thisChr, 1));
			}
		}
		return sb.toString();
	}

	/**
	 * Return an empty byte array with specified length
	 */
	public binary function newByte(required numeric len) {
		var sb = createObject("java", "java.lang.StringBuilder").init();
		sb.setLength(arguments.len);
		return sb.toString().getBytes();
	}

	/**
	 * Creates a MessageFormat with the given pattern and uses it to format the given arguments.
	 */
	public string function messageFormat(required string pattern, required array args) {
		return createObject("java", "java.text.MessageFormat").format(javaCast("string", arguments.pattern), arguments.args);
	}

	public array function parseStackTrace(required stackTrace=createObject("java", "java.lang.Throwable").getStackTrace()) {
		var result = [];

		for (var thisStack in arguments.stackTrace) {
			if (listFindNoCase("runPage,runFunction", propertyValue(thisStack, "MethodName"))) {
				var data = {};
				data["Template"] = propertyValue(thisStack, "FileName");
				if (propertyValue(thisStack, "MethodName") == "runFunction") {
					data["Function"] = reReplace(propertyValue(thisStack, "ClassName"), "^.+\$func", "");
				}
				else {
					data["Function"] = "";
				}
				data["LineNumber"] = propertyValue(thisStack, "LineNumber");
				arrayAppend(result, duplicate(data));
			}
		}
		return result;
	}

	private function propertyValue(required properties, required string propertyName) {
		if (isStruct(arguments.properties)) {
			if (structKeyExists(arguments.properties, "get" & arguments.propertName)) {
				var fn = arguments.properties["get" & arguments.propertName];
				return fn();
			}
			else if (structKeyExists(arguments.properties, arguments.propertName)) {
				return arguments.properties[arguments.propertName];
			}
		}
		return "";
	}

}