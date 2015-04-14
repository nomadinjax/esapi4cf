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
import "org.owasp.esapi.util.Utils";

component {

	public boolean function isEquals(required another) {
		return new Utils().isEquals(this, arguments.another);
	}

	private void function raiseException(required exception) {
		if (isInstanceOf(arguments.exception, "java.lang.Throwable")) {
			throw(object=arguments.exception);
		}
		else if (isInstanceOf(arguments.exception, "org.owasp.esapi.errors.EnterpriseSecurityException")) {
			if (isNull(arguments.exception.getCause())) {
				throw(type=arguments.exception.getType(), message=arguments.exception.getUserMessage(), detail=arguments.exception.getLogMessage());
			}
			throw(type=arguments.exception.getType(), message=arguments.exception.getUserMessage(), detail=arguments.exception.getLogMessage(), extendedInfo=serializeJSON(parseException(arguments.exception.getCause())));
		}
		else if (isInstanceOf(arguments.exception, "org.owasp.esapi.util.Exception")) {
			if (isNull(arguments.exception.getCause())) {
				throw(type=arguments.exception.getType(), message=arguments.exception.getMessage());
			}
			throw(type=arguments.exception.getType(), message=arguments.exception.getMessage(), extendedInfo=serializeJSON(parseException(arguments.exception.getCause())));
		}
		else if (isStruct(arguments.exception)) {
			throw(type=arguments.exception.type, message=arguments.exception.message, detail=arguments.exception.detail);
		}
	}

	private struct function parseException(required exception) {
		return {
			"type": arguments.exception.type,
			"message": arguments.exception.message,
			"detail": arguments.exception.detail
		};
	}

}