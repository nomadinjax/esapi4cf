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
import "org.owasp.esapi.errors.EncodingException";
import "org.owasp.esapi.errors.IntrusionException";

/**
 * Reference implementation of the Encoder interface. This implementation takes
 * a whitelist approach to encoding, meaning that everything not specifically identified in a
 * list of "immune" characters is encoded.
 */
component implements="org.owasp.esapi.Encoder" extends="org.owasp.esapi.util.Object" {

	variables.ESAPI = "";
	variables.logger = "";

	variables.isJavaEncoderAvailable = false;
	variables.isJavaEncoderPreferred = false;
	variables.JavaEncoder = "";
	variables.ESAPIEncoder = "";

	variables.ESAPIEncoderConstants = createObject("java", "org.owasp.esapi.EncoderConstants");

	/**
	 * Standard character sets
	 */
	this.CHAR_LOWERS = ESAPIEncoderConstants.CHAR_LOWERS;
	this.CHAR_UPPERS = ESAPIEncoderConstants.CHAR_UPPERS;
	this.CHAR_DIGITS = ESAPIEncoderConstants.CHAR_DIGITS;
	this.CHAR_SPECIALS = ESAPIEncoderConstants.CHAR_SPECIALS;
	this.CHAR_LETTERS = ESAPIEncoderConstants.CHAR_LETTERS;
	this.CHAR_ALPHANUMERICS = ESAPIEncoderConstants.CHAR_ALPHANUMERICS;

	/**
	 * Password character set, is alphanumerics (without l, i, I, o, O, and 0)
	 * selected specials like + (bad for URL encoding, | is like i and 1,
	 * etc...)
	 */
	this.CHAR_PASSWORD_LOWERS = ESAPIEncoderConstants.CHAR_PASSWORD_LOWERS;
	this.CHAR_PASSWORD_UPPERS = ESAPIEncoderConstants.CHAR_PASSWORD_UPPERS;
	this.CHAR_PASSWORD_DIGITS = ESAPIEncoderConstants.CHAR_PASSWORD_DIGITS;
	this.CHAR_PASSWORD_SPECIALS = ESAPIEncoderConstants.CHAR_PASSWORD_SPECIALS;
	this.CHAR_PASSWORD_LETTERS = ESAPIEncoderConstants.CHAR_PASSWORD_LETTERS;

	/**
	 * Instantiates a new Encoder
	 */
	public org.owasp.esapi.Encoder function init(required org.owasp.esapi.ESAPI ESAPI, array codecNames) {
		variables.ESAPI = arguments.ESAPI;
		variables.logger = variables.ESAPI.getLogger("Encoder");

		if (isNull(arguments.codecNames)) {
			variables.ESAPIEncoder = createObject("java", "org.owasp.esapi.ESAPI").encoder();
		}
		else {
			variables.ESAPIEncoder = createObject("java", "org.owasp.esapi.reference.DefaultEncoder").init(arguments.codecNames);
		}

		// see if JavaEncoder is available
		try {
			variables.JavaEncoder = createObject("java", "org.owasp.encoder.Encode");
			variables.isJavaEncoderAvailable = true;
		}
		catch (any e) {}

		// set JavaEncoder to preferred if so desired and it was available
		if (variables.ESAPI.securityConfiguration().isJavaEncoderPreferred() && variables.isJavaEncoderAvailable) {
			variables.isJavaEncoderPreferred = true;
		}

		return this;
	}

	public string function canonicalize(required string input, boolean restrictMultiple=true, boolean restrictMixed=arguments.restrictMultiple) {
		if (isNull(arguments.input)) return "";

		try {
			return variables.ESAPIEncoder.canonicalize(javaCast("string", arguments.input), javaCast("boolean", arguments.restrictMultiple), javaCast("boolean", arguments.restrictMixed));
		}
		catch (org.owasp.esapi.errors.IntrusionException e) {
			raiseException(new IntrusionException(variables.ESAPI, e.userMessage, e.logMessage));
		}
	}

	public string function encodeForHTML(required string input) {
		if (isNull(arguments.input)) return "";
		if (variables.isJavaEncoderPreferred) return forHtml(arguments.input);
		else return variables.ESAPIEncoder.encodeForHTML(javaCast("string", arguments.input));
	}

	public string function decodeForHTML(required string input) {
		if (isNull(arguments.input)) return "";
		return variables.ESAPIEncoder.decodeForHTML(javaCast("string", arguments.input));
	}

	public string function encodeForHTMLAttribute(required string input) {
		if (isNull(arguments.input)) return "";
		if (variables.isJavaEncoderPreferred) return forHtmlAttribute(arguments.input);
		else return variables.ESAPIEncoder.encodeForHTMLAttribute(javaCast("string", arguments.input));
	}

	public string function encodeForCSS(required string input) {
		if (isNull(arguments.input)) return "";
		if (variables.isJavaEncoderPreferred) return forCssString(arguments.input);
		else return variables.ESAPIEncoder.encodeForCSS(javaCast("string", arguments.input));
	}

	public string function encodeForJavaScript(required string input) {
		if (isNull(arguments.input)) return "";
		if (variables.isJavaEncoderPreferred) return forJavaScript(arguments.input);
		else return variables.ESAPIEncoder.encodeForJavaScript(javaCast("string", arguments.input));
	}

	public string function encodeForVBScript(required string input) {
		if (isNull(arguments.input)) return "";
		return variables.ESAPIEncoder.encodeForVBScript(javaCast("string", arguments.input));
    }

	public string function encodeForSQL(required codec, required string input) {
		if (isNull(arguments.input)) return "";
		return variables.ESAPIEncoder.encodeForSQL(arguments.codec, javaCast("string", arguments.input));
    }

	public string function encodeForOS(required codec, required string input) {
		if (isNull(arguments.input)) return "";
		return variables.ESAPIEncoder.encodeForOS(arguments.codec, javaCast("string", arguments.input));
    }

	public string function encodeForLDAP(required string input) {
		if (isNull(arguments.input)) return "";
		return variables.ESAPIEncoder.encodeForLDAP(javaCast("string", arguments.input));
    }

	public string function encodeForDN(required string input) {
		if (isNull(arguments.input)) return "";
		return variables.ESAPIEncoder.encodeForDN(javaCast("string", arguments.input));
    }

	public string function encodeForXPath(required string input) {
		if (isNull(arguments.input)) return "";
		return variables.ESAPIEncoder.encodeForXPath(javaCast("string", arguments.input));
    }

	public string function encodeForXML(required string input) {
		if (isNull(arguments.input)) return "";
		if (variables.isJavaEncoderPreferred) return forXml(arguments.input);
		else return variables.ESAPIEncoder.encodeForXML(javaCast("string", arguments.input));
	}

	public string function encodeForXMLAttribute(required string input) {
		if (isNull(arguments.input)) return "";
		if (variables.isJavaEncoderPreferred) return forXmlAttribute(arguments.input);
		else return variables.ESAPIEncoder.encodeForXMLAttribute(javaCast("string", arguments.input));
	}

	public string function encodeForURL(required string input) {
		if (isNull(arguments.input)) return "";
		if (variables.isJavaEncoderPreferred) return forUriComponent(arguments.input);
		else return variables.ESAPIEncoder.encodeForURL(javaCast("string", arguments.input));
	}

    public string function decodeFromURL(required string input) {
		if (isNull(arguments.input)) return "";
		return variables.ESAPIEncoder.decodeFromURL(javaCast("string", arguments.input));
	}

	public string function encodeForBase64(required binary input, required boolean wrap) {
		if (isNull(arguments.input)) return "";
		return variables.ESAPIEncoder.encodeForBase64(arguments.input, javaCast("boolean", arguments.wrap));
	}

	public binary function decodeFromBase64(required string input) {
		if (isNull(arguments.input)) return "";
		return variables.ESAPIEncoder.decodeFromBase64(javaCast("string", arguments.input));
	}

	// Java Encoders

	/**
	 * Encodes data for an XML CDATA section. On the chance that the input contains a terminating ""]]>"", it will be replaced by ""]]>]]<![CDATA[>"". As with all XML contexts, characters that are invalid according to the XML specification will be replaced by a space character. Caller must provide the CDATA section boundaries.
	 *
	 * @param input the input to encode
	 */
	public string function forCDATA(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forCDATA(javaCast("string", arguments.input));
	}

	/**
	 * Encodes for CSS strings. The context must be surrounded by quotation characters. It is safe for use in both style blocks and attributes in HTML.
	 *
	 * @param input the input to encode
	 */
	public string function forCssString(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forCssString(javaCast("string", arguments.input));
	}

	/**
	 * Encodes for CSS URL contexts. The context must be surrounded by ""url("" and "")"". It is safe for use in both style blocks and attributes in HTML. Note: this does not do any checking on the quality or safety of the URL itself. The caller should insure that the URL is safe for embedding (e.g. input validation) by other means.
	 *
	 * @param input the input to encode
	 */
	public string function forCssUrl(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forCssUrl(javaCast("string", arguments.input));
	}

	/**
	 * Encodes for (X)HTML text content and text attributes. Since this method encodes for both contexts, it may be slightly less efficient to use this method over the methods targeted towards the specific contexts (forHtmlAttribute(String) and forHtmlContent(String). In general this method should be preferred unless you are really concerned with saving a few bytes or are writing a framework that utilizes this package.
	 *
	 * @param input the input to encode
	 */
	public string function forHtml(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forHtml(javaCast("string", arguments.input));
	}

	/**
	 * This method encodes for HTML text attributes.
	 *
	 * @param input the input to encode
	 */
	public string function forHtmlAttribute(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forHtmlAttribute(javaCast("string", arguments.input));
	}

	/**
	 * This method encodes for HTML text content. It does not escape quotation characters and is thus unsafe for use with HTML attributes. Use either forHtml or forHtmlAttribute for those methods.
	 *
	 * @param input the input to encode
	 */
	public string function forHtmlContent(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forHtmlContent(javaCast("string", arguments.input));
	}

	/**
	 * Encodes for unquoted HTML attribute values. forHtml(String) or forHtmlAttribute(String) should usually be preferred over this method as quoted attributes are XHTML compliant. When using this method, the caller is not required to provide quotes around the attribute (since it is encoded for such context). The caller should make sure that the attribute value does not abut unsafe characters--and thus should usually err on the side of including a space character after the value. Use of this method is discouraged as quoted attributes are generally more compatible and safer. Also note, that no attempt has been made to optimize this encoding, though it is still probably faster than other encoding libraries.
	 *
	 * @param input the input to encode
	 */
	public string function forHtmlUnquotedAttribute(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forHtmlUnquotedAttribute(javaCast("string", arguments.input));
	}

	/**
	 * Encodes for a Java string. This method will use ""\b"", ""\t"", ""\r"", ""\f"", ""\n"", ""\"""", ""\'"", ""\\"", octal and unicode escapes. Valid surrogate pairing is not checked. The caller must provide the enclosing quotation characters. This method is useful for when writing code generators and outputting debug messages.
	 *
	 * @param input the input to encode
	 */
	public string function forJava(requirerd string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forJava(javaCast("string", arguments.input));
	}

	/**
	 * Encodes for a JavaScript string. It is safe for use in HTML script attributes (such as onclick), script blocks, JSON files, and JavaScript source. The caller MUST provide the surrounding quotation characters for the string. Since this performs additional encoding so it can work in all of the JavaScript contexts listed, it may be slightly less efficient then using one of the methods targetted to a specific JavaScript context (forJavaScriptAttribute(String), forJavaScriptBlock(java.lang.String), forJavaScriptSource(java.lang.String)). Unless you are interested in saving a few bytes of output or are writing a framework on top of this library, it is recommend that you use this method over the others.
	 *
	 * @param input the input to encode
	 */
	public string function forJavaScript(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forJavaScript(javaCast("string", arguments.input));
	}

	/**
	 * This method encodes for JavaScript strings contained within HTML script attributes (such as onclick). It is NOT safe for use in script blocks. The caller MUST provide the surrounding quotation characters. This method performs the same encode as forJavaScript(String) with the exception that / is not escaped. Unless you are interested in saving a few bytes of output or are writing a framework on top of this library, it is recommend that you use forJavaScript(String) over this method.
	 *
	 * @param input the input to encode
	 */
	public string function forJavaScriptAttribute(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forJavaScriptAttribute(javaCast("string", arguments.input));
	}

	/**
	 * This method encodes for JavaScript strings contained within HTML script blocks. It is NOT safe for use in script attributes (such as onclick). The caller must provide the surrounding quotation characters. This method performs the same encode as forJavaScript(String) with the exception that "" and ' are encoded as \"" and \' respectively. Unless you are interested in saving a few bytes of output or are writing a framework on top of this library, it is recommend that you use forJavaScript(String) over this method.
	 *
	 * @param input the input to encode
	 */
	public string function forJavaScriptBlock(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forJavaScriptBlock(javaCast("string", arguments.input));
	}

	/**
	 * This method encodes for JavaScript strings contained within a JavaScript or JSON file. This method is NOT safe for use in ANY context embedded in HTML. The caller must provide the surrounding quotation characters. This method performs the same encode as forJavaScript(String) with the exception that / and & are not escaped and "" and ' are encoded as \"" and \' respectively. Unless you are interested in saving a few bytes of output or are writing a framework on top of this library, it is recommend that you use forJavaScript(String) over this method.
	 *
	 * @param input the input to encode
	 */
	public string function forJavaScriptSource(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forJavaScriptSource(javaCast("string", arguments.input));
	}

	/**
	 * Performs percent-encoding of a URL according to RFC 3986. The provided URL is assumed to a valid URL. This method does not do any checking on the quality or safety of the URL itself. In many applications it may be better to use URI instead. Note: this is a particularly dangerous context to put untrusted content in, as for example a ""javascript:"" URL provided by a malicious user would be ""properly"" escaped, and still execute.
	 *
	 * @param input the input to encode
	 */
	public string function forUri(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forUri(javaCast("string", arguments.input));
	}

	/**
	 * Performs percent-encoding for a component of a URI, such as a query parameter name or value, path or query-string. In particular this method insures that special characters in the component do not get interpreted as part of another component.
	 *
	 * @param input the input to encode
	 */
	public string function forUriComponent(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forUriComponent(javaCast("string", arguments.input));
	}

	/**
	 * Encoder for XML and XHTML. See forHtml(String) for a description of the encoding and context.
	 *
	 * @param input the input to encode
	 */
	public string function forXml(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forXml(javaCast("string", arguments.input));
	}

	/**
	 * Encoder for XML and XHTML attribute content. See forHtmlAttribute(String) for description of encoding and context.
	 *
	 * @param input the input to encode
	 */
	public string function forXmlAttribute(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forXmlAttribute(javaCast("string", arguments.input));
	}

	/**
	 * Encoder for XML comments. NOT FOR USE WITH (X)HTML CONTEXTS. (X)HTML comments may be interpreted by browsers as something other than a comment, typically in vendor specific extensions (e.g. <--if[IE]-->). For (X)HTML it is recommend that unsafe content never be included in a comment. The caller must provide the comment start and end sequences. This method replaces all invalid XML characters with spaces, and replaces the ""--"" sequence (which is invalid in XML comments) with ""-~"" (hyphen-tilde). This encoding behavior may change in future releases. If the comments need to be decoded, the caller will need to come up with their own encode/decode variables.System.
	 *
	 * @param input the input to encode
	 */
	public string function forXmlComment(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forXmlComment(javaCast("string", arguments.input));
	}

	/**
	 * Encoder for XML and XHTML text content. See forHtmlContent(String) for description of encoding and context.
	 *
	 * @param input the input to encode
	 */
	public string function forXmlContent(required string input) {
		if (!variables.isJavaEncoderAvailable) missingJavaEncoder();
		if (isNull(arguments.input)) return "";
		return variables.JavaEncoder.forXmlContent(javaCast("string", arguments.input));
	}

	private void function missingJavaEncoder() {
		raiseException(new EncodingException(variables.ESAPI, "Error encoding data.", "Java Encoder must be loaded."));
	}

}