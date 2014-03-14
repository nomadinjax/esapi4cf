<!---
/**
 * OWASP Enterprise Security API for ColdFusion/CFML (ESAPI4CF)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011-2014, The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 */
--->
<cfscript>
	encoder = application.ESAPI.encoder();

	rc.container = "-fluid";
</cfscript>
<cfoutput>
<div class="row">
	<div class="col-lg-12">
		<div class="page-header">
			<h3>Encoder Samples and Comparisons</h3>
		</div>

		<div class="page-header">
			<h4>ASCII 0-255</h4>
		</div>

		<div class="table-responsive">
			<table class="table table-hover">
				<thead>
					<tr>
						<th rowspan="2"></th>
						<th colspan="3" class="success">HTML</th>
						<th colspan="2" class="warning">XML</th>
						<th colspan="2" class="danger">URL</th>
						<th colspan="2" class="info">JS</th>
					</tr>
					<tr>
						<th class="success">CF:htmlEditFormat</th>
						<th class="success">ESAPI:encodeForHTML</th>
						<th class="success">ESAPI:encodeForHTMLAttribute</th>
						<th class="warning">CF:xmlFormat</th>
						<th class="warning">ESAPI:encodeForXML</th>
						<th class="danger">CF:urlEncodedFormat</th>
						<th class="danger">ESAPI:encodeForURL</th>
						<th class="info">CF:jsStringFormat</th>
						<th class="info">ESAPI:encodeForJavaScript</th>
					</tr>
				</thead>
				<tbody>
					<cfloop index="c" from="0" to="255">
						<tr>
							<td>#c#&nbsp;:&nbsp;#chr(c)#</td>
							<td class="success">#replace(htmlEditFormat(chr(c)), "&", "&amp;")#</td>
							<td class="success">#replace(encoder.encodeForHTML(chr(c)), "&", "&amp;")#</td>
							<td class="success">#replace(encoder.encodeForHTMLAttribute(chr(c)), "&", "&amp;")#</td>
							<td class="warning">#replace(xmlFormat(chr(c)), "&", "&amp;")#</td>
							<td class="warning">#replace(encoder.encodeForXML(chr(c)), "&", "&amp;")#</td>
							<td class="danger">#urlEncodedFormat(chr(c))#</td>
							<td class="danger">#encoder.encodeForURL(chr(c))#</td>
							<td class="info">#jsStringFormat(chr(c))#</td>
							<td class="info">#encoder.encodeForJavaScript(chr(c))#</td>
						</tr>
					</cfloop>
				</tbody>
			</table>
		</div>

		<div class="page-header">
			<h4>Asian Characters</h4>
		</div>

		<div class="table-responsive">
			<table class="table table-hover">
				<thead>
					<tr>
						<th rowspan="2"></th>
						<th colspan="3" class="success">HTML</th>
						<th colspan="2" class="warning">XML</th>
						<th colspan="2" class="danger">URL</th>
						<th colspan="2" class="info">JS</th>
					</tr>
					<tr>
						<th class="success">CF:htmlEditFormat</th>
						<th class="success">ESAPI:encodeForHTML</th>
						<th class="success">ESAPI:encodeForHTMLAttribute</th>
						<th class="warning">CF:xmlFormat</th>
						<th class="warning">ESAPI:encodeForXML</th>
						<th class="danger">CF:urlEncodedFormat</th>
						<th class="danger">ESAPI:encodeForURL</th>
						<th class="info">CF:jsStringFormat</th>
						<th class="info">ESAPI:encodeForJavaScript</th>
					</tr>
				</thead>
				<tbody>
					<cfloop index="c" from="20051" to="20060">
						<tr>
							<td>#c#&nbsp;:&nbsp;#chr(c)#</td>
							<td class="success">#replace(htmlEditFormat(chr(c)), "&", "&amp;")#</td>
							<td class="success">#replace(encoder.encodeForHTML(chr(c)), "&", "&amp;")#</td>
							<td class="success">#replace(encoder.encodeForHTMLAttribute(chr(c)), "&", "&amp;")#</td>
							<td class="warning">#replace(xmlFormat(chr(c)), "&", "&amp;")#</td>
							<td class="warning">#replace(encoder.encodeForXML(chr(c)), "&", "&amp;")#</td>
							<td class="danger">#urlEncodedFormat(chr(c))#</td>
							<td class="danger">#encoder.encodeForURL(chr(c))#</td>
							<td class="info">#jsStringFormat(chr(c))#</td>
							<td class="info">#encoder.encodeForJavaScript(chr(c))#</td>
						</tr>
					</cfloop>
				</tbody>
			</table>
		</div>

		<div class="page-header">
			<h4>Arabic Characters</h4>
		</div>

		<div class="table-responsive">
			<table class="table table-hover">
				<thead>
					<tr>
						<th rowspan="2"></th>
						<th colspan="3" class="success">HTML</th>
						<th colspan="2" class="warning">XML</th>
						<th colspan="2" class="danger">URL</th>
						<th colspan="2" class="info">JS</th>
					</tr>
					<tr>
						<th class="success">CF:htmlEditFormat</th>
						<th class="success">ESAPI:encodeForHTML</th>
						<th class="success">ESAPI:encodeForHTMLAttribute</th>
						<th class="warning">CF:xmlFormat</th>
						<th class="warning">ESAPI:encodeForXML</th>
						<th class="danger">CF:urlEncodedFormat</th>
						<th class="danger">ESAPI:encodeForURL</th>
						<th class="info">CF:jsStringFormat</th>
						<th class="info">ESAPI:encodeForJavaScript</th>
					</tr>
				</thead>
				<tbody>
					<cfloop index="c" from="1601" to="1610">
						<tr>
							<td>#c#&nbsp;:&nbsp;#chr(c)#</td>
							<td class="success">#replace(htmlEditFormat(chr(c)), "&", "&amp;")#</td>
							<td class="success">#replace(encoder.encodeForHTML(chr(c)), "&", "&amp;")#</td>
							<td class="success">#replace(encoder.encodeForHTMLAttribute(chr(c)), "&", "&amp;")#</td>
							<td class="warning">#replace(xmlFormat(chr(c)), "&", "&amp;")#</td>
							<td class="warning">#replace(encoder.encodeForXML(chr(c)), "&", "&amp;")#</td>
							<td class="danger">#urlEncodedFormat(chr(c))#</td>
							<td class="danger">#encoder.encodeForURL(chr(c))#</td>
							<td class="info">#jsStringFormat(chr(c))#</td>
							<td class="info">#encoder.encodeForJavaScript(chr(c))#</td>
						</tr>
					</cfloop>
				</tbody>
			</table>
		</div>

	</div>
</div>
</cfoutput>