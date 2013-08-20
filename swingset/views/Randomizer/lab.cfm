<cfoutput>
<script src="#cgi.context_path#/swingset/js/jquery-1.2.6.js"></script>

<script>
//create random get parameter to prevent caching
var xmlhttp;

function timestamp() {
      var nowDate = new Date();
      return nowDate.getTime();
}
function sendAjaxRequest(url, changeMethod) {
		
	xmlhttp = GetXmlHttpObject();
	if (xmlhttp==null)
	{
	  alert ("Your browser does not support XMLHTTP!");
	  return;
	}
	if (changeMethod=='booleanChanged')		
		xmlhttp.onreadystatechange=booleanChanged;
	if (changeMethod=='randomFileNameChanged')
		xmlhttp.onreadystatechange=randomFileNameChanged;
	if (changeMethod=='randomIntegerChanged')
		xmlhttp.onreadystatechange=randomIntegerChanged;
	if (changeMethod=='randomLongChanged')
		xmlhttp.onreadystatechange=randomLongChanged;
	if (changeMethod=='randomRealChanged')
		xmlhttp.onreadystatechange=randomRealChanged;
	if (changeMethod=='randomStringChanged')
		xmlhttp.onreadystatechange=randomStringChanged;
	
	xmlhttp.open("GET",url,true);
	xmlhttp.send(null);			
}
function GetXmlHttpObject()
{
	if (window.XMLHttpRequest)
  	{
  		// code for IE7+, Firefox, Chrome, Opera, Safari
  		return new XMLHttpRequest();
  	}
	if (window.ActiveXObject)
  	{
  		// code for IE6, IE5
  		return new ActiveXObject("Microsoft.XMLHTTP");
  	}
	return null;
}
function booleanChanged(){
	if (xmlhttp.readyState==4)
	{
	  	document.getElementById("randomBoolean").innerHTML=xmlhttp.responseText;
	}
}

function randomFileNameChanged(){
	if (xmlhttp.readyState==4)
	{
  		document.getElementById("randomFileName").innerHTML=xmlhttp.responseText;
	}
}

function randomIntegerChanged(){
	if (xmlhttp.readyState==4)
	{
	  	document.getElementById("randomInteger").innerHTML=xmlhttp.responseText;
	}
}

function randomLongChanged(){
	if (xmlhttp.readyState==4)
	{
  		document.getElementById("randomLong").innerHTML=xmlhttp.responseText;
	}
}

function randomRealChanged(){
	if (xmlhttp.readyState==4)
	{
  		document.getElementById("randomReal").innerHTML=xmlhttp.responseText;
	}
}

function randomStringChanged(){
	if (xmlhttp.readyState==4)
	{
  		document.getElementById("randomString").innerHTML=xmlhttp.responseText;
	}
}



</script>
<div id="navigation">
<a href="#buildURL('')#">Home</a> | 
<a href="#buildURL('Encryption')#">Tutorial</a> | 
<a href="#buildURL('Encryption.lab')#">Lab: Cryptography</a> | 
<a href="#buildURL('Encryption.solution')#">Solution</a> |
<b><a href="#buildURL('Randomizer.lab')#">Lab: Randomizer</a></b> |
<a href="#buildURL('Randomizer.solution')#">Solution</a> |
<a href="#buildURL('Integrity.lab')#">Lab: Integrity Seals</a> |
<a href="#buildURL('Integrity.solution')#">Solution</a>
</div>
<div id="header"></div>
<p>
<hr/>


<h2 text align=center>Randomizer Lab</h2>
<h4>CFM Location: #getCurrentTemplateWebPath()#</h4>

<p>The form below contains ajax calls which invoke the methods of the class org.owasp.esapi.swingset.actions.RandomizerLab</p>

<p>Your goal is to implement these methods fully to generate the random data types below.</p>

<p><b>Java Location: Java Resources:src/org.owasp.esapi.swingset.actions.RandomizerLab.java</b></p>

<form name="secureDemo" action="#buildURL('Randomizer.lab')#" method="POST">
	<div>
		<h4>Generate a random boolean</h4>
		Random Boolean: <font color="green"><span id="randomBoolean"></span></font>
		<br /><br />
		<input type="button" value="Get Random Boolean" onclick="sendAjaxRequest('#buildURL('Randomizer.getRandomBoolean')#&timestamp=' + timestamp(), 'booleanChanged')" />
	</div>
	<div>
		</br><h4>Specify a file extension in the text field below to generate an unguessable random file name</h4>
		File Extension:
		<input type="text" name="fileExtension"/>
		<input type="button" value="Submit" onclick="sendAjaxRequest('/SwingSet/ajax?function=Randomizer&lab&method=getRandomFileName&fileExtension=' + document.secureDemo.fileExtension.value + '&timestamp=' + timestamp(),'randomFileNameChanged')">
		<br /><br />Random File Name: <font color="green"><span id="randomFileName"></span></font>
	</div>
	<div>
		</br><h4>Generate a random integer by giving min, max seed</h4>
		<p>Note: Random integer will be generated based on the input min, max seed where min is inclusive and max is exclusive.</p>
		Min: <input type="text" name="min"/>
		Max: <input type="text" name="max"/>
		<input type="button" value="Submit" onclick="sendAjaxRequest('/SwingSet/ajax?function=Randomizer&lab&method=getRandomInteger&min=' + document.secureDemo.min.value + '&max=' + document.secureDemo.max.value + '&timestamp=' + timestamp(),'randomIntegerChanged')">
		<br><br>Random Integer: <font color="green"><span id="randomInteger"></span></font>
	</div>
	<div>
		<br><h4>Generate a random long value</h4>
		Random Long: <font color="green"><span id="randomLong"></span></font>
		<br/><br/><input type="button" value="Submit" onclick="sendAjaxRequest('ajax?function=Randomizer&lab&method=getRandomLong&timestamp=' + timestamp(),'randomLongChanged')">
	</div>
	<div>
		<br><h4>Generate a random real by giving min, max seed</h4>
		<p>Note: Random real will be generated based on the input min, max seed where min is inclusive and max is exclusive.</p>
		Min: <input type='text' name='minFloat'/>
		Max: <input type='text' name='maxFloat'/>
		<input type="button" value="Submit" onclick="sendAjaxRequest('ajax?function=Randomizer&lab&method=getRandomReal&minFloat=' + document.secureDemo.minFloat.value + '&maxFloat=' + document.secureDemo.maxFloat.value + '&timestamp=' + timestamp(),'randomRealChanged')">
		<br><br>Random Real: <font color="green"><span id="randomReal"></span></font>
	</div>
	<div>
		<br><h4>Generate a random string of a desired length and character set.</h4>
		<p>Sample test values:&nbsp;&nbsp;Length=10&nbsp;&nbsp;Char Set= abc</p>
		Length: <input type='text' name='length'/>
		Char Set: <input type='text' name='charSet'/>
		<input type="button" value="Submit" onclick="sendAjaxRequest('ajax?function=Randomizer&lab&method=getRandomString&length=' + document.secureDemo.length.value + '&charSet=' + document.secureDemo.charSet.value + '&timestamp=' + timestamp(),'randomStringChanged')">
		<br><br>Random String: <font color="green"><span id="randomString"></span></font>
	</div>	
</form>
</cfoutput>