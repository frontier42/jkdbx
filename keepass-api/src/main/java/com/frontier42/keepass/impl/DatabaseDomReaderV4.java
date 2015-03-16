package com.frontier42.keepass.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Hashtable;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.sax.SAXTransformerFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.bouncycastle.crypto.StreamCipher;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import com.keepassdroid.database.exception.InvalidDBException;
import com.keepassdroid.database.exception.InvalidDBVersionException;
import com.keepassdroid.database.exception.InvalidPasswordException;


public class DatabaseDomReaderV4 extends DatabaseReaderV4 {
	public Document loadData(InputStream is, String password) throws IOException, InvalidDBVersionException, InvalidPasswordException, InvalidDBException {
		InputStream decrypted=openDecryptedStrem(is, password);
		return parseXmlData(decrypted, randomStream);
	}
	
	private Document parseXmlData(InputStream readerStream, StreamCipher cipher) throws IOException {
		Document doc=null;
		try {
			doc=sax2dom(new InputSource(readerStream));
			XPathFactory xPathfactory = XPathFactory.newInstance();
			XPath xpath = xPathfactory.newXPath();
			XPathExpression expr = xpath.compile("//Entry");
			NodeList entries=(NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			Map<String, Element> hexUuidIndex=new Hashtable<String, Element>(entries.getLength());
			
			//Index by UUID, also decrypts the password values
			for (int i=0; i<entries.getLength();i++){
				Element entry=(Element) entries.item(i);
				Element uuid=(Element) entry.getElementsByTagName("UUID").item(0);
		    	byte[] uuidBytes=javax.xml.bind.DatatypeConverter.parseBase64Binary(uuid.getTextContent().trim());
		    	String uuidHex=javax.xml.bind.DatatypeConverter.printHexBinary(uuidBytes);
		    	hexUuidIndex.put(uuidHex, entry);
		    	Map<String, Element> fieldsMap=new Hashtable<String, Element>();
		    	entry.setUserData("fields", fieldsMap, null);
		    	NodeList fields=entry.getElementsByTagName("String");
		    	for (int j=0; j<fields.getLength();j++){
		    		Element field=(Element) fields.item(j);
		    		Element fieldKey=(Element) field.getElementsByTagName("Key").item(0);
		    		Element fieldValue=(Element) field.getElementsByTagName("Value").item(0);
		    		fieldsMap.put(fieldKey.getTextContent(), fieldValue);
		    		Attr attrProtected=fieldValue.getAttributeNode("Protected");
		    		//Decrypt password
		    		if (attrProtected!=null && "true".equalsIgnoreCase(attrProtected.getValue())){
						String encrypted=fieldValue.getTextContent();
						byte[] buf = javax.xml.bind.DatatypeConverter.parseBase64Binary(encrypted);
						byte[] plainBuf = new byte[buf.length];
						//System.out.println("raw:"+node.getTextContent());
						randomStream.processBytes(buf, 0, buf.length, plainBuf, 0);
						fieldValue.setTextContent(new String(plainBuf, "UTF-8"));
						fieldValue.removeAttributeNode(attrProtected);
		    		}
		    	}
			}
			
			//resolve all field references
			expr = xpath.compile("//String/Value[contains(text(), '{REF:')]");
			NodeList nodes=(NodeList) expr.evaluate(doc, XPathConstants.NODESET);
			Pattern refRegex=Pattern.compile("\\{REF:([^@]+)@([^:]+):([^\\}]+)\\}");
			StringBuffer sb=new StringBuffer();
			for (int i=0; i<nodes.getLength();i++){
				Element node=(Element)nodes.item(i);
				String rawValue=node.getTextContent();
				Matcher m = refRegex.matcher(rawValue);
				sb.setLength(0);
				while(m.find()){
					Element entry=null;
					String replacement=m.group(0);
					
					if ("I".equals(m.group(2))){
						entry=hexUuidIndex.get(m.group(3));
					}
					if (entry!=null){
						Map<String, Element> fields=(Map<String, Element>) entry.getUserData("fields");
						Element value=null;
						if ("U".equals(m.group(1))){
							value=fields.get("UserName");
						}else if ("P".equals(m.group(1))){
							value=fields.get("Password");
						}
						if (value!=null){
							replacement=value.getTextContent();
						}
					}
					
					//findByUUIDExpr = xpath.compile("//Entry[UUID='"+javax.xml.bind.DatatypeConverter.pa +"']");
					m.appendReplacement(sb, replacement);
				}
				m.appendTail(sb);
				node.setTextContent(sb.toString());
			}
		} catch (TransformerFactoryConfigurationError e) {
			throw new IOException(e);
		} catch (TransformerException e) {
			throw new IOException(e);
		} catch (XPathExpressionException e) {
			throw new IOException(e);
		}
		return doc;
	}
	private void dumpXmlData(InputStream readerStream) throws IOException {
		BufferedReader reader = new BufferedReader(new InputStreamReader(
				readerStream));
		String line = null;
		while ((line = reader.readLine()) != null) {
			System.out.println(line);
		}
	}
	public Document sax2dom(InputSource input) throws TransformerFactoryConfigurationError, TransformerException{
		TransformerFactory tfactory=TransformerFactory.newInstance();
		SAXTransformerFactory saxTFactory = (SAXTransformerFactory) tfactory;
		Transformer t=tfactory.newTransformer();
		Source s=new SAXSource(input);
		
		DOMResult r=new DOMResult();
		
		t.transform(s, r);
		return (Document) r.getNode();
	}
	
	private void ReadXmlStreamed(InputStream readerStream) throws IOException, InvalidDBException {
		try {
			ReadDocumentStreamed(CreatePullParser(readerStream));
		} catch (XmlPullParserException e) {
			e.printStackTrace();
			throw new IOException(e.getLocalizedMessage());
		}
	}

	private static XmlPullParser CreatePullParser(InputStream readerStream)
			throws XmlPullParserException {
		XmlPullParserFactory xppf = XmlPullParserFactory.newInstance();
		xppf.setNamespaceAware(false);

		XmlPullParser xpp = xppf.newPullParser();
		xpp.setInput(readerStream, null);

		return xpp;
	}

	private void ReadDocumentStreamed(XmlPullParser xpp)
			throws XmlPullParserException, IOException, InvalidDBException {

		System.out.println();
		while (true) {
			if (xpp.next() == XmlPullParser.END_DOCUMENT)
				break;

			switch (xpp.getEventType()) {
			case XmlPullParser.START_TAG:
				System.out.print("<");
				System.out.print(xpp.getName());
				// System.out.print(" att-count=\""+xpp.getAttributeCount()+"\"");
				System.out.println(">");
				break;
			case XmlPullParser.TEXT:
				System.out.print(xpp.getText());
				break;
			case XmlPullParser.END_TAG:
				System.out.print("</");
				System.out.print(xpp.getName());
				System.out.println(">");
				break;

			default:
				System.err.println("EventType:" + xpp.getEventType());
				break;

			}

		}
	}
}
