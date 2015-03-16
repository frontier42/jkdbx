package com.frontier42.keepass.ant;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Hashtable;
import java.util.Map;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;

import org.bouncycastle.crypto.StreamCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.frontier42.keepass.KeepassDatabase;
import com.frontier42.keepass.KeepassDatabaseFactory;
import com.frontier42.keepass.KeepassEntry;
import com.frontier42.keepass.KeepassGroup;
import com.frontier42.keepass.impl.DatabaseReaderV4;

public class KeepassStreamReader {
	protected StreamCipher randomStream;
	
	private static final String EL_UUID = "UUID";
	private final Logger LOG=LoggerFactory.getLogger(getClass());
	private static final String EL_VALUE = "Value";
	private static final String EL_NAME = "Name";
	private static final String EL_ROOT = "Root";
	private static final String EL_GROUP = "Group";
	private static final String EL_ENTRY = "Entry";
	private static final String EL_HISTORY = "History";
	private static final String EL_PASSWORD = "Password";
	private static final String EL_USER_NAME = "UserName";
	private static final String EL_TITLE = "Title";
	private static final String EL_STRING = "String";
	private static final String EL_KEY = "Key";

	/*
	public static class SAXHandler extends DefaultHandler {

	}

	public void testReadAsSAX() throws Exception {
		SAXParserFactory parserFactor = SAXParserFactory.newInstance();
		SAXParser parser = parserFactor.newSAXParser();
		SAXHandler handler = new SAXHandler();
		parser.parse(ClassLoader.getSystemResourceAsStream("xml/employee.xml"), handler);
	}
	*/
	
	public String readCharacters(XMLStreamReader reader, String element) throws Exception {
		while (reader.hasNext()) {
			int event = reader.next();
			switch (event) {
			case XMLStreamConstants.START_ELEMENT:
				if (element.equals(reader.getLocalName())) {
					return readCharacters(reader);
				}
				break;
			case XMLStreamConstants.END_ELEMENT:
				if (element.equals(reader.getLocalName())) {
					return null;
				}
				break;
			}
		}
		return null;
	}
	private static class ElementText{
		private String _text;
		private Map<String, String> attributes=new Hashtable<String, String>();
		
		ElementText(){
		}
		public void setText(String text) {
			this._text = text;
		}
		public String getText() {
			return _text;
		}
		public void setAttribute(String name, String value){
			this.attributes.put(name, value);
		}
		public String getAttribute(String name){
			return this.attributes.get(name);
		}
		public Map<String, String> getAttributes() {
			return attributes;
		}
	}
	public ElementText readCharactersWithAtt(XMLStreamReader reader, String element) throws Exception {
		while (reader.hasNext()) {
			int event = reader.next();
			switch (event) {
			case XMLStreamConstants.START_ELEMENT:
				if (element.equals(reader.getLocalName())) {
					ElementText el=new ElementText();
					for (int i=0;i<reader.getAttributeCount();i++){
						el.setAttribute(reader.getAttributeLocalName(i), reader.getAttributeValue(i));
					}
					el.setText(reader.getElementText());
					return el;
				}
				break;
			case XMLStreamConstants.END_ELEMENT:
				if (element.equals(reader.getLocalName())) {
					return null;
				}
				break;
			}
		}
		return null;
	}
	public void skipHistory(XMLStreamReader reader, KeepassEntry entry) throws Exception {
		while (reader.hasNext()) {
			int event = reader.next();
			switch (event) {
			case XMLStreamConstants.START_ELEMENT:
				String localName = reader.getLocalName();
				switch (localName) {
				case EL_VALUE:
					if ("True".equalsIgnoreCase(reader.getAttributeValue(null, "Protected"))){
						decryptField(reader.getElementText());
					}
					break;
				}
			case XMLStreamConstants.END_ELEMENT:
				if (EL_HISTORY.equals(reader.getLocalName())){
					return;
				}
			}
		}
	}
	public String decryptField(String encrypted) throws UnsupportedEncodingException{
		byte[] buf = javax.xml.bind.DatatypeConverter.parseBase64Binary(encrypted);
		byte[] plainBuf = new byte[buf.length];
		//System.out.println("raw:"+node.getTextContent());
		randomStream.processBytes(buf, 0, buf.length, plainBuf, 0);
		return new String(plainBuf, "UTF-8");
	}
	public void readEntry(XMLStreamReader reader, KeepassEntry entry) throws Exception {
		while (reader.hasNext()) {
			int event = reader.next();
			switch (event) {
			case XMLStreamConstants.START_ELEMENT:
				String localName = reader.getLocalName();
				switch (localName) {
				case EL_STRING:
					String key = readCharacters(reader, EL_KEY);
					ElementText value = readCharactersWithAtt(reader, EL_VALUE);
					if (EL_TITLE.equals(key)) {
						LOG.info("Reading Entry:"+value.getText());
						entry.setTitle(value.getText());
					} else if (EL_USER_NAME.equals(key)) {
						entry.setUsername(entry.createValue(value.getText()));
					} else if (EL_PASSWORD.equals(key)) {
						if ("True".equalsIgnoreCase(value.getAttribute("Protected"))){
							entry.setPassword(entry.createValue(decryptField(value.getText())));
						}else{
							entry.setPassword(entry.createValue(value.getText()));
						}
					}
					break;
				case EL_UUID:
					String rawUUID=readCharacters(reader);
			    	byte[] uuidBytes=javax.xml.bind.DatatypeConverter.parseBase64Binary(rawUUID.trim());
			    	String uuidHex=javax.xml.bind.DatatypeConverter.printHexBinary(uuidBytes);
					entry.setUUID(uuidHex);
					break;
				case EL_HISTORY:
					skipHistory(reader, entry);
					break;
				}
				break;
			case XMLStreamConstants.END_ELEMENT:
				if (EL_ENTRY.equals(reader.getLocalName())){
					return;
				}
			}
		}
	}

	public String readCharacters(XMLStreamReader reader) throws Exception {
		StringBuilder builder = new StringBuilder();
		while (reader.hasNext()) {
			int event = reader.next();
			switch (event) {
			case XMLStreamConstants.CHARACTERS:
				builder.append(reader.getText().trim());
				break;
			default:
				return builder.toString();
			}
		}
		return builder.toString();
	}

	public void readGroup(XMLStreamReader reader, KeepassGroup group) throws Exception {
		while (reader.hasNext()) {
			int event = reader.next();
			switch (event) {
			case XMLStreamConstants.START_ELEMENT:
				String localName = reader.getLocalName();
				switch (localName) {
				case EL_NAME:
					group.setName(readCharacters(reader));
					LOG.info("Reading group:"+group.getName());
					break;
				case EL_ENTRY:
					KeepassEntry entry = group.newEntry();
					readEntry(reader, entry);
					group.add(entry);
					break; 
				case EL_GROUP:
					KeepassGroup subgroup = group.newGroup();
					readGroup(reader, subgroup);
					group.add(subgroup);
					break;
				}
				break;
			case XMLStreamConstants.END_ELEMENT:
				if (EL_GROUP.equals(reader.getLocalName())) {
					return;
				}
				break;
			}
		}
	}

	public void readRoot(XMLStreamReader reader, KeepassDatabase db) throws Exception {
		while (reader.hasNext()) {
			int event = reader.next();
			switch (event) {
			case XMLStreamConstants.START_ELEMENT:
				if (EL_GROUP.equals(reader.getLocalName())) {
					KeepassGroup group = db.newGroup();
					readGroup(reader, group);
					db.add(group);
					db.setRootGroup(group);
				}
				break;
			case XMLStreamConstants.END_ELEMENT:
				if (EL_ROOT.equals(reader.getLocalName())) {
					return;
				}
			}
		}
	}

	public KeepassDatabase load(InputStream encryptedStream, String password) throws Exception {
		XMLInputFactory factory = XMLInputFactory.newInstance();
		DatabaseReaderV4 kdbxReader=new DatabaseReaderV4();
		InputStream stream = KeepassDatabaseFactory.openDecryptedStrem(kdbxReader, encryptedStream, password);
		XMLStreamReader reader = factory.createXMLStreamReader(stream);
		this.randomStream=kdbxReader.getRandomStreamCipher();
		KeepassDatabase db=new KeepassDatabase();
		
		while (reader.hasNext()) {
			int event = reader.next();
			switch (event) {
			case XMLStreamConstants.START_DOCUMENT:
				break;
			case XMLStreamConstants.END_DOCUMENT:
				break;
			case XMLStreamConstants.START_ELEMENT:
				if (EL_ROOT.equals(reader.getLocalName())) {
					readRoot(reader, db);
				}
				break;
			case XMLStreamConstants.CHARACTERS:
				break;
			case XMLStreamConstants.END_ELEMENT:
				break;
			}
		}
		
		return db;
	}
}
