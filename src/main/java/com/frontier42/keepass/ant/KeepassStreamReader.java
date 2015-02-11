package com.frontier42.keepass.ant;

import java.io.InputStream;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;

import com.frontier42.keepass.KeepassDatabase;
import com.frontier42.keepass.KeepassDatabaseFactory;
import com.frontier42.keepass.KeepassEntry;
import com.frontier42.keepass.KeepassGroup;

public class KeepassStreamReader {
	private static final String EL_VALUE = "Value";
	private static final String EL_NAME = "Name";
	private static final String EL_ROOT = "Root";
	private static final String EL_GROUP = "Group";
	private static final String EL_ENTRY = "Entry";
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

	public void readEntry(XMLStreamReader reader, KeepassEntry entry) throws Exception {
		while (reader.hasNext()) {
			int event = reader.next();
			switch (event) {
			case XMLStreamConstants.START_ELEMENT:
				String localName = reader.getLocalName();
				switch (localName) {
				case EL_STRING:
					String key = readCharacters(reader, EL_KEY);
					String value = readCharacters(reader, EL_VALUE);
					if (EL_TITLE.equals(key)) {
						entry.setTitle(value);
					} else if (EL_USER_NAME.equals(key)) {
						entry.setUsername(entry.createValue(value));
					} else if (EL_PASSWORD.equals(key)) {
						entry.setPassword(entry.createValue(value));
					}
					break;
				case "UUID":
					String rawUUID=readCharacters(reader);
			    	byte[] uuidBytes=javax.xml.bind.DatatypeConverter.parseBase64Binary(rawUUID.trim());
			    	String uuidHex=javax.xml.bind.DatatypeConverter.printHexBinary(uuidBytes);
					entry.setUUID(uuidHex);
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
					break;
				case EL_ENTRY:
					KeepassEntry entry = group.newEntry();
					readEntry(reader, entry);
					group.add(entry);
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
		InputStream stream = KeepassDatabaseFactory.openDecryptedStrem(encryptedStream, password);
		XMLStreamReader reader = factory.createXMLStreamReader(stream);
		
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
