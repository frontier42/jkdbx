package com.frontier42.keepass.impl;

import java.util.Stack;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class DatabaseContentHandler extends DefaultHandler  {
	private static final String EL_GROUP="Group";
	private static final String EL_ENTRY="Entry";
	private static final String EL_FIELD_KEY_TITLE="Title";
	private static final String EL_FIELD_KEY_USERNAME="UserName";
	private static final String EL_FIELD_KEY_PASSWORD="Password";
	private static final String EL_FIELD_KEY="Key";
	private static final String EL_FIELD_VALUE="Value";
	private static final String EL_FIELD_STRING="String";
	private static final String EL_UUID="UUID";
	private static final char GROUP_SEP=':';
	
	private boolean readingUUID=false;
	private boolean readingEntryField=false;
	private boolean readingEntryKey=false;
	private boolean readingEntryValue=false;
	private boolean readingFieldTitle=false;
	private boolean readingFieldUserName=false;
	private boolean readingFieldPassword=false;
	private boolean readingEntryProtectedValue=false;
	
	private Stack<KeepassElement> stack=new Stack<DatabaseContentHandler.KeepassElement>();
	
	private static class KeepassElement{
		String uuid;
	}
	private static class GroupElement extends KeepassElement{
	}
	private static class EntryElement extends KeepassElement{

		public String title;
		public String username;
		public String password;
	}	
	@Override
	public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
		if (EL_GROUP.equals(localName)){
			GroupElement el=new GroupElement();
			stack.push(el);
		}else if (EL_ENTRY.equals(localName)){
			EntryElement el=new EntryElement();
			stack.push(el);
		}else if (EL_UUID.equals(localName)){
			readingUUID=true;
		}else if (stack.peek() instanceof EntryElement){
			if (EL_FIELD_STRING.equals(localName)){
				readingEntryField=true;
			}else if (readingEntryField && EL_FIELD_KEY.equals(localName)){
				readingEntryKey=true;
			}else if (readingEntryField && EL_FIELD_VALUE.equals(localName)){
				readingEntryValue=true;
				String strProtected=attributes.getValue("Protected");
				if ("true".equalsIgnoreCase(strProtected)){
					readingEntryProtectedValue=true;
				}
			}
		}
	}
	@Override
	public void characters(char[] ch, int start, int length) throws SAXException {
		if (readingUUID){
			stack.peek().uuid=new String(ch, length, length);
		}else if (readingEntryKey){
			String key=new String(ch, length, length);
			if (EL_FIELD_KEY_TITLE.equals(key)){
				readingFieldTitle=true;
			}else if (EL_FIELD_KEY_USERNAME.equals(key)){
				readingFieldUserName=true;
			}else if (EL_FIELD_KEY_PASSWORD.equals(key)){
				readingFieldPassword=true;
			}
		}else if (readingEntryValue){
			String value=new String(ch, length, length);
			if (readingEntryProtectedValue){
				
			}
			if (readingFieldTitle){
				((EntryElement)stack.peek()).title=value;
			}else if (readingFieldUserName){
				((EntryElement)stack.peek()).username=value;
			}else if (readingFieldPassword){
				((EntryElement)stack.peek()).password=value;
			}
		}
	}
	@Override
	public void endElement(String uri, String localName, String qName) throws SAXException {
		if (EL_GROUP.equals(localName)){
			stack.pop();
		}else if (EL_ENTRY.equals(localName)){
			stack.pop();
		}else if (EL_UUID.equals(localName)){
			readingUUID=false;
		}else if (stack.peek() instanceof EntryElement){
			if (EL_FIELD_STRING.equals(localName)){
				readingEntryField=false;
			}else if (EL_FIELD_KEY.equals(localName)){
				readingEntryKey=false;
			}else if (EL_FIELD_VALUE.equals(localName)){
				readingEntryValue=false;
				readingEntryProtectedValue=false;
			}
			
			if (!readingEntryField){
				readingEntryKey=false;
				readingEntryValue=false;
				readingEntryProtectedValue=false;
				readingFieldTitle=false;
				readingFieldUserName=false;
				readingFieldPassword=false;
			}
		}
	}
}
