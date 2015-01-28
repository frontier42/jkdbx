package com.frontier42.keepass;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import org.w3c.dom.Document;

import com.frontier42.keepass.impl.DatabaseReaderV4;
import com.keepassdroid.database.exception.InvalidDBException;
import com.keepassdroid.database.exception.InvalidDBVersionException;
import com.keepassdroid.database.exception.InvalidPasswordException;


public class KeepassDatabase {
	public static Document loadDocument(File file, String password) throws IOException, InvalidDBVersionException, InvalidPasswordException, InvalidDBException{
		Document doc=null;
		InputStream inputStream=new FileInputStream(file);
		try{
			doc=loadDocument(inputStream, password);
		}finally{
			if (inputStream!=null)inputStream.close();
		}
		return doc;
	}
	public static Document loadDocument(URL url, String password) throws IOException, InvalidDBVersionException, InvalidPasswordException, InvalidDBException{
		Document doc=null;
		InputStream inputStream=url.openStream();
		try{
			doc=loadDocument(inputStream, password);
		}finally{
			if (inputStream!=null)inputStream.close();
		}
		return doc;
	}
	public static Document loadDocument(InputStream is, String password) throws IOException, InvalidDBVersionException, InvalidPasswordException, InvalidDBException{
		BufferedInputStream bis = new BufferedInputStream(is);
		DatabaseReaderV4 reader=new DatabaseReaderV4();
		long startTime=System.nanoTime();
		Document doc= reader.loadData(bis, password);
		long endTime=System.nanoTime();
		long loadTime=endTime-startTime;
		//System.err.println("loadTime:"+loadTime);
		doc.getDocumentElement().setAttribute("loadTime",Long.toString(loadTime));
		return doc;
	}
}
