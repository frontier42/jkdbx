package com.frontier42.keepass.keepass.server;

import java.io.File;
import java.io.InputStream;
import java.net.URL;

import org.apache.commons.io.IOUtils;

import com.frontier42.keepass.ant.UrlStreamHelper;

public class KeepassServerClient  {
	public static void main(String[] args) throws Exception {
		UrlStreamHelper helper=new UrlStreamHelper();
		helper.setKeystore(new File(System.getProperty("keepass.server.keyStore")));
		helper.setKeystorePassword(System.getProperty("keepass.server.keyStorePassword"));
		helper.setTruststore(new File(System.getProperty("keepass.server.trustStore")));
		helper.setTruststorePassword(System.getProperty("keepass.server.trustStorePassword"));
		InputStream stream=helper.openStream(new URL(args[0]));
		IOUtils.copy(stream, System.out);
	}
}
