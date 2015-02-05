package com.frontier42.keepass.ant;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Properties;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.taskdefs.Property;

public class KeepassProperty extends Property {
	private File certFile;
	private String certPassword;

	public void includeProperties(Properties props) {
		super.addProperties(props);
	}

	protected void setSSLSocketFactory(URLConnection conn) throws Exception {
		if (conn instanceof HttpsURLConnection) {

			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("X509");
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			InputStream keyInput = new FileInputStream(certFile);
			keyStore.load(keyInput, certPassword.toCharArray());
			keyInput.close();
			keyManagerFactory.init(keyStore, certPassword.toCharArray());
			
			TrustManager[] trustManagers=null;
			/*
			TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			KeyStore trustStore = KeyStore.getInstance("PKCS12");
			trustStore.load(null);
			trustManagerFactory.init(trustStore);
			trustManagers=trustManagerFactory.getTrustManagers();
			*/
			
			SSLContext context = SSLContext.getInstance("TLS");
			context.init(keyManagerFactory.getKeyManagers(), trustManagers , new SecureRandom());
			SSLSocketFactory sf = context.getSocketFactory();
			((HttpsURLConnection) conn).setSSLSocketFactory(sf);
		}
	}

	@Override
	protected void loadUrl(URL url) throws BuildException {
		Properties props = new Properties();
		log("Loading " + url, Project.MSG_VERBOSE);
		try {
			URLConnection conn = url.openConnection();
			setSSLSocketFactory(conn);
			InputStream is = conn.getInputStream();
			try {
				props.load(is);
			} finally {
				if (is != null) {
					is.close();
				}
			}
			addProperties(props);
		} catch (Exception ex) {
			throw new BuildException(ex, getLocation());
		}
	}
}
