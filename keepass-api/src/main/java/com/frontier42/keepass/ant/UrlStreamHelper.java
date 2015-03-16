package com.frontier42.keepass.ant;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class UrlStreamHelper{
	/*
	private static final String TRUSTSTORE_FILE = "C:/temp/client-truststore.jks";
	private static final String TRUSTSTORE_PASSWORD = "changeit";
	private static final String TRUSTSTORE_TYPE = "jks";
	private static final String KEYSTORE_FILE = "C:/temp/client-keystore.jks";
	private static final String KEYSTORE_PASSWORD = "changeit";
	private static final String KEYSTORE_TYPE = "jks";
	*/
	private File truststore;
	private String truststoreType="jks";
	private String truststorePassword;
	private File keystore;
	private String keystoreType="jks";
	private String keystorePassword;
	private String sslProtocol="TLSv1.2";
	
	
	public File getTruststore() {
		return truststore;
	}

	public void setTruststore(File truststore) {
		this.truststore = truststore;
	}

	public String getTruststoreType() {
		return truststoreType;
	}

	public void setTruststoreType(String truststoreType) {
		this.truststoreType = truststoreType;
	}

	public String getTruststorePassword() {
		return truststorePassword;
	}

	public void setTruststorePassword(String truststorePassword) {
		this.truststorePassword = truststorePassword;
	}

	public File getKeystore() {
		return keystore;
	}

	public void setKeystore(File keystore) {
		this.keystore = keystore;
	}

	public String getKeystoreType() {
		return keystoreType;
	}

	public void setKeystoreType(String keystoreType) {
		this.keystoreType = keystoreType;
	}

	public String getKeystorePassword() {
		return keystorePassword;
	}

	public void setKeystorePassword(String keystorePassword) {
		this.keystorePassword = keystorePassword;
	}
	public String getSslProtocol() {
		return sslProtocol;
	}
	public void setSslProtocol(String sslProtocol) {
		this.sslProtocol = sslProtocol;
	}
	protected KeyManager[] getKeyManagers(String keyStoreType, InputStream keyStoreFile, String keyStorePassword) throws GeneralSecurityException, IOException {
		KeyStore keyStore = KeyStore.getInstance(keyStoreType);
		keyStore.load(keyStoreFile, keyStorePassword.toCharArray());
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keyStore, keyStorePassword.toCharArray());
		return kmf.getKeyManagers();
	}

	protected TrustManager[] getTrustManagers(String trustStoreType, InputStream trustStoreFile, String trustStorePassword) throws GeneralSecurityException, IOException {
		KeyStore trustStore = KeyStore.getInstance(trustStoreType);
		trustStore.load(trustStoreFile, trustStorePassword.toCharArray());
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(trustStore);
		return tmf.getTrustManagers();
	}

	protected SSLContext createSSLContext() throws GeneralSecurityException, IOException {
		SSLContext sslcontext = SSLContext.getInstance(getSslProtocol());
		InputStream trustStoreInputStream = null;
		InputStream keyStoreInputStream = null;

		try {
			trustStoreInputStream= new FileInputStream(getTruststore());
			keyStoreInputStream=new FileInputStream(getKeystore());
			TrustManager[] trustManagers = getTrustManagers(getTruststoreType(), trustStoreInputStream, getTruststorePassword());
			KeyManager[] keyManagers = getKeyManagers(getKeystoreType(), keyStoreInputStream, getKeystorePassword());
			sslcontext.init(keyManagers, trustManagers, new SecureRandom());
			
		} finally {
			if (trustStoreInputStream!=null)trustStoreInputStream.close();
			if (keyStoreInputStream!=null)keyStoreInputStream.close();
		}
		return sslcontext;
	}
	protected void setSSLSocketFactory(URLConnection conn) throws GeneralSecurityException, IOException {
		if (conn instanceof HttpsURLConnection) {
			SSLContext context = createSSLContext();
			SSLSocketFactory sf = context.getSocketFactory();
			((HttpsURLConnection) conn).setSSLSocketFactory(sf);
			((HttpsURLConnection) conn).setHostnameVerifier(new HostnameVerifier() {
				@Override
				public boolean verify(String hostname, SSLSession session) {
					return true;
				}
			});
		}
	}


	public InputStream openStream(URL url) throws IOException, GeneralSecurityException  {
		URLConnection conn = url.openConnection();
		setSSLSocketFactory(conn);
		return conn.getInputStream();
	}
}
