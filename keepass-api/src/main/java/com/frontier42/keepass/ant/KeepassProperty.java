package com.frontier42.keepass.ant;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.taskdefs.Property;

import com.frontier42.keepass.KeepassDatabase;
import com.frontier42.keepass.KeepassEntry;
import com.frontier42.keepass.KeepassGroup;

public class KeepassProperty extends Property {
	private File truststore;
	private String truststoreType="jks";
	private String truststorePassword;
	private File keystore;
	private String keystoreType="jks";
	private String keystorePassword;
	private String masterKey;
	
	public String getMasterKey() {
		return masterKey;
	}
	public void setMasterKey(String masterkey) {
		this.masterKey = masterkey;
	}
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
	@Override
	protected void loadUrl(URL url) throws BuildException {
		Properties props = new Properties();
		log("Loading " + url, Project.MSG_WARN);
		try {
			UrlStreamHelper helper=new UrlStreamHelper();
			InputStream is = null;
			if (url.getProtocol().toLowerCase().startsWith("http")){
				helper.setTruststore(getTruststore());
				helper.setTruststorePassword(getTruststorePassword());
				helper.setKeystore(getKeystore());
				helper.setKeystorePassword(getKeystorePassword());
				helper.setKeystoreType(getKeystoreType());
				is = helper.openStream(url);
			}
			
			is = helper.openStream(url);
			KeepassStreamReader reader=new KeepassStreamReader();
			KeepassDatabase database=reader.load(is, getMasterKey());
			String pPrefix="";
			log("prefix:"+this.getPrefix(), Project.MSG_INFO);
			for(KeepassGroup group:database.getGroups()){
				addProperty(pPrefix, group, props);
			}
			//System.out.println("groups:"+database.getGroups().size());
			//KeepassDatabaseFactory.openDecryptedStrem(is, getPassword());
			/*
			try {
				props.load(is);
			} finally {
				if (is != null) {
					is.close();
				}
			}
			*/
			addProperties(props);
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new BuildException(ex, getLocation());
		}
	}
	protected void addProperty(String pPrefix, KeepassGroup group, Properties props){
		log("Group:"+group.getName(), Project.MSG_INFO);
		for(KeepassEntry entry:group.getEntries()){
			String entryPrefix=pPrefix+group.getName()+"."+entry.getTitle();
			log("Entry:"+entry.getTitle(), Project.MSG_INFO);
			props.put(entryPrefix+".username",entry.getUsername());
			props.put(entryPrefix+".password",entry.getPassword());
		}
		
	}
	@Override
	public void execute() throws BuildException {
		super.execute();
	}
}
