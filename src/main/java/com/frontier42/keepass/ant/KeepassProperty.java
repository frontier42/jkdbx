package com.frontier42.keepass.ant;

import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.taskdefs.Property;

public class KeepassProperty extends Property {
	@Override
	protected void loadUrl(URL url) throws BuildException {
		Properties props = new Properties();
		log("Loading " + url, Project.MSG_VERBOSE);
		try {
			UrlStreamHelper helper=new UrlStreamHelper();

			InputStream is = helper.openStream(url);
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
