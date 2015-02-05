package com.frontier42.keepass.ant;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.Properties;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.taskdefs.Property;

public class KeepassProperty extends Property {
	public void includeProperties(Properties props) {
		super.addProperties(props);
	}
	@Override
    protected void loadUrl(URL url) throws BuildException {
        Properties props = new Properties();
        log("Loading " + url, Project.MSG_VERBOSE);
        try {
        	URLConnection conn=url.openConnection();
            InputStream is = conn.getInputStream();
            try {
            	props.load(is);
            } finally {
                if (is != null) {
                    is.close();
                }
            }
            addProperties(props);
        } catch (IOException ex) {
            throw new BuildException(ex, getLocation());
        }
    }
}
