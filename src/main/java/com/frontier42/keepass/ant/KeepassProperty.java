package com.frontier42.keepass.ant;

import java.util.Properties;

import org.apache.tools.ant.taskdefs.Property;

public class KeepassProperty extends Property {
	public void includeProperties(Properties props) {
		super.addProperties(props);
	}
}
