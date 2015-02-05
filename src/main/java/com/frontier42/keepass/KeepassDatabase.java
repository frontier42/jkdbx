package com.frontier42.keepass;

import java.util.ArrayList;
import java.util.List;

public class KeepassDatabase {
	private List<KeepassGroup> groups=new ArrayList<KeepassGroup>();

	public void add(KeepassGroup group) {
		groups.add(group);
	}
	public List<KeepassGroup> getGroups() {
		return groups;
	}
	public KeepassGroup newGroup() {
		return new KeepassGroup(this);
	}
}
