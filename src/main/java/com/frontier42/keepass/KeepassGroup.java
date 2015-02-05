package com.frontier42.keepass;

import java.util.ArrayList;
import java.util.List;

public class KeepassGroup {
	private final KeepassDatabase database;
	
	private List<KeepassEntry> entries=new ArrayList<KeepassEntry>();
	private String name;
	
	public KeepassGroup(KeepassDatabase database) {
		this.database=database;
	}
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	public KeepassEntry newEntry() {
		return new KeepassEntry(this);
	}
	public void add(KeepassEntry entry) {
		entries.add(entry);
	}
	public List<KeepassEntry> getEntries() {
		return entries;
	}
	public KeepassDatabase getDatabase() {
		return database;
	}
}
