package com.frontier42.keepass;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

public class KeepassGroup {
	private final KeepassDatabase database;
	public final static EqualsComparator KEY_COMPARATOR=new EqualsComparator(){
		public int hashCode(Object obj) {
			return ((KeepassGroup)obj).getName().toLowerCase().hashCode();
		};
		public boolean equals(Object obj1, Object obj2) {
			if (obj2 instanceof String){
				return ((KeepassGroup)obj1).getName().toLowerCase().equalsIgnoreCase((String)obj2);
			}
			return obj1.equals(obj2);
		};
	};
	public static MyKeyReferencey MAKE_KEY(KeepassGroup newItem) {
		return new MyKey<KeepassGroup>(newItem, KEY_COMPARATOR);
	}
	public static Map<MyKeyReferencey,KeepassGroup> MAKE_MAP(){
		return new Hashtable<MyKeyReferencey, KeepassGroup>(){
			private static final long serialVersionUID = -7821988784939001383L;

			@Override
			public synchronized KeepassGroup get(Object key) {
				return super.get(((String)key).toLowerCase());
			}
		};
	}
	private List<KeepassEntry> entries=new ArrayList<KeepassEntry>();
	private Map<MyKeyReferencey, KeepassGroup> groups=MAKE_MAP();
	
	private String name;
	
	public KeepassGroup(KeepassDatabase database) {
		this.database=database;
	}
	
	public KeepassGroup(KeepassGroup group) {
		this.database=group.getDatabase();
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
		this.database.onAdd(entry);
	}
	public List<KeepassEntry> getEntries() {
		return entries;
	}
	public KeepassDatabase getDatabase() {
		return database;
	}
	public KeepassGroup newGroup() {
		return new KeepassGroup(this);
	}
	public Collection<KeepassGroup> getGroups() {
		return groups.values();
	}
	public KeepassGroup getGroup(String name){
		return groups.get(name);
	}
	public void add(KeepassGroup group) {
		groups.put(MAKE_KEY(group), group);
		this.database.onAdd(group);
	}
}

