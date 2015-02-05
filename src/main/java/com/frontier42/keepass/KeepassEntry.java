package com.frontier42.keepass;


public class KeepassEntry {
	private final KeepassGroup group;
	
	private String title;
	private String username;
	private String password;
	private String uuid;
	
	public KeepassEntry(KeepassGroup group) {
		this.group=group;
	}
	public String getTitle() {
		return title;
	}
	public void setTitle(String title) {
		this.title = title;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public void setUUID(String uuid) {
		this.uuid=uuid;
	}
	@Override
	public int hashCode() {
		return this.uuid.hashCode();
	}
	public KeepassGroup getGroup() {
		return group;
	}
}
