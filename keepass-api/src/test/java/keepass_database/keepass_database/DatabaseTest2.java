package keepass_database.keepass_database;

import java.net.URL;

import junit.framework.TestCase;

import com.frontier42.keepass.KeepassDatabase;
import com.frontier42.keepass.KeepassEntry;
import com.frontier42.keepass.KeepassGroup;
import com.frontier42.keepass.ant.KeepassStreamReader;

public class DatabaseTest2 extends TestCase {

	public void testReadAsStAX() throws Exception {
		KeepassStreamReader reader=new KeepassStreamReader();
		URL url = this.getClass().getResource("/test.kdbx");
		KeepassDatabase db=reader.load(url.openStream(), "123!AbC");

		for (KeepassGroup group:db.getGroups()){
			for (KeepassEntry entry:group.getEntries()){
				System.out.println(group.getName()+"."+entry.getTitle()+".username="+entry.getUsername());
				System.out.println(group.getName()+"."+entry.getTitle()+".password="+entry.getPassword());
			}
		}
		
	}
}
