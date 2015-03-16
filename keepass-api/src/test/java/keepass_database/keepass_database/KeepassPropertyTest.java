package keepass_database.keepass_database;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;

import junit.framework.TestCase;

import com.frontier42.keepass.ant.UrlStreamHelper;

public class KeepassPropertyTest extends TestCase {

	public void testOpenStream() throws MalformedURLException, IOException,
			GeneralSecurityException {
		try {
			UrlStreamHelper helper = new UrlStreamHelper();
			helper.setTruststore(new File("c:/temp/client-truststore.jks"));
			helper.setTruststorePassword("changeit");
			helper.setKeystore(new File("c:/temp/client-keystore.jks"));
			helper.setKeystorePassword("changeit");
			InputStream stream= helper.openStream(new URL("https://localhost/webapp/index.html"));
			InputStreamReader is = new InputStreamReader(stream);
			BufferedReader br = new BufferedReader(is);
			String read = br.readLine();
			while((read=br.readLine()) != null) {
			    System.out.println(read);
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
}
