package keepass_database.keepass_database;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Arrays;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import com.frontier42.keepass.KeepassDatabase;

/**
 * Unit test for simple App.
 */
public class DatabaseTest 
    extends TestCase
{
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public DatabaseTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( DatabaseTest.class );
    }

    /**
     * Rigourous Test :-)
     * @throws IOException 
     * @throws Exception 
     */
    public void testApp() throws Exception
    {
    	String masterKey="123!AbC";
        KeepassDatabase db=new KeepassDatabase();
        URL url=new URL("file:/C:/Data/projects/keepass-database/keepass-database/src/test/resources/test.kdbx");
        System.out.println("url:"+url);
        InputStream stream=url.openStream();
        db.loadDocument(stream, masterKey);
    }
    public void testUUID() throws Exception{
    	String rawString="Fp5HWPqEL0uDezfoANQXLA==";
    	byte[] decodedBytes=javax.xml.bind.DatatypeConverter.parseBase64Binary(rawString);
    	String hexValue=javax.xml.bind.DatatypeConverter.printHexBinary(decodedBytes);
    	byte[] hexBytes=javax.xml.bind.DatatypeConverter.parseHexBinary(hexValue);
    	String encodedString=javax.xml.bind.DatatypeConverter.printBase64Binary(hexBytes);
    	
    	assertEquals(rawString, encodedString);
    	assertEquals("169E4758FA842F4B837B37E800D4172C", hexValue);
    	assertTrue(Arrays.equals(decodedBytes, hexBytes));
    }
    
}
