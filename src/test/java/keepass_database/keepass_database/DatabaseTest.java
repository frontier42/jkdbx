package keepass_database.keepass_database;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Arrays;
import java.util.Properties;

import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

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

    public void loadProperties(Properties props,  Element parent){
    	NodeList entries=parent.getChildNodes();
    	if (entries!=null){
			for (int i=0; i<entries.getLength();i++){
				Node node=entries.item(i);
				if (node instanceof Element && "Entry".equalsIgnoreCase(node.getLocalName())){
					Element entry=(Element) node;
					NodeList fields=entry.getChildNodes();
					String title=null;
					String username=null;
					String password=null;
					for (int j=0; j<fields.getLength();j++){
						Node field=fields.item(j);
						if (field instanceof Element && "String".equalsIgnoreCase(field.getLocalName())){
							Element fieldKey=(Element) ((Element) field).getElementsByTagName("Key").item(0);
							Element fieldValue=(Element) ((Element) field).getElementsByTagName("Value").item(0);
							
							if (fieldKey.getTextContent().equals("Title")){
								title=fieldValue.getTextContent();
							}else if (fieldKey.getTextContent().equals("Password")){
								password=fieldValue.getTextContent();
							}else if (fieldKey.getTextContent().equals("UserName")){
								username=fieldValue.getTextContent();
							}
								
						}
					}
					
					System.out.println("title:"+title);
					if ((username!=null && username.length()>0) && (password!=null && password.length()>0)){
						props.put(title+".username", username);
						props.put(title+".password", password);
					}else if (username!=null && username.length()>0){
						props.put(title, username);
					}else if (password!=null && password.length()>0){
						props.put(title, password);
					}
				}
			}
    	}
    }
    /**
     * Rigourous Test :-)
     * @throws IOException 
     * @throws Exception 
     */
    public void testApp() throws Exception
    {
    	String masterKey="123!AbC";
        URL url=this.getClass().getResource("/test.kdbx");
        System.out.println("url:"+url);
        File xmlFile=new File(new File(url.toURI()).getParentFile().getParentFile().getParentFile(), "target/output.kdbx.xml");
        InputStream stream=url.openStream();
        Document doc=KeepassDatabase.loadDocument(stream, masterKey);
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        System.out.println(xmlFile);
        Result output = new StreamResult(xmlFile);
        Source input = new DOMSource(doc);
        transformer.transform(input, output);
        
		XPathFactory xPathfactory = XPathFactory.newInstance();
		XPath xpath = xPathfactory.newXPath();
		Element eSytem=(Element) xpath.compile("//Group[Name='System']").evaluate(doc, XPathConstants.NODE);
		Element eOS=(Element) xpath.compile("Group[Name='windows']").evaluate(eSytem, XPathConstants.NODE);
		Element eApp=(Element) xpath.compile("//Group[Name='Applications']/Group[Name='IPS']").evaluate(doc, XPathConstants.NODE);
		
		Properties props=new Properties();
		System.out.println("Loading System");
		loadProperties(props, eSytem);
		System.out.println("Loading OS");
		loadProperties(props, eOS);
		System.out.println("Loading App");
		loadProperties(props, eApp);
		
		System.out.println(props);
		System.out.println(eSytem);
		System.out.println(eOS);
		System.out.println(eApp);
		
    }
    @SuppressWarnings("restriction")
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
