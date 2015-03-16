package com.frontier42.keepass.keepass.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.frontier42.keepass.KeepassDatabase;
import com.frontier42.keepass.KeepassEntry;
import com.frontier42.keepass.KeepassGroup;
import com.frontier42.keepass.ant.KeepassStreamReader;

public class KeepassServlet extends HttpServlet {
	private static final long serialVersionUID = -5517604609122789055L;
	AtomicReference<KeepassDatabase> kdb = new AtomicReference<KeepassDatabase>();
	
	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
	}
	private String getProperty(String name){
		return System.getProperty(name);
	}
	public void open(String password) throws ServletException{
		FileInputStream istream=null;
		try{
			File file=new File(getProperty("keepass-file"));
			getServletContext().log("Loading database ["+file.getAbsolutePath()+"] ...");
			KeepassStreamReader reader=new KeepassStreamReader();
			istream=new FileInputStream(file);
			kdb.set(reader.load(istream, password));
			getServletContext().log("Database Successfully Loaded.");
		}catch(Exception ex){
			throw new ServletException("Error loading keepass database.",ex);
		}finally{
			if (istream!=null)try{istream.close();} catch (IOException e) {}finally{};
		}
	}
	private void writeEntries(KeepassGroup group, Properties properties){
		if (group!=null){
			for (KeepassEntry entry: group.getEntries()) {
				String username=entry.getUsername().toString();
				String password=entry.getPassword().toString();
				if (username.length()>0 && password.length()>0){
					properties.setProperty(entry.getTitle().toLowerCase()+".username", username);
					properties.setProperty(entry.getTitle().toLowerCase()+".password", password);
				}else if (username.length()>0){
					properties.setProperty(entry.getTitle().toLowerCase(), username);
				}else if (password.length()>0){
					properties.setProperty(entry.getTitle().toLowerCase(), password);
				}
			}
		}
	}
	private void renderUnlockForm(HttpServletRequest req, HttpServletResponse resp) throws IOException{
		resp.setContentType("text/html");
		renderUnlockForm(req, resp.getWriter(), resp);
		resp.flushBuffer();
		
	}
	
	private void renderUnlockForm(HttpServletRequest req, PrintWriter w, HttpServletResponse resp){
		w.println("<html>");
		w.println("<body>");
		w.println("<form action=\""+resp.encodeURL( req.getRequestURI())+"\" method=\"POST\">");
		w.println("<input type=\"password\" name=\"password\">");
		w.println("<br/>");
		w.println("<input type=\"submit\" value=\"submit\">");
		w.println("</form>");
		w.println("</body>");
		w.println("</html>");
		w.flush();
	}
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		if (req.getPathInfo().endsWith("/load.html")){
			open(req.getParameter("password"));
		}
	}
	private void writeEntries(KeepassDatabase db, HttpServletRequest req, HttpServletResponse resp) throws IOException{
		String appName=req.getParameter("app.name");
		X509Certificate[] certs = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");

		Properties properties=new Properties();
		InetAddress remote=InetAddress.getByName(req.getRemoteAddr());
		String remoteHostname=remote.getHostName();
		String remoteFqdn=remote.getCanonicalHostName();
		
		if ("true".equalsIgnoreCase(getProperty("check-cert-subject"))){
			LdapName certSubject;
			boolean matchesHostName=false;
			
			try {
				certSubject=new LdapName(certs[0].getSubjectX500Principal().getName(X500Principal.RFC2253));
			} catch (InvalidNameException e) {
				throw new IOException(e);
			}
			
			for(Rdn rdn:certSubject.getRdns()){
				if (rdn.getType().equalsIgnoreCase("CN")){
					String cn=rdn.getValue().toString();
					matchesHostName=remoteFqdn.equalsIgnoreCase(cn);
					break;
				}
			}
			
			if (!matchesHostName){
				throw new IOException("Invalid certificate");
			}
		}
		
		
		properties.setProperty("remote.hostname.fqdn", remoteFqdn);
		properties.setProperty("remote.hostname",remoteHostname);
		KeepassGroup root=db.getRootGroup();
		KeepassGroup group0=root.getGroup("default");
		writeEntries(group0, properties);
		
		KeepassGroup groupHosts=group0.getGroup("hosts");
		if (groupHosts!=null){
			KeepassGroup hostGroup=groupHosts.getGroup(remoteHostname);
			writeEntries(hostGroup, properties);
		}
		String sourceOsFamily=properties.getProperty("os.family");
		if (sourceOsFamily!=null){
			KeepassGroup familyGroup=group0.getGroup(sourceOsFamily);
			writeEntries(familyGroup, properties);
		}
		KeepassGroup group1=root.getGroup("applications");
		if (group1!=null){
			KeepassGroup appGroup=group1.getGroup(appName);
			writeEntries(appGroup, properties);
		}
		resp.setContentType("text/plain");
		OutputStream out=resp.getOutputStream();
		properties.setProperty("state", "1");
		properties.store(out, "No Comments");
	}
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		if (req.getPathInfo().endsWith("/load.html")){
			kdb.set(null);
			renderUnlockForm(req, resp);
		}else if (req.getPathInfo().endsWith("/unload.html")){
			kdb.set(null); 
		}else if (req.getPathInfo().endsWith("/gc.html")){
			Runtime.getRuntime().gc();
		}else if (req.getPathInfo().endsWith("/get.properties")){
			
			KeepassDatabase db=kdb.get();
			if (db!=null){
				writeEntries(db, req, resp);
			}else{
				resp.setContentType("text/plain");
				PrintWriter w=resp.getWriter();
				Properties prop=new Properties();
				prop.setProperty("state", "0");
				prop.store(w, "Not loaded");
			}
		}
	}
}
