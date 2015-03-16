package com.frontier42.keepass.keepass.server;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;

/**
 * Hello world!
 *
 */
//http://www.smartjava.org/content/embedded-jetty-client-certificates
public class KeepassServer {
	public static void main(String[] args) throws Exception {
		Server server = new Server();

		
		HttpConfiguration https = new HttpConfiguration();
		https.addCustomizer(new SecureRequestCustomizer());


		List<Connector> connectors=new ArrayList<Connector>();
		
		if (System.getProperty("https.port") != null){
			SslContextFactory sslContextFactory = new SslContextFactory();
			sslContextFactory.setKeyStorePath(System.getProperty("keepass.server.keyStore"));
			sslContextFactory.setKeyStorePassword(System.getProperty("keepass.server.keyStorePassword","changeit"));
			sslContextFactory.setTrustStorePath(System.getProperty("keepass.server.trustStore"));
			sslContextFactory.setTrustStorePassword(System.getProperty("keepass.server.trustStorePassword","changeit"));
			//sslContextFactory.setTrustAll(true);
			//sslContextFactory.setKeyManagerPassword("changeit");
			sslContextFactory.setWantClientAuth(true);
			sslContextFactory.setNeedClientAuth(true);
			sslContextFactory.setIncludeProtocols("TLSv1.2");
			sslContextFactory.setIncludeCipherSuites("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
			
			ServerConnector httpsConnector = new ServerConnector(server, new SslConnectionFactory(sslContextFactory, "http/1.1"), new HttpConnectionFactory(https));
			httpsConnector.setPort(Integer.parseInt(System.getProperty("https.port", "443")));
			httpsConnector.setHost(System.getProperty("https.host", null));
			connectors.add(httpsConnector);
		}
		
		if (System.getProperty("http.port") != null){
			ServerConnector httpConnector = new ServerConnector(server, new HttpConnectionFactory());
			httpConnector.setPort(Integer.parseInt(System.getProperty("http.port", "80")));
			httpConnector.setHost(System.getProperty("http.host", null));
	        connectors.add(httpConnector);
		}
		/*
		ServerConnector httpConnector = new ServerConnector(server, new HttpConnectionFactory());
        httpConnector.setPort(80);
        connectors.add(httpConnector);
        */
		server.setConnectors(connectors.toArray(new Connector[]{}));
		
		
		ServletContextHandler context = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
		//context.addServlet(new ServletHolder KeepassServlet.class, "/keepass/*");
		context.addServlet(KeepassServlet.class, "/keepass/*");
		context.setContextPath("/");
        server.setHandler(context);
        
		System.out.println("Starting...");
		server.start();
		server.join();
	}
}
