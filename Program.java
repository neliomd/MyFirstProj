import java.io.IOException;
import java.net.Socket;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.operator.OperatorCreationException;


public class Program {

	public static void main(String[] args) throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
		
		URL url = new URL("http://www.stackoverflow.com/Adf/def?Asdf");
		System.out.println(url.getPath());
		System.out.println(url.getFile());
		
//		Socket webSocket = new Socket("www.google.co.in", 443);
//		
//		SSLSocketFactory sslSf = (SSLSocketFactory) SSLSocketFactory
//				.getDefault();
//		final SSLSocket webSslSocket = (SSLSocket) sslSf.createSocket(
//				webSocket, "www.google.co.in", 443, false);
//		webSslSocket.startHandshake();
		
		CertificateManager certificateManager = new CertificateManager();
		certificateManager.setup();
		
		ProxyServer proxyServer = new ProxyServer(3933, certificateManager);
		proxyServer.startListening();
	}

}
