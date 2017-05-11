import ByteCache.ByteCacheManager;
import ByteCache.DataToHashList;
import httpstream.HttpInputStream;
import httpstream.HttpOutputStream;
import httpstream.exceptions.HeadersSizeExceedException;
import httpstream.exceptions.RequestResponseLineSizeExceedException;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.operator.OperatorCreationException;

import MITM.DataStructures.CertificateGetParams;



public class ProxyServer {

	int _port;
	ServerSocket _serverSocket;

	CertificateManager _certificateManager;
	private static ThreadLocal<DataToHashList> _dthl = new ThreadLocal<DataToHashList>();
	public ByteCacheManager 	_bcm = ByteCacheManager.getInstance();
	
	public ProxyServer(int port, CertificateManager certificateManager) {
		this._port = port;
		this._certificateManager = certificateManager;
	}

	public void startListening() throws IOException, KeyManagementException,
			UnrecoverableKeyException, NoSuchAlgorithmException,
			CertificateException, KeyStoreException {

		_serverSocket = new ServerSocket(this._port);

		while (true) {
			final Socket socket = _serverSocket.accept();

			Thread thread = new Thread(new Runnable() {

				public void run() {
					try {
						runSocket(socket);
					} 
					catch(EOFException e){
						
					}
					catch (Exception e) {
						e.printStackTrace();
					}
				}
			});

			thread.start();
		}
	}

	void runSocket(Socket clientSocket) throws IOException,
			CertificateParsingException, HeadersSizeExceedException, RequestResponseLineSizeExceedException {

		int bufferSize = 1024;

		InputStream clientInputStream = clientSocket.getInputStream();
		OutputStream clientOutputStream = clientSocket.getOutputStream();

		HttpInputStream clientHttpInputStream = new HttpInputStream(
				clientInputStream, bufferSize);
		HttpOutputStream clientHttpOutputStream = new HttpOutputStream(
				clientOutputStream);

		String currentWebHost = "";
		int currentWebPort = 0;

		Socket webSocket = null;
		InputStream webServerInputStream = null;
		OutputStream webServerOutputStream = null;

		HttpInputStream webServerHttpInputStream = null;
		HttpOutputStream webServerHttpOutputStream = null;

		boolean isLocked = false;
		byte[] buffer = new byte[bufferSize];

		while (true) {

			String requestLine = clientHttpInputStream.readRequestLine();
			String[] requestLinePartsStrings = requestLine.split(" ");

			System.out.println(requestLine);

			String httpMethod = requestLinePartsStrings[0].toUpperCase();
			if (!requestLinePartsStrings[1].toUpperCase().startsWith("HTTP")) {
				if (httpMethod.equals("CONNECT"))
					requestLinePartsStrings[1] = "https://"
							+ requestLinePartsStrings[1];
				else {
					requestLinePartsStrings[1] = "http://"
							+ requestLinePartsStrings[1];
				}
			}

			if (!isLocked) {

				URL requestUrl = new URL(requestLinePartsStrings[1]);
				int requestPort = requestUrl.getPort();
				if (requestPort <= 0) {
					String requestProtocol = requestUrl.getProtocol()
							.toLowerCase();
					if (requestProtocol.equals("https")) {
						requestPort = 443;
					} else if (requestProtocol.equals("http")) {
						requestPort = 80;
					}
				}

				if (!requestUrl.getHost().equals(currentWebHost)
						|| requestPort != currentWebPort) {
					if (webSocket != null) {
						webSocket.close();
					}

					currentWebHost = requestUrl.getHost();
					currentWebPort = requestPort;

					webSocket = new Socket(currentWebHost, currentWebPort);
					webServerInputStream = webSocket.getInputStream();
					webServerOutputStream = webSocket.getOutputStream();

					webServerHttpInputStream = new HttpInputStream(
							webServerInputStream, bufferSize);
					webServerHttpOutputStream = new HttpOutputStream(
							webServerOutputStream);
				}
			}

			if (httpMethod.equals("GET") || httpMethod.equals("POST")) {
				Map<String, String> requestHeaders = new HashMap<String, String>();
				clientHttpInputStream.readHeaders(requestHeaders);

				// String modifiedRequestLine = requestLine.replace(
				// requestUrl.getProtocol() + "://"
				// + requestHeaders.get("Host").trim(), "");
				webServerHttpOutputStream.writeLine(requestLine);
				webServerHttpOutputStream.writeHeaders(requestHeaders);

				if (httpMethod.equals("POST")) {
					// Handle content-upload.
					handleDataUpload();
				}

				String responseLine = webServerHttpInputStream.readRequestLine();
				Map<String, String> responseHeaders = new HashMap<String, String>();
				webServerHttpInputStream.readHeaders(responseHeaders);
				System.out.println("Response Header:\n"+ responseHeaders);

				clientHttpOutputStream.writeLine(responseLine);
				clientHttpOutputStream.writeHeaders(responseHeaders);

				handleResponseBody(responseHeaders, clientHttpOutputStream,
						webServerHttpInputStream, buffer, requestLinePartsStrings[1]);

			} else if (httpMethod.equals("CONNECT")) {

				Map<String, String> requestHeaders = new HashMap<String, String>();
				clientHttpInputStream.readHeaders(requestHeaders);

				clientHttpOutputStream
						.writeLine("HTTP/1.1 200 Connection established");
				clientHttpOutputStream
						.writeHeaders(new HashMap<String, String>());

				long startTime = System.nanoTime();

				// Now actual MITM logic starts for https.
				SSLSocketFactory sslSf = (SSLSocketFactory) SSLSocketFactory
						.getDefault();
				final SSLSocket webSslSocket = (SSLSocket) sslSf.createSocket(
						webSocket, currentWebHost, currentWebPort, false);
				webSslSocket.startHandshake();
				
				webServerInputStream = webSslSocket.getInputStream();
				webServerOutputStream = webSslSocket.getOutputStream();

				webServerHttpInputStream = new HttpInputStream(
						webServerInputStream, bufferSize);
				webServerHttpOutputStream = new HttpOutputStream(
						webServerOutputStream);

				// Client socket.

				SSLSocket clientSslSocket = getSelfSignServerSocket(
						clientSocket, currentWebHost);

				clientSslSocket.setUseClientMode(false);
				clientSslSocket.startHandshake();

				clientSocket = clientSslSocket;
				clientInputStream = clientSocket.getInputStream();
				clientOutputStream = clientSocket.getOutputStream();

				clientHttpInputStream = new HttpInputStream(clientInputStream,
						bufferSize);
				clientHttpOutputStream = new HttpOutputStream(
						clientOutputStream);

				long timeTaken = System.nanoTime() - startTime;
				double timeTakenInMiliSeconds = ((double) timeTaken) / 1000000;
				System.out.println("Handshake TimeTaken : "
						+ timeTakenInMiliSeconds);

				isLocked = true;
			}
			_bcm.show();
		}

	}
	
	SSLSocket getSelfSignServerSocket(Socket clientSocket, String host) throws IOException {
		SSLSocketFactory sslSocketFactory;
		try {
			try {
				
				CertificateGetParams certificateGetParams = new CertificateGetParams();
				certificateGetParams.requestUrl = new URL("https://" + host);
				_certificateManager.getOrCreateCertificate(certificateGetParams);
				
				sslSocketFactory =  certificateGetParams.certificateInfo.sslSocketFactory;
				InetSocketAddress socketAddress = (InetSocketAddress)clientSocket.getRemoteSocketAddress();
				
				return (SSLSocket) sslSocketFactory.createSocket(clientSocket,
						socketAddress.getHostString(), socketAddress.getPort(), false);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (OperatorCreationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	void handleDataUpload() {

	}

	int handleResponseBody(Map<String, String> responseHeaders,
			HttpOutputStream clientHttpOutputStream,
			HttpInputStream webServerHttpInputStream, byte[] buffer, String url)
			throws IOException, RequestResponseLineSizeExceedException {

		int returnValue = 0;
		String ctype = "";
		_dthl.set(new DataToHashList());

		if (responseHeaders.containsKey("Content-Type")) {
			ctype = responseHeaders.get("Content-Type");
		}

		if (responseHeaders.containsKey("Transfer-Encoding")
				&& responseHeaders.get("Transfer-Encoding").trim()
						.equals("chunked")) {
			returnValue = handleChunkedBody(clientHttpOutputStream,
					webServerHttpInputStream, buffer, ctype);
		} else {
			returnValue = handleNormalBody(clientHttpOutputStream,
					webServerHttpInputStream, buffer, responseHeaders, ctype);
		}
		_dthl.get().computeHashlist();
		_bcm.insertURLHash(url, _dthl.get(), ctype);
		_dthl.get().reset();
		return returnValue;
	}

	int handleNormalBody(HttpOutputStream clientHttpOutputStream,
			HttpInputStream webServerHttpInputStream, byte[] buffer,
			Map<String, String> responseHeaders, String ctype) throws IOException {

		if (responseHeaders.containsKey("Content-Length")) {
			String value = responseHeaders.get("Content-Length");
			int contentLength = Integer.parseInt(value.trim());

			Read(clientHttpOutputStream, webServerHttpInputStream,
					contentLength, buffer);
			return contentLength;
		} else {
			Read(clientHttpOutputStream, webServerHttpInputStream,
					Integer.MAX_VALUE, buffer);
			return 0;
		}
	}

	int handleChunkedBody(HttpOutputStream clientHttpOutputStream,
			HttpInputStream webServerHttpInputStream, byte[] buffer, String ctype)
			throws IOException, RequestResponseLineSizeExceedException {
		// Read Chunked Body.
		int contentLength = 0;

		while (true) {
			String chunkSizeLine = webServerHttpInputStream.readRequestLine();
			int chunkSize = Integer.parseInt(chunkSizeLine, 16);
			clientHttpOutputStream.writeLine(chunkSizeLine);

			if (chunkSize <= 0)
				break;

			contentLength += chunkSize;

			Read(clientHttpOutputStream, webServerHttpInputStream, chunkSize,
					buffer);

			String line = webServerHttpInputStream.readRequestLine();
			clientHttpOutputStream.writeLine(line);
		}

		// Read Entity Headers
		while (true) {
			String header = webServerHttpInputStream.readRequestLine();
			clientHttpOutputStream.writeLine(header);
			if (header.equals(""))
				break;
		}

		return contentLength;
	}

	public static void Read(HttpOutputStream clientHttpOutputStream,
			HttpInputStream webServerHttpInputStream, int count, byte[] buffer)
			throws IOException {

		int bufferSize = buffer.length;
		int totalbytes = 0;
		while (count > 0) {
			int bytesRead = webServerHttpInputStream.read(buffer, 0,
					Math.min(count, bufferSize));

			if (bytesRead <= 0)
				break;
			_dthl.get().insertBuffer(buffer, bytesRead);
			count -= bytesRead;
			clientHttpOutputStream.write(buffer, 0, bytesRead);
		}
	}
}


