import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
































import MITM.DataStructures.CertificateKey;
import MITM.DataStructures.*;

public class CertificateManager {

	private static final String BC = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
	
	private final static String ROOT_CERTIFICATE_ALIAS = "root";
	private final static String CHILD_CERTIFICATE_ALIAS = "child";
	
	private File _storeDirectory;
	private File _rootCertificateFile;
	private File _rootKeyStoreFile;
	private String _rootKeyStorePassword;
	private PrivateKey _rootPrivateKey;
	private X509Certificate _rootCertificate;
	
	private String _childKeyStorePassword;
	private char[] _childKeyStorePasswordArray;
	
	private Map<String, CertificateKey> _certificateKeyMap;
	private Map<CertificateKey, CertificateInfo> _certificateMap;
	
	private long _certificateSerialId;
	private Object _certificateSerialIdSync;
	
	public CertificateManager() {

		_storeDirectory = new File("store");
		_rootCertificateFile = new File("root.cer");
		_rootKeyStoreFile = new File("root.keystore");
		_rootKeyStorePassword = "password";
		
		_childKeyStorePassword = "password";
		_childKeyStorePasswordArray = _childKeyStorePassword.toCharArray();
		
		_certificateKeyMap = new ConcurrentHashMap<String, CertificateKey>();
		_certificateMap = new ConcurrentHashMap<CertificateKey, CertificateInfo>();
		
		_certificateSerialIdSync = new Object();
		
		if(!_storeDirectory.exists()){
			_storeDirectory.mkdirs();
		}
	}

	public void setup() {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		if (!_rootCertificateFile.exists()) {
			createRootCertificate();
		}
		try {
			 loadRootCertificate();
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void createRootCertificate() {

		try {
		
			KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
			kpGen.initialize(2048, new SecureRandom());
			KeyPair pair = kpGen.generateKeyPair();

			// Generate self-signed certificate
			X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
			nameBuilder.addRDN(BCStyle.CN, "Emerging Markets Communications Global CA");
			nameBuilder.addRDN(BCStyle.O, "Emerging Markets Communications");
			nameBuilder.addRDN(BCStyle.L, "Miami");
			nameBuilder.addRDN(BCStyle.ST, "Florida");
			nameBuilder.addRDN(BCStyle.C, "US");
			
			Date notBefore = new Date(System.currentTimeMillis() - 86400 * 1000);
			Date notAfter = new Date(System.currentTimeMillis() + 31536000 * 1000);
			BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

			X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(nameBuilder.build(), serial, notBefore, notAfter, nameBuilder.build(),
					pair.getPublic());
			
//			KeyPurposeId[] purposeIds = new KeyPurposeId[] { KeyPurposeId.id_kp_capwapAC , KeyPurposeId.id_kp_capwapWTP , KeyPurposeId.id_kp_clientAuth , KeyPurposeId.id_kp_codeSigning
//					, KeyPurposeId.id_kp_dvcs , KeyPurposeId.id_kp_eapOverLAN , KeyPurposeId.id_kp_eapOverPPP , KeyPurposeId.id_kp_emailProtection
//					, KeyPurposeId.id_kp_ipsecEndSystem , KeyPurposeId.id_kp_ipsecIKE , KeyPurposeId.id_kp_ipsecTunnel
//					, KeyPurposeId.id_kp_ipsecUser , KeyPurposeId.id_kp_OCSPSigning , KeyPurposeId.id_kp_sbgpCertAAServerAuth
//					, KeyPurposeId.id_kp_scvp_responder , KeyPurposeId.id_kp_scvpClient , KeyPurposeId.id_kp_scvpServer
//					, KeyPurposeId.id_kp_serverAuth , KeyPurposeId.id_kp_smartcardlogon , KeyPurposeId.id_kp_timeStamping };
			
			certGen.addExtension( Extension.keyUsage, false,
				new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
			
			// Add CA type basic constraints. Except this Firefox will not allow import.
			certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
			
			ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(pair.getPrivate());
			X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));
			cert.checkValidity(new Date());
			cert.verify(cert.getPublicKey());

			// Save to JKS
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null);
			keyStore.setKeyEntry(ROOT_CERTIFICATE_ALIAS, pair.getPrivate(), _rootKeyStorePassword.toCharArray(), new java.security.cert.Certificate[] { cert });
			FileOutputStream fos = new FileOutputStream(_rootKeyStoreFile);
			keyStore.store(fos, _rootKeyStorePassword.toCharArray());
			fos.close();
			
			// Save as .cer file
			fos = new FileOutputStream(_rootCertificateFile);
			fos.write(cert.getEncoded());
			fos.close();
			
		} catch (Throwable t) {
			t.printStackTrace();
			throw new RuntimeException("Failed to generate root certificate!", t);
		}
	}
	
	private void loadRootCertificate() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException{
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		FileInputStream fis = new FileInputStream(_rootKeyStoreFile);
		keyStore.load(fis, _rootKeyStorePassword.toCharArray());
		fis.close();
		
		_rootCertificate = (X509Certificate) keyStore.getCertificate(ROOT_CERTIFICATE_ALIAS);
		_rootPrivateKey = (PrivateKey)keyStore.getKey(ROOT_CERTIFICATE_ALIAS, _rootKeyStorePassword.toCharArray());
	}
	
	public boolean createSignedCertificate(CertificateInfo certificateInfo, X509Certificate originalCertificate) throws OperatorCreationException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, KeyStoreException{
		
		JcaX509CertificateHolder originalCertificateHolder = new JcaX509CertificateHolder(originalCertificate);
		
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
		kpGen.initialize(2048, new SecureRandom());
		KeyPair pair = kpGen.generateKeyPair();

		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(_rootCertificate, new BigInteger(Long.toString(System.currentTimeMillis())), originalCertificateHolder.getNotBefore() , originalCertificateHolder.getNotAfter(), originalCertificateHolder.getSubject(),
				pair.getPublic());
		if(originalCertificateHolder.hasExtensions()){
			Set extensionOIDSet = originalCertificateHolder.getCriticalExtensionOIDs();
			for (Object object : extensionOIDSet) {
				ASN1ObjectIdentifier extensionOID = (ASN1ObjectIdentifier) object;
				certGen.addExtension(extensionOID, true, originalCertificateHolder.getExtension(extensionOID).getParsedValue());
			}
			
			extensionOIDSet = originalCertificateHolder.getNonCriticalExtensionOIDs();
			for (Object object : extensionOIDSet) {
				ASN1ObjectIdentifier extensionOID = (ASN1ObjectIdentifier) object;
				certGen.addExtension(extensionOID, false, originalCertificateHolder.getExtension(extensionOID).getParsedValue());
			}
		}
		
		ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(_rootPrivateKey);
		X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certGen.build(sigGen));
		
		cert.verify(_rootCertificate.getPublicKey());
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null);
		// keyStore.setCertificateEntry(ROOT_CERTIFICATE_ALIAS, _rootCertificate);
		keyStore.setKeyEntry(CHILD_CERTIFICATE_ALIAS, pair.getPrivate(), _childKeyStorePasswordArray, new java.security.cert.Certificate[] { cert, _rootCertificate});
		certificateInfo.sslSocketFactory = createSSLSocketFactory(keyStore);
		
		FileOutputStream fos = new FileOutputStream(new File(_storeDirectory, certificateInfo.id + ".keystore" ));
		keyStore.store(fos, _childKeyStorePasswordArray);
		fos.close();
		
		fos = new FileOutputStream(new File(_storeDirectory, certificateInfo.id + ".cer" ));
		fos.write(cert.getEncoded());
		fos.close();
		
		return true;
	}
	
	public void getOrCreateCertificate(CertificateGetParams certificateGetParams) throws UnknownHostException, IOException, InvalidKeyException, OperatorCreationException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, KeyStoreException{
		
		 String hostAndPort = getHostAndPort(certificateGetParams.requestUrl);
		 CertificateKey certificateKey = getCertificateKey(hostAndPort);
		 if(certificateKey == null){
			 X509Certificate serverCertificate = getX509Certificate(certificateGetParams.requestUrl);
			 certificateKey = new CertificateKey(serverCertificate);
			 CertificateKey existingCertificateKey = _certificateKeyMap.putIfAbsent(hostAndPort, certificateKey);
			 if(existingCertificateKey != null){
				 certificateKey = existingCertificateKey;
			 }
		 }
		 
		 CertificateInfo certificateInfo = getCertificateInfo(certificateKey);
		 if(certificateInfo == null){
			 long certificateSerialId;
			 synchronized (_certificateSerialIdSync) {
				 certificateSerialId = ++_certificateSerialId;
			 }
			 certificateInfo = new CertificateInfo(certificateSerialId);
			 X509Certificate serverCertificate = getX509Certificate(certificateGetParams.requestUrl);
			 createSignedCertificate(certificateInfo, serverCertificate);
			 CertificateInfo existingCertificateInfo = _certificateMap.putIfAbsent(certificateKey, certificateInfo);
			 if(existingCertificateInfo != null){
				 certificateInfo = existingCertificateInfo;
			 }
		 }
		 loadCertificateInfo(certificateInfo);
		 
		 certificateGetParams.certificateInfo = certificateInfo;
	}
	
	private void loadCertificateInfo(CertificateInfo certificateInfo) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		if(certificateInfo.sslSocketFactory == null){
			synchronized (certificateInfo) {
				if(certificateInfo.sslSocketFactory == null){
					
					KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
					FileInputStream fis = new FileInputStream(new File(_storeDirectory, certificateInfo.id + ".keystore"));
					keyStore.load(fis, _childKeyStorePasswordArray);
					fis.close();
					
					certificateInfo.sslSocketFactory = createSSLSocketFactory(keyStore);
				}
			}
			
		}
	}
	
	private SSLSocketFactory createSSLSocketFactory(KeyStore keyStore){
		try {
			KeyManagerFactory keyManagerFactory = KeyManagerFactory
					.getInstance(KeyManagerFactory.getDefaultAlgorithm());

			SSLContext sslContext = SSLContext.getInstance("SSL");
			
			keyManagerFactory.init(keyStore, _childKeyStorePasswordArray);
			sslContext.init(keyManagerFactory.getKeyManagers(),
					new TrustManager[] { new TrustEveryone() }, null);
			
			return sslContext.getSocketFactory();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	private X509Certificate getX509Certificate(URL url) throws UnknownHostException, IOException{
		
		Socket webSocket = new Socket(url.getHost(),getPort(url));
		
		SSLSocketFactory sslSf = (SSLSocketFactory) SSLSocketFactory
				.getDefault();
		SSLSocket webSslSocket = (SSLSocket) sslSf.createSocket(
				webSocket, url.getHost(),getPort(url), false);
		webSslSocket.startHandshake();
		return ((X509Certificate) (webSslSocket
				.getSession().getPeerCertificates()[0]));
		
	}
	
	private CertificateInfo getCertificateInfo(CertificateKey certificateKey ){
		return _certificateMap.get(certificateKey);
	}
	
	private CertificateKey getCertificateKey(String hostAndPort){
		return _certificateKeyMap.get(hostAndPort);
	}

	public static int getPort(URL url){
		int port = url.getPort();
		if(port == -1){
			return url.getDefaultPort();
		}
		else{
			return port;
		}
	}
	
	public static String getHostAndPort(URL url){
		return getHostAndPort(url.getHost(), getPort(url));
	}
	
	public static String getHostAndPort(String host, int port){
		return host + ":" + port;
	}
}

/**
 * We're carrying out a MITM attack, we don't care whether the cert chains are
 * trusted or not ;-)
 *
 */
class TrustEveryone implements X509TrustManager {
	public java.security.cert.X509Certificate[] getAcceptedIssuers() {
		return null;
	}

	public void checkClientTrusted(java.security.cert.X509Certificate[] arg0,
			String arg1) throws CertificateException {
		// TODO Auto-generated method stub

	}

	public void checkServerTrusted(java.security.cert.X509Certificate[] arg0,
			String arg1) throws CertificateException {
		// TODO Auto-generated method stub

	}
}
