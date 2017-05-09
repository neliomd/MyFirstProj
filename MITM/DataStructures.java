package MITM;

import java.net.URL;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLSocketFactory;

public class DataStructures {

	public static class CertificateKey {

		private final long _serialNumber;
		private final String _issuer;
		
		public CertificateKey(long serialNumber, String issuer) {
			_serialNumber = serialNumber;
			_issuer = issuer;
		}

		public CertificateKey(X509Certificate x509Certificate) {
			_serialNumber = x509Certificate.getSerialNumber().longValue();
			_issuer = x509Certificate.getIssuerX500Principal().getName();
		}
		
		@Override
		public boolean equals(Object o) {
			if (this == o)
				return true;
			if (!(o instanceof CertificateKey))
				return false;
			CertificateKey certificateKey = (CertificateKey) o;
			return _serialNumber == certificateKey._serialNumber && _issuer.equals(certificateKey._issuer);
		}

		@Override
		public int hashCode() {
			return (int) (_serialNumber + _issuer.hashCode());
		}
	}

	public static class CertificateInfo {
		public long id;
		public SSLSocketFactory sslSocketFactory;
		public CertificateInfo(){
			
		}
		
		public CertificateInfo(long id){
			this.id = id;
		}
	}
	
	public static class CertificateGetParams{
		public URL requestUrl;
		public CertificateKey certificateKey;
		public CertificateInfo certificateInfo;
	}

}
