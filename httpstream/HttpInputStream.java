package httpstream;

import httpstream.exceptions.HeadersSizeExceedException;
import httpstream.exceptions.RequestResponseLineSizeExceedException;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.Charset;
import java.util.Map;

import javax.naming.SizeLimitExceededException;

public class HttpInputStream {

	private static class GetLineOutputParams {
		boolean found;
	}

	private int _bufferedDataStartIndex;
	private int _bufferedDataEndIndex = -1;

	private byte[] _bufferedData;

	private InputStream _inputStream;
	
	private Charset _currentCharset;

	private boolean _ignoreSocketReadTimeoutException = true;

	private static int _requestLineMaxLength = 8 * 1024; // 8 KB
	private static int _responseLineMaxLength = 8 * 1024; // 8 KB
	private static int _headersMaxLength = 64 * 1024; // 64 KB

	private static int _objectCount;
	
	private static final boolean _enableLogging = false;
	
	private int _id;
	
	public boolean _enableThreadVerification;
	public long _ownerThreadId;
	
	public HttpInputStream(InputStream inputStream, int bufferSize) {
		if (inputStream == null) {
			throw new NullPointerException("inputStream can't be null.");
		}

		_inputStream = inputStream;
		_currentCharset = Charset.forName("US-ASCII");

		_bufferedData = new byte[bufferSize];
		
		if(_enableLogging){
			synchronized (HttpInputStream.class) {
				_id =  ++_objectCount;
			}
		}
	}

	public InputStream getInnerStream(){
		return _inputStream;
	}
	
	public int available() throws IOException{
		return getBufferredDataCount() + _inputStream.available();
	}
	
	private int readInternal() throws IOException {
		while (true) {
			try {
				return _inputStream.read();
			} catch (SocketTimeoutException e) {
				// Silently Ignore timeout exception if that behavior is
				// required.
				if (!_ignoreSocketReadTimeoutException) {
					throw e;
				}
			}
		}
	}

	private int readInternal(byte[] buffer, int offset, int count) throws IOException {
		while (true) {
			try {
				return _inputStream.read(buffer, offset, count);
			} catch (SocketTimeoutException e) {
				// Silently Ignore timeout exception if that behavior is
				// required.
				if (!_ignoreSocketReadTimeoutException) {
					throw e;
				}
			}
		}
	}

	private int getBufferredDataCount(){
		return Math.max(_bufferedDataEndIndex - _bufferedDataStartIndex + 1, 0);
	}
	
	public int read() throws IOException{
		if (_bufferedDataEndIndex >= _bufferedDataStartIndex) {
			return _bufferedData[_bufferedDataStartIndex++] & 0xFF; 
		}
		return readInternal();
	}
	
	public int read(byte[] buffer, int offset, int count) throws IOException {
		int totalCount = 0;

		if (_bufferedDataEndIndex >= _bufferedDataStartIndex) {
			int blockCopyCount = Math.min(count, _bufferedDataEndIndex - _bufferedDataStartIndex + 1);
			System.arraycopy(_bufferedData, _bufferedDataStartIndex, buffer, offset, blockCopyCount);

			offset += blockCopyCount;
			count -= blockCopyCount;

			_bufferedDataStartIndex += blockCopyCount;

			totalCount += blockCopyCount;
		}

		if (count > 0) {
			totalCount += readInternal(buffer, offset, count);
		}

		return totalCount;
	}

	private String getLine(GetLineOutputParams outputParams) throws IOException, EOFException {
		String line = "";

		outputParams.found = false;

		if (_bufferedDataEndIndex >= _bufferedDataStartIndex) {
			int extraCharacter = -1;
			int i;
			for (i = _bufferedDataStartIndex; i <= _bufferedDataEndIndex; i++) {
				if (_bufferedData[i] == '\r') {
					// if '\r' found at last index in buffer then read one more
					// character.
					if (i == _bufferedDataEndIndex) {
						extraCharacter = readInternal();
						if (extraCharacter == -1) {
							throw new EOFException("HttpInputStream");
						} else if (extraCharacter == '\n') {
							extraCharacter = -1;
							outputParams.found = true;
							break;
						}
					} else {
						if (_bufferedData[i + 1] == '\n') {
							outputParams.found = true;
							break;
						}
					}
				}
			}

			line = new String(_bufferedData, _bufferedDataStartIndex, i - _bufferedDataStartIndex, _currentCharset);
			if (extraCharacter >= 0) {
				line += (char) extraCharacter;
			}

			_bufferedDataStartIndex = i + 2;
		}
		
		if(_enableLogging) {
			// Logger.getRootLogger().info(String.format("HttpInputStream Id : %d, Info : %s",_id,line));
		}
		
		return line;

	}

	public String readLine(int maxLimit) throws IOException, SizeLimitExceededException, EOFException {
		GetLineOutputParams getLineOutputParams = new GetLineOutputParams();

		String line = getLine(getLineOutputParams);
		if (getLineOutputParams.found)
			return line;

		while (true) {
			_bufferedDataStartIndex = 0;
			int bytesRead = readInternal(_bufferedData, 0, _bufferedData.length);
			_bufferedDataEndIndex = bytesRead - 1;

			if (bytesRead < 0)
				throw new EOFException("HttpInputStream");

			line += getLine(getLineOutputParams);
			if (getLineOutputParams.found)
				return line;

			if (line.length() >= maxLimit)
				throw new SizeLimitExceededException();
		}
	}

	public String readRequestLine() throws IOException, EOFException, RequestResponseLineSizeExceedException {
		try {
			return readLine(_requestLineMaxLength);
		} catch (SizeLimitExceededException e) {
			throw new RequestResponseLineSizeExceedException(e);
		}
	}

	public String readResponseLine() throws IOException, EOFException, RequestResponseLineSizeExceedException {
		try {
			return readLine(_responseLineMaxLength);
		} catch (SizeLimitExceededException e) {
			throw new RequestResponseLineSizeExceedException(e);
		}
	}

	public void readHeaders(Map<String, String> headers) throws IOException, HeadersSizeExceedException, EOFException {

		String header;

		int headersMaxLength = _headersMaxLength;

		while (true) {

			try {
				header = readLine(headersMaxLength);
			} catch (SizeLimitExceededException e) {
				throw new HeadersSizeExceedException(e);
			}

			if (header.length() <= 0)
				break;

			int headerSeparatorIndex;
			if ((headerSeparatorIndex = header.indexOf(':')) > 0) {
				String key = header.substring(0, headerSeparatorIndex);
				String value = header.substring(headerSeparatorIndex + 1);

				headers.put(key, value);
			} else {
				headers.put(header, null);
			}

			headersMaxLength -= header.length();
		}
	}

	public void close() throws IOException {
		_inputStream.close();
	}

}
