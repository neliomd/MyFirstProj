package httpstream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.Map;

public class HttpOutputStream {

	private OutputStream _outputStream;
	private Charset _currentCharset;

	/**
	 * Buffer size to flush Request/Response Line + Headers in one packet.
	 */
	final static int BUFFER_SIZE = 100 * 1024; // 100 KB Buffer
	
	private byte[] _bufferedData;
	private int _bufferedDataCount;
	
	private volatile long _bytesWritten;
	
	public HttpOutputStream(OutputStream outputStream) {
		if (outputStream == null) {
			throw new NullPointerException("outputStream can't be null.");
		}

		_outputStream = outputStream;
		_currentCharset = Charset.forName("US-ASCII");
		_bufferedData = new byte[BUFFER_SIZE];
	}

	public long getAndResetBytesWrittenCount(){
		long bytesWritten = _bytesWritten;
		_bytesWritten = 0;
		return bytesWritten;
	}
	
	
	public OutputStream getInnerStream(){
		return _outputStream;
	}
	
	public void write(byte[] buffer, int offset, int count) throws IOException {
		_outputStream.write(buffer, offset, count);
		_bytesWritten += count;
	}

	public void writeLine(String value) throws IOException {
		byte[] bytes = (value + "\r\n").getBytes(_currentCharset);
		write(bytes, 0, bytes.length);
	}

	public void writeHeaders(Map<String, String> headers) throws IOException {
		for (Map.Entry<String, String> entry : headers.entrySet()) {
			String key = entry.getKey();
			String value = entry.getValue();
			if (value != null){
				writeDataIntoBuffer(key);
				writeDataIntoBuffer(":");
				writeDataIntoBuffer(value);
			}
			else {
				writeDataIntoBuffer(key);
			}
			writeLineTerminationIntoBuffer();
		}

		writeLineTerminationIntoBuffer();
		
		// Flush Request/Response Line + Headers into Socket.
		write(_bufferedData, 0, _bufferedDataCount);
		_bufferedDataCount = 0;
	}

	/**
	 * Writes data into buffer.
	 * @param data
	 */
	private void writeDataIntoBuffer(String data){
		int dataLength = data.length();
		data.getBytes(0, dataLength, _bufferedData, _bufferedDataCount);
		_bufferedDataCount += dataLength;
	}
	
	/**
	 * Writes line termination characters into buffer.
	 */
	private void writeLineTerminationIntoBuffer(){
		_bufferedData[_bufferedDataCount++] = 13;
		_bufferedData[_bufferedDataCount++] = 10;
	}
	
	public void writeRequestOrResponseLine(String requestLine){
		_bufferedDataCount = 0;
		writeDataIntoBuffer(requestLine);
		writeLineTerminationIntoBuffer();
	}
	
	public void close() throws IOException {
		_outputStream.close();
	}
}
