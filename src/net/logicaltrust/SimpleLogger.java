package net.logicaltrust;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

public class SimpleLogger {

	private PrintWriter debug;
	private final PrintWriter error;
	private final PrintWriter originalDebug;
	private static final PrintWriter EMPTY_WRITER = new PrintWriter(new OutputStream() {
		@Override
		public void write(int b) { }
	}, true);

	public SimpleLogger(PrintWriter debug, PrintWriter error) {
		this.originalDebug = debug;
		this.debug = debug;
		this.error = error;
	}

	public void debug(String message) {
		debug.println(message);
	}
	
	public void debugForce(String message) {
		originalDebug.println(message);
	}
	
	public void enableDebug() {
		debug = originalDebug;
	}
	
	public void disableDebug() {
		debug = EMPTY_WRITER;
	}
	
	public void error(Exception e) {
		e.printStackTrace(error);
	}
	
	public PrintWriter getStderr() {
		return error;
	}
	
}
