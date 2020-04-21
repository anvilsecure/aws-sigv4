package burp;

import java.io.OutputStream;
import java.io.PrintWriter;

public class LogWriter
{
    final public static int DEBUG_LEVEL = 0;
    final public static int INFO_LEVEL = 1;
    final public static int ERROR_LEVEL = 2;
    final public static int DEFAULT_LEVEL = ERROR_LEVEL;
    final public static int FATAL_LEVEL = 3;

    private PrintWriter out;
    private PrintWriter err;
    private int logLevel;

    private static LogWriter logWriter;

    private LogWriter()
    {
        this.logLevel = DEFAULT_LEVEL;
    }

    public static LogWriter getLogger()
    {
        if (logWriter == null)
            logWriter = new LogWriter();
        return logWriter;
    }

    public static String levelNameFromInt(final int level)
    {
        switch (level) {
            case DEBUG_LEVEL:
                return "debug";
            case INFO_LEVEL:
                return "info";
            case ERROR_LEVEL:
                return "error";
            case FATAL_LEVEL:
                return "fatal";
        }
        return "*INVALID*";
    }

    public void configure(OutputStream outStream, OutputStream errStream, int logLevel)
    {
        this.out = new PrintWriter(outStream, true);
        this.err = new PrintWriter(errStream, true);
        this.logLevel = logLevel;
    }

    public void setLevel(int level)
    {
        if (level >= DEBUG_LEVEL && level <= FATAL_LEVEL)
            this.logLevel = level;
    }

    public int getLevel() { return this.logLevel; }

    private void log(final String message, int level)
    {
        if (this.logLevel <= level) {
            if (level >= ERROR_LEVEL) {
                this.err.println(message);
            }
            else {
                this.out.println(message);
            }
        }
    }

    public void debug(final String message)
    {
        log("[DEBUG] " + message, DEBUG_LEVEL);
    }

    public void info(final String message)
    {
        log("[INFO] " + message, INFO_LEVEL);
    }

    public void error(final String message)
    {
        log("[ERROR] " + message, ERROR_LEVEL);
    }

    public void fatal(final String message)
    {
        log("[FATAL] " + message, FATAL_LEVEL);
    }
}
