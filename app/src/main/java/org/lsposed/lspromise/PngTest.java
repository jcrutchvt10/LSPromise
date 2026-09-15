package org.lsposed.lspromise;

public class PngTest {
    static {
        try {
            System.loadLibrary("exp");
        } catch (Throwable ignore) {
        }
    }

    public static native String runTest(byte[] png, String label);
}
