package burp.cmartests;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;

import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;

public class CmarTestRunner {
    static PrintWriter stderr;
    Method[] tests;
    IBurpExtenderCallbacks callbacks;
    BurpExtender b;

    public CmarTestRunner(IBurpExtenderCallbacks callbacks, BurpExtender b) {
        this.callbacks = callbacks;
        stderr = new PrintWriter(callbacks.getStderr(), true);
        this.b = b;
    }

    public void run() throws InvocationTargetException, IllegalAccessException {
        CmarTest ctest = new CmarTest();
        BurpExtenderTest btest = new BurpExtenderTest(b);

        tests = ctest.getClass().getDeclaredMethods();
        execTests(tests, ctest);

        tests = btest.getClass().getDeclaredMethods();
        execTests(tests, btest);


        stderr.println("Tests run, hopefully no errors above.");
        stderr.println("Do not use extension with tests enabled, as it interacts with the table and adds testing CMARs.");
    }

    public static void printError(String err) {
        stderr.println(err);
    }

    private void execTests(Method[] tests, Object o) {
        try {
            for (int i = 0; i < tests.length; i++) {
                stderr.println("Running test method: " + tests[i].getDeclaringClass() + "." + tests[i].getName());
                tests[i].invoke(o);
            }
        } catch (Exception e) {
            e.printStackTrace(stderr);
        }

    }

    public static void assertEquals(String error, byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            stderr.println(error);
        }
    }

    public static void assertEquals(String error, Object expected, Object actual) {
        if (!expected.equals(actual)) {
            stderr.println("ERROR: "+error);
        }
    }

}
