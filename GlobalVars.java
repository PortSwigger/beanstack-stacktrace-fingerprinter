package burp;

import burp.*;

class GlobalVars {
	/* We're all hackers: if you want to hack on this client, that's great!
	 * Just include an accurate user agent (there is no UA checking, it only
	 * ends up in our logs, so we can talk to you if there are issues).
	 * If you did not coordinate the release with us, please include something
	 * by which we can reach you in case of problems, or if, for example, our
	 * API is going to change.
	*/
	public static final String USER_AGENT = "X41-BeanStack-BApp";

	public static final String EXTENSION_NAME = "X41 BeanStack (beta)";
	public static final String EXTENSION_NAME_SHORT = "BeanStack";
	public static final String VERSION = "0.6.1";
	public static final String REGURL = "https://beanstack.io";
	public static final String SETTINGDOCURL = "https://beanstack.io/settings.html";
	public static final String CVEURL = "https://nvd.nist.gov/vuln/detail/";
	public static final String SETTINGS = "Settings";
	public static final int SLEEP_DURATION = 100; // ms
	public static final int SLEEP_MAXTIME = 15; // s

	public static IBurpExtenderCallbacks callbacks;
	public static Config config;
	public static java.io.PrintStream debug = System.out;

	public static void debug(Object o) {
		if (GlobalVars.config.getBoolean("debug")) {
			GlobalVars.debug.print(new java.text.SimpleDateFormat("HH:mm:ss").format(java.util.Calendar.getInstance().getTime()) + " ");
			GlobalVars.debug.println(o);
		}
	}
}

