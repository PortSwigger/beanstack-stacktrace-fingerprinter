package beanstack;

import burp.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.swing.*;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IHttpListener, IExtensionStateListener {
	// Dictionary mapping request body hashes to response bodies
	private Map<ByteBuffer, String> HttpReqMemoization;

	// Hashes of issues to avoid duplicates
	private Set<ByteBuffer> AlreadyFingerprinted;

	// Background thread that does the lookups
	private ExecutorService threader;

	final Blake2b blake2b = Blake2b.Digest.newInstance(16);

	private boolean showed429AlertWithApiKey = false;
	private boolean showed429Alert = false;

	final String htmlindent = "&nbsp;&nbsp;&nbsp;";
	final String CRLF = "\r\n";
	final String hexchars = "0123456789abcdefABCDEF";

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		GlobalVars.callbacks = callbacks;

		GlobalVars.callbacks.setExtensionName(GlobalVars.EXTENSION_NAME);
		GlobalVars.callbacks.registerHttpListener(this);
        GlobalVars.callbacks.registerExtensionStateListener(this);

		this.AlreadyFingerprinted = new HashSet<ByteBuffer>();
		this.HttpReqMemoization = new HashMap<ByteBuffer, String>();

		this.threader = Executors.newSingleThreadExecutor();

		GlobalVars.config = new Config();
		GlobalVars.config.printSettings();

		GlobalVars.callbacks.registerContextMenuFactory(new ContextMenuSettingsOptionAdder());

		// Check if we already checked this URL
		IScanIssue[] issuelist = GlobalVars.callbacks.getScanIssues("");

		if (issuelist == null) {
			JOptionPane.showMessageDialog(null,
				"Error loading scan issues. Unfortunately, this extension\nuses features only available in Burp Pro.",
				"Burp Extension " + GlobalVars.EXTENSION_NAME,
				JOptionPane.ERROR_MESSAGE
			);
			return;
		}

		for (IScanIssue si : issuelist) {
			// Only add fingerprinting items
			if (si.getIssueName().equals(GlobalVars.config.getString("issuetitle"))) {
				AlreadyFingerprinted.add(hashScanIssue(si));
			}
		}
		GlobalVars.debug("Found " + AlreadyFingerprinted.size() + " fingerprints in already-existing issues (to avoid creating duplicate issues).");

		threader.submit(new Runnable() {
			public void run() {
				int timeSlept = 0;
				while (Config.getBurpFrame().getJMenuBar() == null) {
					if (timeSlept > GlobalVars.SLEEP_MAXTIME * 1000) {
						GlobalVars.debug("Sleeper timed out. Here be dragons.");
						break;
					}

					try { java.lang.Thread.sleep(GlobalVars.SLEEP_DURATION); } catch (java.lang.InterruptedException e) { break; }
					GlobalVars.debug("Sleeping " + GlobalVars.SLEEP_DURATION + "ms before adding " + GlobalVars.EXTENSION_NAME_SHORT + " menu button because Burp's menu bar UI does not yet exist...");
					timeSlept += GlobalVars.SLEEP_DURATION;
				}
				SwingUtilities.invokeLater(new BeanstackMenu());
			}
		});
	}

    @Override
    public void extensionUnloaded() {
        GlobalVars.debug("Extension unloading: shutting down thread pool...");
        if (threader != null) {
            threader.shutdownNow();

            try {
                if (!threader.awaitTermination(5, TimeUnit.SECONDS)) {
                    GlobalVars.debug("Thread pool did not terminate within timeout.");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            threader = null;
        }
    }

	private String cvssToBurpSeverity(float cvss) {
		// Based on https://www.first.org/cvss/specification-document#5-Qualitative-Severity-Rating-Scale
		if (cvss < 4.0f) return "Information";
		if (cvss < 7.0f) return "Low";
		if (cvss < 9.0f) return "Medium";
		return "High";
	}

	private ByteBuffer hashScanIssue(IScanIssue si) {
		return ByteBuffer.wrap(blake2b.digest((si.getUrl().toString() + "\n" + si.getIssueDetail()).getBytes()));
	}

	private byte[] buildHttpRequest(String host, String URI, String method, String body) {
		String headers = "";
		headers += "User-Agent: " + GlobalVars.USER_AGENT + "/" + GlobalVars.VERSION + CRLF;
		if (method.equals("POST")) {
			headers += "Content-Type: application/x-www-form-urlencoded\r\n";
			headers += "Content-Length: " + body.length() + CRLF;
		}
		return (method + " " + URI + " HTTP/1.1\r\nHost: " + host + CRLF + headers + CRLF + body).getBytes();
	}

	private SHR parseHttpResponse(byte[] response) {
		String[] headersbody = new String(response).split("\r\n\r\n", 2);
		String[] headers = headersbody[0].split(CRLF);
		Map<String,String> headermap = new HashMap<>();
		for (String header : headers) {
			if (Objects.equals(header, headers[0])) continue; // Skip first: that's the status line
			String[] nameval = header.split(":", 2);
			headermap.put(nameval[0].toLowerCase().trim(), nameval[1].trim());
		}
		String[] methodcodestatus = headers[0].split(" ", 3);

		int status = Integer.parseInt(methodcodestatus[1]);
		return new SHR(status, headermap, headersbody[1]);
	}

	private String url2uri(URL url) {
		return (url.getPath() != null ? url.getPath() : "")
			+ (url.getQuery() != null ? url.getQuery() : "");
	}

	private boolean isBlacklisted(String stacktraceline) {
		String[] blacklisted_class_prefixes = GlobalVars.config.getString("classblacklist").split(",");
		for (String blacklisted_class_prefix : blacklisted_class_prefixes) {
			if (blacklisted_class_prefix.length() < 3) {
				continue;
			}
			if (stacktraceline.contains(blacklisted_class_prefix)) {
				return true;
			}
		}

		return false;
	}

	private String getHashedTrace(String stacktrace) {
		// This function assumes a sanitized stack trace
		StringBuilder hashedTrace = new StringBuilder();
		for (String line : stacktrace.split("\n")) {
			String[] match = line.trim().split("\\(|\\)|:");
			String fullfunctionname = match[0];
			String sourcename = match[1];
			int lineno = Integer.parseInt(match[2]);

			String[] splitfunc = fullfunctionname.split("\\.");
			String[] tmp = Arrays.copyOfRange(splitfunc, 0, splitfunc.length - 1);
			String classname = String.join(".", tmp);
			String functionname = splitfunc[splitfunc.length - 1];

			String functionname_2b = beanstack.Blake2b.Engine.LittleEndian.toHexStr(blake2b.digest(functionname.getBytes()));
			String classname_2b = beanstack.Blake2b.Engine.LittleEndian.toHexStr(blake2b.digest(classname.getBytes()));
			String fullfunctionname_2b = beanstack.Blake2b.Engine.LittleEndian.toHexStr(blake2b.digest(fullfunctionname.getBytes()));

			hashedTrace.append(String.format("%s:%s:%s:%d\n", fullfunctionname_2b, classname_2b, functionname_2b, lineno));
		}

		return hashedTrace.toString();
	}

	private String checktrace(String stacktrace) {
		String retval = null; // Return value

		try {
			ByteBuffer tracedigest = ByteBuffer.wrap(blake2b.digest((GlobalVars.config.getString("apikey") + stacktrace).getBytes("UTF-8")));
			if (HttpReqMemoization.containsKey(tracedigest)) {
				GlobalVars.debug("Trace found in memoization table, returning stored response.");
				return HttpReqMemoization.get(tracedigest);
			}

			boolean retry = true;
			while (retry) {
				retry = false;

				boolean isset_apikey = GlobalVars.config.getString("apikey").length() > 4;
				boolean submit_hashed_trace = isset_apikey && GlobalVars.config.getBoolean("hashtrace");

				URL url = new URI(GlobalVars.config.getString("apiurl") + (submit_hashed_trace ? "hashTrace" : "")).toURL();
				boolean ishttps = url.getProtocol().equalsIgnoreCase("https");
				int port = url.getPort() == -1 ? url.getDefaultPort() : url.getPort();

				GlobalVars.debug(String.format("Submitting a trace to %s", url));

				String body = "";
				if (isset_apikey) {
					body += "apikey=";
					body += GlobalVars.config.getString("apikey").trim();
					body += "&";
				}
				body += "trace=";
				body += java.net.URLEncoder.encode(submit_hashed_trace ? getHashedTrace(stacktrace) : stacktrace, StandardCharsets.UTF_8);

				byte[] httpreq = buildHttpRequest(url.getHost(), url2uri(url), "POST", body);
				SHR response = parseHttpResponse(GlobalVars.callbacks.makeHttpRequest(url.getHost(), port, ishttps, httpreq));
				GlobalVars.debug("Response status " + response.status);

				if (response.status == 204) {
					retval = null;
				}
				else if (response.status == 301 && response.headers.containsKey("location") && response.headers.get("location").equals(GlobalVars.config.getString("apiurl").replace("http://", "https://"))) {
					// Oblige an HTTP -> HTTPS redirect (but nothing else)
					GlobalVars.debug(String.format("Got a 301, updating apiurl setting from <%s> to <%s>.", GlobalVars.config.getString("apiurl"), response.headers.get("location")));
					GlobalVars.config.putAndSave("apiurl", response.headers.get("location"));
					retry = true;
				}
				else if (response.status == 429) {
					if (isset_apikey) {
						GlobalVars.debug("HTTP request failed: 429 (with API key)");
						// An API key is set
						String msg = "Your API key ran out of requests. For bulk\nlookup of stack traces, please contact us.";
						if ( ! showed429AlertWithApiKey) {
							// Only alert once; nobody wants to be annoyed by this stuff
							showed429AlertWithApiKey = true;

							JOptionPane.showMessageDialog(null, msg, "Burp Extension " + GlobalVars.EXTENSION_NAME, JOptionPane.ERROR_MESSAGE);
						}
						GlobalVars.callbacks.issueAlert(msg);
					}
					else {
						GlobalVars.debug("HTTP request failed: 429 (no API key set)");
						if ( ! showed429Alert) {
							// Only alert once; nobody wants to be annoyed by this stuff
							showed429Alert = true;

							// No API key set. Prompt for one and mention where they can get one.
							String result = JOptionPane.showInputDialog(GlobalVars.config.getBurpFrame(),
								"You have reached the request limit for " + GlobalVars.EXTENSION_NAME_SHORT + ". "
									+ "Please register on " + GlobalVars.REGURL + "\nfor a free API key. If you already have an API key, please enter it here.",
								GlobalVars.EXTENSION_NAME + " API key",
								JOptionPane.PLAIN_MESSAGE
							);
							if (!result.isEmpty()) {
								GlobalVars.config.putAndSave("apikey", result);
								GlobalVars.debug("apikey configured after prompt");
								retry = true;
							}
						}
						else {
							GlobalVars.callbacks.issueAlert("Extension " + GlobalVars.EXTENSION_NAME_SHORT + ": You hit the request limit for the API. "
								+ "To continue, please register for a free API key at " + GlobalVars.REGURL + ", or slow the rate of requests.");
						}
					}
					if (!retry) {
						return null;
					}
				}
				else if (response.status == 401 && isset_apikey) {
					GlobalVars.debug("HTTP request failed: invalid API key (401)");

					// N.B. we thread this, but due to the thread pool of 1, further requests will just be queued, so we won't get dialogs on top of each other.
					// Further requests will also automatically use the API key if the user enters one here, even if they were already queued previously.

					String result = (String)JOptionPane.showInputDialog(GlobalVars.config.getBurpFrame(),
						"Your API key is invalid.\nIf you want to use a different API key, please enter it here.",
						GlobalVars.EXTENSION_NAME + " API key invalid",
						JOptionPane.PLAIN_MESSAGE,
						null,
						null,
						GlobalVars.config.getString("apikey")
					);
					if (result != null && !result.isEmpty()) {
						GlobalVars.config.putAndSave("apikey", result);
						GlobalVars.debug("apikey reconfigured");
						retry = true;
					}
					else {
						// If they cancelled the dialog or emptied it, override the string so they don't get more of those alerts.
						GlobalVars.config.putAndSave("apikey", "none");
					}

					if (!retry) {
						return null;
					}
				}
				else if (response.status != 200) {
					GlobalVars.callbacks.issueAlert("Extension " + GlobalVars.EXTENSION_NAME + ": HTTP request to back-end failed with status " + response.status);

					GlobalVars.debug("HTTP request failed with status " + response.status);

					return null;
				}
				else {
					retval = response.body;
				}
			} // End of while(retry) loop

			// The code should only reach here if we want to memoize the result. Otherwise, early exit (return) above!

			GlobalVars.debug("Result: " + (retval == null ? "null" : retval.substring(0, Math.min(150, retval.length()))));

			HttpReqMemoization.put(tracedigest, retval);

			return retval;
		}
		catch (IOException | URISyntaxException e) {
			e.printStackTrace(new java.io.PrintStream(GlobalVars.debug));
		}

        return null;
	}

	private String DecodeUrl(String tracestr) {
		// Because java.net.URLDecoder.decode (understandably) throws an exception if there is a percent symbol anywhere not followed by two hex chars.

		int pos = -1;
		while ((pos = tracestr.indexOf("%", pos + 1)) > -1) {
			if (pos > tracestr.length() - 2) break;

			if (hexchars.indexOf(tracestr.charAt(pos + 1)) > -1 && hexchars.indexOf(tracestr.charAt(pos + 2)) > -1) {
				tracestr = tracestr.replace(tracestr.substring(pos, pos + 3), ((char)Integer.parseInt(tracestr.substring(pos + 1, pos + 3), 16)) + "");
				pos--;
			}
		}

		return tracestr;
	}

	private String DecodeStackTraceHtml(String tracestr) {
		// It seems we'd need to include a library to do HTML decoding... but it's not all that difficult given the limited charset in a stack trace,
		// so that seems like overkill, and now we can do things like fix double encoding, ignore invalid encoding without aborting altogether, etc.

		if ( ! tracestr.contains("&")) {
			return tracestr;
		}

		tracestr = tracestr.replace("&amp;", "&"); // Fix any double encoding first

		Map<String, String> replacemap = new HashMap<String, String>() {{
			put("nbsp", " ");
			put("nonbreakingspace", " ");
			put("tab", " ");
			put("lt", "<");
			put("gt", ">");
			put("dollar", "$");
			put("lpar", "(");
			put("rpar", ")");
			put("period", ".");
			put("colon", ":");
		}};
		// If the {1,6} is expanded to allow >=8 chars (technically valid b/c leading zeroes... currently unsupported because that's within the realm of obfuscation
		// and if you want to obfuscate your stack traces... there are easier methods to evade BeanStack), then you will need to try{} below to avoid >int_max.
		Pattern pattern = Pattern.compile("(&(#[0-9]{1,6}|#x[0-9a-f]{1,9}|nbsp|NonBreakingSpace|tab|lt|gt|dollar|lpar|rpar|period|colon);)", Pattern.CASE_INSENSITIVE);
		Matcher matcher = pattern.matcher(tracestr);
		while (matcher.find()) {
			if (matcher.group(2).startsWith("#")) { // If we have a third group, then we matched a numeric or hex entity
				if (matcher.group(2).toLowerCase().startsWith("#x")) {
					tracestr = tracestr.replace(matcher.group(1), ((char)Integer.parseInt(matcher.group(2).substring(2), 16)) + "");
				}
				else {
					tracestr = tracestr.replace(matcher.group(1), ((char)Integer.parseInt(matcher.group(2).substring(1))) + "");
				}
			}
			else {
				String lce = matcher.group(2).toLowerCase();
				if ( ! replacemap.containsKey(lce)) {
					continue;
				}
				tracestr = tracestr.replace(matcher.group(1), replacemap.get(lce));
			}
		}

		return tracestr;
	}

    @SuppressWarnings("unchecked")
	public static double determineCvssScore(Map<String, Object> cve) {
		    /**
	         * There's an array of scores from different organizations. We're prioritizing
	         * NIST scores over other (i.e. potentially vendor) scores.
	         *
	         * Schema:
	         * https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
	         */

	        if (!((Map<String, String>) cve.get("data")).containsKey("metrics")) {
	            return -1;
	        }

            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> metricsObj = mapper.convertValue(((Map<String, String>) cve.get("data")).get("metrics"), new TypeReference<>() {
            });
	        if (metricsObj.isEmpty()) {
	            return -1;
	        }

	        // keys need to be in order of preference, to prefer later versions
	        String[] cvssKeys = {"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"};
	        List<List<Map<String, Object>>> allMetrics = new ArrayList<>();

	        for (String key : cvssKeys) {
	            if (metricsObj.containsKey(key)) {
	                allMetrics.add((List<Map<String, Object>>) metricsObj.get(key));
	            }
	        }

	        Double newestSecondaryScore = null;

	        for (List<Map<String, Object>> metricArray : allMetrics) {
	            for (Map<String, Object> rating : metricArray) {
	                Map<String, Object> cvssData = (Map<String, Object>) rating.get("cvssData");
	                double baseScore = ((Number) cvssData.get("baseScore")).doubleValue();

	                String type = (String) rating.get("type");
	                if ("Primary".equals(type)) {
	                    return baseScore;
	                } else if (newestSecondaryScore == null) {
	                    newestSecondaryScore = baseScore;
	                }
	            }
	        }

		return newestSecondaryScore != null ? newestSecondaryScore : -1.0;
	}

	@Override
    @SuppressWarnings("unchecked")
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse baseRequestResponse) {
		if (messageIsRequest) {
			// If the trace is locally generated, it probably isn't interesting for us
			return;
		}

		if ( ! GlobalVars.config.getBoolean("enable")) {
			GlobalVars.debug("Note: " + GlobalVars.EXTENSION_NAME_SHORT + " plugin is disabled.");
			return;
		}

		threader.submit(new Runnable() {
			public void run() {
                try {
                    int sizelimit = GlobalVars.config.getInt("sizelimit") * 1024 * 1024;

                    byte[] bytesresponse = baseRequestResponse.getResponse();
                    if (bytesresponse.length > sizelimit) {
                        byte[] partial = new byte[sizelimit];
                        System.arraycopy(bytesresponse, 0, partial, 0, sizelimit / 2);
                        System.arraycopy(bytesresponse, bytesresponse.length - sizelimit / 2, partial, sizelimit / 2, sizelimit / 2);
                        bytesresponse = partial;
                    }
                    String response = new String(bytesresponse, StandardCharsets.UTF_8);

                    response = response.replace("\\$", "$").replace("\\/", "/");
                    response = DecodeUrl(response);
                    response = DecodeStackTraceHtml(response);

                    // Basically the pattern checks /\s[valid class path chars].[more valid class chars]([filename chars].java:1234)/
                    Pattern pattern = Pattern.compile("(\\s|/)([a-zA-Z0-9\\.\\$]{1,300}\\.[a-zA-Z0-9\\.\\$]{1,300})\\(([a-zA-Z0-9]{1,300})\\.java:\\d{1,6}\\)");
                    Matcher matcher = pattern.matcher(response);

                    // Reconstruct the trace (since who knows what might be in between the lines, e.g. "&lt;br&gt;" or "," or "\n")
                    StringBuilder stacktrace = new StringBuilder();
                    while (matcher.find()) {
                        if (!matcher.group(2).contains(".")) {
                            // Enforce a dot in the full class name (sanity check)
                            continue;
                        }
                        if (!(matcher.group(2).indexOf(matcher.group(3) + "$") >= 2
                                || matcher.group(2).indexOf(matcher.group(3) + ".") >= 2)) {
                            // (^Some extra checks to prevent submitting false positives to our API.)
                            // The filename should occur in the first part, either followed by a dollar or by a dot,
                            // and it usually does not start with that (so match from position 2 onwards, because
                            // there should be at least 1 character and a dot, like "a.test.run(test.java:42)").
                            continue;
                        }
                        String line = matcher.group(0).substring(1);
                        if (!isBlacklisted(line)) {
                            GlobalVars.debug(" " + line);
                            stacktrace.append(" ").append(line).append("\n");
                        } else {
                            GlobalVars.debug(String.format("[filtered out blacklisted class: %s]", matcher.group(2)));
                        }
                    }

                    if (stacktrace.isEmpty()) {
                        return;
                    }

                    Instant start = Instant.now();

                    // Check the trace with our back-end
                    String result = checktrace(stacktrace.toString());

                    GlobalVars.debug("checktrace() returned in " + Duration.between(start, Instant.now()).toMillis() + "ms");

                    // Either some error (already handled) or no results
                    if (result == null) {
                        return;
                    }

                    ObjectMapper mapper = new ObjectMapper();
                    // Deserialize JSON into a Map
                    Map<String, Object> products = mapper.readValue(
                            result,
                            new TypeReference<>() {}
                    );

                    StringBuilder issuetext = new StringBuilder();
                    String comma = "";

                    boolean is_uncertain_cve;
                    boolean any_uncertain_cves = false;
                    boolean any_certain_cves = false;
                    double maxcvss = 0;
                    int i = 0;

                    String outdated = "";
                    String notice = "";

                    issuetext.append("X41 BeanStack found the following versions based on the stack trace:<br>");
                    for (Map.Entry<String, Object> product : products.entrySet()) {
                        if (product.getKey().equals("__BeanStack_demo")) {
                            notice = "<br><br>Note: CVEs are shown for this stack trace as a demo. To view CVEs with other stack traces, please <a href='https://beanstack.io/signup.html'>request an API key</a>.";
                            continue;
                        }

                        if (product.getKey().equals("__BeanStack_needs_upgrading")) {
                            outdated = (String) product.getValue();
                            continue;
                        }

                        i += 1;
                        issuetext.append(String.format("%d. %s<br>" + htmlindent, i, product.getKey()));

                        Map<String, Object> productmap = (Map<String, Object>) product.getValue();
                        Object[] versions = ((List<Object>) productmap.get("versions")).toArray();

                        for (Object v : versions) {
                            System.out.println(v);
                        }
                        if (versions.length == 1) {
                            issuetext.append("version: ").append(versions[0].toString());
                        } else {
                            issuetext.append("matching versions: ");
                            comma = "";
                            for (Object ver : versions) {
                                issuetext.append(comma).append(ver.toString());
                                comma = ", ";
                            }
                        }

                        if (productmap.containsKey("cves")) {
                            Object[] cves = ((List<Object>) productmap.get("cves")).toArray();
                            if (cves.length > 0) {
                                issuetext.append("<br>" + htmlindent + "CVE(s): ");

                                comma = "";
                                for (Object cveobj : cves) {
                                    Map<String, Object> cvemap = (Map<String, Object>) cveobj;

                                    String cveid = ((Map<String, String>) cvemap.get("data")).get("id");
                                    is_uncertain_cve = Integer.parseInt(cvemap.get("vermatch").toString()) != 0;
                                    any_uncertain_cves = is_uncertain_cve ? is_uncertain_cve : any_uncertain_cves;
                                    any_certain_cves = is_uncertain_cve ? any_certain_cves : !is_uncertain_cve;
                                    issuetext.append(comma).append("<a href='").append(GlobalVars.CVEURL).append(cveid).append("'>").append(cveid).append("</a>").append(is_uncertain_cve ? "*" : "");
                                    comma = ", ";

                                    String score = "(not given)";
                                    double cvssScore = determineCvssScore(cvemap);
                                    if (cvssScore != -1.0) {
                                        issuetext.append(" (").append(cvssScore).append(")");
                                        score = Double.toString(cvssScore);
                                        maxcvss = Math.max(cvssScore, maxcvss);
                                    }
                                    System.out.println("Score: " + score);

                                    if (GlobalVars.config.getBoolean("issuepercve") && !is_uncertain_cve) {
                                        GlobalVars.debug(String.format("Logging separate issue for %s", cveid));
                                        GlobalVars.callbacks.addScanIssue(new CustomScanIssue(
                                                baseRequestResponse.getHttpService(),
                                                GlobalVars.callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
                                                new IHttpRequestResponse[]{baseRequestResponse},
                                                String.format("%s (%s)", GlobalVars.config.getString("issuetitle"), cveid),
                                                String.format("In the stack trace, %s with CVSS score %s was discovered. It is present in %s.", cveid, score, product.getKey()),
                                                cvssToBurpSeverity(Float.parseFloat(score)),
                                                "Firm"
                                        ));
                                    }
                                }
                                issuetext.append("<br>");
                            }
                        } else {
                            if (GlobalVars.config.getString("apikey").length() > 4) {
                                issuetext.append(" (no CVEs known)<br>");
                            } else {
                                issuetext.append("<br>");
                            }
                        }
                    }

                    if (any_uncertain_cves) {
                        issuetext.append("<br>* This CVE applies to a range of versions. Many projects use non-semver versioning schemes and CVEs do not mention which versioning scheme " + "is used, so we can only do reliable version matching when an exact version is given instead of a range. Therefore, this CVE may not apply.");
                    }

                    if (notice.isEmpty() && GlobalVars.config.getString("apikey").length() <= 4) {
                        notice = "<br><br>Note: to check for CVEs, please <a href='https://beanstack.io/signup.html'>request an API key</a> or <a href='https://beanstack.io/settings.html'>configure your key</a>.";
                    }

                    String certainty;
                    if (any_uncertain_cves || any_certain_cves) {
                        // If there are CVEs at all
                        if (!any_uncertain_cves) {
                            // Since the severity is determined by the highest CVSS score, and since that
                            // CVSS score might belong to an uncertain CVE (one that might not apply to
                            // the product we found, but we don't know because we can't do version
                            // comparisons without knowing the versioning scheme), we can only be
                            // "certain" if there are no uncertain CVEs.
                            certainty = "Certain";
                        } else if (any_certain_cves) {
                            certainty = "Firm";
                        } else {
                            // Not a single one was an exact version match, so this is fairly uncertain
                            certainty = "Tentative";
                        }
                    } else {
                        // We didn't find any CVEs, so return the standard certainty
                        certainty = "Certain";
                    }

                    IScanIssue issue = new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            GlobalVars.callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
                            new IHttpRequestResponse[]{baseRequestResponse},
                            GlobalVars.config.getString("issuetitle"),
                            outdated + issuetext + notice,
                            cvssToBurpSeverity((float) maxcvss),
                            certainty
                    );

                    ByteBuffer hash = hashScanIssue(issue);

                    if (!AlreadyFingerprinted.add(hash)) {
                        // We already created an issue for this, avoid creating a duplicate.
                        if (GlobalVars.config.getBoolean("logdups")) {
                            GlobalVars.debug("Issue already exists, but logging anyway because logdups config is set.");
                        } else {
                            GlobalVars.debug("Issue already exists! Avoiding duplicate.");
                            return;
                        }
                    }

                    GlobalVars.callbacks.addScanIssue(issue);
                    GlobalVars.debug("Logged issue");

                } catch (Exception e) {
                    System.err.println(e.getMessage());
                    throw new RuntimeException(e);
                }
            }
		});
	}
}

class BeanstackMenu implements Runnable, java.awt.event.ActionListener, IExtensionStateListener {
	private JMenu topMenu;

	BeanstackMenu() {
		GlobalVars.callbacks.registerExtensionStateListener(this);
	}

	public void run() {
		topMenu = new JMenu(GlobalVars.EXTENSION_NAME_SHORT);

		JMenuItem settingsButton = new JMenuItem(GlobalVars.SETTINGS);
		settingsButton.addActionListener(this);

		JMenuItem menuHeader = new JMenuItem(GlobalVars.EXTENSION_NAME);
		menuHeader.setEnabled(false);

		topMenu.add(menuHeader);
		topMenu.add(settingsButton);

		GlobalVars.config.getBurpFrame().getJMenuBar().add(topMenu);
		GlobalVars.config.getBurpFrame().getJMenuBar().updateUI();
	}

	public void actionPerformed(java.awt.event.ActionEvent e) {
		SwingUtilities.invokeLater(new Runnable() {
			public void run(){
				GlobalVars.config.showSettings();
			}
		});
	}

	public void extensionUnloaded() {
		GlobalVars.config.getBurpFrame().getJMenuBar().remove(topMenu);
		GlobalVars.config.getBurpFrame().getJMenuBar().updateUI();
	}
}

class SHR {
	public final int status;
	public final String body;
	public final Map<String,String> headers;
	public SHR(int status, Map<String,String> headers, String body) {
		this.status = status;
		this.headers = headers;
		this.body = body;
	}
}

// From the example project
class CustomScanIssue implements IScanIssue {
	private IHttpService httpService;
	private URL url;
	private IHttpRequestResponse[] httpMessages;
	private String name;
	private String detail;
	private String severity;
	private String confidence;

	public CustomScanIssue(
			IHttpService httpService,
			URL url,
			IHttpRequestResponse[] httpMessages,
			String name,
			String detail,
			String severity,
			String confidence) {
		this.httpService = httpService;
		this.url = url;
		this.httpMessages = httpMessages;
		this.name = name;
		this.detail = detail;
		this.severity = severity;
		this.confidence = confidence;
	}

	@Override
	public URL getUrl() {
		return url;
	}

	@Override
	public String getIssueName() {
		return name;
	}

	@Override
	public int getIssueType() {
		return 0;
	}

	@Override
	public String getSeverity() {
		return severity;
	}

	@Override
	public String getConfidence() {
		return confidence;
	}

	@Override
	public String getIssueBackground() {
		return null;
	}

	@Override
	public String getRemediationBackground() {
		return null;
	}

	@Override
	public String getIssueDetail() {
		return detail;
	}

	@Override
	public String getRemediationDetail() {
		return null;
	}

	@Override
	public IHttpRequestResponse[] getHttpMessages() {
		return httpMessages;
	}

	@Override
	public IHttpService getHttpService() {
		return httpService;
	}
}

