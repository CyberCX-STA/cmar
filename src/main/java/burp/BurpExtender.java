package burp;

import burp.cmarui.BurpSuiteTab;
import burp.cmarui.CmarTableModel;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IHttpListener {
    private final Boolean runTests = false;
    public PrintWriter stderr;
    public IExtensionHelpers helpers;
    protected String pluginName = "CMAR";
    private IBurpExtenderCallbacks callbacks;
    private final CmarTableModel tableModel = new CmarTableModel();
    private final ArrayList<cmar> cmarArrayList = new ArrayList<>();
    Boolean debug = false;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        callbacks.setExtensionName("Conditional Match and Replace");

        helpers = callbacks.getHelpers();

        stderr = new PrintWriter(callbacks.getStderr(), true);



        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);

        //Add some example cmars
        this.addExamples(cmarArrayList);


        //add example cmars to table model
        for (cmar c : this.cmarArrayList) {
            tableModel.addCmar(c);
        }

        //Create the ui tab
        BurpSuiteTab mTab = new BurpSuiteTab(pluginName, tableModel, callbacks);

        //add the tab
        callbacks.customizeUiComponent(mTab);

        if (this.runTests) {
            burp.cmartests.CmarTestRunner runner = new burp.cmartests.CmarTestRunner(callbacks, this);
            try {
                runner.run();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    void debugPrint(String in) {
        //this slows the extension down a lot, leave off unless needed
        if (this.debug) {
            stderr.println(in);
        }
    }

    public void addCmar(cmar c) {
        //for unit testing
        //marArrayList = new ArrayList<>();
        this.cmarArrayList.add(c);
    }

    public CmarTableModel getTableModel() {
        //for unit testing
        //marArrayList = new ArrayList<>();
        return this.tableModel;
    }

    private void addExamples(ArrayList<cmar> cmarArrayList) {
        //add some example cmar rules to illustrate usage

        cmar cmar1 = new cmar(false, enums.TargetType.Request, enums.ConditionRelationship.Matches, "Host: localhost",
                enums.TargetType.RequestTargetPort, "80", "8080", false, false, "Change target port for localhost:80 requests");

        cmar cmar2 = new cmar(false, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, ".css",
                enums.TargetType.ResponseHeader, "", "Cache-Control: public", false, false, "Alter response based on request condition, to insert a new header");

        cmar cmar3 = new cmar(false, enums.TargetType.Response, enums.ConditionRelationship.Matches, "Python/3.8.10",
                enums.TargetType.ResponseHeader, "", "Python: true", false, false, "Insert a response header");


        cmar cmar4 = new cmar(false, enums.TargetType.Response, enums.ConditionRelationship.Matches, "application/json",
                enums.TargetType.ResponseBody, "5", "\"5\"", false, false, "Alter response");

        cmar cmar5 = new cmar(false, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "GET",
                enums.TargetType.RequestHeader, "", "X-Forwarded-For: 127.0.0.1", false, false, "Insert an HTTP X-Forwarded-For header");

        cmar cmar6 = new cmar(false, enums.TargetType.Request, enums.ConditionRelationship.Matches, "Replace: Yes",
                enums.TargetType.ResponseBody, "Error.*", "zzzzzzzz", true, false, "Regex Match");

        cmar cmar7 = new cmar(false, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "(\\.js|\\.css)",
                enums.TargetType.ResponseHeader, "Expires: 0", "Expires: 7200", false, true, "Enable caching common  static files");

        cmar cmar8 = new cmar(false, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "(\\.js|\\.css)",
                enums.TargetType.ResponseHeader, "Cache-Control: .*", "Cache-Control: private", true, true, "Enable caching common  static files");

        cmar cmar9 = new cmar(false, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "(\\.js|\\.css)",
                enums.TargetType.ResponseHeader, "Pragma: no-cache", "", false, true, "Enable caching common  static files");


        cmarArrayList.add(cmar1);
        cmarArrayList.add(cmar2);
        cmarArrayList.add(cmar3);
        cmarArrayList.add(cmar4);
        cmarArrayList.add(cmar5);
        cmarArrayList.add(cmar6);
        cmarArrayList.add(cmar7);
        cmarArrayList.add(cmar8);
        cmarArrayList.add(cmar9);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        long startTime = System.nanoTime();
        debugPrint("starttime = " + (float) startTime / 1000000);

        // 3 types of CMAR rules:
        // 1: Request on its way out
        // 2: Response arrived, and there is a rule matching the response
        // 3: Response arrived, and there is a rule matching the response's associated request
        if (this.tableModel.getSize() > 0) {
            for (cmar c : this.tableModel.getAllEnabled()) { //iterate through enabled cmar list
                //message handled is request, and cmar condition for a request and cmar target for a request
                if (messageIsRequest && c.conditionTargetIsRequest() && !c.procedureTargetIsResponse()) { //type1
                    debugPrint("Matched request type");
                    String replaced;
                    IHttpService hs;

                    if (checkCondition(messageInfo, c)) {
                        //condition passed, do some MAR!
                        enums.TargetType ta = c.getProcedureTarget();
                        byte[] reqMessage;


                        switch (ta) {
                            case RequestFirstLine:
                                String firstLine = getFirstLine(messageInfo);
                                replaced = matchAndReplace(firstLine, c.getMatch(), c.getReplace(), c.getRegex());

                                if (replaced == null) {
                                    break;
                                }

                                //get the rest of the headers to add
                                java.util.List<String> allHeaders = this.getRequestHeaderList(messageInfo);
                                allHeaders.remove(0);
                                allHeaders.add(0, replaced);


                                reqMessage = helpers.buildHttpMessage(allHeaders, this.getRequestBodyBytes(messageInfo));
                                messageInfo.setRequest(reqMessage);

                                break;
                            case RequestHeader:
                                //working
                                java.util.List<String> headers;

                                //match and replace
                                String headersString = getRequestHeaders(messageInfo);

                                if (c.getMatch().equals("") || c.getMatch() == null) {
                                    //blank match, just add a header to the request
                                    headers = getRequestHeaderList(messageInfo);
                                    headers.add(c.getReplace());
                                }

                                else if (c.getReplace().equals("")){ // replacing a header with blank line, just remove it from the header list otherwise we end up with a line in the middle of the headers
                                    headers = getRequestHeaderList(messageInfo);
                                    boolean removed = false;

                                    for (String header: headers) {
                                        if(!c.getRegex() && header.equals(c.getMatch())){
                                            //non-regex matched
                                            headers.remove(header);
                                            removed = true;
                                        }
                                        else if(c.getRegex() && fullregexMatch(header,c.getMatch())){
                                            //Regex match, remove header
                                            headers.remove(header);
                                            removed = true;
                                        }
                                    }

                                    if (removed == false)
                                    {
                                        //no full line matches, may want to remove part of a header. continue to generic MAR
                                        replaced = matchAndReplace(headersString, c.getMatch(), c.getReplace(), c.getRegex());
                                        if (replaced == null) {
                                            break;
                                        }
                                        //turn the replaced headers back into an array for burp
                                        headers = Arrays.asList(replaced.split("\r\n"));
                                    }
                                }



                                else {
                                    replaced = matchAndReplace(headersString, c.getMatch(), c.getReplace(), c.getRegex());
                                    if (replaced == null) {
                                        break;
                                    }
                                    //turn the replaced headers back into an array for burp
                                    headers = Arrays.asList(replaced.split("\r\n"));
                                }


                                //build a new http request from the replace variables and send it instead
                                reqMessage = helpers.buildHttpMessage(headers, this.getRequestBodyBytes(messageInfo));
                                messageInfo.setRequest(reqMessage);
                                break;

                            case RequestBody:
                                String body = getRequestBody(messageInfo);

                                //check if the match succeeds
                                replaced = matchAndReplace(body, c.getMatch(), c.getReplace(), c.getRegex());
                                if (replaced == null) {
                                    break;
                                }

                                //update the outgoing message
                                reqMessage = helpers.buildHttpMessage(this.getRequestHeaderList(messageInfo), replaced.getBytes(StandardCharsets.UTF_8));
                                messageInfo.setRequest(reqMessage);

                                debugPrint(replaced);
                                break;

                            case RequestTargetHost:

                                //updating the target the request is sent to.
                                //we just need to set a new "httpservice" on the messageInfo, no need to mess with the request message itself
                                String host = getRequestTargetHost(messageInfo);
                                replaced = matchAndReplace(host, c.getMatch(), c.getReplace(), c.getRegex());
                                if (replaced == null) {
                                    break;
                                }

                                //update the target
                                hs = helpers.buildHttpService(replaced, this.getRequestTargetPortInt(messageInfo), this.getRequestTargetProto(messageInfo));
                                messageInfo.setHttpService(hs);

                                debugPrint("Updated target host");
                                break;

                            case RequestTargetPort:

                                int port = getRequestTargetPortInt(messageInfo);
                                if (c.getRegex() == true) {
                                    stderr.println("Cannot M/R with regex condition on port");
                                    break;
                                }
                                try {
                                    int matchPort = Integer.parseInt(c.getMatch());
                                    int replacePort = Integer.parseInt(c.getReplace());
                                    if (checkCondition(messageInfo, c)) {

                                        int replacedPort = matchandReplacePort(port, matchPort, replacePort);
                                        if (replacedPort == -1) {
                                            break;
                                        }

                                        //update the target
                                        hs = helpers.buildHttpService(this.getRequestTargetHost(messageInfo), replacedPort, this.getRequestTargetProto(messageInfo));
                                        messageInfo.setHttpService(hs);

                                        debugPrint("Updated target port");
                                        break;
                                    }
                                } catch (Exception e) {
                                    e.printStackTrace(stderr);
                                    break;
                                }

                                debugPrint("Updating target port but no match");
                                break;


                            case Request:
                                String full = getFullRequest(messageInfo);

                                replaced = matchAndReplace(full, c.getMatch(), c.getReplace(), c.getRegex());
                                if (replaced == null) {
                                    break;
                                }
                                byte[] requestBytes = replaced.getBytes(StandardCharsets.UTF_8);


                                //analyze the replaced string to get the header/body split details
                                IRequestInfo ir = helpers.analyzeRequest(requestBytes);

                                //get headers and body from altered request
                                int bodyOffset = ir.getBodyOffset();
                                List<String> replacedHeaders = ir.getHeaders();

                                byte[] replacedBodyBytes = Arrays.copyOfRange(requestBytes, bodyOffset, requestBytes.length);

                                reqMessage = helpers.buildHttpMessage(replacedHeaders, replacedBodyBytes);
                                messageInfo.setRequest(reqMessage);

                                debugPrint(replaced);
                                break;

                            default:
                                stderr.println("switch statement fell through");
                                break;
                        }

                    }

                    debugPrint("Type1 done" + timeLog(startTime));
                }

                //type2 or type3
                else if ((!messageIsRequest && c.conditionTargetIsResponse()) || (!messageIsRequest && c.conditionTargetIsRequest() && c.procedureTargetIsResponse())) {
                    String replaced;

                    if (checkCondition(messageInfo, c)) {
                        enums.TargetType ta = c.getProcedureTarget();
                        byte[] respMessage;

                        switch (ta) {
                            case Response:

                                String full = getFullResponse(messageInfo);


                                replaced = matchAndReplace(full, c.getMatch(), c.getReplace(), c.getRegex());
                                if (replaced == null) {
                                    break;
                                }
                                byte[] responseBytes = replaced.getBytes(StandardCharsets.UTF_8);


                                //analyze the replaced string to get the header/body split details
                                IResponseInfo ir = helpers.analyzeResponse(responseBytes);

                                //get the body
                                int bodyOffset = ir.getBodyOffset();
                                byte[] replacedBodyBytes = Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length);

                                List<String> replacedHeaders = ir.getHeaders();

                                respMessage = helpers.buildHttpMessage(replacedHeaders, replacedBodyBytes);
                                messageInfo.setResponse(respMessage);
                                break;

                            case ResponseHeader:

                                java.util.List<String> headers;
                                String headersString = getResponseHeaders(messageInfo);
                                debugPrint("DEBUG1: here0");

                                if (c.getMatch().equals("") || c.getMatch() == null) { //blank match, just add a header to the request
                                    headers = getResponseHeaderList(messageInfo);
                                    debugPrint("DEBUG1: here0a");
                                    headers.add(c.getReplace());
                                } else if (c.getReplace().equals("")) { // replacing a header with blank line, just remove it from the header list otherwise we end up with a line in the middle of the headers
                                    debugPrint("DEBUG1: here");
                                    headers = getResponseHeaderList(messageInfo);
                                    List<String> iterHeaders = new ArrayList<String>(headers);
                                    boolean removed = false;


                                    for (String header : iterHeaders) {
                                        if (!c.getRegex() && header.equals(c.getMatch())) {
                                            //non-regex matched
                                            headers.remove(header);
                                            removed = true;
                                        }
                                        else if (c.getRegex() && fullregexMatch(header, c.getMatch())) {
                                            //Regex match, remove header
                                            headers.remove(header);
                                            removed = true;
                                        }
                                    }

                                    if (removed == false)
                                    {
                                        //no full line matches, may want to remove part of a header. continue to generic MAR

                                        replaced = matchAndReplace(headersString, c.getMatch(), c.getReplace(), c.getRegex());
                                        if (replaced == null) {
                                            break;
                                        }
                                        //turn the replaced headers back into an array for burp
                                        headers = Arrays.asList(replaced.split("\r\n"));
                                    }
                                }

                                else {
                                    debugPrint("DEBUG1: here2");
                                    //full match and replace on response header
                                    replaced = matchAndReplace(headersString, c.getMatch(), c.getReplace(), c.getRegex());
                                    if (replaced == null) {
                                        break;
                                    }
                                    //turn the replaced headers back into an array for burp
                                    headers = Arrays.asList(replaced.split("\r\n"));
                                }
                                //build a new http response from the replace variables and send it instead
                                respMessage = helpers.buildHttpMessage(headers, this.getResponseBodyBytes(messageInfo));
                                messageInfo.setResponse(respMessage);
                                break;


                            case ResponseBody:

                                String body = getResponseBody(messageInfo);

                                replaced = matchAndReplace(body, c.getMatch(), c.getReplace(), c.getRegex());
                                if (replaced == null) {
                                    break;
                                }

                                //update the outgoing message
                                respMessage = helpers.buildHttpMessage(this.getResponseHeaderList(messageInfo), replaced.getBytes(StandardCharsets.UTF_8));
                                messageInfo.setResponse(respMessage);

                                debugPrint(replaced);
                                break;

                            default:
                                stderr.println("switch fell through");
                        }
                    }

                    debugPrint("type 2 done" + timeLog(startTime));
                } else if (!messageIsRequest && c.conditionTargetIsRequest()) {
                    //response && condition is for request?
                    //we can hit this when it fires for a response, where the conditional and operation were both on the req. just ignore.
                    debugPrint("Response recieved, but CMAR applies to request. Doing nothing.");
                } else if (messageIsRequest && c.procedureTargetIsResponse()) {
                    //nothing to do here, we process this when the response arrives
                    debugPrint("nothing to do");
                } else {
                    stderr.println("Message and conditions didn't match any known combo, probably shouldn't be here");
                }
                debugPrint("loop iteration complete: " + timeLog(startTime));
            }
        }

    }


    private String timeLog(long startTime) {
        long current = System.nanoTime();
        long duration = (current - startTime);
        float f = (float) duration / 1000000;
        return Float.toString(f);
    }

    private int matchandReplacePort(int target, int match, int replace) {
        int responsePort = -1;
        debugPrint("replacing port");
        if (target != match) {
            return -1;
        }
        responsePort = replace;
        return responsePort;
    }

    public boolean fullregexMatch(String target, String match){
        Pattern p = Pattern.compile(match);
        return p.matcher(target).matches();
    }


    public String matchAndReplace(String target, String match, String replace, boolean isRegex) {
        String outs;

        debugPrint("Running MAR...");
        debugPrint("Target: " + target);
        debugPrint("\n");
        debugPrint("Match: " + match);
        debugPrint("\n");
        debugPrint("Replace: " + replace);
        debugPrint("\n");
        debugPrint("Regex: " + isRegex);

        if (isRegex) {
            Pattern p = Pattern.compile(match);
            Matcher m = p.matcher(target);

            boolean found = false;
            StringBuffer outsSb = new StringBuffer();

            //match and replace
            while (m.find()) {
                String matchedText = m.group();
                if (!matchedText.equals("")) {
                    found = true;
                    m.appendReplacement(outsSb, replace);
                }
            }
            m.appendTail(outsSb);

            if (!found) {
                return null;
            }
            return outsSb.toString();
        } else {
            //plain match and replace
            debugPrint("Non-regex match and replace");
            if (!target.contains(match)) {
                return null;
            }
            outs = target.replace(match, replace);
            debugPrint("Literal MAR outs = "+outs);
            return outs;
        }
    }


    public Boolean checkCondition(IHttpRequestResponse messageInfo, cmar c) {
        enums.TargetType ct = c.getConditionTarget();
        String area = null;
        int port = 0;
        int condPort = -1;

        boolean isConditionRegex = c.getConditionRegex();

        switch (ct) {
            case RequestFirstLine:
                area = this.getFirstLine(messageInfo);
                break;
            case Request:
                area = this.getFullRequest(messageInfo);
                break;
            case RequestBody:
                area = this.getRequestBody(messageInfo);
                break;
            case RequestHeader:
                area = this.getRequestHeaders(messageInfo);
                break;
            case RequestTargetHost:
                area = this.getRequestTargetHost(messageInfo);
                break;
            case RequestTargetPort:
                port = this.getRequestTargetPortInt(messageInfo);

                if (c.getConditionRegex()) {
                    area = String.valueOf(port);
                    break;
                }

                try {
                    condPort = Integer.parseInt(c.getCondition());
                    break;
                } catch (Exception e) {
                    e.printStackTrace(stderr);
                    break;
                }
            case Response:
                area = this.getFullResponse(messageInfo);
                break;
            case ResponseBody:
                area = this.getResponseBody(messageInfo);
                break;
            case ResponseHeader:
                area = this.getResponseHeaders(messageInfo);
                break;
            default:
                stderr.println("switch fell through in checkcondition");
                break;
        }



        debugPrint("debug area = " + area);
        debugPrint("debug condition = " + c.getCondition());


        if (isConditionRegex) {
            String condition = c.getCondition();
            Pattern p = Pattern.compile(condition, Pattern.MULTILINE);
            Matcher m = p.matcher(area);

            debugPrint("condition is regex, checking for match");
            debugPrint("CR = " + condition);
            debugPrint(area);

            if (m.find()) {
                debugPrint("found true conditional regex");
                return c.getConditionRelationship() == enums.ConditionRelationship.Matches;
            } else {
                return c.getConditionRelationship() == enums.ConditionRelationship.DoesntMatch;
            }
        }


        //handling checks for target port
        if (ct == enums.TargetType.RequestTargetPort) {
            //matching for port integer
            debugPrint("checking port equivalence");
            if (port == condPort) {
                return c.getConditionRelationship() == enums.ConditionRelationship.Matches;
            } else {
                return c.getConditionRelationship() == enums.ConditionRelationship.DoesntMatch;
            }
        }


        //check if the cmars target condition area contains the condition
        if (area.contains(c.getCondition())) {
            return c.getConditionRelationship() == enums.ConditionRelationship.Matches;
        } else {
            return c.getConditionRelationship() == enums.ConditionRelationship.DoesntMatch;
        }

    }


    public String getRequestTargetProto(IHttpRequestResponse messageInfo) {
        IHttpService hs = messageInfo.getHttpService();
        debugPrint("http service proto= " + hs.getProtocol());
        return hs.getProtocol();
    }

    public String getRequestTargetHost(IHttpRequestResponse messageInfo) {
        IHttpService hs = messageInfo.getHttpService();
        debugPrint("http service = " + hs.getHost());
        return hs.getHost();
    }

    public int getRequestTargetPortInt(IHttpRequestResponse messageInfo) {
        IHttpService hs = messageInfo.getHttpService();
        debugPrint("http service port = " + hs.getPort());

        return hs.getPort();
    }

    public String getFirstLine(IHttpRequestResponse messageInfo) {
        byte[] mr = messageInfo.getRequest();
        IRequestInfo ir = helpers.analyzeRequest(mr);
        List<String> headers = ir.getHeaders();
        return headers.get(0);
    }

    public String getRequestHeaders(IHttpRequestResponse messageInfo) {
        byte[] mr = messageInfo.getRequest();
        IRequestInfo ir = helpers.analyzeRequest(mr);
        int bodyOffset = ir.getBodyOffset();
        byte[] headersBytes = Arrays.copyOfRange(mr, 0, bodyOffset);
        return new String(headersBytes, StandardCharsets.UTF_8);
    }

    public String getResponseHeaders(IHttpRequestResponse messageInfo) {
        byte[] mr = messageInfo.getResponse();
        IResponseInfo ir = helpers.analyzeResponse(mr);
        int bodyOffset = ir.getBodyOffset();
        byte[] headersBytes = Arrays.copyOfRange(mr, 0, bodyOffset);
        return new String(headersBytes, StandardCharsets.UTF_8);
    }

    public List<String> getRequestHeaderList(IHttpRequestResponse messageInfo) {
        byte[] mr = messageInfo.getRequest();
        IRequestInfo ir = helpers.analyzeRequest(mr);
        return ir.getHeaders();
    }

    public List<String> getResponseHeaderList(IHttpRequestResponse messageInfo) {
        byte[] mr = messageInfo.getResponse();
        IResponseInfo ir = helpers.analyzeResponse(mr);
        return ir.getHeaders();
    }

    public byte[] getRequestBodyBytes(IHttpRequestResponse messageInfo) {
        byte[] mr = messageInfo.getRequest();
        IRequestInfo ir = helpers.analyzeRequest(mr);
        int bodyOffset = ir.getBodyOffset();
        byte[] bodyBytes = Arrays.copyOfRange(mr, bodyOffset, mr.length);
        return bodyBytes;
    }

    public byte[] getResponseBodyBytes(IHttpRequestResponse messageInfo) {
        byte[] mr = messageInfo.getResponse();
        IResponseInfo ir = helpers.analyzeResponse(mr);
        int bodyOffset = ir.getBodyOffset();
        byte[] bodyBytes = Arrays.copyOfRange(mr, bodyOffset, mr.length);
        return bodyBytes;
    }


    public String getRequestBody(IHttpRequestResponse messageInfo) {
        byte[] mr = messageInfo.getRequest();
        IRequestInfo ir = helpers.analyzeRequest(mr);
        int bodyOffset = ir.getBodyOffset();
        byte[] bodyBytes = Arrays.copyOfRange(mr, bodyOffset, mr.length);
        return new String(bodyBytes, StandardCharsets.UTF_8);
    }

    public String getResponseBody(IHttpRequestResponse messageInfo) {
        byte[] mr = messageInfo.getResponse();
        IResponseInfo ir = helpers.analyzeResponse(mr);
        int bodyOffset = ir.getBodyOffset();
        byte[] bodyBytes = Arrays.copyOfRange(mr, bodyOffset, mr.length);
        return new String(bodyBytes, StandardCharsets.UTF_8);
    }


    public String getFullRequest(IHttpRequestResponse messageInfo) {
        byte[] mr = messageInfo.getRequest();
        return new String(mr, StandardCharsets.UTF_8);
    }

    public String getFullResponse(IHttpRequestResponse messageInfo) {
        byte[] mr = messageInfo.getResponse();
        return new String(mr, StandardCharsets.UTF_8);
    }


}
