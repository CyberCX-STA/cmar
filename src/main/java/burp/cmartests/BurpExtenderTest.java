package burp.cmartests;


import burp.*;
import burp.cmarui.CmarTableModel;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;


public class BurpExtenderTest {
    BurpExtender b;
    IExtensionHelpers helpers;
    HTTPMock request1;
    HTTPMock request2;
    HTTPMock response1;
    String r1;
    String r2;
    String resp1_h;
    String resp1_b;
    String resp1;


    public BurpExtenderTest(BurpExtender b) {
        this.b = b;
        this.helpers = b.helpers;
        this.setupRequestObjects();

    }

    void setupRequestObjects() {
        IHttpService hs = helpers.buildHttpService("1.3.3.7", 80, true);
        //Setting up some test requests and responses
        request1 = new HTTPMock();
        r1 = "GET /asd.css HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Replace: Yes\r\n" +
                "invalid: zzz\r\n" +
                "asd: asd\r\n" +
                "\r\n";

        request1.setRequest(r1.getBytes(StandardCharsets.UTF_8));
        request1.setHttpService(hs);


        request2 = new HTTPMock();
        r2 = "POST /test HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Replace: Yes\r\n" +
                "invalid: zzz\r\n" +
                "Content-Type: application/json\r\n" +
                "\r\n" +
                "param1=test&param2=test";

        request2.setRequest(r2.getBytes(StandardCharsets.UTF_8));
        request2.setHttpService(hs);


        response1 = new HTTPMock();
        resp1_h = "HTTP/1.0 404 File not found\r\n" +
                "Server: SimpleHTTP/0.6 Python/3.8.10\r\n" +
                "Date: Tue, 08 Feb 2022 01:54:28 GMT\r\n" +
                "Connection: close\r\n" +
                "Content-Type: text/html;charset=utf-8\r\n" +
                "Content-Length: 469\r\n" +
                "\r\n";


        resp1_b = "<html>\r\n" +
                "    <head>\r\n" +
                "        <meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">\r\n" +
                "        <title>Error response</title>\r\n" +
                "    </head>\r\n" +
                "    <body>";


        resp1 = resp1_h + resp1_b;

        response1.setRequest(r2.getBytes(StandardCharsets.UTF_8)); //set request to get this response
        response1.setResponse(resp1.getBytes(StandardCharsets.UTF_8));
        response1.setHttpService(hs);
    }


    public void testProcessMessage() throws NoSuchFieldException, IllegalAccessException {

        cmar c = new cmar(false, enums.TargetType.Request, enums.ConditionRelationship.Matches, "Host: localhost",
                enums.TargetType.RequestTargetPort, "80", "8080", false, false, "Change target port for localhost:80 requests");
        b.addCmar(c);

    }


    public void testTableModel() {
        burp.cmarui.CmarTableModel tm = b.getTableModel();
        //clear out table
        tm.removeAll();

        CmarTestRunner.assertEquals("Table not empty", 0, tm.getAll().size());

        tm.insertCmar(0, new cmar(false, enums.TargetType.Request, enums.ConditionRelationship.Matches, "Host: localhost",
                enums.TargetType.RequestTargetPort, "80", "8080", false, false, "Change target port for localhost:80 requests"));

        CmarTestRunner.assertEquals("Failed to insert", 1, tm.getAll().size());

    }


    public void testExtenderMessageHelpers() {
        CmarTableModel tm = b.getTableModel();
        tm.removeAll();
        this.setupRequestObjects();


        tm.insertCmar(0, new cmar(true, enums.TargetType.Request, enums.ConditionRelationship.Matches, "Host: localhost",
                enums.TargetType.RequestTargetPort, "80", "8080", false, false, "Change target port for localhost:80 requests"));


        CmarTestRunner.assertEquals("Firstline invalid", "GET /asd.css HTTP/1.1", b.getFirstLine(request1));
        CmarTestRunner.assertEquals("Invalid protocol", "https", b.getRequestTargetProto(request1));
        CmarTestRunner.assertEquals("Invalid host", "1.3.3.7", b.getRequestTargetHost(request1));
        CmarTestRunner.assertEquals("Invalid port", 80, b.getRequestTargetPortInt(request1));
        CmarTestRunner.assertEquals("Geting request headers failed", r1, b.getRequestHeaders(request1));

        List<String> expectedHeaders = Arrays.asList(r1.split("\r\n"));
        CmarTestRunner.assertEquals("Getting request headers list failed", expectedHeaders, b.getRequestHeaderList(request1));

        List<String> expectedResponseHeaders = Arrays.asList(resp1_h.split("\r\n"));
        CmarTestRunner.assertEquals("Geting response headers list failed", expectedResponseHeaders, b.getResponseHeaderList(response1));


        CmarTestRunner.assertEquals("Request body incorrect", "param1=test&param2=test", b.getRequestBody(request2));

        CmarTestRunner.assertEquals("Request body bytes incorrect", "param1=test&param2=test".getBytes(), b.getRequestBodyBytes(request2));


        CmarTestRunner.assertEquals("Response body incorrect", resp1_b, b.getResponseBody(response1));
        CmarTestRunner.assertEquals("Response body bytes  incorrect", resp1_b.getBytes(), b.getResponseBodyBytes(response1));
        CmarTestRunner.assertEquals("Geting response headers failed", resp1_h, b.getResponseHeaders(response1));


        CmarTestRunner.assertEquals("Full request invalid", r2, b.getFullRequest(request2));
        CmarTestRunner.assertEquals("Full response invalid", resp1, b.getFullResponse(response1));

    }

    public void checkCheckConditionsLiteral() {

        CmarTableModel tm = b.getTableModel();
        tm.removeAll();
        this.setupRequestObjects();

        cmar c = new cmar(true, enums.TargetType.Request, enums.ConditionRelationship.DoesntMatch, "yyyyy",
                null, null, null, false, false, "Testing");

        CmarTestRunner.assertEquals("Check condition Request not match did not succeed", true, b.checkCondition(request1, c));

        c.setConditionRelationship(enums.ConditionRelationship.Matches);

        c.setConditionTarget(enums.TargetType.RequestFirstLine);
        c.setCondition("GET /asd.css HTTP/1.1");
        CmarTestRunner.assertEquals("Check condition RequestFirstLine did not succeed", true, b.checkCondition(request1, c));

        c.setConditionTarget(enums.TargetType.RequestHeader);
        c.setCondition("Replace: Yes");
        CmarTestRunner.assertEquals("Check condition RequestHeader did not succeed", true, b.checkCondition(request1, c));

        c.setConditionTarget(enums.TargetType.Request);
        c.setCondition("param1=test");
        CmarTestRunner.assertEquals("Check condition Full Request did not succeed", true, b.checkCondition(request2, c));


        c.setConditionTarget(enums.TargetType.RequestBody);
        c.setCondition("param1=test");
        CmarTestRunner.assertEquals("Check condition RequestBody did not succeed", true, b.checkCondition(request2, c));

        c.setConditionTarget(enums.TargetType.RequestTargetHost);
        c.setCondition("1.3.3.7");
        CmarTestRunner.assertEquals("Check condition RequestTargetHost did not succeed", true, b.checkCondition(request2, c));

        c.setConditionTarget(enums.TargetType.RequestTargetPort);
        c.setCondition("80");
        CmarTestRunner.assertEquals("Check condition RequestTargetPort did not succeed", true, b.checkCondition(request2, c));


        c.setConditionTarget(enums.TargetType.ResponseHeader);
        c.setCondition("Server: SimpleHTTP/0.6 Python/3.8.10");
        CmarTestRunner.assertEquals("Check condition ResponseHeader did not succeed", true, b.checkCondition(response1, c));

        c.setConditionTarget(enums.TargetType.ResponseBody);
        c.setCondition("Error response");
        CmarTestRunner.assertEquals("Check condition ResponseBody did not succeed", true, b.checkCondition(response1, c));

        c.setConditionTarget(enums.TargetType.Response);
        c.setCondition("meta http-equiv");
        CmarTestRunner.assertEquals("Check condition Response did not succeed", true, b.checkCondition(response1, c));

    }


    public void checkCheckConditionsRegex() {
        CmarTableModel tm = b.getTableModel();
        tm.removeAll();
        this.setupRequestObjects();


        cmar c = new cmar(true, enums.TargetType.Request, enums.ConditionRelationship.Matches, "yyyyy",
                null, null, null, false, true, "Testing");

        c.setConditionTarget(enums.TargetType.RequestFirstLine);
        c.setCondition("GET /.* HTTP/1.1");
        CmarTestRunner.assertEquals("Check condition RequestFirstLine did not succeed", true, b.checkCondition(request1, c));

        c.setConditionTarget(enums.TargetType.RequestHeader);
        c.setCondition("^Replace: [Y|N]es$");
        CmarTestRunner.assertEquals("Check condition RequestHeader did not succeed", true, b.checkCondition(request1, c));


        c.setConditionTarget(enums.TargetType.RequestBody);
        c.setCondition("param[0-9]*=test");
        CmarTestRunner.assertEquals("Check condition RequestBody did not succeed", true, b.checkCondition(request2, c));

        c.setConditionTarget(enums.TargetType.Request);
        c.setCondition("param[0-9]*=test");
        CmarTestRunner.assertEquals("Check condition Full Request did not succeed", true, b.checkCondition(request2, c));

        c.setConditionTarget(enums.TargetType.RequestTargetHost);
        c.setCondition("1.[^4]{1}.3.7");
        CmarTestRunner.assertEquals("Check condition RequestTargetHost did not succeed", true, b.checkCondition(request2, c));


        c.setConditionTarget(enums.TargetType.RequestTargetPort);
        c.setCondition("^[0-9]{2}$");
        CmarTestRunner.assertEquals("Check condition RequestTargetPort did not succeed", true, b.checkCondition(request2, c));


        c.setConditionTarget(enums.TargetType.ResponseHeader);
        c.setCondition("Python/[^2]*");
        CmarTestRunner.assertEquals("Check condition ResponseHeader did not succeed", true, b.checkCondition(response1, c));

        c.setConditionTarget(enums.TargetType.ResponseBody);
        c.setCondition("Error r[a-z]+sponse");
        CmarTestRunner.assertEquals("Check condition ResponseBody did not succeed", true, b.checkCondition(response1, c));

        c.setConditionTarget(enums.TargetType.Response);
        c.setCondition("meta\\shttp-equiv");
        CmarTestRunner.assertEquals("Check condition Response did not succeed", true, b.checkCondition(response1, c));

    }

    public void checkMovingRules() {
        CmarTableModel tm = b.getTableModel();
        tm.removeAll();
        this.setupRequestObjects();

        cmar c1 = new cmar(true, enums.TargetType.Request, enums.ConditionRelationship.Matches, "yyyyy",
                null, null, null, false, true, "Testing1");

        cmar c2 = new cmar(true, enums.TargetType.Request, enums.ConditionRelationship.Matches, "yyyyy",
                null, null, null, false, true, "Testing2");


        tm.addCmar(c1);
        tm.addCmar(c2);

        tm.moveUp(0);
        CmarTestRunner.assertEquals("Check moving top cmar up does nothing", true, tm.getCmar(0).equals(c1));
        CmarTestRunner.assertEquals("Check moving top cmar up does nothing", true, tm.getCmar(1).equals(c2));
        tm.moveUp(1);
        CmarTestRunner.assertEquals("Check moving cmar up works", true, tm.getCmar(0).equals(c2));
        CmarTestRunner.assertEquals("Check moving cmar up works", true, tm.getCmar(1).equals(c1));

        tm.removeAll();
        tm.addCmar(c1);
        tm.addCmar(c2);

        tm.moveDown(1);
        CmarTestRunner.assertEquals("Check moving bottom cmar down does nothing", true, tm.getCmar(0).equals(c1));
        CmarTestRunner.assertEquals("Check moving bottom cmar down does nothing", true, tm.getCmar(1).equals(c2));
        tm.moveDown(0);
        CmarTestRunner.assertEquals("Check moving cmar down works", true, tm.getCmar(0).equals(c2));
        CmarTestRunner.assertEquals("Check moving cmar down works", true, tm.getCmar(1).equals(c1));

    }


    public void checkMatchAndReplaceLiteral() {
        /* Exercise the (literal) match and replace method. We will assume here that the condition match is working appropriately as it is tested elsewhere

         */

        CmarTableModel tm = b.getTableModel();
        tm.removeAll();
        this.setupRequestObjects();


        cmar c1 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "asd.css",
                enums.TargetType.RequestFirstLine, "css", "def", false, false, "Testing1");
        tm.addCmar(c1);

        b.processHttpMessage(0, true, request1);
        CmarTestRunner.assertEquals("first line check", true, b.getFirstLine(request1).equals("GET /asd.def HTTP/1.1"));

        //Replace a header
        this.setupRequestObjects();
        tm.removeAll();
        cmar c2 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "asd.css",
                enums.TargetType.RequestHeader, "invalid: zzz", "invalid: yyy", false, false, "Testing2");
        tm.addCmar(c2);
        b.processHttpMessage(0, true, request1);
        CmarTestRunner.assertEquals("Header replace", true, (b.getRequestHeaders(request1).contains("invalid: yyy") && !b.getRequestHeaders(request1).contains("invalid: zzz")));

        //Remove a request header
        this.setupRequestObjects();
        tm.removeAll();
        cmar c2a = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "asd.css",
                enums.TargetType.RequestHeader, "invalid: zzz", "", false, false, "Testing2");
        tm.addCmar(c2a);
        b.processHttpMessage(0, true, request1);
        CmarTestRunner.assertEquals("Remove request header", true, (b.getRequestHeaders(request1).contains("Replace: Yes\r\nasd: asd") && !b.getRequestHeaders(request1).contains("invalid: zzz")));
        //CmarTestRunner.printError(b.getRequestHeaders(request1));

        //Remove part of a request header
        this.setupRequestObjects();
        tm.removeAll();
        cmar c2a1 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "asd.css",
                enums.TargetType.RequestHeader, "alid", "", false, false, "Testing2");
        tm.addCmar(c2a1);
        b.processHttpMessage(0, true, request1);
        CmarTestRunner.assertEquals("Remove request header", true, (b.getRequestHeaders(request1).contains("inv:") && !b.getRequestHeaders(request1).contains("invalid")));
        //CmarTestRunner.printError(b.getRequestHeaders(request1));



        //Remove a response header
        this.setupRequestObjects();
        tm.removeAll();
        response1.setRequest(r1.getBytes(StandardCharsets.UTF_8)); //set associated request to the GET one
        cmar c2b = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "asd.css",
                        enums.TargetType.ResponseHeader, "Date: Tue, 08 Feb 2022 01:54:28 GMT", "", false, false, "Testing2");
        tm.addCmar(c2b);
        b.processHttpMessage(0, false, response1);
        CmarTestRunner.assertEquals("Remove response header", true, (b.getResponseHeaders(response1).contains("Python/3.8.10\r\nConnection: close") && !b.getResponseHeaders(response1).contains("Date: ")));


        //Remove part of a response header
        this.setupRequestObjects();
        tm.removeAll();
        response1.setRequest(r1.getBytes(StandardCharsets.UTF_8)); //set associated request to the GET one
        cmar c2b1 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "asd.css",
                enums.TargetType.ResponseHeader, "Tue,", "", false, false, "Testing2");
        tm.addCmar(c2b1);
        b.processHttpMessage(0, false, response1);
        CmarTestRunner.assertEquals("Remove response header - partial", true, (b.getResponseHeaders(response1).contains("Date:  08 Feb 2022 01:54:28 GMT") && !b.getResponseHeaders(response1).contains("Tue,")));


        //Replace body
        this.setupRequestObjects();
        tm.removeAll();
        cmar c3 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "POST /test",
                enums.TargetType.RequestBody, "param2=test", "param2=asdf", false, false, "Testing2");
        tm.addCmar(c3);
        b.processHttpMessage(0, true, request2);
        CmarTestRunner.assertEquals("Body replace", true, (b.getRequestBody(request2).contains("param2=asdf") && !b.getRequestBody(request2).contains("param2=test")));


        //replace full req
        this.setupRequestObjects();
        tm.removeAll();
        cmar c4 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "POST /test",
                enums.TargetType.Request, "param2=test", "param2=asdf", false, false, "Testing2");
        tm.addCmar(c4);
        b.processHttpMessage(0, true, request2);
        CmarTestRunner.assertEquals("Full request Body replace", true, (b.getRequestBody(request2).contains("param2=asdf") && !b.getRequestBody(request2).contains("param2=test")));


        //target port
        this.setupRequestObjects();
        tm.removeAll();
        cmar c6 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "POST /test",
                enums.TargetType.RequestTargetPort, "80", "1234", false, false, "Testing2");
        tm.addCmar(c6);
        b.processHttpMessage(0, true, request2);
        CmarTestRunner.assertEquals("Target Port replace", true, b.getRequestTargetPortInt(request2) == 1234);


        //target host
        this.setupRequestObjects();
        tm.removeAll();
        cmar c7 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "POST /test",
                enums.TargetType.RequestTargetHost, "1.3.3.7", "1.1.1.1", false, false, "Testing2");
        tm.addCmar(c7);
        b.processHttpMessage(0, true, request2);
        CmarTestRunner.assertEquals("Target Host replace", true, b.getRequestTargetHost(request2).equals("1.1.1.1"));


        //response
        this.setupRequestObjects();
        tm.removeAll();
        response1.setRequest(r1.getBytes(StandardCharsets.UTF_8));
        cmar c8 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "asd.css",
                enums.TargetType.Response, "SimpleHTTP/0.6", "SimpleHTTP/1.1", false, false, "Testing2");
        tm.addCmar(c8);
        b.processHttpMessage(0, false, response1);
        CmarTestRunner.assertEquals("Response full", true, (b.getFullResponse(response1).contains("SimpleHTTP/1.1") && !b.getFullResponse(response1).contains("SimpleHTTP/0.6")));


        //response body
        this.setupRequestObjects();
        tm.removeAll();
        cmar c9 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "POST /test",
                enums.TargetType.ResponseBody, "Error response", "Test response", false, false, "Testing2");
        tm.addCmar(c9);
        b.processHttpMessage(0, false, response1);
        CmarTestRunner.assertEquals("Response Body ", true, (b.getResponseBody(response1).contains("Test response") && !b.getResponseBody(response1).contains("Error response")));


        //response header
        this.setupRequestObjects();
        tm.removeAll();
        cmar c10 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "POST /test",
                enums.TargetType.ResponseHeader, "Content-Type: text/html", "Content-Type: next/html", false, false, "Testing2");
        tm.addCmar(c10);
        b.processHttpMessage(0, false, response1);
        CmarTestRunner.assertEquals("Response header", true, (b.getResponseHeaders(response1).contains("Content-Type: next/html") && !b.getResponseHeaders(response1).contains("Content-Type: text/html")));


        //match response, alter response
        this.setupRequestObjects();
        tm.removeAll();
        cmar c11 = new cmar(true, enums.TargetType.ResponseHeader, enums.ConditionRelationship.Matches, "404 File not found",
                enums.TargetType.ResponseHeader, "Content-Type: text/html", "Content-Type: next/html", false, false, "Testing2");
        tm.addCmar(c11);
        b.processHttpMessage(0, false, response1);
        CmarTestRunner.assertEquals("Response header", true, (b.getResponseHeaders(response1).contains("Content-Type: next/html") && !b.getResponseHeaders(response1).contains("Content-Type: text/html")));

        this.setupRequestObjects();
        tm.removeAll();
        cmar c12 = new cmar(true, enums.TargetType.ResponseHeader, enums.ConditionRelationship.Matches, "404 File not found",
                enums.TargetType.ResponseBody, "Error response", "Test response", false, false, "Testing2");
        tm.addCmar(c12);
        b.processHttpMessage(0, false, response1);
        CmarTestRunner.assertEquals("Response body 2", true, (b.getFullResponse(response1).contains("Test response") && !b.getFullResponse(response1).contains("Error response")));

        this.setupRequestObjects();
        tm.removeAll();
        cmar c13 = new cmar(true, enums.TargetType.ResponseHeader, enums.ConditionRelationship.Matches, "404 File not found",
                enums.TargetType.Response, "SimpleHTTP/0.6", "SimpleHTTP/1.1", false, false, "Testing2");
        tm.addCmar(c13);
        b.processHttpMessage(0, false, response1);
        CmarTestRunner.assertEquals("Response response 2", true, (b.getResponseHeaders(response1).contains("SimpleHTTP/1.1") && !b.getResponseHeaders(response1).contains("SimpleHTTP/0.6")));

        this.setupRequestObjects();
        tm.removeAll();
    }


    public void checkMatchAndReplaceRegex() {

        CmarTableModel tm = b.getTableModel();
        tm.removeAll();
        this.setupRequestObjects();


        cmar c1 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "asd.css",
                enums.TargetType.RequestFirstLine, "c.*s", "def", true, false, "Testing1");
        tm.addCmar(c1);

        b.processHttpMessage(0, true, request1);
        CmarTestRunner.assertEquals("first line check", true, b.getFirstLine(request1).equals("GET /asd.def HTTP/1.1"));

        //Replace a header
        this.setupRequestObjects();
        tm.removeAll();
        cmar c2 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "asd.css",
                enums.TargetType.RequestHeader, "invalid: .*z", "invalid: yyy", true, false, "Testing2");
        tm.addCmar(c2);
        b.processHttpMessage(0, true, request1);
        CmarTestRunner.assertEquals("Header replace", true, (b.getRequestHeaders(request1).contains("invalid: yyy") && !b.getRequestHeaders(request1).contains("invalid: zzz")));

        //Remove a request header
        this.setupRequestObjects();
        tm.removeAll();
        cmar c2a = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "asd.css",
                enums.TargetType.RequestHeader, "inval.*", "", true, false, "Testing2");
        tm.addCmar(c2a);
        b.processHttpMessage(0, true, request1);
        CmarTestRunner.assertEquals("Remove request header - regex", true, (b.getRequestHeaders(request1).contains("Replace: Yes\r\nasd: asd") && !b.getRequestHeaders(request1).contains("invalid: zzz")));
        //CmarTestRunner.printError(b.getRequestHeaders(request1));



        //Remove part of a request header
        this.setupRequestObjects();
        tm.removeAll();
        cmar c2a1 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "asd.css",
                enums.TargetType.RequestHeader, "inval.*", "", true, false, "Testing2");
        tm.addCmar(c2a1);
        b.processHttpMessage(0, true, request1);
        CmarTestRunner.assertEquals("Remove request header - regex", true, (b.getRequestHeaders(request1).contains("Replace: Yes\r\nasd: asd") && !b.getRequestHeaders(request1).contains("invalid: zzz")));
        //CmarTestRunner.printError(b.getRequestHeaders(request1));


        //Remove a response header
        this.setupRequestObjects();
        tm.removeAll();
        response1.setRequest(r1.getBytes(StandardCharsets.UTF_8)); //set associated request to the GET one
        cmar c2b = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "asd.css",
                enums.TargetType.ResponseHeader, "Date: Tue, .*", "", true, false, "Testing2");
        tm.addCmar(c2b);
        //CmarTestRunner.printError("before" + b.getResponseHeaders(response1));
        b.processHttpMessage(0, false, response1);
        //CmarTestRunner.printError("afer"+b.getResponseHeaders(response1));
        CmarTestRunner.assertEquals("Remove response header - regex", true, (b.getResponseHeaders(response1).contains("Python/3.8.10\r\nConnection: close") && !b.getResponseHeaders(response1).contains("Date: ")));

        //Remove part of a response header
        this.setupRequestObjects();
        tm.removeAll();
        response1.setRequest(r1.getBytes(StandardCharsets.UTF_8)); //set associated request to the GET one
        cmar c2b1 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "asd.css",
                enums.TargetType.ResponseHeader, "Tue, [0-9]{2}", "", true, false, "Testing2");
        tm.addCmar(c2b1);

        b.processHttpMessage(0, false, response1);

        CmarTestRunner.assertEquals("Remove response header partial - regex", true, (b.getResponseHeaders(response1).contains("Date:  Feb 2022 01:54:28 GMT") && !b.getResponseHeaders(response1).contains("Tue, 08")));







        //Replace body
        this.setupRequestObjects();
        tm.removeAll();
        cmar c3 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "POST /test",
                enums.TargetType.RequestBody, "param[0-9]*=test", "param2=asdf", true, false, "Testing2");
        tm.addCmar(c3);
        b.processHttpMessage(0, true, request2);
        CmarTestRunner.assertEquals("Body replace", true, (b.getRequestBody(request2).contains("param2=asdf") && !b.getRequestBody(request2).contains("param2=test")));


        //replace full req
        this.setupRequestObjects();
        tm.removeAll();
        cmar c4 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "POST /test",
                enums.TargetType.Request, "param[0-9]*=test", "param2=asdf", true, false, "Testing2");
        tm.addCmar(c4);
        b.processHttpMessage(0, true, request2);
        CmarTestRunner.assertEquals("Full request Body replace", true, (b.getRequestBody(request2).contains("param2=asdf") && !b.getRequestBody(request2).contains("param2=test")));


        //target port
        //this is actually not possible via regex currently, so checking it fails.
        this.setupRequestObjects();
        tm.removeAll();
        cmar c6 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "POST /test",
                enums.TargetType.RequestTargetPort, "^[0-9]{2}$", "1234", true, false, "Testing2");

        tm.addCmar(c6);
        b.processHttpMessage(0, true, request2);
        CmarTestRunner.assertEquals("Target Port replace", false, b.getRequestTargetPortInt(request2) == 1234);


        //target host
        this.setupRequestObjects();
        tm.removeAll();
        cmar c7 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "POST /test",
                enums.TargetType.RequestTargetHost, "1.[^4]{1}.3.7", "1.1.1.1", true, false, "Testing2");
        tm.addCmar(c7);
        b.processHttpMessage(0, true, request2);
        CmarTestRunner.assertEquals("Target Host replace", true, b.getRequestTargetHost(request2).equals("1.1.1.1"));


        //response
        this.setupRequestObjects();
        tm.removeAll();
        response1.setRequest(r1.getBytes(StandardCharsets.UTF_8));
        cmar c8 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "asd.css",
                enums.TargetType.Response, "SimpleHTTP.*6", "SimpleHTTP/1.1", true, false, "Testing2");
        tm.addCmar(c8);
        b.processHttpMessage(0, false, response1);
        CmarTestRunner.assertEquals("Response full", true, (b.getFullResponse(response1).contains("SimpleHTTP/1.1") && !b.getFullResponse(response1).contains("SimpleHTTP/0.6")));


        //response body
        this.setupRequestObjects();
        tm.removeAll();
        cmar c9 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "POST /test",
                enums.TargetType.ResponseBody, "Error response", "Test response", true, false, "Testing2");
        tm.addCmar(c9);
        b.processHttpMessage(0, false, response1);
        CmarTestRunner.assertEquals("Response Body ", true, (b.getResponseBody(response1).contains("Test response") && !b.getResponseBody(response1).contains("Error response")));


        //response header
        this.setupRequestObjects();
        tm.removeAll();
        cmar c10 = new cmar(true, enums.TargetType.RequestFirstLine, enums.ConditionRelationship.Matches, "POST /test",
                enums.TargetType.ResponseHeader, "Content-Type: text/html", "Content-Type: next/html", true, false, "Testing2");
        tm.addCmar(c10);
        b.processHttpMessage(0, false, response1);
        CmarTestRunner.assertEquals("Response header", true, (b.getResponseHeaders(response1).contains("Content-Type: next/html") && !b.getResponseHeaders(response1).contains("Content-Type: text/html")));

        tm.removeAll();


        //match response, alter response
        this.setupRequestObjects();
        tm.removeAll();
        cmar c11 = new cmar(true, enums.TargetType.ResponseHeader, enums.ConditionRelationship.Matches, "404 File not found",
                enums.TargetType.ResponseHeader, "Content-Type: text/html", "Content-Type: next/html", true, false, "Testing2");
        tm.addCmar(c11);
        b.processHttpMessage(0, false, response1);
        CmarTestRunner.assertEquals("Response header", true, (b.getResponseHeaders(response1).contains("Content-Type: next/html") && !b.getResponseHeaders(response1).contains("Content-Type: text/html")));

        this.setupRequestObjects();
        tm.removeAll();
        cmar c12 = new cmar(true, enums.TargetType.ResponseHeader, enums.ConditionRelationship.Matches, "404 File not found",
                enums.TargetType.ResponseBody, "Error response", "Test response", true, false, "Testing2");
        tm.addCmar(c12);
        b.processHttpMessage(0, false, response1);
        CmarTestRunner.assertEquals("Response body 2", true, (b.getFullResponse(response1).contains("Test response") && !b.getFullResponse(response1).contains("Error response")));

        this.setupRequestObjects();
        tm.removeAll();
        cmar c13 = new cmar(true, enums.TargetType.ResponseHeader, enums.ConditionRelationship.Matches, "404 File not found",
                enums.TargetType.Response, "SimpleHTTP.*6", "SimpleHTTP/1.1", true, false, "Testing2");
        tm.addCmar(c13);
        b.processHttpMessage(0, false, response1);
        CmarTestRunner.assertEquals("Response response 2", true, (b.getResponseHeaders(response1).contains("SimpleHTTP/1.1") && !b.getResponseHeaders(response1).contains("SimpleHTTP/0.6")));


        this.setupRequestObjects();
        tm.removeAll();
    }


}
