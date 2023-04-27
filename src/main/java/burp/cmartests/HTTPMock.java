package burp.cmartests;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class HTTPMock implements IHttpRequestResponse {
    byte[] request;
    byte[] response;
    IHttpService ih;

    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public void setRequest(byte[] message) {
        request = message;
    }

    @Override
    public byte[] getResponse() {
        return response;
    }

    @Override
    public void setResponse(byte[] message) {
        response = message;
    }

    @Override
    public String getComment() {
        return null;
    }

    @Override
    public void setComment(String comment) {

    }

    @Override
    public String getHighlight() {
        return null;
    }

    @Override
    public void setHighlight(String color) {

    }

    @Override
    public IHttpService getHttpService() {
        return ih;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        ih = httpService;
    }
}
