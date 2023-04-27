package burp;

import java.util.EnumSet;
import java.util.Set;

public class enums {
    public enum TargetType {
        Request,
        RequestHeader,
        RequestFirstLine,
        RequestBody,
        RequestTargetHost,
        RequestTargetPort,
        Response,
        ResponseHeader,
        ResponseBody
    }


    public static Set<TargetType> requestTargetTypes = EnumSet.of(TargetType.Request, TargetType.RequestHeader, TargetType.RequestBody, TargetType.RequestFirstLine, TargetType.RequestTargetHost, TargetType.RequestTargetPort);
    public static Set<TargetType> responseTargetTypes = EnumSet.of(TargetType.Response, TargetType.ResponseHeader, TargetType.ResponseBody);

    public enum ConditionRelationship {
        Matches,
        DoesntMatch
    }
}
