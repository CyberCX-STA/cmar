package burp.cmartests;

import burp.cmar;
import burp.enums;
//import burp.ui.DialogPanel;


public class CmarTest {

    public void testCreateCmar() {
        cmar cmar = new cmar(false, enums.TargetType.Request, enums.ConditionRelationship.Matches, "Host: localhost",
                enums.TargetType.RequestTargetPort, "80", "8080", false, false, "Change target port for localhost:80 requests");
        CmarTestRunner.assertEquals("Comment wrong", "Change target port for localhost:80 requests", cmar.getComment());
        CmarTestRunner.assertEquals("Enabled wrong", false, cmar.getEnabled());

    }


    public void testCmarEnabled() {
        cmar c = new cmar(false, enums.TargetType.Request, enums.ConditionRelationship.Matches, "temp",
                enums.TargetType.RequestTargetPort, "80", "8080", false, false, "temp");
        CmarTestRunner.assertEquals("Enable failed", false, c.getEnabled());

        c = new cmar(true, enums.TargetType.Request, enums.ConditionRelationship.Matches, "temp",
                enums.TargetType.RequestTargetPort, "80", "8080", false, false, "temp");


        CmarTestRunner.assertEquals("Enable failed", true, c.getEnabled());
    }


    public void testCmarConditionTarget() {
        cmar c = new cmar(false, enums.TargetType.Request, enums.ConditionRelationship.Matches, "temp",
                enums.TargetType.RequestTargetPort, "80", "8080", false, false, "temp");
        CmarTestRunner.assertEquals("Target type failed", enums.TargetType.Request, c.getConditionTarget());

        c = new cmar(false, enums.TargetType.ResponseHeader, enums.ConditionRelationship.Matches, "temp",
                enums.TargetType.RequestTargetPort, "80", "8080", false, false, "temp");
        CmarTestRunner.assertEquals("Target type failed", enums.TargetType.ResponseHeader, c.getConditionTarget());

        c.setConditionTarget(enums.TargetType.RequestBody);
        CmarTestRunner.assertEquals("Setting condition target failed", enums.TargetType.RequestBody, c.getConditionTarget());
    }


}
