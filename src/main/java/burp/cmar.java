package burp;


public class cmar {
    boolean enabled;
    enums.TargetType conditionTarget;
    enums.ConditionRelationship conditionRelationship;
    String condition;
    enums.TargetType procedureTarget;
    String match;
    String replace;
    Boolean regex;
    Boolean conditionRegex;
    String comment;


    public cmar(boolean enabled, enums.TargetType conditionTarget, enums.ConditionRelationship conditionRelationship, String condition, enums.TargetType procedureTarget,
                String match, String replace, Boolean regex, Boolean conditionRegex, String comment) {
        this.enabled = enabled;
        this.conditionTarget = conditionTarget;
        this.conditionRelationship = conditionRelationship;
        this.condition = condition;
        this.procedureTarget = procedureTarget;
        this.match = match;
        this.replace = replace;
        this.regex = regex;
        this.conditionRegex = conditionRegex;
        this.comment = comment;
    }

    public cmar(cmar c){
        this.enabled = c.enabled;
        this.conditionTarget = c.conditionTarget;
        this.conditionRelationship = c.conditionRelationship;
        this.condition = c.condition;
        this.procedureTarget = c.procedureTarget;
        this.match = c.match;
        this.replace = c.replace;
        this.regex = c.regex;
        this.conditionRegex = c.conditionRegex;
        this.comment = c.comment;
    }

    @Override
    public String toString() {
        return String.format("enabled: %s\nconditiontarget: %s\nconditionrelationship %s\ncondition: %s\nprocedureTarget: %s\nmatch: %s\nreplace: %s\nregex: %s\nconditionRegex: %s\ncomment: %s",
                this.enabled,this.conditionTarget,this.conditionRelationship,this.condition,this.procedureTarget,this.match,this.replace,this.regex,this.conditionRegex,this.comment);
    }


    public boolean conditionTargetIsRequest() {
        return enums.requestTargetTypes.contains(this.conditionTarget);
    }

    public boolean conditionTargetIsResponse() {
        return enums.responseTargetTypes.contains(this.conditionTarget);
    }

    public boolean procedureTargetIsResponse() {
        return enums.responseTargetTypes.contains(this.procedureTarget);
    }


    //standard getters and setters
    public boolean getEnabled() {
        return this.enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public enums.TargetType getConditionTarget() {
        return this.conditionTarget;
    }

    public void setConditionTarget(enums.TargetType conditionTarget) {
        this.conditionTarget = conditionTarget;
    }

    public enums.ConditionRelationship getConditionRelationship() {
        return this.conditionRelationship;
    }

    public void setConditionRelationship(enums.ConditionRelationship conditionRelationship) {
        this.conditionRelationship = conditionRelationship;
    }

    public String getCondition() {
        return this.condition;
    }

    public void setCondition(String condition) {
        this.condition = condition;
    }

    public enums.TargetType getProcedureTarget() {
        return this.procedureTarget;
    }

    public void setProcedureTarget(enums.TargetType procedureTarget) {
        this.procedureTarget = procedureTarget;
    }

    public String getMatch() {
        return this.match;
    }

    public void setMatch(String match) {
        this.match = match;
    }

    public String getReplace() {
        return this.replace;
    }

    public void setReplace(String replace) {
        this.replace = replace;
    }

    public Boolean getRegex() {
        return this.regex;
    }

    public void setRegex(Boolean regex) {
        this.regex = regex;
    }

    public Boolean getConditionRegex() {
        return this.conditionRegex;
    }

    public void setConditionRegex(Boolean conditionRegex) {
        this.conditionRegex = conditionRegex;
    }

    public String getComment() {
        return this.comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }
}
