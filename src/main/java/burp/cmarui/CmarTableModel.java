package burp.cmarui;

import burp.cmar;
import burp.enums;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


public class CmarTableModel extends AbstractTableModel {
    private final String[] COLUMN_NAMES = {
            "Enabled",
            "Condition Target",
            "Condition Relation",
            "Condition",
            "Regex",
            "Procedure Type",
            "Procedure Match",
            "Procedure Replace",
            "Regex",
            "Comment"
    };

    private List<cmar> cmars;

    public CmarTableModel() {
        cmars = new ArrayList<>();
    }

    public CmarTableModel(List<cmar> cmars) {
        this.cmars = cmars;
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public int getRowCount() {
        return cmars.size();
    }

    @Override
    public Class getColumnClass(int column) {
        switch (column) {
            case 0:
                return Boolean.class; //enabled
            case 1:
                return enums.TargetType.class; // condition target
            case 2:
                return enums.ConditionRelationship.class; // condition relationship
            case 3:
                return String.class; //condition
            case 4:
                return Boolean.class; //condition regex
            case 5:
                return enums.TargetType.class; // procedure target
            case 6:
                return String.class; // procedure match
            case 7:
                return String.class; // procedure replace
            case 8:
                return Boolean.class; // regex mode
            case 9:
                return String.class; // comment

            default:
                return null;
        }
    }

    //Allow checking the "enabled" and regex buttons
    @Override
    public boolean isCellEditable(int row, int col) {
        return col == 0 || col == 4 || col == 8;
    }

    @Override
    public Object getValueAt(int row, int column) {
        cmar cmar = getCmar(row);

        switch (column) {
            case 0:
                return cmar.getEnabled();
            case 1:
                return makeEnumUserFriendly(cmar.getConditionTarget());
            case 2:
                return cmar.getConditionRelationship();
            case 3:
                return cmar.getCondition();
            case 4:
                return cmar.getConditionRegex();
            case 5:
                return makeEnumUserFriendly(cmar.getProcedureTarget());
            case 6:
                return cmar.getMatch();
            case 7:
                return cmar.getReplace();
            case 8:
                return cmar.getRegex();
            case 9:
                return cmar.getComment();

            default:
                return null;
        }
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        cmar cmar = getCmar(row);

        switch (column) {
            case 0:
                cmar.setEnabled((Boolean) value);
                break;
            case 1:
                cmar.setConditionTarget((enums.TargetType) value);
                break;
            case 2:
                cmar.setConditionRelationship((enums.ConditionRelationship) value);
                break;
            case 3:
                cmar.setCondition((String) value);
                break;
            case 4:
                cmar.setConditionRegex((Boolean) value);
                break;
            case 5:
                cmar.setProcedureTarget((enums.TargetType) value);
                break;
            case 6:
                cmar.setMatch((String) value);
                break;
            case 7:
                cmar.setReplace((String) value);
                break;
            case 8:
                cmar.setRegex((Boolean) value);
                break;
            case 9:
                cmar.setComment((String) value);
                break;
        }

        fireTableCellUpdated(row, column);
    }

    public cmar getCmar(int row) {
        return cmars.get(row);
    }

    public int getSize() {
        return cmars.size();
    }


    public String makeEnumUserFriendly(enums.TargetType tt) {
        switch (tt) {
            case Request:
                return "Request";
            case RequestFirstLine:
                return "Request First Line";
            case RequestHeader:
                return "Request Header";
            case RequestBody:
                return "Request Body";
            case RequestTargetHost:
                return "Request Target Host";
            case RequestTargetPort:
                return "Request Target Port";
            case Response:
                return "Response";
            case ResponseHeader:
                return "Response Header";
            case ResponseBody:
                return "Response Body";

            default:
                return null;
        }
    }

    public void addCmar(cmar cmar) {
        insertCmar(getRowCount(), cmar);
    }

    public void editCmar(int row, cmar cmar) {
        //rather than actually editing it, we just remove it and add a new one in its place
        removeCmar(row);
        insertCmar(row, cmar);
    }

    public List<cmar> getAll() {
        return cmars;
    }

    public void removeAll() {
        cmars = new ArrayList<>();
    }

    public List<cmar> getAllEnabled() {
        ArrayList<cmar> enabled = new ArrayList<>();
        for (cmar c : cmars) {
            if (c.getEnabled()) {
                enabled.add(c);
            }
        }
        return enabled;
    }


    public void insertCmar(int row, cmar cmar) {
        cmars.add(row, cmar);
        fireTableRowsInserted(row, row);
    }

    public void removeCmar(int row) {
        cmars.remove(row);
        fireTableRowsDeleted(row, row);
    }

    public void moveUp(int r) {
        if (cmars.indexOf(r) != 0 && r != 0) {
            Collections.swap(cmars, r, r - 1);
        }
    }

    public void moveDown(int r) {
        if (cmars.size() - 1 != r) {
            Collections.swap(cmars, r, r + 1);
        }
    }
}
