package burp.cmarui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.cmar;
import burp.enums;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.HashMap;

public class BurpSuiteTab extends javax.swing.JPanel implements ITab {
    IBurpExtenderCallbacks mCallbacks;
    String tabName;
    CmarTableModel tableModel;
    private final PrintWriter stdout;
    private final PrintWriter stderr;

    int ADD_HEIGHT = 340;
    int ADD_WIDTH = 450;


    /**
     * Creates new form BurpSuiteTab
     *
     * @param tabName   The name displayed on the tab
     * @param callbacks For UI Look and Feel
     */
    public BurpSuiteTab(String tabName, CmarTableModel tableModel, IBurpExtenderCallbacks callbacks) {
        this.tabName = tabName;
        mCallbacks = callbacks;
        this.tableModel = tableModel;




        mCallbacks.customizeUiComponent(this);
        mCallbacks.addSuiteTab(this);

        stdout = new PrintWriter(mCallbacks.getStdout(), true);
        stderr = new PrintWriter(mCallbacks.getStderr(), true);
    }


    @Override
    public String getTabCaption() {
        return tabName;
    }

    @Override
    public Component getUiComponent() {
        //main panel contains two sub panels, one for text label at the top and the other with two subsub panels containing the buttons panel and the CMAR table
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));


        JPanel buttonsPanel = new JPanel();
        buttonsPanel.setLayout(new BoxLayout(buttonsPanel, BoxLayout.Y_AXIS));

        JButton addButton = new JButton("Add");
        JButton editButton = new JButton("Edit");
        JButton copyButton = new JButton("Copy");
        JButton removeButton = new JButton("Remove");
        JButton upButton = new JButton("Up");
        JButton downButton = new JButton("Down");


        addButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                HashMap<String, Object> userInput = new HashMap<>();
                JPanel addPanel = new DialogPanel().createDialogPanel(userInput, null);



                int dialogResponse = JOptionPane.showConfirmDialog(null, addPanel, "Add Match/Replace Rule", JOptionPane.OK_CANCEL_OPTION);


                int currentHeight = addPanel.getHeight();
                int currentWidth = addPanel.getWidth();

                int adjustHeight = Math.max(currentHeight, ADD_HEIGHT);
                int adjustWidth = Math.max(currentWidth, ADD_WIDTH);
                addPanel.setMinimumSize(new Dimension(adjustWidth, adjustHeight));
                addPanel.setPreferredSize(new Dimension(adjustWidth, adjustHeight));

                if (dialogResponse == 0) { // user clicked OK, adding cmar
                    //get the input from dialog and create a cmar with it
                    handleAddCmar(userInput);
                }
            }
        });


        //Label at the top with text to describe the plugin
        JPanel toplabelPanel = new JPanel();
        JLabel l = new JLabel();
        l.setText("Conditional Match and Replace \n");
        Font f = l.getFont();
        l.setFont(f.deriveFont(f.getStyle() | Font.BOLD));
        JLabel l2 = new JLabel();
        l2.setText("Replace data in requests and responses, if they match a certain condition");
        toplabelPanel.add(l);
        toplabelPanel.add(l2);
        toplabelPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, toplabelPanel.getMinimumSize().height)); //make the text panel only as high as the text within


        JTable table = new JTable(tableModel);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);

        //resize some table columns so it is easier to read
        table.getColumnModel().getColumn(0).setPreferredWidth(50);
        table.getColumnModel().getColumn(0).setMaxWidth(60);

        table.getColumnModel().getColumn(1).setPreferredWidth(150);
        table.getColumnModel().getColumn(1).setMaxWidth(200);

        table.getColumnModel().getColumn(2).setPreferredWidth(120);
        table.getColumnModel().getColumn(2).setMaxWidth(120);

        table.getColumnModel().getColumn(4).setPreferredWidth(50);
        table.getColumnModel().getColumn(4).setMaxWidth(60);

        table.getColumnModel().getColumn(5).setPreferredWidth(150);
        table.getColumnModel().getColumn(5).setMaxWidth(200);

        table.getColumnModel().getColumn(8).setPreferredWidth(50);
        table.getColumnModel().getColumn(8).setMaxWidth(60);

        table.getColumnModel().getColumn(9).setPreferredWidth(500);
        table.getColumnModel().getColumn(9).setMaxWidth(800);


        JScrollPane scrollPane = new JScrollPane(table);
        table.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);


        //handle editing cmar
        editButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                cmar cmarToEdit;

                //create a a new dialog panel
                HashMap<String, Object> userInput = new HashMap<>();


                int editCmarRow = table.getSelectedRow();

                if (editCmarRow >= 0) {
                    cmarToEdit = tableModel.getCmar(editCmarRow);
                } else {
                    JOptionPane.showMessageDialog(mainPanel, "No rule selected");
                    return;
                }

                JPanel editPanel = new DialogPanel().createDialogPanel(userInput, cmarToEdit);



                //populate it with the selected cmar values
                //on OK, update the selected cmar in the table.
                int dialogResponse = JOptionPane.showConfirmDialog(null, editPanel, "Edit Match/Replace Rule", JOptionPane.OK_CANCEL_OPTION);


                if (dialogResponse == 0) { //user clicked OK, editing
                    handleEditCmar(userInput, editCmarRow);
                    table.setRowSelectionInterval(editCmarRow, editCmarRow); //select the edited row
                }
            }
        });

        //copy a cmar
        copyButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                int r = table.getSelectedRow();

                if (r != -1) {
                    cmar c = tableModel.getCmar(r);
                    cmar c2 = new cmar(c);
                    tableModel.addCmar(c2);
                }
            }
        });


        //listener for clicking remove button
        removeButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                int r = table.getSelectedRow();
                int rc = tableModel.getRowCount();

                if (r != -1) {
                    // remove selected row from the model
                    tableModel.removeCmar(r);

                    if (r == rc - 1) {
                        table.setRowSelectionInterval(r - 1, r - 1);
                    } else {
                        table.setRowSelectionInterval(r, r);
                    }

                }
            }
        });


        //Move row up
        upButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                // check for selected row first
                if (table.getSelectedRow() > 0) {
                    int r = table.getSelectedRow();
                    tableModel.moveUp(r);
                    table.setRowSelectionInterval(r - 1, r - 1);
                }
            }
        });


        //Move Row Down
        downButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                // check for selected row first
                if (table.getSelectedRow() < tableModel.getRowCount() - 1) {
                    int r = table.getSelectedRow();
                    tableModel.moveDown(r);
                    table.setRowSelectionInterval(r + 1, r + 1);
                }
            }
        });

        Dimension buttonPadding = new Dimension(0, 8);

        //add all buttons to the buttons panel
        buttonsPanel.add(addButton);
        buttonsPanel.add(Box.createRigidArea(buttonPadding));
        buttonsPanel.add(editButton);
        buttonsPanel.add(Box.createRigidArea(buttonPadding));
        buttonsPanel.add(copyButton);
        buttonsPanel.add(Box.createRigidArea(buttonPadding));
        buttonsPanel.add(removeButton);
        buttonsPanel.add(Box.createRigidArea(buttonPadding));
        buttonsPanel.add(upButton);
        buttonsPanel.add(Box.createRigidArea(buttonPadding));
        buttonsPanel.add(downButton);



        //add table
        JPanel tablePanel = new JPanel();
        tablePanel.setLayout(new BoxLayout(tablePanel, BoxLayout.X_AXIS));
        tablePanel.add(Box.createHorizontalStrut(30));
        tablePanel.add(buttonsPanel);
        tablePanel.add(Box.createHorizontalStrut(10));
        tablePanel.add(scrollPane);


        mainPanel.add(toplabelPanel);
        mainPanel.add(tablePanel);


        return mainPanel;
    }

    private HashMap<String, enums.TargetType> getTypeMap() {
        HashMap<String, enums.TargetType> typeMap = new HashMap<>();
        typeMap.put("Request First Line", enums.TargetType.RequestFirstLine);
        typeMap.put("Request Header", enums.TargetType.RequestHeader);
        typeMap.put("Request Body", enums.TargetType.RequestBody);
        typeMap.put("Request", enums.TargetType.Request);
        typeMap.put("Request Target Host", enums.TargetType.RequestTargetHost);
        typeMap.put("Request Target Port", enums.TargetType.RequestTargetPort);
        typeMap.put("Response Header", enums.TargetType.ResponseHeader);
        typeMap.put("Response Body", enums.TargetType.ResponseBody);
        typeMap.put("Response", enums.TargetType.Response);

        return typeMap;
    }


    public cmar getFromUserInput(HashMap userInput) {
        HashMap<String, enums.TargetType> typeMap = this.getTypeMap();

        try {
            //need to map from the combo box string to the enum it represents
            Object ct = ((JComboBox) userInput.get("ConditionType")).getSelectedItem();
            enums.TargetType conditionType = typeMap.get(ct);

            //procedure type combo
            Object pt = ((JComboBox) userInput.get("ProcedureType")).getSelectedItem();
            enums.TargetType procedureType = typeMap.get(pt);


            //matches/doesnt match selection
            String cr = (String)((JComboBox) userInput.get("ConditionRelationship")).getSelectedItem();
            enums.ConditionRelationship conditionRelationship;
            if (cr.equals("Matches")) {
                conditionRelationship = enums.ConditionRelationship.Matches;
            } else {
                conditionRelationship = enums.ConditionRelationship.DoesntMatch;
            }


            String conditionText = ((JTextField) userInput.get("Condition")).getText();
            String matchText = ((JTextField) userInput.get("Match")).getText();
            String replaceText = ((JTextField) userInput.get("Replace")).getText();
            Boolean regexVal = ((JCheckBox) userInput.get("Regex")).isSelected();
            Boolean conditionRegexVal = ((JCheckBox) userInput.get("ConditionRegex")).isSelected();
            String commentText = ((JTextField) userInput.get("Comment")).getText();

            cmar c = new cmar(true, conditionType, conditionRelationship, conditionText,
                    procedureType, matchText, replaceText, regexVal, conditionRegexVal, commentText);

            return c;
        } catch (Exception e) {
            e.printStackTrace(stderr);
        }

        return null;

    }


    public void handleEditCmar(HashMap userInput, int editCmarRow) {
        cmar c = this.getFromUserInput(userInput);
        tableModel.editCmar(editCmarRow, c);
    }

    public void handleAddCmar(HashMap userInput) {
        tableModel.addCmar(this.getFromUserInput(userInput));
    }
}
