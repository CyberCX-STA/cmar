package burp.cmarui;

import burp.cmar;
import burp.enums;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class DialogPanel {
    public JPanel createDialogPanel(HashMap<String, Object> userInput, cmar cmarToEdit) {
        int rowSpacer = 100;
        int inputWidth = 10;
        int borderWidth = 5;

        //combine these (combostrings and typemap)
        String[] comboStrings = {"Request First Line", "Request Header", "Request Body", "Request", "Request Target Host", "Request Target Port", "Response Header", "Response Body", "Response"};
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

        String[] comboStringsLimit = {"Response Header", "Response Body", "Response"};


        JComboBox<String> conditionTargetCB = new JComboBox<>(comboStrings);
        JComboBox<String> procedureTargetCB = new JComboBox<>(comboStrings);
        JTextField conditionField = new JTextField();
        JComboBox<String> conditionRelationshipBox = new JComboBox<>(new String[]{"Matches", "Does Not match"});
        JTextField matchField = new JTextField();
        JTextField replaceField = new JTextField();
        JTextField commentField = new JTextField();
        JCheckBox regexCheck = new JCheckBox("Match Regex");
        JCheckBox conditionRegexCheck = new JCheckBox("Match Condition Regex");


        //editing, fill the fields out with the selected cmar
        if (cmarToEdit != null) {
            conditionField.setText(cmarToEdit.getCondition());

            if (cmarToEdit.getConditionRelationship() == enums.ConditionRelationship.Matches) {
                conditionRelationshipBox.setSelectedIndex(0);
            } else {
                conditionRelationshipBox.setSelectedIndex(1);
            }


            //iterate through the typemap to fill out the target combo boxes
            //probably a better way to do this
            for (Map.Entry<String, enums.TargetType> entry : typeMap.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();

                if (value.equals(cmarToEdit.getConditionTarget())) {
                    conditionTargetCB.setSelectedItem(key);
                }
                if (value.equals(cmarToEdit.getProcedureTarget())) {
                    procedureTargetCB.setSelectedItem(key);
                }

            }


            matchField.setText(cmarToEdit.getMatch());
            matchField.setAlignmentX( Component.LEFT_ALIGNMENT );
            replaceField.setText(cmarToEdit.getReplace());
            commentField.setText(cmarToEdit.getComment());
            regexCheck.setSelected(cmarToEdit.getRegex());
            conditionRegexCheck.setSelected(cmarToEdit.getConditionRegex());
        }


        userInput.put("Condition", conditionField);
        userInput.put("ConditionRelationship", conditionRelationshipBox);
        userInput.put("Match", matchField);
        userInput.put("Replace", replaceField);
        userInput.put("Regex", regexCheck);
        userInput.put("ConditionRegex", conditionRegexCheck);
        userInput.put("Comment", commentField);
        userInput.put("ConditionType", conditionTargetCB);
        userInput.put("ProcedureType", procedureTargetCB);


        JPanel topPanel = new JPanel();


        topPanel.setLayout(new BoxLayout(topPanel,BoxLayout.Y_AXIS));

        JPanel conditionPanel = new JPanel();
        conditionPanel.setLayout(new GridLayout(6, 1));


        //Condition target to match
        JPanel cTargetPanel = new JPanel();
        cTargetPanel.setLayout(new BoxLayout(cTargetPanel, BoxLayout.X_AXIS));
        cTargetPanel.setBorder(BorderFactory.createEmptyBorder(0,0,borderWidth,0));
        cTargetPanel.add(new JLabel("Type:"));
        cTargetPanel.add(Box.createRigidArea(new Dimension(10,0)));


        conditionTargetCB.setAlignmentX( Component.LEFT_ALIGNMENT );


        //if user selects a response for the condition, update the procedure to allow only targeting responses (because request already sent)
        conditionTargetCB.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                //if user selects a response for the condition, can only operate on responses
                Object procedureSelected = procedureTargetCB.getSelectedItem();
                if (Arrays.asList(comboStringsLimit).contains(conditionTargetCB.getSelectedItem().toString())) {
                    procedureTargetCB.removeAllItems();
                    for (String s : comboStringsLimit) {
                        procedureTargetCB.addItem(s);
                    }

                    //remember what the user had selected
                    procedureTargetCB.setSelectedItem(procedureSelected);

                } else { //if user selects a request, allow all selections (request/response)
                    //this results in procedure loss of state if we switch the request type

                    procedureTargetCB.removeAllItems();
                    for (String s : comboStrings) {
                        procedureTargetCB.addItem(s);
                    }
                    procedureTargetCB.setSelectedItem(procedureSelected);
                }

                //procJcb.
            }
        });

        cTargetPanel.add(conditionTargetCB);

        //Condition relationship
        JPanel cRelationshipPanel = new JPanel();
        cRelationshipPanel.setLayout(new BoxLayout(cRelationshipPanel, BoxLayout.X_AXIS));
        cRelationshipPanel.setBorder(BorderFactory.createEmptyBorder(0,0,borderWidth,0));
        cRelationshipPanel.add(new JLabel("Relationship:"));

        cRelationshipPanel.add(Box.createRigidArea(new Dimension(10,0)));
        conditionRelationshipBox.setAlignmentX( Component.LEFT_ALIGNMENT );
        cRelationshipPanel.add(conditionRelationshipBox);

        //Condition text
        JPanel cTextPanel = new JPanel();
        cTextPanel.setLayout(new BoxLayout(cTextPanel, BoxLayout.X_AXIS));
        cTextPanel.setBorder(BorderFactory.createEmptyBorder(0,0,borderWidth,0));
        cTextPanel.add(new JLabel("Match Condition:"));
        cTextPanel.add(Box.createRigidArea(new Dimension(10,0)));
        cTextPanel.add(conditionField);

        JPanel cRegexPanel = new JPanel();
        cRegexPanel.setLayout(new BoxLayout(cRegexPanel, BoxLayout.X_AXIS));
        cRegexPanel.add(conditionRegexCheck);


        JPanel conditionLabel = new JPanel();
        JLabel clab = new JLabel("Condition");
        clab.setFont(clab.getFont().deriveFont(clab.getFont().getStyle() | Font.BOLD));
        conditionLabel.add(clab);
        conditionPanel.add(conditionLabel);
        conditionPanel.add(cTargetPanel);
        conditionPanel.add(cRelationshipPanel);
        conditionPanel.add(cTextPanel);
        conditionPanel.add(cRegexPanel);
        conditionPanel.add(Box.createVerticalStrut(10));


        // Procedure
        JPanel procedurePanel = new JPanel();

        JPanel panel = new JPanel();
        JPanel panel2 = new JPanel();
        JPanel panel3 = new JPanel();
        JPanel panel4 = new JPanel();
        JPanel panel5 = new JPanel();


        procedurePanel.setLayout(new GridLayout(6, 1));

        //Layout for add dialog pane
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.add(new JLabel("Type:"));
        panel.add(Box.createRigidArea(new Dimension(10,0)));
        panel.add(procedureTargetCB);
        panel.setBorder(BorderFactory.createEmptyBorder(0,0,borderWidth,0));

        panel2.setLayout(new BoxLayout(panel2, BoxLayout.X_AXIS));
        panel2.add(new JLabel("Match:"));
        panel2.add(Box.createRigidArea(new Dimension(10,0)));
        panel2.add(matchField);
        panel2.setBorder(BorderFactory.createEmptyBorder(0,0,borderWidth,0));

        panel3.setLayout(new BoxLayout(panel3, BoxLayout.X_AXIS));
        panel3.add(new JLabel("Replace:"));
        panel3.add(Box.createRigidArea(new Dimension(10,0)));
        panel3.add(replaceField);
        panel3.setBorder(BorderFactory.createEmptyBorder(0,0,borderWidth,0));

        panel4.setLayout(new BoxLayout(panel4, BoxLayout.X_AXIS));
        panel4.add(new JLabel( "Comment:"));
        panel4.add(Box.createRigidArea(new Dimension(10,0)));
        panel4.add(commentField);
        panel4.setBorder(BorderFactory.createEmptyBorder(0,0,borderWidth,0));


        panel5.setLayout(new BoxLayout(panel5, BoxLayout.X_AXIS));
        panel5.add(regexCheck);


        JPanel sectionLabel = new JPanel();
        JLabel mar = new JLabel("Match and Replace");
        Font f = mar.getFont();
        mar.setFont(f.deriveFont(f.getStyle() | Font.BOLD));
        sectionLabel.add(mar);
        procedurePanel.add(sectionLabel);
        procedurePanel.add(panel);
        procedurePanel.add(panel2);
        procedurePanel.add(panel3);
        procedurePanel.add(panel4);
        procedurePanel.add(panel5);

        topPanel.add(conditionPanel);
        topPanel.add(Box.createVerticalGlue());
        topPanel.add(procedurePanel);


        return topPanel;
    }

}
