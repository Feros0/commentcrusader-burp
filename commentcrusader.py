# -*- coding: utf-8 -*-
"""
Comment Crusader — Burp Extension
------------------------------------------------

Author: Farzan Karimi (@jumpycastle)

Description:
    A Burp Suite extension that detects, catalogs, and exports developer comments, secrets,
    and keywords embedded in both HTTP response bodies and JavaScript files. Supports live
    scanning, replay detection, and advanced filtering across domains and content types.

License:
    MIT
"""

from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import (
    JPanel, JScrollPane, JTable, JMenuItem, JPopupMenu, JOptionPane,
    JLabel, JCheckBox, JTextField, JButton, Box, SwingUtilities
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, Font, Color
from collections import deque
import re

MAX_PREVIEW_LENGTH = 300
MAX_ROWS = 1000
MAX_COMMENTS_TRACKED = 5000

KEYWORD_COLORS = {
    "auth ": Color(255, 85, 85),
    "password": Color(255, 105, 180),
    "secret": Color(255, 215, 0),
    "bypass": Color(144, 238, 144),
    "backdoor": Color(30, 144, 255),
    "fixed": Color(255, 165, 0),
    "not logged in": Color(255, 0, 0),
    "todo": Color(147, 112, 219),
    "TODO": Color(147, 112, 219),
    "magic": Color(0, 255, 255)
}

class KeywordHighlightRenderer(DefaultTableCellRenderer):
    def __init__(self, keywords, custom_keywords):
        self.keywords = [k.lower() for k in keywords]
        self.custom_keywords = [k.lower() for k in custom_keywords]

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        label = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )
        if column == 1:  # Comment column
            val = str(value).lower()
            for keyword in self.keywords:
                if keyword in val:
                    label.setFont(Font("Monospaced", Font.BOLD, 12))
                    label.setForeground(KEYWORD_COLORS.get(keyword, Color(255, 85, 85)))
                    return label
            for keyword in self.custom_keywords:
                if keyword in val:
                    label.setFont(Font("Monospaced", Font.BOLD, 12))
                    label.setForeground(Color(0, 255, 255))  # Cyan
                    return label
            label.setFont(Font("Monospaced", Font.PLAIN, 12))
            label.setForeground(Color(160, 160, 160))
        return label

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.seen_comment_url_pairs = set()
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Comment Crusader")

        self.comments_seen = deque(maxlen=MAX_COMMENTS_TRACKED)
        self.keyword_matches_seen = set()
        self.table_model = DefaultTableModel(["Type", "Comment", "Keyword", "URL"], 0)
        self.default_keywords = ["auth ", "password", "secret", "bypass", "backdoor", "fixed", "not logged in", "todo", "TODO", "magic"]
        self.custom_keywords = []
        self.sensitive_keywords = list(self.default_keywords)
        self.row_to_http = {}

        self._init_ui()

        self._callbacks.registerHttpListener(self)
        self._callbacks.addSuiteTab(self)
        print("[+] Comment Crusader v3.0 loaded. All comments shown, alerts highlighted.")

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())

        keyword_panel = Box.createHorizontalBox()
        self.checkboxes = []
        for kw in self.default_keywords:
            box = JCheckBox(kw, True)
            keyword_panel.add(box)
            self.checkboxes.append(box)

        self.custom_keyword_input = JTextField(15)
        self.add_keyword_button = JButton("Add")
        self.add_keyword_button.addActionListener(self._add_custom_keyword)
        keyword_panel.add(self.custom_keyword_input)
        keyword_panel.add(self.add_keyword_button)
        self.panel.add(keyword_panel, BorderLayout.NORTH)

        self.table = JTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)
        self._refresh_table_renderer()
        scroll_pane = JScrollPane(self.table)
        self.panel.add(scroll_pane, BorderLayout.CENTER)

        self.status_label = JLabel("Total comments captured: 0")
        self.panel.add(self.status_label, BorderLayout.SOUTH)

        popup = JPopupMenu()
        show_item = JMenuItem("Send to Repeater")
        show_item.addActionListener(self._show_selected_message)
        popup.add(show_item)
        self.table.setComponentPopupMenu(popup)

    def _refresh_table_renderer(self):
        renderer = KeywordHighlightRenderer(self.default_keywords, self.custom_keywords)
        self.table.getColumnModel().getColumn(1).setCellRenderer(renderer)
        self.table.repaint()

    def _add_custom_keyword(self, event):
        new_kw = self.custom_keyword_input.getText().strip()
        if new_kw:
            self.custom_keywords.append(new_kw)
            self.sensitive_keywords.append(new_kw)
            box = JCheckBox(new_kw, True)
            self.panel.getComponent(0).add(box)
            self.checkboxes.append(box)
            self.panel.revalidate()
            self.panel.repaint()
            self.custom_keyword_input.setText("")
            self._refresh_table_renderer()
            self._recheck_existing_comments()

    def _update_active_keywords(self):
        self.sensitive_keywords = [box.getText() for box in self.checkboxes if box.isSelected()]
        self.default_keywords = [kw for kw in self.default_keywords if kw in self.sensitive_keywords]
        self.custom_keywords = [kw for kw in self.sensitive_keywords if kw not in self.default_keywords]
        self._refresh_table_renderer()

    def _safe_add_row(self, row_data, messageInfo):
        def add():
            if self.table_model.getRowCount() >= MAX_ROWS:
                self.table_model.removeRow(0)
            row_index = self.table_model.getRowCount()
            self.table_model.addRow(row_data)
            self.row_to_http[row_index] = messageInfo
            self.status_label.setText("Total comments captured: {}".format(self.table_model.getRowCount()))
            self.table.revalidate()
            self.table.repaint()
        SwingUtilities.invokeLater(add)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        try:
            response = messageInfo.getResponse()
            if not response:
                return

            url_obj = self._helpers.analyzeRequest(messageInfo).getUrl()
            url = url_obj.toString()

            analyzed = self._helpers.analyzeResponse(response)
            body = response[analyzed.getBodyOffset():]
            body_str = self._helpers.bytesToString(body)

            comments = self._extract_comments(body_str)
            self._update_active_keywords()
            keywords = [k.lower() for k in self.sensitive_keywords]

            for c in comments:
                comment = c.strip()
                if not comment or comment.isspace():
                    continue
                # Skip single HTML tags like <link> etc.
                if re.match(r"^<\s*\w+\s+[^>]+>$", comment.strip()):
                    continue       
                # Skip likely URL paths (false positives like //cdn.google.com...)
                if re.match(r"^//[a-zA-Z0-9.\-]+(/.*)?$", comment):
                    continue

                full_comment = comment.replace("\n", " ").strip()
                truncated = full_comment[:MAX_PREVIEW_LENGTH]

                pair_key = (truncated, url)
                if pair_key in self.seen_comment_url_pairs:
                    continue
                self.seen_comment_url_pairs.add(pair_key)

                if truncated in self.comments_seen:
                    continue
                self.comments_seen.append(truncated)
                comment_type = "INFO"
                matched_keyword = ""

                for keyword in keywords:
                    if keyword in truncated.lower():
                        comment_type = "ALERT"
                        matched_keyword = keyword
                        self.keyword_matches_seen.add(truncated)
                        break

                self._log("{} [{}] → {}".format(comment_type, matched_keyword, truncated))
                self._safe_add_row([comment_type, truncated, matched_keyword, url], messageInfo)

        except Exception as e:
            print("[ERROR] {}".format(str(e)))

    def _extract_comments(self, text):
        try:
            html_comments = re.findall(r'<!--\s*(.*?)\s*-->', text, re.DOTALL)
            js_line_comments = re.findall(r'(?://[^\n\r]*)', text)
            js_block_comments = re.findall(r'/\*.*?\*/', text, re.DOTALL)
            return html_comments + js_line_comments + js_block_comments
        except Exception as e:
            print("[ERROR] Comment extraction failed: {}".format(str(e)))
            return []

    def _show_selected_message(self, event):
        view_row = self.table.getSelectedRow()
        model_row = self.table.convertRowIndexToModel(view_row)
        if view_row != -1:
            model_row = self.table.convertRowIndexToModel(view_row)
            message_info = self.row_to_http.get(model_row)
            if message_info:
                try:
                    http_service = message_info.getHttpService()
                    host = http_service.getHost()
                    port = http_service.getPort()
                    use_https = http_service.getProtocol() == "https"
                    self._callbacks.sendToRepeater(host, port, use_https, message_info.getRequest(), "Crusader")
                except Exception as e:
                    print("[ERROR] Failed to send to Repeater: {}".format(str(e)))
            else:
                JOptionPane.showMessageDialog(self.panel, "Message not found for selected row.")

#    def _recheck_existing_comments(self):
#        keywords = [k.lower() for k in self.sensitive_keywords]
#        for truncated in list(self.comments_seen):
#            for keyword in keywords:
#                if keyword in truncated.lower() and truncated not in self.keyword_matches_seen:
#                    self.keyword_matches_seen.add(truncated)
#                    self._safe_add_row(["ALERT", truncated, keyword, "Unknown"], None)
#                if keyword in truncated.lower():
#                    comment_type = "ALERT"
#                    matched_keyword = keyword
#                    self.keyword_matches_seen.add(truncated)
#                    break
    def _recheck_existing_comments(self):
        keywords = [k.lower() for k in self.sensitive_keywords]
        for truncated in list(self.comments_seen):
            comment_type = "INFO"
            matched_keyword = ""

            for keyword in keywords:
                if keyword in truncated.lower():
                    comment_type = "ALERT"
                    matched_keyword = keyword
                    self.keyword_matches_seen.add(truncated)
                    break

            # Log and display the row regardless of alert status
            self._log("{} [{}] → {}".format(comment_type, matched_keyword, truncated))
            self._safe_add_row([comment_type, truncated, matched_keyword, "Unknown"], None)



    def _log(self, msg):
        print("[Comment Crusader] " + msg)

    def getTabCaption(self):
        return "Comment Crusader"

    def getUiComponent(self):
        wrapper = JPanel(BorderLayout())
        wrapper.add(self.panel, BorderLayout.CENTER)
        return wrapper

