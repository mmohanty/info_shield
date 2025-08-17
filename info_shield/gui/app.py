from __future__ import annotations
import json
import os
from typing import List
from PyQt5 import QtWidgets, QtCore
from ..registry import PatternRegistry, NlpRuleRegistry
from ..scanner import GuardrailScanner
from ..redactor import Redactor
from ..config import USER_RULE_DIR

class RulePicker(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Regex/NLP Guardrail – Rule Picker")
        self.resize(1000, 650)

        self.patternReg = PatternRegistry.load_builtin()
        self.nlpReg = NlpRuleRegistry.load_builtin()
        self.regexPatterns = self.patternReg.list_all()
        self.nlpRules = self.nlpReg.list_all()

        # UI elements
        self.userEdit = QtWidgets.QLineEdit()
        self.userEdit.setPlaceholderText("User ID / Username")
        self.loadBtn = QtWidgets.QPushButton("Load User Rules")
        self.saveBtn = QtWidgets.QPushButton("Save User Rules")

        self.textInput = QtWidgets.QPlainTextEdit()
        self.textInput.setPlaceholderText("Paste text to scan…")
        self.scanBtn = QtWidgets.QPushButton("Scan")
        self.redactChk = QtWidgets.QCheckBox("Redact")
        self.results = QtWidgets.QPlainTextEdit(); self.results.setReadOnly(True)

        # Two rule trees: Regex and NLP
        self.regexTree = QtWidgets.QTreeWidget(); self.regexTree.setHeaderLabels(["Enabled","Pattern","Category","Severity","Description"]) ; self.regexTree.setRootIsDecorated(False)
        self.nlpTree = QtWidgets.QTreeWidget(); self.nlpTree.setHeaderLabels(["Enabled","Rule","Category","Severity","Description"]) ; self.nlpTree.setRootIsDecorated(False)

        # Layout
        top = QtWidgets.QHBoxLayout()
        top.addWidget(self.userEdit, 2)
        top.addWidget(self.loadBtn)
        top.addWidget(self.saveBtn)

        splitter = QtWidgets.QSplitter()
        left = QtWidgets.QWidget(); left_layout = QtWidgets.QVBoxLayout(left)
        left_layout.addWidget(QtWidgets.QLabel("Regex Rules"))
        left_layout.addWidget(self.regexTree)
        left_layout.addWidget(QtWidgets.QLabel("NLP Rules"))
        left_layout.addWidget(self.nlpTree)

        right = QtWidgets.QWidget(); right_layout = QtWidgets.QVBoxLayout(right)
        right_layout.addWidget(QtWidgets.QLabel("Text"))
        right_layout.addWidget(self.textInput, 3)
        right_bottom = QtWidgets.QHBoxLayout()
        right_bottom.addWidget(self.redactChk)
        right_bottom.addStretch(1)
        right_bottom.addWidget(self.scanBtn)
        right_layout.addLayout(right_bottom)
        right_layout.addWidget(QtWidgets.QLabel("Results"))
        right_layout.addWidget(self.results, 2)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        root = QtWidgets.QVBoxLayout(self)
        root.addLayout(top)
        root.addWidget(splitter)

        # Populate rules
        self._populate_regex()
        self._populate_nlp()

        # signals
        self.loadBtn.clicked.connect(self.load_rules_for_user)
        self.saveBtn.clicked.connect(self.save_rules_for_user)
        self.scanBtn.clicked.connect(self.scan_text)

        os.makedirs(USER_RULE_DIR, exist_ok=True)

    def _populate_regex(self):
        self.regexTree.clear()
        for p in sorted(self.regexPatterns, key=lambda x: (x.category, x.severity, x.name)):
            item = QtWidgets.QTreeWidgetItem(["", p.name, p.category, p.severity, p.description])
            item.setCheckState(0, QtCore.Qt.Checked)
            item.setData(0, QtCore.Qt.UserRole, p.name)
            self.regexTree.addTopLevelItem(item)
        self.regexTree.resizeColumnToContents(1)

    def _populate_nlp(self):
        self.nlpTree.clear()
        for r in sorted(self.nlpRules, key=lambda x: (x.category, x.severity, x.name)):
            item = QtWidgets.QTreeWidgetItem(["", r.name, r.category, r.severity, getattr(r, "description", r.name)])
            item.setCheckState(0, QtCore.Qt.Checked)
            item.setData(0, QtCore.Qt.UserRole, r.name)
            self.nlpTree.addTopLevelItem(item)
        self.nlpTree.resizeColumnToContents(1)

    def _selected_names(self, tree: QtWidgets.QTreeWidget) -> List[str]:
        names = []
        for i in range(tree.topLevelItemCount()):
            it = tree.topLevelItem(i)
            if it.checkState(0) == QtCore.Qt.Checked:
                names.append(it.data(0, QtCore.Qt.UserRole))
        return names

    def _profile_path(self, user: str) -> str:
        safe = "".join(ch for ch in user if ch.isalnum() or ch in ("-","_","@","."))
        return os.path.join(USER_RULE_DIR, f"{safe}.json")

    def save_rules_for_user(self):
        user = self.userEdit.text().strip()
        if not user:
            QtWidgets.QMessageBox.warning(self, "Missing user", "Enter a user id/name")
            return
        profile = {
            "include_regex": self._selected_names(self.regexTree),
            "include_nlp": self._selected_names(self.nlpTree),
        }
        with open(self._profile_path(user), "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2)
        QtWidgets.QMessageBox.information(self, "Saved", f"Rules saved for {user}")

    def load_rules_for_user(self):
        user = self.userEdit.text().strip()
        if not user:
            QtWidgets.QMessageBox.warning(self, "Missing user", "Enter a user id/name")
            return
        path = self._profile_path(user)
        if not os.path.exists(path):
            QtWidgets.QMessageBox.information(self, "No profile", f"No saved rules for {user}. Using defaults.")
            self._populate_regex(); self._populate_nlp()
            return
        with open(path, "r", encoding="utf-8") as f:
            profile = json.load(f)
        regex_inc = set(profile.get("include_regex", []))
        nlp_inc = set(profile.get("include_nlp", []))
        for i in range(self.regexTree.topLevelItemCount()):
            it = self.regexTree.topLevelItem(i)
            it.setCheckState(0, QtCore.Qt.Checked if it.data(0, QtCore.Qt.UserRole) in regex_inc else QtCore.Qt.Unchecked)
        for i in range(self.nlpTree.topLevelItemCount()):
            it = self.nlpTree.topLevelItem(i)
            it.setCheckState(0, QtCore.Qt.Checked if it.data(0, QtCore.Qt.UserRole) in nlp_inc else QtCore.Qt.Unchecked)

    def scan_text(self):
        regex_names = set(self._selected_names(self.regexTree))
        nlp_names = set(self._selected_names(self.nlpTree))
        regex = [p for p in self.regexPatterns if p.name in regex_names] if regex_names else self.regexPatterns
        nlp_rules = [r for r in self.nlpRules if r.name in nlp_names] if nlp_names else self.nlpRules
        scanner = GuardrailScanner(regex, nlp_rules)
        text = self.textInput.toPlainText()
        matches = scanner.scan_text(text)
        out_lines = []
        for m in matches:
            out_lines.append(f"[{m.severity.upper()}] {m.pattern} @ line {m.line}, col {m.col}: {m.preview}")
        if self.redactChk.isChecked():
            out_lines.append("\n--- Redacted ---\n" + Redactor(regex).apply(text, matches))
        self.results.setPlainText("\n".join(out_lines) if out_lines else "No findings.")


def main():
    import sys
    app = QtWidgets.QApplication(sys.argv)
    w = RulePicker()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()