import sys
import os
import subprocess
import json
import platform
import socket
import psutil
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QTabWidget, QTextEdit, QPushButton, 
                            QLabel, QTreeWidget, QTreeWidgetItem, QSplitter,
                            QHeaderView, QFileDialog, QMessageBox, QProgressBar,
                            QGroupBox, QLineEdit, QListWidget, QTableWidget,
                            QTableWidgetItem, QComboBox, QCheckBox, QTextBrowser,
                            QFrame, QScrollArea)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor

class IncidentResponseTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Digital Incident Response Tool")
        self.setGeometry(100, 100, 1400, 900)
        
        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Create different tabs
        self.create_dashboard_tab()
        self.create_process_tab()
        self.create_network_tab()
        self.create_file_system_tab()
        self.create_memory_tab()
        self.create_log_analysis_tab()
        self.create_playbook_tab()  # New playbook tab
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
        # Initialize data
        self.refresh_all_data()
    
    def refresh_all_data(self):
        """Initialize or refresh data for all tabs"""
        # This method is called to initialize or refresh all data in the application
        # Currently just updating status bar, can be expanded to refresh all tabs
        self.statusBar().showMessage("Data refreshed")
    
    def create_playbook_tab(self):
        """Create incident response playbook tab"""
        playbook_tab = QWidget()
        layout = QVBoxLayout(playbook_tab)
        
        # Incident type selection
        type_group = QGroupBox("Incident Type")
        type_layout = QHBoxLayout()
        
        self.incident_type = QComboBox()
        self.incident_type.addItems([
            "Select Incident Type",
            "Malware Infection",
            "Phishing Attack",
            "Data Breach",
            "Ransomware Attack",
            "DDoS Attack",
            "Insider Threat",
            "Unauthorized Access",
            "Network Intrusion"
        ])
        self.incident_type.currentTextChanged.connect(self.load_playbook)
        
        type_layout.addWidget(QLabel("Select Incident Type:"))
        type_layout.addWidget(self.incident_type)
        type_layout.addStretch()
        
        type_group.setLayout(type_layout)
        layout.addWidget(type_group)
        
        # Playbook content area
        content_splitter = QSplitter(Qt.Horizontal)
        
        # Left side - playbook steps
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        self.playbook_steps = QTreeWidget()
        self.playbook_steps.setHeaderLabels(["Step", "Status"])
        self.playbook_steps.setColumnWidth(0, 300)
        self.playbook_steps.itemClicked.connect(self.show_step_details)
        
        left_layout.addWidget(QLabel("Response Steps:"))
        left_layout.addWidget(self.playbook_steps)
        
        # Right side - step details and notes
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Step details
        self.step_details = QTextBrowser()
        self.step_details.setReadOnly(True)
        
        # Notes area
        notes_group = QGroupBox("Investigation Notes")
        notes_layout = QVBoxLayout()
        
        self.incident_notes = QTextEdit()
        self.incident_notes.setPlaceholderText("Record your observations, findings, and actions here...")
        
        notes_layout.addWidget(self.incident_notes)
        notes_group.setLayout(notes_layout)
        
        right_layout.addWidget(QLabel("Step Details:"))
        right_layout.addWidget(self.step_details)
        right_layout.addWidget(notes_group)
        
        content_splitter.addWidget(left_widget)
        content_splitter.addWidget(right_widget)
        content_splitter.setSizes([400, 600])
        
        layout.addWidget(content_splitter)
        
        # Playbook actions
        actions_group = QGroupBox("Playbook Actions")
        actions_layout = QHBoxLayout()
        
        btn_new_incident = QPushButton("New Incident")
        btn_new_incident.clicked.connect(self.new_incident)
        
        btn_save_notes = QPushButton("Save Notes")
        btn_save_notes.clicked.connect(self.save_notes)
        
        btn_export_playbook = QPushButton("Export Playbook")
        btn_export_playbook.clicked.connect(self.export_playbook)
        
        btn_mark_complete = QPushButton("Mark Step Complete")
        btn_mark_complete.clicked.connect(self.mark_step_complete)
        
        actions_layout.addWidget(btn_new_incident)
        actions_layout.addWidget(btn_save_notes)
        actions_layout.addWidget(btn_export_playbook)
        actions_layout.addWidget(btn_mark_complete)
        actions_layout.addStretch()
        
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        self.tabs.addTab(playbook_tab, "IR Playbook")
        
        # Initialize playbook data
        self.playbook_data = {}
        self.current_incident_type = ""
    
    def load_playbook(self, incident_type):
        """Load appropriate playbook based on incident type"""
        if incident_type == "Select Incident Type":
            self.playbook_steps.clear()
            self.step_details.clear()
            return
            
        self.current_incident_type = incident_type
        self.playbook_steps.clear()
        
        # Define playbooks for different incident types
        playbooks = {
            "Malware Infection": self.get_malware_playbook(),
            "Phishing Attack": self.get_phishing_playbook(),
            "Data Breach": self.get_databreach_playbook(),
            "Ransomware Attack": self.get_ransomware_playbook(),
            "DDoS Attack": self.get_ddos_playbook(),
            "Insider Threat": self.get_insider_threat_playbook(),
            "Unauthorized Access": self.get_unauthorized_access_playbook(),
            "Network Intrusion": self.get_network_intrusion_playbook()
        }
        
        self.playbook_data = playbooks.get(incident_type, {})
        
        # Populate steps tree
        for phase, steps in self.playbook_data.get('phases', {}).items():
            phase_item = QTreeWidgetItem(self.playbook_steps, [phase, "Not Started"])
            phase_item.setExpanded(True)
            
            for step in steps:
                step_item = QTreeWidgetItem(phase_item, [step['name'], "Pending"])
                step_item.setData(0, Qt.UserRole, step['details'])
        
        self.statusBar().showMessage(f"Loaded {incident_type} playbook")
    
    def get_malware_playbook(self):
        """Malware infection response playbook"""
        return {
            'title': 'Malware Infection Response',
            'phases': {
                'Preparation': [
                    {'name': 'Verify incident scope', 'details': 'Confirm malware type and affected systems'},
                    {'name': 'Assemble response team', 'details': 'Notify security team and stakeholders'},
                    {'name': 'Document initial findings', 'details': 'Record time, systems affected, symptoms'}
                ],
                'Containment': [
                    {'name': 'Isolate affected systems', 'details': 'Disconnect from network physically or logically'},
                    {'name': 'Change credentials', 'details': 'Reset passwords for affected accounts'},
                    {'name': 'Block malicious domains/IPs', 'details': 'Update firewall rules and DNS blocking'}
                ],
                'Eradication': [
                    {'name': 'Identify malware type', 'details': 'Use antivirus and malware analysis tools'},
                    {'name': 'Remove malware', 'details': 'Use specialized removal tools and manual cleanup'},
                    {'name': 'Patch vulnerabilities', 'details': 'Apply security updates and patches'}
                ],
                'Recovery': [
                    {'name': 'Restore systems', 'details': 'From clean backups after verification'},
                    {'name': 'Monitor for recurrence', 'details': 'Enhanced monitoring for 72 hours'},
                    {'name': 'Validate system integrity', 'details': 'Verify systems are clean and functional'}
                ],
                'Post-Incident': [
                    {'name': 'Conduct root cause analysis', 'details': 'Determine how infection occurred'},
                    {'name': 'Update security controls', 'details': 'Implement additional preventive measures'},
                    {'name': 'Document lessons learned', 'details': 'Update incident response procedures'}
                ]
            }
        }
    
    def get_phishing_playbook(self):
        """Phishing attack response playbook"""
        return {
            'title': 'Phishing Attack Response',
            'phases': {
                'Identification': [
                    {'name': 'Confirm phishing attempt', 'details': 'Analyze email headers and content'},
                    {'name': 'Identify affected users', 'details': 'Check email logs and user reports'},
                    {'name': 'Assess potential impact', 'details': 'Determine if credentials were compromised'}
                ],
                'Containment': [
                    {'name': 'Quarantine malicious emails', 'details': 'Remove from all mailboxes'},
                    {'name': 'Block malicious URLs', 'details': 'Update web filters and firewalls'},
                    {'name': 'Reset compromised credentials', 'details': 'Force password changes if needed'}
                ],
                'Investigation': [
                    {'name': 'Analyze email headers', 'details': 'Trace email origin and routing'},
                    {'name': 'Examine malicious attachments', 'details': 'Sandbox analysis if available'},
                    {'name': 'Check for data exfiltration', 'details': 'Monitor network traffic for suspicious activity'}
                ],
                'Recovery': [
                    {'name': 'User awareness training', 'details': 'Provide immediate phishing education'},
                    {'name': 'Implement additional filtering', 'details': 'Enhance email security controls'},
                    {'name': 'Monitor for further attempts', 'details': 'Increased vigilance for similar attacks'}
                ]
            }
        }
    
    def get_databreach_playbook(self):
        """Data breach response playbook"""
        return {
            'title': 'Data Breach Response',
            'phases': {
                'Initial Assessment': [
                    {'name': 'Confirm data compromise', 'details': 'Verify what data was accessed/exfiltrated'},
                    {'name': 'Activate breach response team', 'details': 'Notify legal, PR, and security teams'},
                    {'name': 'Secure evidence', 'details': 'Preserve logs and system state for investigation'}
                ],
                'Containment': [
                    {'name': 'Isolate affected systems', 'details': 'Disconnect from network to prevent further access'},
                    {'name': 'Change access credentials', 'details': 'Reset passwords and API keys'},
                    {'name': 'Implement additional monitoring', 'details': 'Enhanced logging and alerting'}
                ],
                'Investigation': [
                    {'name': 'Determine breach scope', 'details': 'Identify all affected systems and data'},
                    {'name': 'Identify attack vector', 'details': 'How the breach occurred (vulnerability, misconfiguration)'},
                    {'name': 'Assess regulatory requirements', 'details': 'Determine notification obligations'}
                ],
                'Notification': [
                    {'name': 'Prepare breach notifications', 'details': 'Draft communications for affected parties'},
                    {'name': 'Coordinate with legal counsel', 'details': 'Ensure compliance with regulations'},
                    {'name': 'Execute notification plan', 'details': 'Notify affected individuals and authorities'}
                ]
            }
        }
    
    def get_ransomware_playbook(self):
        """Ransomware attack response playbook"""
        return {
            'title': 'Ransomware Response',
            'phases': {
                'Immediate Response': [
                    {'name': 'Isolate infected systems', 'details': 'Disconnect from network immediately'},
                    {'name': 'Identify ransomware variant', 'details': 'Determine specific ransomware type'},
                    {'name': 'Preserve evidence', 'details': 'Take screenshots and save ransom notes'}
                ],
                'Containment': [
                    {'name': 'Disable shared drives', 'details': 'Prevent spread to network shares'},
                    {'name': 'Check backup integrity', 'details': 'Verify backups are not compromised'},
                    {'name': 'Identify patient zero', 'details': 'Find initial infection source'}
                ],
                'Recovery Decision': [
                    {'name': 'Assess restoration options', 'details': 'Evaluate backup availability and integrity'},
                    {'name': 'Consult with leadership', 'details': 'Discuss payment vs restoration options'},
                    {'name': 'Engage law enforcement', 'details': 'Report to appropriate authorities'}
                ],
                'Restoration': [
                    {'name': 'Restore from clean backups', 'details': 'After ensuring systems are clean'},
                    {'name': 'Rebuild compromised systems', 'details': 'If backups unavailable or compromised'},
                    {'name': 'Implement enhanced security', 'details': 'Strengthen defenses against future attacks'}
                ]
            }
        }
    
    # Additional playbook methods for other incident types
    def get_ddos_playbook(self):
        return {'title': 'DDoS Response', 'phases': {}}
    
    def get_insider_threat_playbook(self):
        return {'title': 'Insider Threat Response', 'phases': {}}
    
    def get_unauthorized_access_playbook(self):
        return {'title': 'Unauthorized Access Response', 'phases': {}}
    
    def get_network_intrusion_playbook(self):
        return {'title': 'Network Intrusion Response', 'phases': {}}
    
    def show_step_details(self, item, column):
        """Show details for selected playbook step"""
        if item.childCount() == 0:  # It's a step item, not a phase
            details = item.data(0, Qt.UserRole)
            if details:
                self.step_details.setText(f"""
                <h3>{item.text(0)}</h3>
                <b>Details:</b><br>
                {details}<br><br>
                <b>Status:</b> {item.text(1)}<br>
                <b>Recommended Tools:</b><br>
                - Process Explorer<br>
                - Wireshark<br>
                - Volatility<br>
                - Autopsy<br>
                - FTK Imager
                """)
    
    def mark_step_complete(self):
        """Mark selected step as complete"""
        item = self.playbook_steps.currentItem()
        if item and item.childCount() == 0:  # Only steps, not phases
            item.setText(1, "Completed")
            item.setBackground(1, QColor(144, 238, 144))  # Light green
            self.statusBar().showMessage(f"Marked '{item.text(0)}' as complete")
    
    def new_incident(self):
        """Start a new incident investigation"""
        reply = QMessageBox.question(self, "New Incident", 
                                   "Start a new incident investigation? Current notes will be cleared.",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.incident_notes.clear()
            self.incident_type.setCurrentIndex(0)
            self.playbook_steps.clear()
            self.step_details.clear()
            self.statusBar().showMessage("New incident investigation started")
    
    def save_notes(self):
        """Save investigation notes to file"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Investigation Notes", 
                f"incident_notes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", 
                "Text Files (*.txt)"
            )
            
            if filename:
                notes = f"""
                INCIDENT RESPONSE NOTES
                ======================
                Incident Type: {self.current_incident_type}
                Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                Analyst: {os.getlogin()}
                
                Notes:
                {self.incident_notes.toPlainText()}
                """
                
                with open(filename, 'w') as f:
                    f.write(notes)
                
                self.statusBar().showMessage(f"Notes saved to {filename}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save notes: {str(e)}")
    
    def export_playbook(self):
        """Export current playbook with status"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Playbook", 
                f"ir_playbook_{self.current_incident_type.lower().replace(' ', '_')}.txt", 
                "Text Files (*.txt)"
            )
            
            if filename:
                export_content = self.generate_playbook_export()
                with open(filename, 'w') as f:
                    f.write(export_content)
                
                self.statusBar().showMessage(f"Playbook exported to {filename}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export playbook: {str(e)}")
    
    def generate_playbook_export(self):
        """Generate export content for current playbook"""
        export_text = f"""
        INCIDENT RESPONSE PLAYBOOK EXPORT
        =================================
        Incident Type: {self.current_incident_type}
        Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        Analyst: {os.getlogin()}
        
        """
        
        # Iterate through all items in the tree
        root = self.playbook_steps.invisibleRootItem()
        for i in range(root.childCount()):
            phase = root.child(i)
            export_text += f"\n{phase.text(0)}:\n"
            export_text += "=" * len(phase.text(0)) + "\n"
            
            for j in range(phase.childCount()):
                step = phase.child(j)
                export_text += f"\n{step.text(0)} - Status: {step.text(1)}\n"
        
        export_text += f"""
        
        INVESTIGATION NOTES:
        ===================
        {self.incident_notes.toPlainText()}
        """
        
        return export_text

    # ... (previous methods remain unchanged, including create_dashboard_tab, create_process_tab, etc.)

    def create_dashboard_tab(self):
        """Create the dashboard tab with system overview"""
        # ... (previous implementation remains unchanged)
        pass

    def create_process_tab(self):
        """Create process analysis tab"""
        # ... (previous implementation remains unchanged)
        pass

    def create_network_tab(self):
        """Create network analysis tab"""
        # ... (previous implementation remains unchanged)
        pass

    def create_file_system_tab(self):
        """Create file system analysis tab"""
        # ... (previous implementation remains unchanged)
        pass

    def create_memory_tab(self):
        """Create memory analysis tab"""
        # ... (previous implementation remains unchanged)
        pass

    def create_log_analysis_tab(self):
        """Create log analysis tab"""
        # ... (previous implementation remains unchanged)
        pass

    # ... (all other previous methods remain unchanged)

def is_admin_windows():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    try:
        print("Starting application...")
        app = QApplication(sys.argv)
        print("QApplication created")
        app.setApplicationName("Digital Incident Response Tool")
        
        # Check if running with appropriate permissions
        if platform.system() == "Windows":
            if not is_admin_windows():
                print("Warning: For best results, run as Administrator on Windows")
        elif platform.system() == "Linux" and os.getuid() != 0:
            print("Warning: For best results, run as root on Linux")
        
        print("Creating main window...")
        window = IncidentResponseTool()
        print("Showing window...")
        window.show()
        print("Entering application event loop...")
        sys.exit(app.exec_())
    except Exception as e:
        print(f"Error in main: {str(e)}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")
