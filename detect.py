import Evtx.Evtx as evtx
import re

def check_dsrm_password_change(filename):
    with evtx.Evtx(filename) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID" in xml and ">4794<" in xml:
                print("[ALERT] T1098 - DSRM Password Change Detected")
                print("MITRE ATT&CK: T1098 (Account Manipulation)")
                print("-" * 50)

check_dsrm_password_change('4794_DSRM_password_change_t1098.evtx')
def check_dcsync_acl_change(filename):
    with evtx.Evtx(filename) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID" in xml and ">5136<" in xml:
                print("[ALERT] T1003.006 - DCSync ACL Modification Detected")
                print("MITRE ATT&CK: T1003.006 (OS Credential Dumping: DCSync)")
                print("-" * 50)
check_dcsync_acl_change('DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl.evtx')
def check_rdp_lateral_movement(filename):
    with evtx.Evtx(filename) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID" in xml and ">104<" in xml:
                print("[ALERT] T1021.001 - RDP Lateral Movement Detected")
                print("MITRE ATT&CK: T1021.001 (Remote Services: RDP)")
                print("-" * 50)
check_rdp_lateral_movement('DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx')
def check_test_signing_enabled(filename):
    with evtx.Evtx(filename) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID" in xml and ">4826<" in xml:
                print("[ALERT] T1553.006 - Test Signing/Kernel Debug Enabled")
                print("MITRE ATT&CK: T1553.006 (Subvert Trust Controls)")
                print("-" * 50)
check_test_signing_enabled('DE_KernelDebug_and_TestSigning_ON_Security_4826.evtx')
def check_named_pipe_discovery(filename):
    with evtx.Evtx(filename) as log:
        for record in log.records():
            xml = record.xml()
            if "<EventID" in xml and ">18<" in xml:
                print("[ALERT] T1018 - Remote System Discovery via Named Pipes")
                print("MITRE ATT&CK: T1018 (Remote System Discovery)")
                print("-" * 50)
check_named_pipe_discovery('Discovery_Remote_System_NamedPipes_Sysmon_18.evtx')