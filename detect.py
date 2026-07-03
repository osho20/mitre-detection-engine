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
