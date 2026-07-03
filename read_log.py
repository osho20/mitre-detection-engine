import Evtx.Evtx as evtx

with evtx.Evtx('4794_DSRM_password_change_t1098.evtx') as log:
    with open('output.txt', 'w', encoding='utf-8') as f:
        for record in log.records():
            f.write(record.xml())
            f.write('\n')