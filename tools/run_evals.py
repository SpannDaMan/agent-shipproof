#!/usr/bin/env python3
"""Run the deterministic Agent ShipProof evaluation cases."""
from __future__ import annotations
import argparse, importlib.util, json, subprocess, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; MODULE=ROOT/'plugins'/'agent-shipproof'/'scripts'/'shipproof.py'
spec=importlib.util.spec_from_file_location('shipproof_evals',MODULE); assert spec and spec.loader
sp=importlib.util.module_from_spec(spec);sys.modules[spec.name]=sp;spec.loader.exec_module(sp)
def make_root(path:Path)->None:
    (path/'src').mkdir();(path/'src'/'a.txt').write_text('one\n',encoding='utf-8');(path/'ok.py').write_text("print('ok')\n",encoding='utf-8')
def run_suite(_:Path)->dict[str,object]:
    results=[]
    def case(name,fn):
        try: fn(); results.append({'id':name,'status':'pass','error':''})
        except Exception as exc: results.append({'id':name,'status':'fail','error':f'{type(exc).__name__}: {exc}'})
    def base(root:Path,**kw): return sp.create_receipt(root,root/'r.json',['Command completed.'],[sys.executable,'ok.py'],['src/**','ok.py'],[],**kw)
    with tempfile.TemporaryDirectory() as t:
        r=Path(t);make_root(r);receipt=base(r);case('unchanged_verifies',lambda: (_ for _ in ()).throw(AssertionError()) if sp.verify_receipt(r,receipt)['status']!='pass' else None)
        (r/'src'/'a.txt').write_text('two',encoding='utf-8');case('changed_path_detected',lambda: (_ for _ in ()).throw(AssertionError()) if sp.verify_receipt(r,receipt)['artifacts']['changed']!=['src/a.txt'] else None)
    with tempfile.TemporaryDirectory() as t:
        r=Path(t);make_root(r);receipt=base(r);(r/'src'/'b.txt').write_text('b');case('added_path_detected',lambda: (_ for _ in ()).throw(AssertionError()) if sp.verify_receipt(r,receipt)['artifacts']['added']!=['src/b.txt'] else None)
    with tempfile.TemporaryDirectory() as t:
        r=Path(t);make_root(r);receipt=base(r);(r/'src'/'a.txt').unlink();case('removed_path_detected',lambda: (_ for _ in ()).throw(AssertionError()) if sp.verify_receipt(r,receipt)['artifacts']['removed']!=['src/a.txt'] else None)
    with tempfile.TemporaryDirectory() as t:
        r=Path(t);make_root(r);receipt=base(r);receipt['claims'][0]['text']='tamper';case('receipt_body_tamper_detected',lambda: (_ for _ in ()).throw(AssertionError()) if sp.verify_receipt(r,receipt)['receipt_integrity']!='fail' else None)
    case('exit_code_changes_digest',lambda: (_ for _ in ()).throw(AssertionError()) if sp.finalize_receipt({'x':0},None,None)['integrity']['payload_sha256']==sp.finalize_receipt({'x':1},None,None)['integrity']['payload_sha256'] else None)
    case('file_hash_changes_digest',lambda: (_ for _ in ()).throw(AssertionError()) if sp.finalize_receipt({'sha':'a'},None,None)['integrity']['payload_sha256']==sp.finalize_receipt({'sha':'b'},None,None)['integrity']['payload_sha256'] else None)
    with tempfile.TemporaryDirectory() as t:
        r=Path(t);make_root(r);receipt=base(r,hmac_key=b'one',key_id='k1');case('hmac_round_trip',lambda: (_ for _ in ()).throw(AssertionError()) if sp.verify_receipt(r,receipt,b'one')['authentication']['status']!='pass' else None);case('wrong_hmac_key_detected',lambda: (_ for _ in ()).throw(AssertionError()) if sp.verify_receipt(r,receipt,b'two')['authentication']['status']!='fail' else None)
    with tempfile.TemporaryDirectory() as t:
        r=Path(t);make_root(r);receipt=base(r)
        def downgrade():
            try: sp.verify_receipt(r,receipt,b'one')
            except sp.ShipProofError:return
            raise AssertionError('downgrade accepted')
        case('hmac_downgrade_rejected',downgrade)
    def rejected(fn):
        try:fn()
        except sp.ShipProofError:return
        raise AssertionError('expected rejection')
    with tempfile.TemporaryDirectory() as t:
        r=Path(t);make_root(r);case('claim_secret_rejected',lambda:rejected(lambda:sp.create_receipt(r,r/'a.json',['sk-12345678'],[sys.executable,'ok.py'],['src/**'],[])));case('argv_secret_rejected',lambda:rejected(lambda:sp.create_receipt(r,r/'b.json',['x'],[sys.executable,'-c',"print('ghp_12345678')"],['src/**'],[])));case('include_escape_rejected',lambda:rejected(lambda:sp.create_receipt(r,r/'c.json',['x'],[sys.executable,'ok.py'],['../x'],[])));(r/'d.json').write_text('old');case('existing_receipt_not_overwritten',lambda:rejected(lambda:sp.create_receipt(r,r/'d.json',['x'],[sys.executable,'ok.py'],['src/**'],[])))
    with tempfile.TemporaryDirectory() as t:
        r=Path(t);make_root(r);case('timeout_recorded_as_124',lambda: (_ for _ in ()).throw(AssertionError()) if sp.run_command(r,[sys.executable,'-c','import time;time.sleep(2)'],1)['exit_code']!=124 else None)
    with tempfile.TemporaryDirectory() as t:
        r=Path(t);make_root(r)
        case('output_limit_recorded_as_125',lambda: (_ for _ in ()).throw(AssertionError()) if sp.run_command(r,[sys.executable,'-c',"import sys;sys.stdout.buffer.write(b'x'*200000)"],10,10_000)['exit_code']!=125 else None)
        def aws_redaction():
            result=sp.run_command(r,[sys.executable,'-c',"print('AKIA'+'A'*16);print('aws_secret_access_key='+'B'*40)"],10)
            if 'AKIA'+'A'*16 in result['stdout']['excerpt'] or 'B'*40 in result['stdout']['excerpt']:raise AssertionError('AWS-shaped secret remained')
        case('aws_output_redacted',aws_redaction)
        case('outside_receipt_path_rejected',lambda:rejected(lambda:sp.create_receipt(r,r.parent/'outside.json',['x'],[sys.executable,'ok.py'],['src/**'],[])))
        def malformed_receipt():
            receipt=base(r);del receipt['command']['output_limit_bytes'];body={k:v for k,v in receipt.items() if k!='integrity'};receipt['integrity']['payload_sha256']=sp.sha256_bytes(sp.canonical_bytes(body))
            rejected(lambda:sp.verify_receipt(r,receipt))
        case('self_consistent_malformed_receipt_rejected',malformed_receipt)
    passed=sum(x['status']=='pass' for x in results);return {'schema_version':'1.0','suite':'agent-shipproof-deterministic-v1','status':'pass' if passed==len(results) else 'fail','passed':passed,'total':len(results),'score':passed/len(results),'cases':results,'publication_action':'none'}
def main():
    p=argparse.ArgumentParser();p.add_argument('--suite',type=Path,default=ROOT/'evals'/'shipproof-suite.json');a=p.parse_args();r=run_suite(a.suite);print(json.dumps(r,indent=2));return 0 if r['status']=='pass' else 1
if __name__=='__main__':raise SystemExit(main())
