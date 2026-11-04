"""Read-only CLI for framework preflight, verification, recovery, and report."""
import argparse
import json
from .core import load_config

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("prepare","preflight","verify","recover","report"))
    parser.add_argument("--config",required=True)
    parser.add_argument("--config-root",action="append",required=True)
    parser.add_argument("--trusted-root",action="append",required=True)
    parser.add_argument("--output-root",action="append",required=True)
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    campaign=load_config(args.config,args.config_root,args.output,args.trusted_root,args.output_root)
    preflight=campaign.preflight()
    if args.action=="prepare":
        from .core import canonical, digest
        from .source_bindings import SourceBindings
        plan = campaign.shard_plan()
        sources = (SourceBindings(campaign).verify_all()
                   if "generic_caller" in campaign.config.get("audit_policy", {}) else None)
        result = {"schema":"pgop1.run-preparation.v1", "preflight":preflight,
                  "source_validation":sources, "plan_sha256":digest(canonical(plan)),
                  "units":plan["EXPECTED_UNITS"], "shards":len(plan["shards"]),
                  "started_units":0, "authorization":"NOT_GRANTED_BY_PREPARATION"}
    elif args.action=="preflight": result=preflight
    elif args.action in ("verify","recover"): result=campaign.recover()
    else: result=campaign.report()
    def serializable(value):
        if isinstance(value,set): return sorted(value)
        if isinstance(value,dict): return {k:serializable(v) for k,v in value.items()}
        if isinstance(value,list): return [serializable(v) for v in value]
        return value
    print(json.dumps(serializable(result),sort_keys=True,ensure_ascii=False,allow_nan=False))

if __name__=="__main__": main()
