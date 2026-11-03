"""Read-only CLI for framework preflight, verification, recovery, and report."""
import argparse
import json
from .core import load_config

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("preflight","verify","recover","report"))
    parser.add_argument("--config",required=True)
    parser.add_argument("--config-root",action="append",required=True)
    parser.add_argument("--trusted-root",action="append",required=True)
    parser.add_argument("--output-root",action="append",required=True)
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    campaign=load_config(args.config,args.config_root,args.output,args.trusted_root,args.output_root)
    preflight=campaign.preflight()
    if args.action=="preflight": result=preflight
    elif args.action in ("verify","recover"): result=campaign.recover()
    else: result=campaign.report()
    def serializable(value):
        if isinstance(value,set): return sorted(value)
        if isinstance(value,dict): return {k:serializable(v) for k,v in value.items()}
        if isinstance(value,list): return [serializable(v) for v in value]
        return value
    print(json.dumps(serializable(result),sort_keys=True,ensure_ascii=False,allow_nan=False))

if __name__=="__main__": main()
