import os,json,stat,pathlib,collections,datetime
ROOT=pathlib.Path(r"D:\PGOP1_DATA\SWEbench")
WS=pathlib.Path(r"D:\PGOP1_DATA\SWEbench\Engineering\PGOP1_RUN_001")
OUT=WS/"frozen_input_listing.jsonl"; SUMMARY=WS/"frozen_input_listing_summary.json"
if OUT.exists() or SUMMARY.exists(): raise SystemExit("Refusing to overwrite frozen snapshot artifacts.")
errors=[]; counts=collections.Counter(); types=collections.Counter(); nbytes=0; excluded=0
with OUT.open("w",encoding="utf-8",newline="\n") as f:
 stack=[ROOT]
 while stack:
  d=stack.pop()
  try: entries=sorted(os.scandir(d),key=lambda e:e.name.casefold(),reverse=True)
  except OSError as e: errors.append({"path":str(d),"error_type":type(e).__name__,"error":str(e)}); continue
  for e in entries:
   p=pathlib.Path(e.path)
   try:
    rel=p.relative_to(ROOT).as_posix()
    if rel.casefold()=="engineering/pgop1_run_001" or rel.casefold().startswith("engineering/pgop1_run_001/"): excluded+=1; continue
    st=e.stat(follow_symlinks=False); mode=st.st_mode
    if stat.S_ISDIR(mode): stack.append(p); counts["directories"]+=1; continue
    if stat.S_ISREG(mode):
     ext=p.suffix.lower() or "[no_extension]"
     f.write(json.dumps({"relative_path":rel,"size_bytes":st.st_size,"mtime_ns":st.st_mtime_ns,"file_type":ext,"kind":"regular_file"},ensure_ascii=False,separators=(",",":"))+"\n")
     counts["files"]+=1; nbytes+=st.st_size; types[ext]+=1
    else:
     f.write(json.dumps({"relative_path":rel,"size_bytes":st.st_size,"file_type":p.suffix.lower() or "[no_extension]","kind":"non_regular"},ensure_ascii=False,separators=(",",":"))+"\n"); counts["non_regular"]+=1
   except OSError as e: errors.append({"path":str(p),"error_type":type(e).__name__,"error":str(e)})
summary={"snapshot_root":str(ROOT),"listing_path":str(OUT),"frozen_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"directories_enumerated":counts["directories"],"regular_files":counts["files"],"non_regular_entries":counts["non_regular"],"total_regular_file_bytes":nbytes,"excluded_run_workspace_entries":excluded,"extension_counts":dict(sorted(types.items())),"listing_errors":errors}
SUMMARY.write_text(json.dumps(summary,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
print(json.dumps({k:summary[k] for k in ("directories_enumerated","regular_files","non_regular_entries","total_regular_file_bytes","excluded_run_workspace_entries")},indent=2))
