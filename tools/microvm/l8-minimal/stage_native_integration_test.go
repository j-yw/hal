//go:build linux && microvm_assets_integration

package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestMinimalNativePackageStageRejectsUnsafeArchives(t *testing.T) {
	script, err := filepath.Abs("stage-native.py")
	if err != nil {
		t.Fatal(err)
	}
	program := `
import gzip, importlib.util, io, pathlib, tarfile, sys
spec=importlib.util.spec_from_file_location("native_stage",sys.argv[1])
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
root=pathlib.Path(sys.argv[2])
cases=("valid","traversal","absolute","duplicate","symlink","hardlink","pax","sparse","truncated","trailing","budget")
for case in cases:
 dest=root/case;dest.mkdir()
 stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode="w",format=tarfile.PAX_FORMAT) as archive:
  entry=tarfile.TarInfo("package/file.js");entry.mode=0o644;entry.size=7
  if case=="traversal":entry.name="package/../escape"
  if case=="absolute":entry.name="/package/escape"
  if case in ("symlink","hardlink"):
   entry.type=tarfile.SYMTYPE if case=="symlink" else tarfile.LNKTYPE;entry.linkname="../escape";entry.size=0
  if case=="pax":entry.pax_headers={"comment":"unexpected"}
  if case=="sparse":entry.pax_headers={"GNU.sparse.size":"7000"}
  archive.addfile(entry,io.BytesIO(b"fixture"))
  if case=="duplicate":archive.addfile(entry,io.BytesIO(b"fixture"))
 expanded=stream.getvalue()
 if case=="trailing":expanded+=b"unexpected tail"
 data=gzip.compress(expanded)
 if case=="truncated":data=data[:-3]
 failed=False
 try:m.unpack(io.BytesIO(data),dest,[1 if case=="budget" else 4096])
 except (ValueError,EOFError,tarfile.TarError):failed=True
 if failed != (case!="valid"):raise AssertionError(case)
 if case=="valid" and (dest/"file.js").read_bytes()!=b"fixture":raise AssertionError("byte mismatch")
 if (root/"escape").exists():raise AssertionError("escaped target")
 print(case+": PASS")
`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-I", "-B", "-c", program, script, t.TempDir())
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bounded archive cases failed: %v\n%s", err, data)
	}
	t.Log(string(data))
}

func TestMinimalNativeMeasuredArchiveFormatsRemainPinBound(t *testing.T) {
	script, err := filepath.Abs("stage-native.py")
	if err != nil {
		t.Fatal(err)
	}
	program := `
import gzip, hashlib, importlib.util, io, pathlib, tarfile, sys
spec=importlib.util.spec_from_file_location("native_stage",sys.argv[1])
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
root=pathlib.Path(sys.argv[2])
measured={
 "http-proxy-agent-7.0.2.tgz":(6088,"fd33b43da34da60d4914780e13fae5d52a7faaa996d687eea5335128de148627"),
 "agent-base-7.1.4.tgz":(7324,"c6503bd5e007db8b73fedf07b6eaaf4a94d5541953f0d06c8a17d1644c29a0c5"),
 "https-proxy-agent-7.0.6.tgz":(7451,"30165586fac3becbc9dbf2b7b5bdaa802a77ac34af9926208f6e94a3bd87ef31"),
}
if m.INDEX_DUPLICATES != measured:raise AssertionError("measured member pins changed")
formats=(
 ("types-retry-0.12.0.tgz","7c97db75aba1e8cb911b9ff349ddeae6153fd3b11fa3f3b772c1dd474ea9f8c8","retry",False,{}),
 ("types-node-22.19.19.tgz","c32937b40ab720ef6242de0bf4c8b8e48f1e4a29fbb4cb9d9f596471ee58d5c4","node v22.19",False,{}),
 ("http-proxy-agent-7.0.2.tgz","785f73faa92bfba8d61da20bf59325ab2b3dca1bbc0bbac523406f404d8a6f02","package",True,{}),
 ("agent-base-7.1.4.tgz","7dd4a61668a9a4e8d4e903f1a254f94d53dafd3f316f2b9b597c5ad8c79cb57e","package",True,{}),
 ("https-proxy-agent-7.0.6.tgz","960f89e8e5240882f64249d04a538421dd39d62ffacc138544647cc3251bc0e0","package",True,{}),
 ("buffer-equal-constant-time-1.0.1.tgz","8f455159e342103e7854ed6a4cc73edbab144d857917c88edefea862f09fe75a","package",False,{"NODETAR.type":"File","SCHILY.nlink":"1"}),
 ("mistralai-mistralai-2.2.6.tgz","972976d054d30dfcdc6bc537b1712e28860cef38ab9e3da09b5846e5a59ef43c","package",False,{"mtime":"499162500"}),
)
for index,(filename,pin,prefix,dot,pax) in enumerate(formats):
 # Only synthetic fixture pins are substituted inside this imported private
 # helper; production has no caller policy override or receipt-minting seam.
 if dot and hasattr(m,"INDEX_DUPLICATES"):m.INDEX_DUPLICATES[filename]=(7,hashlib.sha256(b"fixture").hexdigest())
 cases=("valid","changed_pin","wrong_archive","mixed_prefix","traversal","link","duplicate_canonical","unknown_pax")
 if dot:cases+=("changed_duplicate_bytes","changed_duplicate_mode","extra_occurrence","wrong_order")
 for case in cases:
  dest=root/(str(index)+case);dest.mkdir()
  stream=io.BytesIO()
  name=prefix+("/./dist/index.js" if dot else "/index.js")
  if case=="wrong_order":name="package/dist/index.js"
  if case=="traversal":name=prefix+"/../escape"
  with tarfile.open(fileobj=stream,mode="w",format=tarfile.PAX_FORMAT) as archive:
   h=tarfile.TarInfo(name);h.mode=0o644;h.size=7;h.pax_headers=dict(pax);h.mtime=499162500
   if case=="unknown_pax":h.pax_headers["comment"]="unexpected"
   if case=="link":h.type=tarfile.SYMTYPE;h.linkname="../escape";h.size=0
   archive.addfile(h,io.BytesIO(b"fixture"))
   if dot:
    duplicate=tarfile.TarInfo("package/dist/index.js");duplicate.mode=0o644;duplicate.size=7;duplicate.mtime=499162500
    if case=="changed_duplicate_mode":duplicate.mode=0o755
    archive.addfile(duplicate,io.BytesIO(b"altered" if case=="changed_duplicate_bytes" else b"fixture"))
    if case=="extra_occurrence":archive.addfile(duplicate,io.BytesIO(b"fixture"))
   if case in ("mixed_prefix","duplicate_canonical"):
    h=tarfile.TarInfo("foreign/index.js" if case=="mixed_prefix" else name.replace("/./","/"));h.mode=0o644;h.size=7
    archive.addfile(h,io.BytesIO(b"fixture"))
  failed=False
  try:
   policy=m.archive_format("renamed.tgz" if case=="wrong_archive" else filename,"0"*64 if case=="changed_pin" else pin)
   m.unpack(io.BytesIO(gzip.compress(stream.getvalue())),dest,[4096],policy)
  except (ValueError,EOFError,tarfile.TarError,FileExistsError):failed=True
  # Standard-prefix fixtures without any exception need a deliberately
  # nonstandard record to distinguish a renamed archive's default policy.
  if case=="wrong_archive" and prefix=="package" and not dot and not pax:raise AssertionError("unexercised exception")
  if failed != (case!="valid"):raise AssertionError(filename+":"+case)
  if case=="valid" and (dest/("dist/index.js" if dot else "index.js")).read_bytes()!=b"fixture":raise AssertionError("byte mismatch")
  if (root/"escape").exists():raise AssertionError("escaped target")
  print(filename+":"+case+": PASS")
`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-I", "-B", "-c", program, script, t.TempDir())
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pin-bound format cases failed: %v\n%s", err, data)
	}
	t.Log(string(data))
}

func TestMinimalNativeBuildrootSeedMatchesCompleteLayout(t *testing.T) {
	script, err := filepath.Abs("stage-native.py")
	if err != nil {
		t.Fatal(err)
	}
	program := `
import hashlib, importlib.util, json, pathlib, sys
spec=importlib.util.spec_from_file_location("native_stage",sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root=pathlib.Path(sys.argv[2]);original=m.PROFILE;layout=m.read_json(original/"buildroot-downloads.lock.json")
for case in ("valid","missing_source","changed_source","extra_source","missing_layout","changed_layout","source_symlink"):
 base=root/case;base.mkdir();profile=base/"microvm/l8-minimal";profile.mkdir(parents=True);cache=base/"cache";cache.mkdir();dest=base/"dl";dest.mkdir()
 for lane in ("l5","l8"):
  directory=profile.parent/lane;directory.mkdir();lines=[]
  for line in (original.parent/lane/"cache.manifest").read_text().splitlines():
   name=line.split("\t")[2];body=("fixture:"+name).encode();(cache/name).write_bytes(body);lines.append(hashlib.sha256(body).hexdigest()+"\t"+str(len(body))+"\t"+name)
  (directory/"cache.manifest").write_text("\n".join(sorted(lines))+"\n")
 native=m.read_json(original/"native-sources.lock.json")
 for record in native["records"]:
  body=("fixture:"+record["name"]).encode();(cache/record["name"]).write_bytes(body);record["size"]=len(body);record["sha256"]=hashlib.sha256(body).hexdigest()
 (profile/"native-sources.lock.json").write_text(json.dumps(native));m.PROFILE=profile
 info={str(i):{"dl_dir":r["directory"],"downloads":[{"source":r["filename"]}]} for i,r in enumerate(layout)}
 selected=layout[0]["filename"]
 if case=="missing_source":(cache/selected).unlink()
 if case=="changed_source":(cache/selected).write_bytes(b"corrupt")
 if case=="extra_source":(cache/"extra.tar.gz").write_bytes(b"extra")
 if case=="source_symlink":
  (cache/selected).rename(base/selected);(cache/selected).symlink_to(base/selected)
 if case=="missing_layout":info.pop("0")
 if case=="changed_layout":info["0"]["dl_dir"]="unexpected-package"
 info_path=base/"info.json";info_path.write_text(json.dumps(info));layout_path=base/"layout.json";layout_path.write_text(json.dumps(layout))
 failed=False
 try:m.seed(cache,dest,info_path,layout_path)
 except (ValueError,OSError):failed=True
 if failed != (case!="valid"):raise AssertionError(case)
 if case=="valid":
  for record in layout:
   if (dest/record["directory"]/record["filename"]).read_bytes()!=(cache/record["filename"]).read_bytes():raise AssertionError("seed bytes")
  if len([p for p in dest.rglob("*") if p.is_file()])!=55:raise AssertionError("seed count")
 print(case+": PASS")
`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-I", "-B", "-c", program, script, t.TempDir())
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("offline layout cases failed: %v\n%s", err, data)
	}
	t.Log(string(data))
}
