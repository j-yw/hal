//go:build linux && microvm_assets_integration

package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The actual pinned builder's no-download show-info selects these three host
// tools in addition to the original host-derived 55-pair layout. Their source
// archives are already pinned in L5; no new acquisition or package resolution
// is needed. Exercise the real seeder with synthetic, independently hashed
// source bytes, not a fabricated successful container or receipt.
func TestMinimalNativePinnedBuilderSeedIncludesHostTools(t *testing.T) {
	script, err := filepath.Abs("stage-native.py")
	if err != nil {
		t.Fatal(err)
	}
	program := `
import hashlib, importlib.util, json, pathlib, sys
spec=importlib.util.spec_from_file_location("native_stage",sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root=pathlib.Path(sys.argv[2]);case=sys.argv[3];original=m.PROFILE
layout=m.read_json(original/"buildroot-downloads.lock.json")
host_tools=(("bison","bison-3.8.2.tar.xz"),("flex","flex-2.6.4.tar.gz"),("tar","tar-1.35.cpio.gz"))
observed=sorted({(r["directory"],r["filename"]) for r in layout}|set(host_tools))
if len(observed)!=58:raise AssertionError("pinned-builder fixture layout drift")
profile=root/"microvm/l8-minimal";profile.mkdir(parents=True);cache=root/"cache";cache.mkdir();dest=root/"dl";dest.mkdir()
for lane in ("l5","l8"):
 directory=profile.parent/lane;directory.mkdir();lines=[]
 for line in (original.parent/lane/"cache.manifest").read_text().splitlines():
  name=line.split("\t")[2];body=("fixture:"+name).encode();(cache/name).write_bytes(body);lines.append(hashlib.sha256(body).hexdigest()+"\t"+str(len(body))+"\t"+name)
 (directory/"cache.manifest").write_text("\n".join(sorted(lines))+"\n")
native=m.read_json(original/"native-sources.lock.json")
for record in native["records"]:
 body=("fixture:"+record["name"]).encode();(cache/record["name"]).write_bytes(body);record["size"]=len(body);record["sha256"]=hashlib.sha256(body).hexdigest()
(profile/"native-sources.lock.json").write_text(json.dumps(native));m.PROFILE=profile
if len(list(cache.iterdir()))!=205:raise AssertionError("source closure changed")
if case=="missing_host_tool":observed.remove(host_tools[0])
if case=="extra_host_tool":observed.append(("unlocked","unlocked.tar.gz"))
if case=="wrong_host_directory":observed[observed.index(host_tools[0])]=("wrong-bison",host_tools[0][1])
info={str(i):{"dl_dir":d,"downloads":[{"source":f}]} for i,(d,f) in enumerate(observed)}
info_path=root/"info.json";info_path.write_text(json.dumps(info));layout_path=root/"layout.json";layout_path.write_text(json.dumps(layout))
failed=False
try:m.seed(cache,dest,info_path,layout_path)
except (ValueError,OSError):failed=True
if case=="valid":
 if failed:raise AssertionError("actual pinned-builder host-tool layout rejected before offline seeding")
 for directory,filename in observed:
  if (dest/directory/filename).read_bytes()!=(cache/filename).read_bytes():raise AssertionError("seeded bytes changed")
 if len([p for p in dest.rglob("*") if p.is_file()])!=58:raise AssertionError("incomplete pinned-builder seed")
else:
 if not failed or list(dest.iterdir()):raise AssertionError("layout mismatch admitted or wrote output")
print(case+": PASS")
`
	for _, scenario := range []string{"valid", "missing_host_tool", "extra_host_tool", "wrong_host_directory"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "python3", "-I", "-B", "-c", program, script, t.TempDir(), scenario)
			command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("pinned-builder layout regression: %v\n%s", err, output)
			}
			t.Log(string(output))
		})
	}
}
