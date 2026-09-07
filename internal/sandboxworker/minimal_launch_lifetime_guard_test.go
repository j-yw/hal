package sandboxworker

import (
	"go/ast"
	"go/types"
	"path/filepath"
)

// These audited selected functions retain order as well as symbol identity.
// A changed body cannot inherit an exception by deleting its checked calls.
func l8WorkerV2MinimalDeclarationDigest(scope l8WorkerV2GuardScope) string {
	function, ok := scope.node.(*ast.FuncDecl)
	if !ok || scope.file == nil {
		return ""
	}
	return map[string]string{
		"job_helpers.go/newOpaqueJobID":                               "456ae1476d95545e384177e3627d99d7f002a6fb818f89b01b169c903179c010",
		"job_manager_v2.go/newJobManagerV2":                           "32e298a51b5d96bbe696079c4af3c040a04fcc4c449f60ad31b082f4181e6c17",
		"minimal_launch_dispatch.go/beginMinimalPreparation":          "05fa4b86c84305737a351d6b08c5aba37c0a59ff65d44e1d2ce4af229b49823e",
		"minimal_launch_dispatch.go/endMinimalPreparation":            "3ec422eef00dab736674de293a91bcff8595848f67065185462bfc7b473423b7",
		"minimal_launch_dispatch.go/handleMinimalLaunch":              "4ff2e01144601fa002a17e126cb09411adc6230b75790ef1ac2cb639537c9eb8",
		"minimal_launch_dispatch.go/checkMinimalDispatch":             "e778f2819e7c6f83da8d994fe64b85ee50c9a00301768bbc4b3743a45ebb35bb",
		"minimal_launch_dispatch.go/reserveMinimalLaunch":             "d65edbcd9831cee833a3d4ce2c2d3b5f61c3bd43ea6d0d9267989b7a824180ab",
		"minimal_launch_dispatch.go/finishMinimalDispatch":            "c4207e03f08cfe0c74c395b87feea163591cbc917b4be89181da522de8d4ebf6",
		"minimal_launch_cancel.go/handleMinimalLaunchCancel":          "3ea91dc63f40c0a9346f7f6f045302fcd87d4e172e96dd4f7a4ab9c94d402dce",
		"minimal_launch_cancel.go/cancelMinimalLaunch":                "d278fe364e6f760835d771e62fdad4d22b36d67b3d99f8658f8a52d3cc947700",
		"minimal_launch_cancel.go/minimalLaunchCancelIdentityMatches": "b62f0987ed7f69431b6a9e5bdddebd45f4330475b68251f073501e870a167f88",
		"minimal_launch_dispatch.go/closeMinimalLaunch":               "97feb53573efa29e444e4b0614f79099e9c14dde1dc2f015b6f878e1beac0612",
		"minimal_launch_dispatch.go/finishMinimalClose":               "146bd7b148830181f2ec00dead48752094c8341b2fd5a328c8562f767239de3a",
		"minimal_launch_file_unix.go/openMinimalLaunchNoFollow":       "1f144b986b4b4068df799248704d4d89e9a884385f3534b9d097f4e771fdf2aa",
		"minimal_launch_file_unix.go/minimalLaunchFileOwned":          "396c924ba1b1d32dfb72e921a9a01dd5f1ce24a59e849c1fde20281e02c2294f",
		"minimal_launch_file_unix.go/openMinimalLaunchRelative":       "4852e0c27e86cae1ce079935e37f2838f07d57c6e74a4ad0d847e58b4263ca69",
		"minimal_launch_store.go/requireMinimalLaunchEmpty":           "c0adaa0e78a2833a4a8332b0d2499de8046d3f9aa8dac68ec0900b02b07d4626",
		"minimal_launch_store.go/saveMinimalLaunch":                   "65ab8ab4302896d7a3e6a47c87981c470bc577a7eff7aa8895ceb5727b80baf6",
		"minimal_launch_store.go/validateStoredMinimalLaunchV1":       "6d07f97ebb404c182cc67f3123bbffe7db430ea64380453e6e527b08a6c190c0",
		"minimal_launch_store.go/readMinimalLaunchFile":               "06154b3e15369f2e73e65c4fd4301cacc3da74ca3a3f3ee9edad817b250cf2df",
		"minimal_launch_store.go/validMinimalLaunchStoredFile":        "a60ec924b8393d2e0af50cd32a40f64d84688aaf15116158df863c2ba03ffd76",
		"minimal_launch_store_ops.go/newMinimalLaunchStoreOps":        "f3bdf632fe90bc63d8c4937d4a268633c90b30233137c27996e1f6e37b48b6fd",
		"minimal_launch_store_ops.go/checkMinimalAuthority":           "63ed5b3fcf4cec717ab3352bbe0652773f50b49c81b65658ec4d2485853d0a75",
		"minimal_launch_store_ops.go/closeMinimalStore":               "ed17a613690871fd7cc430077863811ca80bc423c97c312c15f84de17377bac9",
		"minimal_launch_store_ops.go/removeMinimalTemporary":          "3ad80daaec4dce5dd7bac11d25b3fc7e7cbf893db060fc1fda50fcea767f1c5a",
	}[filepath.Base(scope.file.path)+"/"+function.Name.Name]
}

func l8WorkerV2ExactMinimalDeclaration(scope l8WorkerV2GuardScope) bool {
	want := l8WorkerV2MinimalDeclarationDigest(scope)
	return want != "" && want == l8WorkerV2DeclarationDigest(scope)
}

func l8WorkerV2AllowedExactMinimalLifetimeCall(scope l8WorkerV2GuardScope, call *ast.CallExpr, info *types.Info) bool {
	function := l8WorkerV2ScopeFunction(scope)
	if function == nil || !l8WorkerV2ExactMinimalDeclaration(scope) {
		return false
	}
	called := l8WorkerV2CalledObject(call.Fun, info)
	if called == nil || called.Pkg() == nil {
		return false
	}
	path, name := called.Pkg().Path(), called.Name()
	if filepath.Base(scope.file.path) == "job_helpers.go" && function.Name.Name == "newOpaqueJobID" {
		if !l8WorkerV2IsPackageCall(call, "io", "ReadFull", 2, info) {
			return false
		}
		reader := l8WorkerV2CalledObject(call.Args[0], info)
		return reader != nil && reader.Pkg() != nil && reader.Pkg().Path() == "crypto/rand" && reader.Name() == "Reader"
	}
	if function.Name.Name == "newJobManagerV2" {
		return path == "context" && name == "WithCancel"
	}
	if function.Name.Name == "handleMinimalLaunchCancel" {
		return l8WorkerV2ExactReceiverObject(function, "L8Service", true, info) != nil && path == "context" && name == "Done"
	}
	if l8WorkerV2ExactReceiverObject(function, "jobManagerV2", true, info) == nil {
		return false
	}
	switch function.Name.Name {
	case "cancelMinimalLaunch":
		return path == "context" && name == "Err"
	case "beginMinimalPreparation":
		return path == "context" && (name == "Err" || name == "WithDeadline" || name == "AfterFunc")
	case "endMinimalPreparation":
		return path == "github.com/jywlabs/hal/internal/sandboxworker" && (name == "cancel" || name == "stop")
	case "finishMinimalClose":
		return path == "github.com/jywlabs/hal/internal/sandboxworker" && name == "minimalCancel"
	}
	return false
}

func l8WorkerV2AllowedExactMinimalStoreCall(scope l8WorkerV2GuardScope, call *ast.CallExpr, info *types.Info) bool {
	function := l8WorkerV2ScopeFunction(scope)
	if function == nil || !l8WorkerV2ExactMinimalDeclaration(scope) {
		return false
	}
	if filepath.Base(scope.file.path) == "minimal_launch_store.go" && function.Name.Name == "requireMinimalLaunchEmpty" && l8WorkerV2ExactReceiverObject(function, "jobStoreV2", true, info) != nil {
		// The pinned declaration has one literal deferred close of the exact
		// unretained directory. No arbitrary callback parameter is admitted.
		if _, literal := call.Fun.(*ast.FuncLit); literal {
			return len(call.Args) == 0
		}
	}
	called := l8WorkerV2CalledObject(call.Fun, info)
	if called == nil || called.Pkg() == nil {
		return false
	}
	path, name := called.Pkg().Path(), called.Name()
	if function.Name.Name == "minimalLaunchFileOwned" {
		return path == "io/fs" && name == "Sys"
	}
	if function.Name.Name == "validMinimalLaunchStoredFile" {
		return path == "io/fs" && (name == "Mode" || name == "Size")
	}
	file := filepath.Base(scope.file.path)
	if (file != "minimal_launch_store.go" && file != "minimal_launch_store_ops.go") || l8WorkerV2ExactReceiverObject(function, "jobStoreV2", true, info) == nil {
		return false
	}
	if path == "io/fs" && (name == "IsDir" || name == "Mode" || name == "Size") || path == "os" && name == "SameFile" {
		return true
	}
	if function.Name.Name != "saveMinimalLaunch" && function.Name.Name != "readMinimalLaunchFile" {
		return false
	}
	if function.Name.Name == "saveMinimalLaunch" && path == "github.com/jywlabs/hal/internal/sandboxworker" && (name == "rename" || name == "sync") {
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		pointer, ok := types.Unalias(info.TypeOf(selector.X)).(*types.Pointer)
		if !ok {
			return false
		}
		_, exact := l8WorkerV2ExactNamedStructUnderlying(pointer.Elem(), "minimalLaunchStoreOps")
		return exact
	}
	if path == "io" && (name == "ReadAll" || name == "LimitReader") {
		return true
	}
	if path != "github.com/jywlabs/hal/internal/sandboxworker" || name != "decodeStoredJobStateV2Into" || len(call.Args) != 3 || !l8WorkerV2ExactPackageInt64Constant(call.Args[1], "maxStoredJobStateV2Bytes", 64<<10, info) {
		return false
	}
	reader, ok := l8WorkerV2UnparenExpression(call.Args[0]).(*ast.CallExpr)
	output := l8WorkerV2AddressedObject(call.Args[2], "storedJobStateV2", info)
	return ok && l8WorkerV2IsPackageCall(reader, "bytes", "NewReader", 1, info) && output != nil && l8WorkerV2IsExactStoredJobStateSchema(output.Type())
}
