# algorithm 库打包说明（pm 包）

## 打包

```bash
./pack.sh        # 编译 debug/release 两套 libalgorithm.a，打包并发布到 ~/.project_manager/repo/
./pack.sh -f     # 同名同版本已存在时强制覆盖（本地迭代用）
```

产物：

- `~/.project_manager/repo/algorithm-0.1.1.pm`
- `~/.project_manager/repo/algorithm-0.1.1.pm.sha256`

包内结构：

```text
algorithm/
├── manifest.json              # name/version/lib_type=static/link_libs=["algorithm"]
├── include/algorithm.h        # 对外头文件，安装到 extern_inc/algorithm/
└── lib/
    ├── debug/libalgorithm.a   # -g -O0
    └── release/libalgorithm.a # -O2 -mtune=generic（可移植，无 -march=native）
```

`manifest.json` 声明了依赖 `basic@0.1.1`。安装 algorithm 时会递归安装 basic，
并把两个包的 `link_libs` 都写入使用方项目的 `deps.libs`。

## 其它项目依赖 algorithm

```bash
pm init MyApp .
pm pkg install algorithm -p MyApp
# 或
pm deps add algorithm -p MyApp
```

安装后会自动完成（无需手工配置）：

- 头文件 → `MyApp/extern_inc/algorithm/algorithm.h`
- 库文件 → `MyApp/lib/{debug,release}/libalgorithm.a`
- 依赖 `basic` 的头文件和库也会一并安装
- `.pmproject` 写入：
  - `dependencies`：`algorithm@0.1.1`、`basic@0.1.1`
  - `deps.libs`：`["algorithm", "basic"]`

## 代码里怎么引用

pm 把 `extern_inc/` 加在 include 路径上，头文件要带包名前缀：

```cpp
#include <algorithm/algorithm.h>

basic::ByteBuffer in, out;
in.write_bytes("abc", 3);
algorithm::sha1(in, out);
```

`algorithm.h` 内部使用 `#include "basic/byte_buffer.h"`，因此使用方必须同时安装 basic
（pm 会按 manifest 的 `deps` 自动完成）。

## 升级版本

1. 修改 `pack/manifest.json` 的 `version` 与 `pack/pack.sh` 的 `PKG_VERSION`（保持一致）；
2. 执行 `./pack.sh`；
3. 使用方执行 `pm pkg install algorithm@<新版> -p MyApp`（旧版本残留会自动清理）。
