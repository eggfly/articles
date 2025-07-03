# MicroPython Native Module (natmod) 从入门到深度原理解析

## 1. 什么是 Native Module

### 1.1 官方定义

根据 [MicroPython 官方文档](https://docs.micropython.org/en/latest/develop/natmod.html)，Native Module（原生模块）是一种特殊的 `.mpy` 文件，它包含来自非Python语言的原生机器代码。这允许你用C等语言编写代码，将其编译并链接到 `.mpy` 文件中，然后像普通Python模块一样导入这个文件。

### 1.2 核心优势与限制

**主要优势：**
- **动态加载**：原生机器码可以被脚本动态导入，无需重新构建主MicroPython固件
- **性能优化**：关键代码路径使用原生机器码执行，性能显著提升
- **内存效率**：按需加载，减少固件大小
- **开发便利**：支持热更新和快速迭代

**主要限制：**
- **C代码编写复杂度**：相比直接在MicroPython自定义固件中编写C代码，natmod的C代码编写会更麻烦
- **外部库依赖**：引用外部库需要通过跳转表，没有跳转桥的话只能重复集成C代码
- **内存限制**：运行在SRAM中，受代码大小限制
- **架构绑定**：每个 `.mpy` 文件绑定特定架构，不能跨平台使用

### 1.3 与外部C模块的区别

Native Module 与 [MicroPython外部C模块](https://docs.micropython.org/en/latest/develop/cmodules.html) 的主要区别：

| 特性 | Native Module | 外部C模块 |
|------|---------------|-----------|
| 编译时机 | 独立编译，动态加载 | 编译到固件中 |
| 更新方式 | 无需重新刷固件 | 需要重新编译固件 |
| 内存使用 | 运行时分配 | 静态分配 |
| 开发复杂度 | 需要处理重定位 | 直接集成 |

## 2. 支持的功能和限制

### 2.1 支持的架构

当前支持的架构（`ARCH` 变量的有效选项）：

- `x86` (32 bit)
- `x64` (64 bit x86)
- `armv6m` (ARM Thumb, 如 Cortex-M0)
- `armv7m` (ARM Thumb 2, 如 Cortex-M3)
- `armv7emsp` (ARM Thumb 2, 单精度浮点, 如 Cortex-M4F, Cortex-M7)
- `armv7emdp` (ARM Thumb 2, 双精度浮点, 如 Cortex-M7)
- `xtensa` (非窗口化, 如 ESP8266)
- `xtensawin` (窗口化, 窗口大小8, 如 ESP32, ESP32S3)
- `rv32imc` (RISC-V 32位, 压缩指令, 如 ESP32C3, ESP32C6)

### 2.2 支持的功能

链接器和动态加载器支持的功能：

- 可执行代码 (text)
- 只读数据 (rodata)，包括字符串和常量数据（数组、结构体等）
- 零初始化数据 (BSS)
- text段中指向text、rodata和BSS的指针
- rodata段中指向text、rodata和BSS的指针

### 2.3 已知限制

- **不支持data段**：解决方法：使用BSS数据并显式初始化数据值
- **不支持静态BSS变量**：解决方法：使用全局BSS变量
- **运行时库链接**：原生模块不会自动链接标准静态库如 `libm.a` 和 `libgcc.a`
- **符号表限制**：原生模块不会链接到完整MicroPython固件的符号表

## 3. 快速开始：最小示例

### 3.1 项目结构

```
factorial/
├── factorial.c
└── Makefile
```

### 3.2 C源代码

```c
// factorial.c
#include "py/dynruntime.h"

// 计算阶乘的辅助函数
static mp_int_t factorial_helper(mp_int_t x) {
    if (x == 0) {
        return 1;
    }
    return x * factorial_helper(x - 1);
}

// 这是将从Python调用的函数，作为 factorial(x)
static mp_obj_t factorial(mp_obj_t x_obj) {
    // 从MicroPython输入对象中提取整数
    mp_int_t x = mp_obj_get_int(x_obj);
    // 计算阶乘
    mp_int_t result = factorial_helper(x);
    // 将结果转换为MicroPython整数对象并返回
    return mp_obj_new_int(result);
}
// 定义对上述函数的Python引用
static MP_DEFINE_CONST_FUN_OBJ_1(factorial_obj, factorial);

// 这是入口点，在模块导入时调用
mp_obj_t mpy_init(mp_obj_fun_bc_t *self, size_t n_args, size_t n_kw, mp_obj_t *args) {
    // 这必须是第一个，它设置globals dict和其他内容
    MP_DYNRUNTIME_INIT_ENTRY

    // 使函数在模块的命名空间中可用
    mp_store_global(MP_QSTR_factorial, MP_OBJ_FROM_PTR(&factorial_obj));

    // 这必须是最后一个，它恢复globals dict
    MP_DYNRUNTIME_INIT_EXIT
}
```

### 3.3 Makefile

```makefile
# 顶级MicroPython目录的位置
MPY_DIR = ../../..

# 模块名称
MOD = factorial

# 源文件 (.c 或 .py)
SRC = factorial.c

# 构建架构 (x86, x64, armv6m, armv7m, xtensa, xtensawin, rv32imc)
ARCH = x64

# 包含以获得编译和链接模块的规则
include $(MPY_DIR)/py/dynruntime.mk
```

### 3.4 编译模块

**先决条件：**
- MicroPython仓库（至少 `py/` 和 `tools/` 目录）
- CPython 3 和 pyelftools库（如 `pip install 'pyelftools>=0.25'`）
- GNU make
- 目标架构的C编译器（如果使用C源码）
- 可选的 `mpy-cross`（如果使用.py源码）

**编译命令：**
```bash
$ make
# 或者指定架构
$ make ARCH=armv7m
```

### 3.5 在MicroPython中使用

```python
import factorial
print(factorial.factorial(10))
# 应该显示 3628800
```

## 4. 技术实现深度解析

### 4.1 .mpy文件格式

根据源码分析，`.mpy`文件的头部结构如下：

```c
// py/persistentcode.h
#define MPY_VERSION 6
#define MPY_SUB_VERSION 3

// 文件头格式（4字节）
typedef struct {
    uint8_t magic;        // 0x4D ('M')
    uint8_t version;      // MPY_VERSION
    uint8_t features;     // 架构信息 + 子版本
    uint8_t small_int_bits; // 小整数位数
} mpy_header_t;
```

**特征字节编码**：
```c
// py/persistentcode.h
#define MPY_FEATURE_ENCODE_SUB_VERSION(version) (version)
#define MPY_FEATURE_DECODE_SUB_VERSION(feat) ((feat) & 3)
#define MPY_FEATURE_ENCODE_ARCH(arch) ((arch) << 2)
#define MPY_FEATURE_DECODE_ARCH(feat) ((feat) >> 2)
```

### 4.2 支持的架构

```c
// py/persistentcode.h
enum {
    MP_NATIVE_ARCH_NONE = 0,
    MP_NATIVE_ARCH_X86,
    MP_NATIVE_ARCH_X64,
    MP_NATIVE_ARCH_ARMV6,
    MP_NATIVE_ARCH_ARMV6M,
    MP_NATIVE_ARCH_ARMV7M,
    MP_NATIVE_ARCH_ARMV7EM,
    MP_NATIVE_ARCH_ARMV7EMSP,
    MP_NATIVE_ARCH_ARMV7EMDP,
    MP_NATIVE_ARCH_XTENSA,      // ESP8266
    MP_NATIVE_ARCH_XTENSAWIN,   // ESP32, ESP32-S3
    MP_NATIVE_ARCH_RV32IMC,     // ESP32-C3, ESP32-C6
};
```

### 4.3 文件结构详解

```
.mpy文件结构：
┌─────────────────┐
│     头部        │ 4字节：魔数+版本+架构+小整数位数
├─────────────────┤
│   qstr表        │ 字符串常量表
├─────────────────┤
│   对象表        │ 常量对象表
├─────────────────┤
│   代码段        │ 机器码或字节码
├─────────────────┤
│   重定位信息    │ 符号重定位指令
└─────────────────┘
```

## 5. 编译时处理：mpy_ld.py链接器

### 5.1 链接器架构

`mpy_ld.py`是Native Module编译流程的核心工具，它实现了从ELF目标文件到`.mpy`文件的转换。

```python
# tools/mpy_ld.py
class LinkEnv:
    def __init__(self, arch):
        self.arch = ARCH_DATA[arch]
        self.sections = []           # 输出段列表
        self.known_syms = {}         # 已知符号
        self.unresolved_syms = []    # 未解析符号
        self.mpy_relocs = []         # 重定位信息
```

### 5.2 架构特定配置

```python
# tools/mpy_ld.py
ARCH_DATA = {
    "xtensawin": ArchData(
        "EM_XTENSA",
        MP_NATIVE_ARCH_XTENSAWIN << 2,
        4,
        (R_XTENSA_32, R_XTENSA_PLT),
        asm_jump_xtensa,
        separate_rodata=True,
    ),
    "rv32imc": ArchData(
        "EM_RISCV",
        MP_NATIVE_ARCH_RV32IMC << 2,
        4,
        (R_RISCV_32, R_RISCV_GOT_HI20, R_RISCV_GOT32_PCREL),
        asm_jump_rv32,
    ),
}
```

### 5.3 GOT（Global Offset Table）构建

```python
# tools/mpy_ld.py
def populate_got(env):
    # 计算GOT目标地址
    for got_entry in env.got_entries.values():
        sym = got_entry.sym
        if hasattr(sym, "resolved"):
            sym = sym.resolved
        sec = sym.section
        addr = sym["st_value"]
        got_entry.sec_name = sec.name
        got_entry.link_addr += sec.addr + addr
    
    # 布局并填充GOT
    offset = 0
    for got_entry in got_list:
        got_entry.offset = offset
        offset += env.arch.word_size
        o = env.got_section.addr + got_entry.offset
        env.full_text[o : o + env.arch.word_size] = got_entry.link_addr.to_bytes(
            env.arch.word_size, "little"
        )
```

### 5.4 .mpy文件生成

```python
# tools/mpy_ld.py
def build_mpy(env, entry_offset, fmpy, native_qstr_vals):
    # 写入跳转指令到文本段开始
    jump = env.arch.asm_jump(entry_offset)
    env.full_text[: len(jump)] = jump
    
    # MPY: 头部
    out.write_bytes(bytearray([
        ord("M"), MPY_VERSION, 
        env.arch.mpy_feature | MPY_SUB_VERSION, 
        MP_SMALL_INT_BITS
    ]))
    
    # MPY: qstr表
    out.write_uint(1 + len(native_qstr_vals))
    out.write_qstr(fmpy)  # 文件名
    for q in native_qstr_vals:
        out.write_qstr(q)
    
    # MPY: 机器码
    out.write_uint(len(env.full_text) << 3 | (MP_CODE_NATIVE_VIPER - MP_CODE_BYTECODE))
    out.write_bytes(env.full_text)
    
    # MPY: 重定位信息
    for base, addr, kind in env.mpy_relocs:
        # 编码重定位类型和地址
        if isinstance(kind, str) and kind.startswith(".text"):
            kind = 0
        elif kind == "mp_fun_table":
            kind = 8
        else:
            kind = 9 + kind
        out.write_reloc(base, addr // env.arch.word_size, kind, 1)
```

## 6. 运行时动态加载机制

### 6.1 内存分配策略

不同平台采用不同的可执行内存分配策略：

**ESP32平台**：
```c
// ports/esp32/main.c
void *esp_native_code_commit(void *buf, size_t len, void *reloc) {
    len = (len + 3) & ~3;  // 4字节对齐
    size_t len_node = sizeof(native_code_node_t) + len;
    
    // 分配可执行内存（IRAM）
    native_code_node_t *node = heap_caps_malloc(len_node, MALLOC_CAP_EXEC);
    
    if (node == NULL) {
        m_malloc_fail(len_node);
    }
    
    // 链接到native代码链表
    node->next = native_code_head;
    native_code_head = node;
    void *p = node->data;
    
    // 执行重定位
    if (reloc) {
        mp_native_relocate(reloc, buf, (uintptr_t)p);
    }
    
    // 复制代码到可执行内存
    memcpy(p, buf, len);
    return p;
}
```

**Unix平台**：
```c
// ports/unix/alloc.c
void mp_unix_alloc_exec(size_t min_size, void **ptr, size_t *size) {
    *size = (min_size + 0xfff) & (~0xfff);  // 页面对齐
    *ptr = mmap(NULL, *size, PROT_READ | PROT_WRITE | PROT_EXEC, 
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (*ptr == MAP_FAILED) {
        *ptr = NULL;
    }
}
```

### 6.2 重定位机制详解

重定位是Native Module技术的核心，它解决了机器码中符号地址的动态解析问题。

```c
// py/persistentcode.c
void mp_native_relocate(void *ri_in, uint8_t *text, uintptr_t reloc_text) {
    reloc_info_t *ri = ri_in;
    uint8_t op;
    uintptr_t *addr_to_adjust = NULL;
    
    while ((op = read_byte(ri->reader)) != 0xff) {
        if (op & 1) {
            // 确定需要调整的地址位置
            size_t addr = read_uint(ri->reader);
            if ((addr & 1) == 0) {
                // 指向text段
                addr_to_adjust = &((uintptr_t *)text)[addr >> 1];
            } else {
                // 指向rodata段
                addr_to_adjust = &((uintptr_t *)ri->rodata)[addr >> 1];
            }
        }
        op >>= 1;
        
        // 确定目标地址
        uintptr_t dest;
        size_t n = 1;
        if (op <= 5) {
            if (op & 1) {
                n = read_uint(ri->reader);  // 读取调整次数
            }
            op >>= 1;
            if (op == 0) {
                dest = reloc_text;           // text段
            } else if (op == 1) {
                dest = (uintptr_t)ri->rodata; // rodata段
            } else {
                dest = (uintptr_t)ri->bss;     // bss段
            }
        } else if (op == 6) {
            dest = (uintptr_t)ri->context->constants.qstr_table;  // qstr表
        } else if (op == 7) {
            dest = (uintptr_t)ri->context->constants.obj_table;   // 对象表
        } else if (op == 8) {
            dest = (uintptr_t)&mp_fun_table;  // 函数表本身
        } else {
            dest = ((uintptr_t *)&mp_fun_table)[op - 9];  // 函数表中的具体函数
        }
        
        // 执行重定位
        while (n--) {
            *addr_to_adjust++ += dest;
        }
    }
}
```

### 6.3 重定位类型编码

重定位信息使用紧凑的编码格式：

```
重定位指令格式：
┌─────────┬─────────┬─────────┐
│ 操作码  │ 地址    │ 目标    │
└─────────┴─────────┴─────────┘

操作码编码：
- 0-5: 内部段重定位（text/rodata/bss）
- 6: qstr_table重定位
- 7: obj_table重定位  
- 8: mp_fun_table重定位
- 9+: mp_fun_table中的具体函数
```

## 7. Python-C桥接机制

### 7.1 mp_fun_table函数表

`mp_fun_table`是Python和C代码之间的核心桥接机制：

```c
// py/nativeglue.h
typedef struct _mp_fun_table_t {
    mp_const_obj_t const_none;
    mp_const_obj_t const_false;
    mp_const_obj_t const_true;
    mp_uint_t (*native_from_obj)(mp_obj_t obj, mp_uint_t type);
    mp_obj_t (*native_to_obj)(mp_uint_t val, mp_uint_t type);
    mp_obj_dict_t *(*swap_globals)(mp_obj_dict_t * new_globals);
    mp_obj_t (*load_name)(qstr qst);
    mp_obj_t (*load_global)(qstr qst);
    mp_obj_t (*load_attr)(mp_obj_t base, qstr attr);
    mp_obj_t (*call_function_n_kw)(mp_obj_t fun_in, size_t n_args_kw, const mp_obj_t *args);
    // ... 更多函数指针
} mp_fun_table_t;

// 全局函数表实例
extern const mp_fun_table_t mp_fun_table;
```

### 7.2 动态运行时API

Native Module使用动态运行时API来访问MicroPython的功能：

```c
// py/dynruntime.h
#define m_malloc(n)                     (m_malloc_dyn((n)))
#define mp_printf(p, ...)               (mp_fun_table.printf_((p), __VA_ARGS__))
#define mp_obj_new_int(x)               (mp_fun_table.native_to_obj((x), MP_NATIVE_TYPE_INT))
#define mp_obj_get_int(o)               (mp_fun_table.native_from_obj((o), MP_NATIVE_TYPE_INT))

// 内存分配实现
static inline void *m_malloc_dyn(size_t n) {
    return mp_fun_table.realloc_(NULL, n, false);
}

static inline void m_free_dyn(void *ptr) {
    mp_fun_table.realloc_(ptr, 0, false);
}
```

### 7.3 模块初始化机制

```c
// py/dynruntime.h
#define MP_DYNRUNTIME_INIT_ENTRY \
    mp_obj_t old_globals = mp_fun_table.swap_globals(self->context->module.globals); \
    mp_raw_code_truncated_t rc; \
    rc.proto_fun_indicator[0] = MP_PROTO_FUN_INDICATOR_RAW_CODE_0; \
    rc.proto_fun_indicator[1] = MP_PROTO_FUN_INDICATOR_RAW_CODE_1; \
    rc.kind = MP_CODE_NATIVE_VIPER; \
    rc.is_generator = 0; \
    (void)rc;

#define MP_DYNRUNTIME_INIT_EXIT \
    mp_fun_table.swap_globals(old_globals); \
    return mp_const_none;
```

## 8. 架构特定的实现细节

### 8.1 ESP32 (Xtensa) 平台

**内存布局**：
```c
// ESP32使用IRAM作为可执行内存
#define IRAM1_END (0x40108000)
#define FLASH_START (0x40200000)

// 可执行内存分配
native_code_node_t *node = heap_caps_malloc(len_node, MALLOC_CAP_EXEC);
```

**Xtensa特定重定位**：
```c
// tools/mpy_ld.py
elif env.arch.name == "EM_XTENSA" and r_info_type == R_XTENSA_SLOT0_OP:
    # Xtensa特定的字面量槽操作
    sec = s.section
    if sec.name.startswith(".text"):
        return  # 已正确重定位
    assert sec.name.startswith(".literal"), sec.name
    lit_idx = "{}+0x{:x}".format(sec.filename, r_addend)
    lit_ptr = env.xt_literals[lit_idx]
    if isinstance(lit_ptr, str):
        addr = env.got_section.addr + env.got_entries[lit_ptr].offset
    else:
        addr = env.lit_section.addr + env.lit_entries[lit_ptr].offset
    reloc = addr - r_offset
```

### 8.2 ESP32-C3/C6 (RISC-V) 平台

**RISC-V特定重定位**：
```c
# tools/mpy_ld.py
elif env.arch.name == "EM_RISCV" and r_info_type in (
    R_RISCV_32, R_RISCV_GOT_HI20, R_RISCV_GOT32_PCREL
):
    # RISC-V GOT相对寻址
    got_entry = env.got_entries[s.name]
    addr = env.got_section.addr + got_entry.offset
    reloc = addr - r_offset + r_addend
```

## 9. 性能优化与限制

### 9.1 性能优势

1. **直接机器码执行**：避免字节码解释开销
2. **内存局部性**：代码和数据紧密布局
3. **编译器优化**：利用现代编译器的优化能力
4. **减少函数调用开销**：内联和直接调用

### 9.2 当前限制

```c
// 已知限制（来自文档）
// 1. 不支持data段，必须使用BSS段
// 2. 不支持静态BSS变量，必须使用全局BSS变量
// 3. 只能调用mp_fun_table中定义的函数
// 4. 架构特定的限制
// 5. 外部库依赖需要通过跳转表
// 6. 运行在SRAM中，受代码大小限制
```

### 9.3 内存管理考虑

```c
// 内存跟踪机制
#if MICROPY_PERSISTENT_CODE_TRACK_FUN_DATA
// 跟踪函数数据内存，防止被GC回收
track_root_pointer(fun_data);
#endif

#if MICROPY_PERSISTENT_CODE_TRACK_BSS_RODATA
// 跟踪BSS/rodata内存
track_root_pointer(data);
#endif
```

## 10. 调试与开发工具

### 10.1 mpy-tool.py分析工具

```bash
# 分析.mpy文件内容
./tools/mpy-tool.py -xd myfile.mpy

# 输出示例
simple_name: factorial
  raw data: 128 0x12345678...
  prelude: (0, 0, 0, 1, 0, 0, 0)
  args: ['x']
```

### 10.2 版本兼容性检查

```python
# 检查系统支持的.mpy版本
import sys
sys_mpy = sys.implementation._mpy
arch = [None, 'x86', 'x64', 'armv6', 'armv6m', 'armv7m', 
        'armv7em', 'armv7emsp', 'armv7emdp', 'xtensa', 
        'xtensawin', 'rv32imc'][sys_mpy >> 10]
print('mpy version:', sys_mpy & 0xff)
print('mpy sub-version:', sys_mpy >> 8 & 3)
print('mpy flags: -march=' + arch if arch else '')
```

## 11. 最佳实践和注意事项

### 11.1 开发建议

1. **选择合适的架构**：确保编译时指定的架构与目标设备匹配
2. **内存管理**：注意BSS数据的使用限制，避免使用data段
3. **错误处理**：使用适当的异常处理机制
4. **性能测试**：对比原生模块与纯Python实现的性能差异

### 11.2 常见问题解决

1. **未定义符号错误**：检查是否所有外部函数都在mp_fun_table中
2. **内存分配失败**：考虑SRAM大小限制
3. **架构不匹配**：确保编译和运行环境使用相同架构
4. **重定位失败**：检查符号引用是否正确

### 11.3 性能优化技巧

1. **减少函数调用**：内联简单函数
2. **使用BSS数据**：避免重复初始化
3. **合理使用常量**：将不变的数据放在rodata段
4. **内存对齐**：注意数据结构的对齐要求

## 12. 未来发展与扩展

### 12.1 可能的改进方向

1. **更多架构支持**：ARM64、MIPS等
2. **更丰富的API**：扩展mp_fun_table
3. **更好的调试支持**：符号表和调试信息
4. **性能优化**：JIT编译和代码缓存

### 12.2 生态系统发展

1. **标准库模块**：更多内置模块的native版本
2. **第三方库**：社区贡献的native模块
3. **工具链完善**：更好的开发和调试工具

## 结论

MicroPython的Native Module技术通过精心的架构设计，实现了Python和C代码的无缝集成。从`.mpy`文件格式的设计，到`mpy_ld.py`链接器的实现，再到运行时的动态加载和重定位机制，每一个环节都体现了对嵌入式系统特性的深度考虑。

这一技术的主要优势在于**无需重新刷固件**即可动态加载高性能的C代码，为嵌入式Python开发带来了显著的便利性。然而，它也带来了一些限制，如C代码编写的复杂性增加、外部库依赖需要通过跳转表处理、以及SRAM中的代码大小限制等。

随着MicroPython生态系统的不断发展，Native Module技术将继续演进，为更多应用场景提供支持，成为嵌入式Python开发的重要工具。开发者需要在便利性和性能之间找到平衡，合理使用这一技术来优化关键代码路径。

## 参考资料

- [MicroPython Native Module 官方文档](https://docs.micropython.org/en/latest/develop/natmod.html)
- [MicroPython .mpy 文件格式文档](https://docs.micropython.org/en/latest/reference/mpyfiles.html)
- [MicroPython 外部C模块文档](https://docs.micropython.org/en/latest/develop/cmodules.html)
- [MicroPython GitHub 仓库](https://github.com/micropython/micropython) 