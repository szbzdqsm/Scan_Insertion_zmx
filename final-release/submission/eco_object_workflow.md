# ECO对象与跨层操作流程（开发验证说明，不是官方任务或修复答案）

本方法在ScanInsertion 202605-bp2.2c660e19的独立层次小样本中验证；不是功能EQY证明。实际设计仍须使用当前任务、网表、原生查询和帮助确认对象，操作后通过原有阶段、结构、功能EQY、覆盖和审计检查。禁止从本文推断案例的正确修复连接。

## 1. 先绑定设计、类型和唯一完整对象

- `present_design`查询返回当前设计集合；读取它的`full_name`并与任务实际设计核对。不要假定存在`current_instance`命令，也不要假定子模块名能直接切为当前设计；失败的设计切换可能保持原上下文。
- 从当前顶层查已知完整相对路径，使用`get_obj_pins -exact $pin_path`或`get_obj_nets -exact $net_path`。路径相对实际当前设计，不能自行加上顶层模块名。
- `-hier`不是“允许完整层次路径”的通用开关。它逐层搜索匹配模式；本工具中已知完整路径加`-hier`可能匹配不到，叶名模式可能返回多个不同层次对象。可用于发现候选，不能将同叶名直接当作唯一目标。
- 顶层port使用`get_obj_ports -exact $port_name`，实例pin使用`get_obj_pins`，net使用`get_obj_nets`。`get_ports`是已提供映射帮助的别名；不要把顶层port当作实例pin，也不要假定声明DFT信号已经物理创建了端口/net。
- 返回值是原生collection句柄。用`sizeof_collection`计数；0或超过预期均停止这项操作并报告，不能任选首项。不要用`llength`数句柄，不要对句柄做字符串替换，不要用Tcl列表拼多个句柄。
- 用原生`get_property $obj full_name`、`object_class`和需要时的`direction`复核名称/类型/方向。未知属性或空返回不是成功；这里有效的是`object_class`，不是`object_type`。

以下仅为内联校验模板；变量必须从当前真实任务和查询中取得，不填写任何固定设计或对象答案：

```tcl
set current [present_design]
if {[sizeof_collection $current] != 1} {error "Current design absent or ambiguous"}
if {[get_property $current full_name] ne $expected_design} {error "Wrong current design"}
set target [get_obj_pins -exact $pin_path]
if {[sizeof_collection $target] != 1} {error "Pin query must select exactly one object"}
if {[get_property $target object_class] ne "pin"} {error "Wrong object class"}
if {[get_property $target full_name] ne $pin_path} {error "Wrong full object identity"}
```

对port或net采用各自的查询器、类型及完整名称校验。再次加载设计或改变上下文后重新查询，不能复用旧collection作为当前绑定。生产ECO阶段验证拒绝外部`source/eval/uplevel`等未知执行路径；直接内联检查，不通过外部Tcl文件绕过阶段保护。

## 2. 再区分同层与跨层连接

- `connect_net <net> <pins-or-ports>`以及`disconnect_net`用于文档允许的同层对象。`net`可以是已存在的名字或正确collection；不是所有参数都必须包查询。目标必须唯一、类型和层次正确。跨层`connect_net`不能替代跨层连接。
- `connect_pin -from <source-pin-or-port> -to <destination-pins-or-ports> -verbose`用于合法跨层pin/port连接，不能把net误当`-from`的pin/port。父设计应满足工具的唯一性限制，方向和现有驱动也必须合法；多驱动或错误方向仍由原生规则拒绝。
- 顶层输入port作为源时用其真实port集合，子模块pin作为目标时用其唯一完整pin集合。工具可能复用已有层次端口或创建新的穿层端口/net；以原生verbose消息与导出连接核对，不猜生成名字。
- 如果任务确实需要新端口，先依据真实需求使用`add_port ... -direction ...`创建并重新查询。创建端口不等于它已接好，更不等于它可替代任务要求的功能态路径。

## 3. 保持消费者原连接，逐步证实实际效果

针对任务允许的驱动侧MUX改接，可采用以下操作次序，但所有端点和测试逻辑必须另由任务/原连接证明：

1. 唯一定位原输出driver、原net、消费者pin和所需模式/测试源。原生查询`get_obj_nets -of $driver`、`get_obj_nets -of $consumer`确认原关系。
2. 保留消费者原net，只断开已核实的原driver；在同层创建独立net承接原driver与MUX的功能输入。
3. 在合适、唯一的设计层次创建MUX，依据任务和真实Liberty端口语义连接功能输入、测试输入和选择端。不同层用合法的`connect_pin`，同层用`connect_net`。
4. MUX输出继续驱动消费者原net；不能同时保留旧driver驱动该net，也不能留下A0/A1/S悬空。
5. 每项实际命令检查原生返回及错误消息。Tcl `catch`返回0只表示没抛Tcl异常：原生命令可能输出ERROR并返回数值0，此时仍是失败，不能继续假定修改成立。
6. 用原生查询和真实扫描前导出核对MUX全部端点、源驱动、跨层连通、原消费者连接及多驱动情况。`get_obj_connected -leaf`用于net，不应把对pin/port被忽略的`-leaf`当作有效叶对象证据。

单项添加net/instance成功、命令回显、FF数量相同或DRC数量下降，均不能证明整体ECO修复完成。测试态可控不要求某一种固定端口接法；功能态必须保留任务要求的原逻辑。保留ECO后/插链前导出、同轮绑定及原始到修复网表的必要功能EQY；失败、UNKNOWN或缺证明不得进入成功交付。
# 有限内部对象引用接口（由Agent编译，不是ScanInsertion原生命令）

正式返回仍为原有 dofile/dofile_edits。以下仅为独立候选支持的顶层、一对一内部操作，不增加正式交付字段。

- `eco_ref local_alias {get_obj_pins -exact FULL_PATH}`：在执行到此处的真实设计中只读查询，程序核实实际设计、数量、object_class和full_name后发出opaque引用；也可用原生get_obj_ports/get_obj_nets。模型不能填写或覆盖类型/数量。
- `eco_link connect_pin $source_alias $target_alias`：明确选择已查询的源pin/port和目标pin/port；允许原生支持的跨层连接，net不能作为目标。
- `eco_link connect_net $net_alias $pin_alias`：明确选择net和pin/port；实际full_name须证实属于同层，程序不会把跨层连接改成此命令。

每次连接、对象创建/删除、加载或设计切换都会使旧引用失效。连接前应重新执行eco_ref取得当前状态引用；引用不会跨进程/轮次复用。只有1个明确对象可发引用，空、歧义、伪造、陈旧、缺属性或无法解析均停止并反馈，不任选对象，也不net转sink。新增对象只能在真实创建后查询；查询本身不执行ECO。原生观察会提供引用、设计、epoch、实际类型/完整名及证据位置，供后续纠正查看；历史引用仅是诊断，不是可继续使用的当前句柄。

原有connect_pin/connect_net仍由连接前受控解析处理：重查纯getter/可追溯变量selector，核实集合及类型/层次后程序生成调用。任意动态Tcl、无法追溯的opaque句柄和多目标操作超出此有限接口时记unresolved，不能回退执行未检查命令。多步创建和接线可以分步执行，每一步需刷新查询。

引用或调用合法不证明拓扑正确、消费者连接保持、功能等价、DRC清零或任务完成。原有结构/阶段/必要EQY等检查继续执行。需要改变拓扑时必须明确提出实际操作，不隐藏在参数转换中。


## 有界保功能 mode_mux 计划（内部 eco_link，不是官方新增命令）

当目标已经有功能驱动时，不要直接接第二个源。模型须明确选择真实 driver、consumer、test source、mode 的 eco_ref 引用，再提出：

```tcl
eco_link mode_mux $driver_ref $consumer_ref $test_ref $mode_ref LIBERTY_MUX_CELL NEW_INSTANCE NEW_FUNCTIONAL_NET
```

所有四个引用必须在当前设计及同一 ECO epoch 刚签发；任何创建/连接后重新查询，不使用旧 token。新实例/功能网必须不存在，和所选 driver 在同层。mode_mux是这组内部对象的唯一创建入口；不要另行add_inst/add_net创建同一MUX或功能网。对于同一脚本中可静态确认、类型一致且尚未被使用的旧准备声明，编译器会保留来源并推迟其创建，由计划整组预检后唯一执行；不是运行后忽略already-exists。部分准备声明同样统一归属。已实际存在的外部对象不自动采用，即使同名同类型；本有限接口没有已有MUX采用模式。重复计划在执行前拒绝，不能静默复用或重接。设计重载后要从真实新状态重新eco_ref，不能借用旧引用。程序查目标原网的完整 driver 集合，要求唯一且等于显式选择的原 driver；不从多个驱动或多个 sink 中选一个。MUX 引脚由本轮真实 Liberty 的完整功能表与任务功能模式值推导；不信任模型声称的端口类型或默认引脚名。模式引用必须等于任务给出的模式端口。歧义、未知和不支持的模式均拒绝，不回退原命令。

生成步骤是：只把已确认的原输出驱动移到新功能网→MUX功能输入；显式测试源接测试输入，模式源接选择；MUX输出驱动原消费者网，消费者pin/net不改。选择的测试源和有效电平仍须依据任务、原生配置/库和连接提出；不能随意固定功能输入或短接时钟。可先显式创建合法测试源，再刷新四引用。

操作后保留实际驱动观察及原生操作结果。任何失败不作为成功；需要当次扫描前导出、严格结构检查和完整原始到修复网表EQY，之后才能插链。这个接口不证明任意测试源正确，也不保证自主修复成功。

## 新建虚拟常量作为明确测试源

### mode_mux创建位置与设计状态

mode_mux的裸资源名表示所选driver/consumer的唯一共同父实例下的本地名称；带层级的资源名是显式位置，必须与原生查询核验的父实例一致。程序不会因为当前设计是顶层，就把新对象放在顶层。父实例的真实类型、完整路径、模块引用及该模块在当前设计中的所有实例用途均须可核实；复用模块定义涉及多个实例时，此有限计划拒绝，不自动展开或uniquify。不同层级端点需要明确的端口/结构计划，不能只截短路径或移动功能驱动。

创建前整组检查MUX/net不存在；创建后先回查实际完整位置、类型和所有Liberty角色引脚，签发内部当前状态引用，之后才改接功能驱动。失败反馈保存真实父层级、模块用途、实际完成的创建步骤和原生对象；部分创建不是回滚，也不能隐式采用为全新对象。每轮正常工具进程仍重新加载原始设计，CURRENT只表示待编辑脚本；同进程继续操作必须重新查询，设计加载或变化后旧引用失效。

`add_inst NEW_SOURCE -logic 1`是虚拟常量，不是普通Liberty单元。不得猜输出名。优先使用现有接口明确选择该实例的唯一输出：

```tcl
add_inst NEW_SOURCE -logic 1
eco_ref source_ref {get_obj_pins -of {NEW_SOURCE} -filter {direction == out}}
```

程序在真实创建之后，精确查询实例、核对设计/真实cell角色，查询完整pin与方向，再要求输出集合唯一并签发原有引用。端点全名来自原生工具，字面特殊字符保留为数据。若该新常量被明确选为mode_mux测试源（或显式连接源），编译器也将针对同一已声明实例的pin选择降低成此唯一输出意图；原表达式及操作来源留存，不运行一次错误getter后再找别的对象。没有该意图、不是新常量、范围不明或动态表达式不能确认时，不做这种降低。

零/多候选、错角色、设计不符和陈旧引用拒绝，不任选输出、不net转pin。连接仍用原有eco_link，在原生操作后回读实际关系。对象发现并不证明拓扑或功能修复：功能态、消费者连接、扫描前阶段和完整EQY继续严格核验。
