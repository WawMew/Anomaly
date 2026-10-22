#include "reflection.hpp"

#include <Windows.h>

#include <cstring>
#include <string>

namespace anomaly::plugins::pukaland {
namespace {

// —— 定位用的特征码与解析方式 ——
// 与 plugins/common/combat、plugins/CloneEnter 使用的是同一组已验证特征：
// GObjects 访问器（`mov rax,[rip+d]`），以及 GWorld 的全局指针。
constexpr std::string_view kGObjectsPattern =
    "48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8B 04 D1 C3 33 C0 48 8B 00 C3";
constexpr std::string_view kGWorldPattern =
    "48 8B 1D ?? ?? ?? ?? 48 85 DB 74 ?? 41 B0 01";
constexpr std::ptrdiff_t kGObjectsAddend = -16;
constexpr std::uint32_t kRipDisplacementOffset = 3;
constexpr std::uint32_t kRipInstructionSize = 7;

// —— FUObjectArray 分块布局 ——
constexpr std::ptrdiff_t kRegistryItemsOffset = 16;
constexpr std::ptrdiff_t kRegistryCountOffset = 36;
constexpr std::ptrdiff_t kRegistryChunksOffset = 44;
constexpr std::uint32_t kObjectsPerChunk = 65536;
constexpr std::uint32_t kObjectItemStride = 24;

// —— 反射布局 ——
constexpr std::ptrdiff_t kObjectClassOffset = 16;
constexpr std::ptrdiff_t kObjectNameOffset = 24;
constexpr std::ptrdiff_t kStructChildrenOffset = 72;
// UStruct::ChildProperties（FField 链）：FField::Next @+0x18，Name @+0x20。
constexpr std::ptrdiff_t kStructChildPropertiesOffset = 80;
constexpr std::ptrdiff_t kFfieldNextOffset = 24;
// FField::NamePrivate（FName ComparisonIndex）与 FProperty::Offset_Internal。
constexpr std::ptrdiff_t kFieldNameOffset = 32;
constexpr std::ptrdiff_t kPropertyOffsetInternal = 68;
constexpr std::ptrdiff_t kStructSuperOffset = 64;
constexpr std::ptrdiff_t kFieldNextOffset = 40;
// UFunction 的形参区紧随 UStruct：NumParms(0xB4)、ParmsSize(0xB6)、
// ReturnValueOffset(0xB8)。ProcessEvent 用它决定返回值的落点，0xFFFF 表示没有返回值。
constexpr std::ptrdiff_t kFunctionParmsSizeOffset = 182;
constexpr std::ptrdiff_t kFunctionReturnValueOffset = 184;
constexpr std::uint16_t kNoReturnValue = 0xFFFF;

// UObject::ProcessEvent 是 vtable 槽位 76（字节偏移 0x260）。
constexpr std::size_t kProcessEventVtableIndex = 0x4C;

// UHTPukalandComponent 的 owner 字段。证据是 UHTPukalandComponent::GetTicketBalance
// （HTGame_dump.exe.i64 @ 0x146FFEA80 → sub_148494E90）：实现先取 *(this+0xA8)，
// 用 AHTPlayerState 的类链校验它确实是玩家状态，然后才去该 PlayerState 的物品容器里
// 数 `PukalandTicket`（FName 由 UHTPukalandDataAsset 构造写死，dump @ 0x148483A20）。
constexpr std::ptrdiff_t kComponentOwnerOffset = 0xA8;

// —— 本地玩家链路：World → GameInstance → LocalPlayers[0] → Controller → PlayerState ——
constexpr std::ptrdiff_t kWorldGameInstanceOffset = 560;
constexpr std::ptrdiff_t kGameInstancePlayersOffset = 56;
constexpr std::ptrdiff_t kLocalPlayerControllerOffset = 48;
constexpr std::ptrdiff_t kControllerPlayerStateOffset = 720;

// 一次调用最多检查的注册表条目数。整表一次扫完会越过宿主的 2 ms 慢回调阈值，
// 所以把遍历切段，由调用方逐帧推进。
constexpr std::uint32_t kRegistryBatch = 512;
// 每次定位调用推进的片数：512 * 16 = 8192 个对象/tick，约 0.5 ms，
// 41 万对象的注册表约 51 个 tick 扫完。
constexpr std::uint32_t kLocateSlicesPerCall = 64;
// AActor 组件数组在 PlayerState 上的偏移（本构建实测：PukalandComponent 在 +0x248 指向的
// 数组第 26 槽）。只用作快速路径，取不到就退回注册表扫描。
constexpr std::ptrdiff_t kPlayerStateComponentsOffset = 0x248;
constexpr std::uint32_t kComponentArrayCap = 1024;

constexpr std::string_view kComponentClass = "HTPukalandComponent";
constexpr std::string_view kTicketFunction = "GetTicketBalance";
constexpr std::string_view kClassObjectName = "Class";
constexpr std::string_view kClassDefaultPrefix = "Default__";

// 形参缓冲上限。GetTicketBalance 只有一个 int32 返回值，这里的上限只是把
// “读到的 UFunction 是不是我们要的那个”挡在外面。
constexpr std::uint16_t kMaximumParmsSize = 64;
constexpr std::size_t kMaximumClassDepth = 64;
constexpr std::size_t kMaximumNameBytes = 1024;

template <typename T>
bool Read(const std::uintptr_t address, T& value) noexcept {
    if (address == 0) return false;
    __try {
        std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(T));
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

std::uintptr_t ReadPointer(const std::uintptr_t address) noexcept {
    std::uintptr_t value{};
    return Read(address, value) ? value : 0;
}

bool SignatureReady(const AnomalySignatureServiceV1* signature) noexcept {
    return signature != nullptr &&
        signature->struct_size >= offsetof(AnomalySignatureServiceV1, resolve) +
            sizeof(AnomalySignatureServiceV1::resolve) &&
        signature->resolve != nullptr;
}

bool NamesReady(const AnomalyUe5NamesServiceV1* names) noexcept {
    return names != nullptr &&
        names->struct_size >= offsetof(AnomalyUe5NamesServiceV1, resolve_utf8) +
            sizeof(AnomalyUe5NamesServiceV1::resolve_utf8) &&
        names->resolve_utf8 != nullptr;
}

bool ResolveRipRelative(
    const AnomalySignatureServiceV1* signature,
    const std::string_view pattern,
    const std::ptrdiff_t addend,
    std::uintptr_t& address) noexcept {
    address = 0;
    if (!SignatureReady(signature)) return false;
    std::uintptr_t instruction{};
    if (signature->resolve(signature->user,
                           anomaly::sdk::StringView("HTGame.exe"),
                           anomaly::sdk::StringView(".text"),
                           anomaly::sdk::StringView(pattern), &instruction)
                .code != ANOMALY_STATUS_V1_OK ||
        instruction == 0) {
        return false;
    }
    std::int32_t displacement{};
    if (!Read(instruction + kRipDisplacementOffset, displacement)) return false;
    const auto resolved = static_cast<std::intptr_t>(instruction) +
        static_cast<std::intptr_t>(kRipInstructionSize) + displacement;
    if (resolved <= 0) return false;
    if (addend < 0) {
        const auto magnitude = static_cast<std::uintptr_t>(-(addend + 1)) + 1U;
        if (static_cast<std::uintptr_t>(resolved) <= magnitude) return false;
        address = static_cast<std::uintptr_t>(resolved) - magnitude;
    } else {
        address = static_cast<std::uintptr_t>(resolved) +
            static_cast<std::uintptr_t>(addend);
    }
    return address != 0;
}

bool InvokeProcessEvent(
    const std::uintptr_t object,
    const std::uintptr_t function,
    void* parameters) noexcept {
    if (object == 0 || function == 0) return false;
    const std::uintptr_t vtable = ReadPointer(object);
    if (vtable == 0) return false;
    const std::uintptr_t process_event =
        ReadPointer(vtable + kProcessEventVtableIndex * sizeof(void*));
    if (process_event == 0) return false;
    using ProcessEvent = void(__fastcall*)(void*, void*, void*);
    __try {
        reinterpret_cast<ProcessEvent>(process_event)(
            reinterpret_cast<void*>(object), reinterpret_cast<void*>(function),
            parameters);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

struct RegistryView final {
    std::uintptr_t items{};
    std::uint32_t count{};
    std::uint32_t chunks{};
};

[[nodiscard]] bool OpenRegistry(
    const std::uintptr_t registry, RegistryView& view) noexcept {
    if (registry == 0) return false;
    std::int32_t count{};
    std::int32_t chunks{};
    if (!Read(registry + kRegistryItemsOffset, view.items) || view.items == 0) return false;
    if (!Read(registry + kRegistryCountOffset, count) || count <= 0) return false;
    if (!Read(registry + kRegistryChunksOffset, chunks) || chunks <= 0) return false;
    view.count = static_cast<std::uint32_t>(count);
    view.chunks = static_cast<std::uint32_t>(chunks);
    return true;
}

// 按块增量遍历注册表。块指针只在跨块时读一次。
// start 用于把一个完整遍历切成多段、跨帧推进。
class ObjectCursor final {
public:
    ObjectCursor(const RegistryView& view, const std::uint32_t start) noexcept
        : view_(view), index_(start), limit_(view.count) {}

    [[nodiscard]] bool Next(std::uintptr_t& object) noexcept {
        while (index_ < limit_) {
            const std::uint32_t position = index_++;
            const std::uint32_t chunk_index = position / kObjectsPerChunk;
            if (chunk_index != cached_chunk_index_) {
                cached_chunk_index_ = chunk_index;
                cached_chunk_ = chunk_index < view_.chunks
                    ? ReadPointer(view_.items + chunk_index * sizeof(void*))
                    : 0;
            }
            if (cached_chunk_ == 0) continue;
            const std::uint32_t within = position % kObjectsPerChunk;
            const std::uintptr_t item = ReadPointer(
                cached_chunk_ + static_cast<std::uintptr_t>(within) * kObjectItemStride);
            if (item == 0) continue;
            object = item;
            return true;
        }
        return false;
    }

private:
    const RegistryView& view_;
    std::uint32_t index_{};
    std::uint32_t limit_{};
    std::uint32_t cached_chunk_index_{0xFFFFFFFFu};
    std::uintptr_t cached_chunk_{};
};

}  // namespace

void ReflectionBridge::Attach(
    const AnomalySignatureServiceV1* signature,
    const AnomalyUe5NamesServiceV1* names) noexcept {
    signature_ = signature;
    names_ = names;
}

void ReflectionBridge::Reset() noexcept {
    g_world_ = 0;
    registry_ = 0;
    player_state_ = 0;
    component_ = 0;
    function_ = 0;
    class_match_.clear();
}

bool ReflectionBridge::EnsureRegistry() noexcept {
    if (registry_ != 0) return true;
    return ResolveRipRelative(signature_, kGObjectsPattern, kGObjectsAddend, registry_);
}

std::uintptr_t ReflectionBridge::world() noexcept {
    if (!EnsureRegistry()) return 0;
    if (g_world_ == 0 && !ResolveRipRelative(signature_, kGWorldPattern, 0, g_world_)) {
        return 0;
    }
    return ReadPointer(g_world_);
}

std::uintptr_t ReflectionBridge::LocalPlayerState() noexcept {
    if (!EnsureRegistry()) return 0;
    if (g_world_ == 0 &&
        !ResolveRipRelative(signature_, kGWorldPattern, 0, g_world_)) {
        return 0;
    }
    const std::uintptr_t world = ReadPointer(g_world_);
    if (world == 0) return 0;
    const std::uintptr_t game_instance = ReadPointer(world + kWorldGameInstanceOffset);
    if (game_instance == 0) return 0;
    std::int32_t player_count{};
    if (!Read(game_instance + kGameInstancePlayersOffset + 8, player_count) ||
        player_count < 1) {
        return 0;
    }
    const std::uintptr_t players = ReadPointer(game_instance + kGameInstancePlayersOffset);
    if (players == 0) return 0;
    // LocalPlayers 是 TArray<ULocalPlayer*>：[0] 是本地玩家对象本身。
    // +48 是 LocalPlayer → PlayerController，+720 才是 Controller → PlayerState。
    const std::uintptr_t local_player = ReadPointer(players);
    if (local_player == 0) return 0;
    const std::uintptr_t controller =
        ReadPointer(local_player + kLocalPlayerControllerOffset);
    if (controller == 0) return 0;
    return ReadPointer(controller + kControllerPlayerStateOffset);
}

std::string ReflectionBridge::ObjectName(const std::uintptr_t object) const {
    std::uint32_t name_id{};
    if (!Read(object + kObjectNameOffset, name_id) || name_id == 0) return {};
    return ObjectNameById(name_id);
}

std::string ReflectionBridge::ObjectNameById(const std::uint32_t name_id) const {
    if (!NamesReady(names_)) return {};
    std::size_t size{};
    if (names_->resolve_utf8(names_->user, name_id, nullptr, &size).code !=
            ANOMALY_STATUS_V1_OK ||
        size <= 1 || size > kMaximumNameBytes) {
        return {};
    }
    std::string value(size, '\0');
    if (names_->resolve_utf8(names_->user, name_id, value.data(), &size).code !=
            ANOMALY_STATUS_V1_OK ||
        size <= 1 || size > value.size()) {
        return {};
    }
    value.resize(size - 1U);
    return value;
}

std::uintptr_t ReflectionBridge::FindObjectByClassName(const std::string_view class_name) {
    RegistryView view{};
    if (!OpenRegistry(registry_, view)) return 0;
    class_match_.clear();  // 缓存按类指针记，换目标类必须清空
    ObjectCursor cursor(view, 0);
    std::uintptr_t object{};
    while (cursor.Next(object)) {
        const std::uintptr_t klass = ReadPointer(object + kObjectClassOffset);
        if (klass == 0) continue;
        bool hit = false;
        const auto cached = class_match_.find(klass);
        if (cached != class_match_.end()) {
            hit = cached->second;
        } else {
            std::uintptr_t current = klass;
            for (std::size_t depth = 0; current != 0 && depth < kMaximumClassDepth; ++depth) {
                if (ObjectName(current) == class_name) {
                    hit = true;
                    break;
                }
                const std::uintptr_t super = ReadPointer(current + kStructSuperOffset);
                if (super == 0 || super == current) break;
                current = super;
            }
            class_match_.emplace(klass, hit);
        }
        if (!hit) continue;
        const std::string name = ObjectName(object);
        if (name.starts_with(kClassDefaultPrefix)) continue;
        return object;
    }
    return 0;
}

bool ReflectionBridge::MatchesComponentClass(std::uintptr_t owner_class) {    if (owner_class == 0) return false;
    const auto cached = class_match_.find(owner_class);
    if (cached != class_match_.end()) return cached->second;
    bool matched = false;
    std::uintptr_t current = owner_class;
    for (std::size_t depth = 0; current != 0 && depth < kMaximumClassDepth; ++depth) {
        const std::string name = ObjectName(current);
        if (sample_class_.empty() && !name.empty()) sample_class_ = name;
        if (name == kComponentClass) {
            matched = true;
            break;
        }
        const std::uintptr_t super = ReadPointer(current + kStructSuperOffset);
        if (super == 0 || super == current) break;
        current = super;
    }
    class_match_.emplace(owner_class, matched);
    return matched;
}

// 直接探一次名字服务：拿一个已知对象的 NamePrivate 去 resolve_utf8，
// 把原始返回码记下来。用来区分「服务没拿到」和「服务调不通」。
void ReflectionBridge::ProbeNames() noexcept {
    name_probe_code_ = 0;
    if (!NamesReady(names_)) {
        name_probe_code_ = 0xFFFFFFFFu;
        return;
    }
    RegistryView view{};
    if (!OpenRegistry(registry_, view)) return;
    ObjectCursor cursor(view, 0);
    std::uintptr_t object{};
    if (!cursor.Next(object)) return;
    std::uint32_t name_id{};
    if (!Read(object + kObjectNameOffset, name_id) || name_id == 0) return;
    std::size_t size{};
    name_probe_code_ = names_->resolve_utf8(names_->user, name_id, nullptr, &size).code;
    if (name_probe_code_ == 0 && size > 1 && size <= 256) {
        std::string value(size, '\0');
        if (names_->resolve_utf8(names_->user, name_id, value.data(), &size).code == 0 &&
            size > 1) {
            value.resize(size - 1U);
            sample_class_ = std::move(value);
        }
    }
}

ReflectionBridge::LocateStep ReflectionBridge::StepLocate(
    const std::uintptr_t player_state, std::uintptr_t& found) {
    found = 0;
    RegistryView view{};
    if (!OpenRegistry(registry_, view)) return LocateStep::kMissing;
    if (!scan_active_) {
        // 新一轮：类对象会随关卡/BP 重建，地址可能被复用，旧判定不能留到下一轮。
        scan_active_ = true;
        scan_cursor_ = 0;
        class_match_.clear();
    }
    const std::uint32_t end = std::min(scan_cursor_ + kRegistryBatch, view.count);
    ObjectCursor cursor(view, scan_cursor_);
    std::uintptr_t object{};
    while (cursor.Next(object)) {
        const std::uintptr_t klass = ReadPointer(object + kObjectClassOffset);
        if (!MatchesComponentClass(klass)) continue;
        // 先过类链再看 owner：类链判断不越界，能挡掉绝大多数对象。
        if (ReadPointer(object + kComponentOwnerOffset) != player_state) continue;
        const std::string name = ObjectName(object);
        if (name.starts_with(kClassDefaultPrefix)) continue;
        scan_active_ = false;
        found = object;
        return LocateStep::kFound;
    }
    scan_cursor_ = end;
    if (scan_cursor_ >= view.count) {
        scan_active_ = false;
        return LocateStep::kMissing;
    }
    return LocateStep::kScanning;
}

std::uintptr_t ReflectionBridge::LocatePukalandComponent() {
    const std::uintptr_t player_state = LocalPlayerState();
    if (player_state != 0) {
        if (player_state != player_state_) {
            player_state_ = player_state;
            component_ = 0;
            function_ = 0;
            scan_active_ = false;
        }
        if (component_ != 0 &&
            (!MatchesComponentClass(ReadPointer(component_ + kObjectClassOffset)) ||
             ReadPointer(component_ + kComponentOwnerOffset) != player_state)) {
            component_ = 0;
            function_ = 0;
        }
        if (component_ != 0) return component_;
        // 直接走 Actor 的组件数组：几十个元素，逐个比对类名，命中即得，不扫全表。
        const std::uintptr_t components =
            ReadPointer(player_state + kPlayerStateComponentsOffset);
        if (components != 0) {
            for (std::uint32_t index = 0; index < kComponentArrayCap; ++index) {
                const std::uintptr_t candidate = ReadPointer(components + index * 8U);
                if (candidate == 0) continue;
                const std::uintptr_t klass = ReadPointer(candidate + kObjectClassOffset);
                if (klass == 0) continue;
                if (!MatchesComponentClass(klass)) continue;
                if (ReadPointer(candidate + kComponentOwnerOffset) != player_state) continue;
                component_ = candidate;
                return component_;
            }
        }
        // 组件表不可用时才退回全表扫描。
        for (std::uint32_t slice = 0; slice < kLocateSlicesPerCall; ++slice) {
            const LocateStep step = StepLocate(player_state, component_);
            if (step == LocateStep::kFound) return component_;
            if (step == LocateStep::kMissing) return 0;
        }
        return 0;
    }
    // 拿不到本地 PlayerState 时的退路：只按类链找唯一实例，并要求它的 owner 是
    // 某个 PlayerState 类。噗卡组件正常情况下在整局里只有一份。
    if (fallback_component_ != 0) return fallback_component_;
    if (fallback_active_) return 0;
    RegistryView view{};
    if (!OpenRegistry(registry_, view)) return 0;
    class_match_.clear();
    ObjectCursor cursor(view, 0);
    std::uintptr_t object{};
    while (cursor.Next(object)) {
        const std::uintptr_t klass = ReadPointer(object + kObjectClassOffset);
        if (!MatchesComponentClass(klass)) continue;
        const std::uintptr_t owner = ReadPointer(object + kComponentOwnerOffset);
        if (owner == 0) continue;
        const std::uintptr_t owner_class = ReadPointer(owner + kObjectClassOffset);
        if (ObjectName(owner_class).find("PlayerState") == std::string::npos) continue;
        const std::string name = ObjectName(object);
        if (name.starts_with(kClassDefaultPrefix)) continue;
        fallback_component_ = object;
        player_state_ = owner;
        return object;
    }
    fallback_active_ = true;
    return 0;
}

bool ReflectionBridge::ReadBytes(
    const std::uintptr_t address, void* destination, const std::size_t size) const noexcept {
    if (address == 0 || destination == nullptr || size == 0) return false;
    __try {
        std::memcpy(destination, reinterpret_cast<const void*>(address), size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool ReflectionBridge::Invoke(
    const std::uintptr_t object, const std::uintptr_t function,
    void* parms) const noexcept {
    return InvokeProcessEvent(object, function, parms);
}

std::uint32_t ReflectionBridge::ResolveNameId(const std::string_view name) const {    if (!NamesReady(names_) || name.empty()) return 0;
    std::uint32_t id = 0;
    if (names_->find_utf8 != nullptr &&
        names_->struct_size >= offsetof(AnomalyUe5NamesServiceV1, find_utf8) +
                sizeof(AnomalyUe5NamesServiceV1::find_utf8)) {
        if (names_->find_utf8(
                names_->user, anomaly::sdk::StringView(name), &id)
                .code == ANOMALY_STATUS_V1_OK) {
            return id;
        }
    }
    return 0;
}

std::uintptr_t ReflectionBridge::FindFunctionInChain(
    std::uintptr_t owner_class, const std::string_view name) const {
    for (std::size_t depth = 0;
         owner_class != 0 && depth < kMaximumClassDepth; ++depth) {
        std::uintptr_t field = ReadPointer(owner_class + kStructChildrenOffset);
        for (std::uint32_t count = 0; field != 0 && count < 8192; ++count) {
            const std::uintptr_t next = ReadPointer(field + kFieldNextOffset);
            // UFunction 的元类名是 "Function"（不是 "Class"），这里按名字匹配即可。
            if (ObjectName(field) == name) {
                return field;
            }
            if (next == field) break;
            field = next;
        }
        const std::uintptr_t super = ReadPointer(owner_class + kStructSuperOffset);
        if (super == 0 || super == owner_class) break;
        owner_class = super;
    }
    return 0;
}

bool ReflectionBridge::FindPropertyOffset(
    std::uintptr_t owner_class, const std::string_view name,
    std::uint32_t& offset) const {
    offset = 0;
    for (std::size_t depth = 0;
         owner_class != 0 && depth < kMaximumClassDepth; ++depth) {
        // 类属性链走 UStruct::ChildProperties（FField 链），字段便宜且与 ueapi 一致。
        std::uintptr_t node = ReadPointer(owner_class + kStructChildPropertiesOffset);
        for (std::uint32_t count = 0; node != 0 && count < 8192; ++count) {
            const std::uintptr_t next = ReadPointer(node + kFfieldNextOffset);
            std::uint32_t name_id{};
            if (Read(node + kFieldNameOffset, name_id) && name_id != 0 &&
                ObjectNameById(name_id) == name) {
                std::int32_t internal{};
                if (Read(node + kPropertyOffsetInternal, internal) && internal >= 0) {
                    offset = static_cast<std::uint32_t>(internal);
                    return true;
                }
            }
            if (next == node) break;
            node = next;
        }
        const std::uintptr_t super = ReadPointer(owner_class + kStructSuperOffset);
        if (super == 0 || super == owner_class) break;
        owner_class = super;
    }
    return false;
}

std::uintptr_t ReflectionBridge::LocateFunction(std::uintptr_t owner_class) const {
    for (std::size_t depth = 0;
         owner_class != 0 && depth < kMaximumClassDepth; ++depth) {
        std::uintptr_t field = ReadPointer(owner_class + kStructChildrenOffset);
        for (std::uint32_t count = 0; field != 0 && count < 4096; ++count) {
            const std::uintptr_t next = ReadPointer(field + kFieldNextOffset);
            const std::uintptr_t field_class = ReadPointer(field + kObjectClassOffset);
            if (ObjectName(field_class) == kClassObjectName &&
                ObjectName(field) == kTicketFunction) {
                return field;
            }
            if (next == field) break;
            field = next;
        }
        const std::uintptr_t super = ReadPointer(owner_class + kStructSuperOffset);
        if (super == 0 || super == owner_class) break;
        owner_class = super;
    }
    return 0;
}

BridgeState ReflectionBridge::ReadTicketBalance(std::int32_t& balance) {
    if (!SignatureReady(signature_)) return BridgeState::kNoSignatureService;
    if (!EnsureRegistry()) return BridgeState::kNoRegistry;
    if (!NamesReady(names_)) return BridgeState::kNoSignatureService;

    const std::uintptr_t player_state = LocalPlayerState();
    if (player_state == 0) {
        // 世界还没就绪（读条 / 换图）：保留上一次的定位，下轮再试。
        return BridgeState::kNoPlayerState;
    }
    if (player_state != player_state_) {
        player_state_ = player_state;
        component_ = 0;
        function_ = 0;
    }
    if (component_ != 0 &&
        (!MatchesComponentClass(ReadPointer(component_ + kObjectClassOffset)) ||
         ReadPointer(component_ + kComponentOwnerOffset) != player_state)) {
        // 换图后组件可能已经被销毁：拿旧指针去调 UFunction 会把游戏打崩，
        // 所以每次使用前都按“类 + owner”复核一遍。
        component_ = 0;
        function_ = 0;
    }
    if (component_ == 0) {
        const LocateStep step = StepLocate(player_state, component_);
        if (step == LocateStep::kScanning) return BridgeState::kSearching;
        function_ = 0;
        if (step == LocateStep::kMissing) return BridgeState::kNoComponent;
    }

    if (function_ == 0) {
        function_ = LocateFunction(ReadPointer(component_ + kObjectClassOffset));
    }
    if (function_ == 0) return BridgeState::kNoFunction;

    std::uint16_t parms_size{};
    std::uint16_t return_offset{};
    if (!Read(function_ + kFunctionParmsSizeOffset, parms_size) ||
        !Read(function_ + kFunctionReturnValueOffset, return_offset) ||
        parms_size == 0 || parms_size > kMaximumParmsSize ||
        return_offset == kNoReturnValue ||
        static_cast<std::uint32_t>(return_offset) + sizeof(std::int32_t) > parms_size) {
        return BridgeState::kBadShape;
    }

    alignas(16) unsigned char parameters[kMaximumParmsSize]{};
    if (!InvokeProcessEvent(component_, function_, parameters)) {
        return BridgeState::kInvokeFailed;
    }
    std::int32_t value{};
    std::memcpy(&value, parameters + return_offset, sizeof(value));
    // GetTicketBalance 的实现把结果夹在 [0, 0x7FFFFFFF]：负值只可能来自读错。
    if (value < 0) return BridgeState::kInvokeFailed;
    balance = value;
    return BridgeState::kOk;
}

}  // namespace anomaly::plugins::pukaland
