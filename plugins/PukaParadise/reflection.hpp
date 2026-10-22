#pragma once

#include "anomaly/sdk/cpp.hpp"

#include <cstdint>
#include <string>
#include <unordered_map>

namespace anomaly::plugins::pukaland {

// 反射读取桥：解析 UObject 注册表 → 定位本地玩家的 HTPukalandComponent →
// 取该组件类上的 GetTicketBalance → 用对象自己的 vtable ProcessEvent 槽调一次。
//
// 这条链路是只读的：唯一使用 UFunction 的地方是取余额，参数缓冲以零填充，
// 调用后只读返回值。每一步失败都带明确原因，调用方照原样显示，不猜也不降级写入。
enum class BridgeState : std::uint32_t {
    kIdle = 0,
    kOk,
    kNoSignatureService,
    kNoRegistry,
    kNoPlayerState,
    kSearching,
    kNoComponent,
    kNoFunction,
    kBadShape,
    kInvokeFailed,
};

class ReflectionBridge final {
public:
    void Attach(
        const AnomalySignatureServiceV1* signature,
        const AnomalyUe5NamesServiceV1* names) noexcept;

    // 读星票（PukalandTicket）余额。成功返回 kOk 并写入 balance。
    // 找组件要遍历整个 UObject 注册表，所以按片推进：一轮没扫完时返回 kSearching，
    // 调用方下一帧再调一次即可接上，不会把一次 on_update 拖到几十毫秒。
    [[nodiscard]] BridgeState ReadTicketBalance(std::int32_t& balance);

    // 诊断读数：最近一次定位到的对象地址，0 表示还没定位到。
    [[nodiscard]] std::uintptr_t component() const noexcept { return component_; }
    [[nodiscard]] std::uintptr_t player_state() const noexcept { return player_state_; }
    [[nodiscard]] std::uintptr_t function() const noexcept { return function_; }
    [[nodiscard]] std::uintptr_t registry() noexcept { return EnsureRegistry() ? registry_ : 0; }
    [[nodiscard]] std::uintptr_t world() noexcept;
    // 诊断：已扫到的注册表位置 / 最近一次成功解析出的类名 / 名字服务原始返回码。
    [[nodiscard]] std::uint32_t scanned() const noexcept { return scan_cursor_; }
    [[nodiscard]] const std::string& sample_class() const noexcept { return sample_class_; }
    [[nodiscard]] std::uint32_t name_probe_code() const noexcept { return name_probe_code_; }
    void ProbeNames() noexcept;

    // —— 噗卡乐园驱动需要的通用反射原语 ——
    // 类链上按名字找 UFunction（子类覆盖优先）。
    [[nodiscard]] std::uintptr_t FindFunctionInChain(
        std::uintptr_t klass, std::string_view name) const;
    // 按类名在注册表里找第一个非 CDO 实例（类链匹配，带缓存）。
    [[nodiscard]] std::uintptr_t FindObjectByClassName(std::string_view class_name);
    // 类链上按名字找 UProperty 的偏移（FProperty::Offset_Internal）。找不到返回 false。
    [[nodiscard]] bool FindPropertyOffset(
        std::uintptr_t klass, std::string_view name, std::uint32_t& offset) const;
    // 把名字解析成 FName 的 ComparisonIndex；解析不到返回 0。
    [[nodiscard]] std::uint32_t ResolveNameId(std::string_view name) const;
    // 定位本地玩家 PlayerState 上的 HTPukalandComponent 实例。
    [[nodiscard]] std::uintptr_t LocatePukalandComponent();

    // 只读内存与 UFunction 调用（调用方保证参数布局）。
    [[nodiscard]] bool ReadBytes(
        std::uintptr_t address, void* destination, std::size_t size) const noexcept;
    [[nodiscard]] bool Invoke(
        std::uintptr_t object, std::uintptr_t function, void* parms) const noexcept;

    void Reset() noexcept;

private:
    enum class LocateStep : std::uint32_t { kScanning = 0, kFound, kMissing };

    [[nodiscard]] bool EnsureRegistry() noexcept;
    [[nodiscard]] std::string ObjectName(std::uintptr_t object) const;
    [[nodiscard]] std::string ObjectNameById(std::uint32_t name_id) const;
    [[nodiscard]] std::uintptr_t LocalPlayerState() noexcept;
    [[nodiscard]] LocateStep StepLocate(std::uintptr_t player_state, std::uintptr_t& found);
    [[nodiscard]] std::uintptr_t LocateFunction(std::uintptr_t owner_class) const;
    [[nodiscard]] bool MatchesComponentClass(std::uintptr_t owner_class);

    const AnomalySignatureServiceV1* signature_{};
    const AnomalyUe5NamesServiceV1* names_{};
    std::uintptr_t g_world_{};
    std::uintptr_t registry_{};
    std::uintptr_t player_state_{};
    std::uintptr_t component_{};
    std::uintptr_t function_{};
    // GWorld 链路不可用时的退路定位（只做一轮全表扫描，结果缓存）。
    std::uintptr_t fallback_component_{};
    bool fallback_active_{};
    // 组件定位的按片进度：scan_active_ 为真表示这一轮还没扫完，scan_cursor_ 是下次的起点。
    bool scan_active_{};
    std::uint32_t scan_cursor_{};
    // 类对象 → 是否在继承链上含 HTPukalandComponent。注册表扫描时同一批类会反复出现，
    // 缓存后每个进程只需要解析少数几个类名。
    std::unordered_map<std::uintptr_t, bool> class_match_;
    std::string sample_class_;
    std::uint32_t name_probe_code_{};
};

}  // namespace anomaly::plugins::pukaland
