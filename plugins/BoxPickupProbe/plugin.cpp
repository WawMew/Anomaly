// Temporary probe: compares the two pickup mechanisms covered by this analysis.
//
//   * interaction RPC - what BoxAuto does: UPlayerController::ServerInteract(actor, 0)
//     dispatched through ProcessEvent.
//   * direct vtable call - what PinkPawHeistESP does: resolve the pickup entry by
//     signature, locate the interface subobject that carries it, call it with the local
//     controller.
//
// It deliberately does no coordinate work, no teleporting and no table reading: the
// candidate set is every GObject whose class name carries one of the loot-box prefixes.

#include "anomaly/sdk/cpp.hpp"
#include "anomaly/sdk/localization.hpp"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

// Signatures and layout reused from the two plugins under test.
constexpr std::string_view kModuleName = "HTGame.exe";
constexpr std::string_view kTextSection = ".text";
constexpr std::string_view kGWorldPattern =
    "48 8B 1D ?? ?? ?? ?? 48 85 DB 74 ?? 41 B0 01";
constexpr std::string_view kGObjectsPattern =
    "48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8B 04 D1 C3 33 C0 48 8B 00 C3";
constexpr std::string_view kPickupPattern =
    "48 89 5C 24 10 57 48 83 EC 40 48 8B DA 48 8B F9 E8 ?? ?? ?? ?? "
    "84 C0 0F 84 ?? ?? ?? ?? 48 83 BB D0 02 00 00 00 0F 84 ?? ?? ?? ?? "
    "E8 ?? ?? ?? ??";
constexpr std::array<std::uint8_t, 16> kPickupPrologue{
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x57, 0x48, 0x83,
    0xEC, 0x40, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0xF9};
constexpr std::array<std::uint8_t, 13> kPickupSuccessReturn{
    0xB0, 0x01, 0x48, 0x8B, 0x5C, 0x24, 0x58,
    0x48, 0x83, 0xC4, 0x40, 0x5F, 0xC3};
constexpr std::array<std::uint8_t, 13> kPickupFailureReturn{
    0x48, 0x8B, 0x5C, 0x24, 0x58, 0x32, 0xC0,
    0x48, 0x83, 0xC4, 0x40, 0x5F, 0xC3};

constexpr std::uint32_t kRipDisplacementOffset = 3;
constexpr std::uint32_t kRipInstructionSize = 7;
constexpr std::ptrdiff_t kGObjectsAddend = -16;
constexpr std::uintptr_t kPickupSuccessReturnOffset = 0xD6;
constexpr std::uintptr_t kPickupFailureReturnOffset = 0xE3;

constexpr std::ptrdiff_t kObjectClassOffset = 16;
constexpr std::ptrdiff_t kObjectNameOffset = 24;
constexpr std::ptrdiff_t kObjectItemsOffset = 16;
constexpr std::ptrdiff_t kObjectCountOffset = 36;
constexpr std::ptrdiff_t kObjectNumChunksOffset = 44;
constexpr std::uint32_t kObjectChunkSize = 65536;
constexpr std::uint32_t kObjectItemStride = 24;
constexpr std::ptrdiff_t kUClassClassDefaultObjectOffset = 272;
constexpr std::ptrdiff_t kUStructChildrenOffset = 72;
constexpr std::ptrdiff_t kUStructSuperStructOffset = 64;
constexpr std::ptrdiff_t kUFieldNextOffset = 40;
constexpr std::ptrdiff_t kUFunctionNumParmsOffset = 180;
constexpr std::ptrdiff_t kUFunctionParmsSizeOffset = 182;
constexpr std::size_t kProcessEventVtableIndex = 0x4C;
constexpr std::ptrdiff_t kWorldGameInstanceOffset = 560;
constexpr std::ptrdiff_t kGameInstanceLocalPlayersOffset = 56;
constexpr std::ptrdiff_t kLocalPlayerControllerOffset = 48;

constexpr std::size_t kMaximumNameBytes = 1024;
constexpr std::size_t kMaximumCandidates = 16;
constexpr std::size_t kInterfaceScanBytes = 0x1000;
constexpr std::size_t kInterfaceReadChunk = 256;
constexpr std::size_t kInterfaceVtableSlots = 32;
constexpr std::size_t kMinimumPointerValue = 0x10000;

// Class-name fragments the resource boxes are instantiated under. This is the same set
// BoxAuto classifies table rows with, minus every coordinate concern.
constexpr std::array<std::string_view, 10> kLootClassPrefixes{
    "HunterBox_", "CharacterUpBox_", "ChameleonBox", "FurnitureBox", "PropBox_Geft",
    "PropBox_Yahaha", "PropBox_Once", "Prison", "InteractBox", "ShopStealGoods_"};

enum class Action : std::uint32_t { none = 0, rpc = 1, vtable = 2 };

struct Context final {
    const AnomalyHostApiV1* host{};
    anomaly::sdk::Localizer localizer;
    const AnomalyCoreServiceV1* core{};
    const AnomalyUiServiceV1* ui{};
    const AnomalySignatureServiceV1* signature{};
    const AnomalyUe5NamesServiceV1* names{};
    std::uintptr_t g_objects_address{};
    std::uintptr_t g_world_address{};
    std::uintptr_t controller{};
    std::uintptr_t server_interact{};
    std::uintptr_t pickup_function{};
    bool started{};
    Action pending{Action::none};
    std::vector<std::string> report;
    std::mutex mutex;
};

struct Candidate final {
    std::uintptr_t actor{};
    std::string class_name;
};

struct ScanResult final {
    std::int32_t object_count{};
    std::vector<Candidate> candidates;
};

struct InterfaceHit final {
    std::uintptr_t offset{};
    std::uint32_t slot{};
};

AnomalyStatusV1 Status(
    const std::uint32_t code,
    const std::string_view message = {}) noexcept {
    return {code, 0, {message.data(), message.size()}};
}

template <typename Struct, typename Field>
bool HasField(const Struct* value, const std::size_t offset) noexcept {
    return value != nullptr && value->struct_size >= offset + sizeof(Field);
}

template <typename Service>
const Service* Query(
    const AnomalyHostApiV1* host,
    const char* id,
    const std::uint32_t version) noexcept {
    if (!HasField<AnomalyHostApiV1, decltype(AnomalyHostApiV1::query_service)>(
            host, offsetof(AnomalyHostApiV1, query_service)) ||
        host->query_service == nullptr) {
        return nullptr;
    }
    const void* table{};
    if (host->query_service(
            host->host_context, anomaly::sdk::StringView(id), version, &table).code !=
            ANOMALY_STATUS_V1_OK ||
        table == nullptr) {
        return nullptr;
    }
    const auto* service = static_cast<const Service*>(table);
    constexpr std::size_t prefix = offsetof(Service, user) + sizeof(void*);
    return service->struct_size >= prefix && service->service_version >= version
        ? service
        : nullptr;
}

template <typename T>
bool Read(const Context& context, const std::uintptr_t address, T& value) noexcept {
    if (address == 0 || context.core == nullptr || context.core->read_memory == nullptr) {
        return false;
    }
    AnomalyMutableByteSpanV1 span{
        reinterpret_cast<std::uint8_t*>(&value), sizeof(T)};
    return context.core->read_memory(context.core->user, address, span).code ==
        ANOMALY_STATUS_V1_OK;
}

bool ReadBlock(
    const Context& context,
    const std::uintptr_t address,
    void* destination,
    const std::size_t size) noexcept {
    if (address == 0 || destination == nullptr || size == 0 || context.core == nullptr ||
        context.core->read_memory == nullptr) {
        return false;
    }
    AnomalyMutableByteSpanV1 span{static_cast<std::uint8_t*>(destination), size};
    return context.core->read_memory(context.core->user, address, span).code ==
        ANOMALY_STATUS_V1_OK;
}

std::uintptr_t ReadPointer(const Context& context, const std::uintptr_t address) noexcept {
    std::uintptr_t value{};
    return Read(context, address, value) ? value : 0;
}

std::string ResolveName(const Context& context, const std::uint32_t name_id) {
    if (context.names == nullptr || context.names->resolve_utf8 == nullptr ||
        name_id == 0) {
        return {};
    }
    std::size_t size{};
    if (context.names->resolve_utf8(context.names->user, name_id, nullptr, &size).code !=
            ANOMALY_STATUS_V1_OK ||
        size <= 1 || size > kMaximumNameBytes) {
        return {};
    }
    std::string value(size, '\0');
    if (context.names->resolve_utf8(context.names->user, name_id, value.data(), &size)
                .code != ANOMALY_STATUS_V1_OK ||
        size == 0 || size > value.size()) {
        return {};
    }
    value.resize(size - 1U);
    return value;
}

std::string ObjectName(const Context& context, const std::uintptr_t object) {
    std::uint32_t name_id{};
    if (!Read(context, object + kObjectNameOffset, name_id)) return {};
    return ResolveName(context, name_id);
}

bool ResolvePattern(
    const Context& context,
    const std::string_view pattern,
    std::uintptr_t& address) noexcept {
    address = 0;
    if (context.signature == nullptr || context.signature->resolve == nullptr) return false;
    std::uintptr_t resolved{};
    if (context.signature->resolve(
            context.signature->user, anomaly::sdk::StringView(kModuleName),
            anomaly::sdk::StringView(kTextSection), anomaly::sdk::StringView(pattern),
            &resolved)
            .code != ANOMALY_STATUS_V1_OK) {
        return false;
    }
    address = resolved;
    return address != 0;
}

bool ResolveRip(
    const Context& context,
    const std::string_view pattern,
    const std::ptrdiff_t addend,
    std::uintptr_t& address) noexcept {
    std::uintptr_t instruction{};
    if (!ResolvePattern(context, pattern, instruction)) return false;
    std::int32_t displacement{};
    if (!Read(context, instruction + kRipDisplacementOffset, displacement)) return false;
    const auto target = static_cast<std::intptr_t>(instruction) +
        static_cast<std::intptr_t>(kRipInstructionSize) + displacement;
    address = static_cast<std::uintptr_t>(target + addend);
    return address != 0;
}

std::uintptr_t ObjectAt(
    const Context& context,
    const std::uintptr_t g_objects,
    const std::uint32_t index) noexcept {
    std::int32_t count{};
    std::int32_t num_chunks{};
    std::uintptr_t items{};
    if (!Read(context, g_objects + kObjectItemsOffset, items) || items == 0 ||
        !Read(context, g_objects + kObjectCountOffset, count) ||
        !Read(context, g_objects + kObjectNumChunksOffset, num_chunks) || count <= 0 ||
        index >= static_cast<std::uint32_t>(count) || num_chunks <= 0) {
        return 0;
    }
    const auto chunk_index = index / kObjectChunkSize;
    const auto within = index % kObjectChunkSize;
    if (chunk_index >= static_cast<std::uint32_t>(num_chunks)) return 0;
    const auto chunk = ReadPointer(
        context, items + static_cast<std::uintptr_t>(chunk_index) * sizeof(void*));
    if (chunk == 0) return 0;
    return ReadPointer(
        context, chunk + static_cast<std::uintptr_t>(within) * kObjectItemStride);
}

bool FindFunction(
    const Context& context,
    const std::uintptr_t cls,
    const std::string_view target,
    const std::uint8_t num_parms,
    const std::uint16_t parms_size,
    std::uintptr_t& result) noexcept {
    std::uintptr_t owner = cls;
    for (std::uint32_t depth{}; owner != 0 && depth < 64; ++depth) {
        std::uintptr_t field{};
        Read(context, owner + kUStructChildrenOffset, field);
        for (std::uint32_t count{}; field != 0 && count < 4096; ++count) {
            std::uintptr_t next{};
            std::uintptr_t field_class{};
            if (!Read(context, field + kUFieldNextOffset, next) ||
                !Read(context, field + kObjectClassOffset, field_class)) {
                break;
            }
            if (ObjectName(context, field_class) == "Function" &&
                ObjectName(context, field) == target) {
                std::uint8_t np{};
                std::uint16_t ps{};
                Read(context, field + kUFunctionNumParmsOffset, np);
                Read(context, field + kUFunctionParmsSizeOffset, ps);
                if (np == num_parms && ps == parms_size) {
                    result = field;
                    return true;
                }
            }
            if (next == field) break;
            field = next;
        }
        std::uintptr_t super{};
        if (!Read(context, owner + kUStructSuperStructOffset, super) || super == 0 ||
            super == owner) {
            break;
        }
        owner = super;
    }
    return false;
}

// ProcessEvent through the object's own vtable (slot 0x4C), the way BoxAuto dispatches
// ServerInteract: a reflected RPC needs the virtual entry, not the UFunction body.
bool InvokeProcessEvent(
    const Context& context,
    void* object,
    void* function,
    void* parameters) noexcept {
    if (object == nullptr || function == nullptr) return false;
    const auto vtable = ReadPointer(context, reinterpret_cast<std::uintptr_t>(object));
    if (vtable == 0) return false;
    const auto entry = ReadPointer(
        context, vtable + kProcessEventVtableIndex * sizeof(void*));
    if (entry == 0) return false;
    using ProcessEvent = void(__fastcall*)(void*, void*, void*);
    __try {
        reinterpret_cast<ProcessEvent>(entry)(object, function, parameters);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool CallPickup(
    const std::uintptr_t function,
    void* interface_object,
    void* controller,
    bool& returned) noexcept {
    returned = false;
    if (function == 0 || interface_object == nullptr) return false;
    using Pickup = bool(__fastcall*)(void*, void*);
    __try {
        returned = reinterpret_cast<Pickup>(function)(interface_object, controller);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool Matches(
    const Context& context,
    const std::uintptr_t address,
    const std::uint8_t* expected,
    const std::size_t size) noexcept {
    std::array<std::uint8_t, 16> actual{};
    if (size > actual.size() || !ReadBlock(context, address, actual.data(), size)) {
        return false;
    }
    return std::memcmp(actual.data(), expected, size) == 0;
}

bool ResolvePickupFunction(Context& context) noexcept {
    if (context.pickup_function != 0) return true;
    std::uintptr_t pickup{};
    if (!ResolvePattern(context, kPickupPattern, pickup)) return false;
    if (!Matches(context, pickup, kPickupPrologue.data(), kPickupPrologue.size()) ||
        !Matches(
            context, pickup + kPickupSuccessReturnOffset, kPickupSuccessReturn.data(),
            kPickupSuccessReturn.size()) ||
        !Matches(
            context, pickup + kPickupFailureReturnOffset, kPickupFailureReturn.data(),
            kPickupFailureReturn.size())) {
        return false;
    }
    context.pickup_function = pickup;
    return true;
}

bool GetController(Context& context) noexcept {
    if (context.controller != 0) return true;
    if (context.g_world_address == 0 &&
        !ResolveRip(context, kGWorldPattern, 0, context.g_world_address)) {
        return false;
    }
    std::uintptr_t world{};
    if (!Read(context, context.g_world_address, world) || world == 0) return false;
    std::uintptr_t game_instance{};
    if (!Read(context, world + kWorldGameInstanceOffset, game_instance) ||
        game_instance == 0) {
        return false;
    }
    std::uintptr_t players{};
    std::int32_t players_count{};
    if (!Read(context, game_instance + kGameInstanceLocalPlayersOffset, players) ||
        players == 0 ||
        !Read(context, game_instance + kGameInstanceLocalPlayersOffset + 8,
              players_count) ||
        players_count < 1) {
        return false;
    }
    std::uintptr_t local_player{};
    if (!Read(context, players, local_player) || local_player == 0) return false;
    std::uintptr_t controller{};
    if (!Read(context, local_player + kLocalPlayerControllerOffset, controller) ||
        controller == 0) {
        return false;
    }
    std::uintptr_t controller_class{};
    if (!Read(context, controller + kObjectClassOffset, controller_class) ||
        controller_class == 0) {
        return false;
    }
    std::uintptr_t fn{};
    if (!FindFunction(context, controller_class, "ServerInteract", 2, 12, fn)) {
        return false;
    }
    context.controller = controller;
    context.server_interact = fn;
    return true;
}

bool MatchesLootClass(const std::string_view class_name) noexcept {
    for (const auto prefix : kLootClassPrefixes) {
        if (class_name.find(prefix) != std::string_view::npos) return true;
    }
    return false;
}

bool ScanObjects(Context& context, ScanResult& result) {
    if (context.g_objects_address == 0 &&
        !ResolveRip(context, kGObjectsPattern, kGObjectsAddend,
                    context.g_objects_address)) {
        return false;
    }
    std::uintptr_t g_objects{};
    if (!Read(context, context.g_objects_address, g_objects) || g_objects == 0) {
        return false;
    }
    std::int32_t count{};
    if (!Read(context, g_objects + kObjectCountOffset, count) || count <= 0) {
        return false;
    }
    result.object_count = count;
    for (std::int32_t index = 0; index < count; ++index) {
        if (result.candidates.size() >= kMaximumCandidates) break;
        const auto object =
            ObjectAt(context, g_objects, static_cast<std::uint32_t>(index));
        if (object == 0) continue;
        std::uintptr_t cls{};
        if (!Read(context, object + kObjectClassOffset, cls) || cls == 0) continue;
        std::uintptr_t cdo{};
        if (Read(context, cls + kUClassClassDefaultObjectOffset, cdo) && cdo == object) {
            continue;
        }
        std::string class_name = ObjectName(context, cls);
        if (class_name.empty() || !MatchesLootClass(class_name)) continue;
        result.candidates.push_back({object, std::move(class_name)});
    }
    return true;
}

// The interface subobject is found rather than assumed: scan the actor for a pointer
// whose vtable carries the resolved pickup entry, which also reports the offset and slot
// the call actually uses.
bool FindInterface(
    const Context& context,
    const std::uintptr_t actor,
    InterfaceHit& hit) noexcept {
    std::array<std::uint8_t, kInterfaceReadChunk> chunk{};
    for (std::uintptr_t base{}; base < kInterfaceScanBytes; base += chunk.size()) {
        if (!ReadBlock(context, actor + base, chunk.data(), chunk.size())) continue;
        for (std::size_t within{}; within + sizeof(std::uintptr_t) <= chunk.size();
             within += sizeof(std::uintptr_t)) {
            std::uintptr_t candidate{};
            std::memcpy(&candidate, chunk.data() + within, sizeof(candidate));
            if (candidate < kMinimumPointerValue ||
                candidate % sizeof(std::uintptr_t) != 0) {
                continue;
            }
            std::array<std::uintptr_t, kInterfaceVtableSlots> slots{};
            if (!ReadBlock(context, candidate, slots.data(), sizeof(slots))) continue;
            for (std::uint32_t slot{}; slot < slots.size(); ++slot) {
                if (slots[slot] != context.pickup_function) continue;
                hit.offset = base + within;
                hit.slot = slot;
                return true;
            }
        }
    }
    return false;
}

std::string Hex(const std::uintptr_t value) {
    std::string text = "0x";
    constexpr char digits[] = "0123456789ABCDEF";
    bool started = false;
    for (int shift = static_cast<int>(sizeof(value) * 8U) - 4; shift >= 0; shift -= 4) {
        const auto nibble = static_cast<std::uint32_t>((value >> shift) & 0xFU);
        if (nibble != 0) started = true;
        if (started || shift == 0) text.push_back(digits[nibble]);
    }
    return text;
}

// Localizer::Format consumes string views, so the owning strings stay alive in `values`.
template <std::size_t N>
std::array<std::string_view, N> Views(const std::array<std::string, N>& values) noexcept {
    std::array<std::string_view, N> views{};
    for (std::size_t index = 0; index < N; ++index) {
        views[index] = values[index];
    }
    return views;
}

void AddReportLine(Context& context, std::string line) {
    context.report.push_back(std::move(line));
}

void AddError(Context& context, const std::string_view code, const std::string& detail) {
    const std::array arguments{code, std::string_view(detail)};
    AddReportLine(context, context.localizer.Format(
        "status.error", "{0} - {1}", arguments));
}

void AddScanLine(Context& context, const ScanResult& scan) {
    const std::array<std::string, 2> arguments{
        std::to_string(scan.object_count),
        std::to_string(scan.candidates.size())};
    AddReportLine(context, context.localizer.Format(
        "status.scan", "Scanned {0} objects, matched {1} candidates", Views(arguments)));
}

void RunRpc(Context& context) {
    ScanResult scan;
    if (!ScanObjects(context, scan)) {
        AddError(context, "SCAN", "GObjects");
        return;
    }
    AddScanLine(context, scan);
    if (scan.candidates.empty()) {
        AddReportLine(
            context,
            context.localizer.Text("status.no_candidates", "No candidate objects"));
        return;
    }
    if (!GetController(context)) {
        AddError(context, "PROFILE", "ServerInteract");
        return;
    }
    std::size_t sent{};
    std::size_t failed{};
    for (const auto& candidate : scan.candidates) {
        std::uint8_t params[12]{};
        std::memcpy(params, &candidate.actor, sizeof(candidate.actor));
        if (InvokeProcessEvent(
                context, reinterpret_cast<void*>(context.controller),
                reinterpret_cast<void*>(context.server_interact), params)) {
            ++sent;
        } else {
            ++failed;
        }
    }
    const std::array<std::string, 2> arguments{std::to_string(sent), std::to_string(failed)};
    AddReportLine(context, context.localizer.Format(
        "status.rpc", "RPC: sent {0}, not sent {1}", Views(arguments)));
}

void RunVtable(Context& context) {
    ScanResult scan;
    if (!ScanObjects(context, scan)) {
        AddError(context, "SCAN", "GObjects");
        return;
    }
    AddScanLine(context, scan);
    if (scan.candidates.empty()) {
        AddReportLine(
            context,
            context.localizer.Text("status.no_candidates", "No candidate objects"));
        return;
    }
    if (!ResolvePickupFunction(context)) {
        AddError(context, "SIGNATURE", "pickup");
        return;
    }
    if (!GetController(context)) {
        AddError(context, "PROFILE", "ServerInteract");
        return;
    }
    std::size_t tried{};
    std::size_t accepted{};
    std::size_t rejected{};
    std::size_t missing{};
    std::string first_hit;
    for (const auto& candidate : scan.candidates) {
        InterfaceHit hit{};
        if (!FindInterface(context, candidate.actor, hit)) {
            ++missing;
            continue;
        }
        bool returned{};
        if (!CallPickup(
                context.pickup_function,
                reinterpret_cast<void*>(candidate.actor + hit.offset),
                reinterpret_cast<void*>(context.controller), returned)) {
            continue;
        }
        ++tried;
        if (returned) {
            ++accepted;
        } else {
            ++rejected;
        }
        if (first_hit.empty()) {
            const std::array<std::string, 3> arguments{
                candidate.class_name, Hex(hit.offset), std::to_string(hit.slot)};
            first_hit = context.localizer.Format(
                "status.interface", "First interface: {0} at {1} slot {2}", Views(arguments));
        }
    }
    const std::array<std::string, 4> arguments{
        std::to_string(tried), std::to_string(accepted), std::to_string(rejected),
        std::to_string(missing)};
    AddReportLine(context, context.localizer.Format(
        "status.vtable", "Vtable: tried {0}, true {1}, false {2}, no interface {3}",
        Views(arguments)));
    if (!first_hit.empty()) AddReportLine(context, std::move(first_hit));
}

bool UiReady(const AnomalyUiServiceV1* service) noexcept {
    return HasField<AnomalyUiServiceV1,
               decltype(AnomalyUiServiceV1::button_enabled)>(
               service, offsetof(AnomalyUiServiceV1, button_enabled)) &&
        service->begin_window != nullptr && service->end_window != nullptr &&
        service->text != nullptr && service->button_enabled != nullptr;
}

bool MemoryReady(const AnomalyCoreServiceV1* service) noexcept {
    return HasField<AnomalyCoreServiceV1, decltype(AnomalyCoreServiceV1::read_memory)>(
               service, offsetof(AnomalyCoreServiceV1, read_memory)) &&
        service->read_memory != nullptr;
}

bool NamesReady(const AnomalyUe5NamesServiceV1* service) noexcept {
    return HasField<AnomalyUe5NamesServiceV1,
               decltype(AnomalyUe5NamesServiceV1::resolve_utf8)>(
               service, offsetof(AnomalyUe5NamesServiceV1, resolve_utf8)) &&
        service->resolve_utf8 != nullptr;
}

AnomalyStatusV1 ANOMALY_CALL Load(
    const AnomalyHostApiV1* host,
    void** plugin_context) {
    if (host == nullptr || plugin_context == nullptr) {
        return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT, "host is invalid");
    }
    *plugin_context = nullptr;
    auto context = std::make_unique<Context>();
    context->host = host;
    context->localizer = anomaly::sdk::Localizer(host);
    context->core = Query<AnomalyCoreServiceV1>(
        host, ANOMALY_CORE_SERVICE_V1_ID, ANOMALY_CORE_SERVICE_V1_VERSION);
    context->ui = Query<AnomalyUiServiceV1>(
        host, ANOMALY_UI_SERVICE_V1_ID, ANOMALY_UI_SERVICE_V1_VERSION);
    context->signature = Query<AnomalySignatureServiceV1>(
        host, ANOMALY_SIGNATURE_SERVICE_V1_ID, ANOMALY_SIGNATURE_SERVICE_V1_VERSION);
    // resolve_utf8 is part of names v1; find_utf8 (v2) is not needed here.
    context->names = Query<AnomalyUe5NamesServiceV1>(
        host, ANOMALY_UE5_NAMES_SERVICE_V1_ID, 1);
    if (!UiReady(context->ui) || !MemoryReady(context->core) ||
        context->signature == nullptr || context->signature->resolve == nullptr ||
        !NamesReady(context->names)) {
        return Status(
            ANOMALY_STATUS_V1_UNAVAILABLE, "required services are unavailable");
    }
    *plugin_context = context.release();
    return anomaly::sdk::Ok();
}

AnomalyStatusV1 ANOMALY_CALL Start(void* user) {
    auto* context = static_cast<Context*>(user);
    if (context == nullptr) return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT);
    std::scoped_lock lock(context->mutex);
    context->started = true;
    return anomaly::sdk::Ok();
}

AnomalyStatusV1 ANOMALY_CALL Stop(void* user, std::uint32_t) {
    auto* context = static_cast<Context*>(user);
    if (context == nullptr) return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT);
    std::scoped_lock lock(context->mutex);
    context->started = false;
    context->pending = Action::none;
    return anomaly::sdk::Ok();
}

void ANOMALY_CALL Unload(void* user) {
    delete static_cast<Context*>(user);
}

// on_update runs on the Game domain, which is where both calls belong: ProcessEvent and
// the interface entry both assume the game thread.
void ANOMALY_CALL Update(void* user, double) {
    auto* context = static_cast<Context*>(user);
    if (context == nullptr) return;
    Action action{Action::none};
    {
        std::scoped_lock lock(context->mutex);
        if (!context->started || context->pending == Action::none) return;
        action = context->pending;
        context->pending = Action::none;
        context->report.clear();
    }
    if (action == Action::rpc) {
        RunRpc(*context);
    } else if (action == Action::vtable) {
        RunVtable(*context);
    }
    if (context->report.empty()) {
        AddError(*context, "PROBE", "no report");
    }
}

void ANOMALY_CALL Draw(void* user, const AnomalyUiServiceV1* supplied_ui) {
    auto* context = static_cast<Context*>(user);
    if (context == nullptr) return;
    const AnomalyUiServiceV1* ui = UiReady(supplied_ui) ? supplied_ui : context->ui;
    if (!UiReady(ui)) return;
    std::vector<std::string> report;
    {
        std::scoped_lock lock(context->mutex);
        report = context->report;
    }
    const std::string title =
        context->localizer.Label("window.title", "Pickup probe", "pickup-probe");
    anomaly::sdk::UiWindow window(ui, title);
    if (!window) return;
    const std::string rpc_label = context->localizer.Label(
        "action.rpc", "Interaction RPC", "pickup-probe-rpc");
    if (ui->button_enabled(ui->user, anomaly::sdk::StringView(rpc_label), 0.0F, 0.0F, 1) !=
        0) {
        std::scoped_lock lock(context->mutex);
        context->pending = Action::rpc;
    }
    const std::string vtable_label = context->localizer.Label(
        "action.vtable", "Direct vtable call", "pickup-probe-vtable");
    if (ui->button_enabled(
            ui->user, anomaly::sdk::StringView(vtable_label), 0.0F, 0.0F, 1) != 0) {
        std::scoped_lock lock(context->mutex);
        context->pending = Action::vtable;
    }
    ui->separator(ui->user);
    if (report.empty()) {
        const std::string idle = context->localizer.Text(
            "status.idle", "Idle. A press scans GObjects and calls on the game thread.");
        ui->text(ui->user, anomaly::sdk::StringView(idle));
    }
    for (const auto& line : report) {
        ui->text(ui->user, anomaly::sdk::StringView(line));
    }
}

}  // namespace

ANOMALY_SDK_EXPORT AnomalyStatusV1 ANOMALY_CALL AnomalyPluginEntryV1(
    AnomalyPluginDescriptorV1* descriptor) {
    if (descriptor == nullptr || descriptor->struct_size < sizeof(*descriptor)) {
        return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT, "descriptor is invalid");
    }
    *descriptor = {
        sizeof(*descriptor), ANOMALY_PLUGIN_API_V1_MAJOR, ANOMALY_PLUGIN_API_V1_MINOR,
        anomaly::sdk::StringView("anomaly.local.box-pickup-probe"),
        anomaly::sdk::StringView("Box Pickup Probe"),
        anomaly::sdk::StringView("Anomaly"),
        anomaly::sdk::StringView("0.1.0"),
        Load, Start, Stop, Unload, Update, Draw};
    return anomaly::sdk::Ok();
}
