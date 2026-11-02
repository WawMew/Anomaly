// Temporary probe: compares the two pickup mechanisms covered by this analysis.
//
//   * interaction RPC - what BoxAuto does, in the order it does it: arm the entry through
//     the actor's BPGetInteractEntries / BPCanTryInteract, fire it with the controller's
//     TriggerInteract(actor, choice, 0), and fall back to ServerInteract(actor, 0) when the
//     actor offers no entry at all. Both are dispatched through ProcessEvent.
//   * direct vtable call - what PinkPawHeistESP does: resolve the pickup entry by
//     signature, read the container interface vtable stored at actor+872, check slot 3
//     still holds that entry, then call it with the local controller.
//
// Neither plugin calls these from a distance and hopes: BoxAuto moves the player inside
// 250cm (120cm in developer mode) before every interact and then verifies the box's
// bInteractFinish byte three seconds later, and PinkPawHeistESP only calls containers whose
// pickability it has already checked. This probe keeps the same verification so a press
// reports what the game actually did instead of what dispatch returned.
//
// It deliberately does no coordinate work, no teleporting and no table reading: the
// candidate set is every GObject whose class name carries one of the loot-box prefixes.

#include "anomaly/sdk/cpp.hpp"
#include "anomaly/sdk/localization.hpp"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
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
constexpr std::ptrdiff_t kUStructChildrenOffset = 72;
constexpr std::ptrdiff_t kUStructSuperStructOffset = 64;
constexpr std::ptrdiff_t kUFieldNextOffset = 40;
constexpr std::ptrdiff_t kUFunctionNumParmsOffset = 180;
constexpr std::ptrdiff_t kUFunctionParmsSizeOffset = 182;
constexpr std::size_t kProcessEventVtableIndex = 0x4C;
constexpr std::ptrdiff_t kWorldGameInstanceOffset = 560;
constexpr std::ptrdiff_t kGameInstanceLocalPlayersOffset = 56;
constexpr std::ptrdiff_t kLocalPlayerControllerOffset = 48;

// Reflection offsets needed for the interact precondition and for the box-state check.
constexpr std::ptrdiff_t kObjectInternalIndexOffset = 12;
constexpr std::ptrdiff_t kUStructPropertyLinkOffset = 112;
constexpr std::ptrdiff_t kFFieldNameOffset = 32;
constexpr std::ptrdiff_t kFPropertyLinkNextOffset = 72;
constexpr std::ptrdiff_t kFPropertyOffsetInternalOffset = 68;
constexpr std::ptrdiff_t kUFunctionFlagsOffset = 176;
constexpr std::uint32_t kFuncNativeFlag = 0x400;

// BoxAuto's interact contract: BPGetInteractEntries(controller, out TArray<int32>) on the
// actor returns 360-byte elements whose first int32 is the choice, BPCanTryInteract
// (controller, choice) reports a byte, and TriggerInteract(actor, choice, 0) performs it.
constexpr std::size_t kInteractEntriesParams = 24;
constexpr std::size_t kServerInteractParams = 12;
constexpr std::size_t kCanTryParams = 13;
constexpr std::size_t kTriggerInteractParams = 13;
constexpr std::uintptr_t kInteractArrayStride = 360;
constexpr std::int32_t kMaximumInteractEntries = 128;

// PinkPawHeistESP's container interface: the vtable pointer sits at actor+872 and the
// pickup entry is virtual slot 3 (byte offset 24).
constexpr std::uintptr_t kPinkPawInterfaceOffset = 872;
constexpr std::uint32_t kPinkPawPickupSlot = 3;

// `bInteractFinish` moved from 976 to 984 in the 9/26 build; resolve it by name and keep
// the old offset as the fallback, the way BoxAuto does.
constexpr std::ptrdiff_t kInteractFinishOffset = 976;
constexpr auto kVerifyDelay = std::chrono::milliseconds(3000);

constexpr std::size_t kMaximumNameBytes = 1024;
constexpr std::size_t kMaximumCandidates = 64;
constexpr std::size_t kInterfaceScanBytes = 0x1000;
constexpr std::size_t kInterfaceReadChunk = 256;
constexpr std::size_t kInterfaceVtableSlots = 32;
constexpr std::size_t kMinimumPointerValue = 0x10000;
// The Host serves the entity frame in pages of at most this many entities.
constexpr std::size_t kEntityPageCapacity = ANOMALY_NTE_ENTITY_PAGE_V1_MAX_CAPACITY;

// Class-name fragments the resource boxes are instantiated under. This is the same set
// BoxAuto classifies table rows with, minus every coordinate concern.
constexpr std::array<std::string_view, 10> kLootClassPrefixes{
    "HunterBox_", "CharacterUpBox_", "ChameleonBox", "FurnitureBox", "PropBox_Geft",
    "PropBox_Yahaha", "PropBox_Once", "Prison", "InteractBox", "ShopStealGoods_"};

enum class Action : std::uint32_t {
    none = 0,
    server_interact = 1,
    trigger_interact = 2,
    host_pickup = 3,
    vtable = 4,
    diagnostic = 5,
};

// BoxAuto only ever interacts inside 250cm (120cm in developer mode); the probe keeps a
// looser ring so a press still reports "too far" instead of silently picking a box across
// the map.
constexpr double kInteractTargetRadiusCentimeters = 400.0;
// The Host pickup request from BoxAuto's food path.
constexpr double kPickupRadiusCentimeters = 600.0;
constexpr std::uint32_t kPickupMaximumItems = 1;
constexpr auto kPickupTimeout = std::chrono::milliseconds(8000);

struct Candidate final {
    std::uintptr_t actor{};
    std::string class_name;
    // Planar distance from the player camera, in centimetres.
    double distance{};
};

struct ScanResult final {
    std::uintptr_t g_objects{};
    std::uint64_t entity_count{};
    std::vector<Candidate> candidates;
};

// nte.pickup answers on a later tick: the sequence proves a request ran, `confirmed` counts
// the actors whose registry slot disappeared while the Host watched them.
struct PickupWatch final {
    bool active{};
    std::uint64_t baseline{};
    std::chrono::steady_clock::time_point deadline{};
};

struct InterfaceHit final {
    std::uintptr_t offset{};
    std::uint32_t slot{};
};

// One pending post-interact check: the byte read before the call and the moment the game
// has had time to act on it.
struct VerifyState final {
    bool active{};
    std::uintptr_t actor{};
    std::uint8_t baseline{};
    std::chrono::steady_clock::time_point due{};
};

struct Context final {
    const AnomalyHostApiV1* host{};
    anomaly::sdk::Localizer localizer;
    const AnomalyCoreServiceV1* core{};
    const AnomalyUiServiceV1* ui{};
    const AnomalySignatureServiceV1* signature{};
    const AnomalyUe5NamesServiceV1* names{};
    const AnomalyNteEntitiesServiceV1* entities{};
    const AnomalyNtePickupServiceV1* pickup{};
    std::uintptr_t g_objects_address{};
    std::uintptr_t g_world_address{};
    std::uintptr_t controller{};
    std::uintptr_t server_interact{};
    std::uintptr_t trigger_interact{};
    std::uintptr_t pickup_function{};
    bool started{};
    // `pending` is the render-to-game handoff; `running`, `scan` and `verify` belong to
    // Update alone.
    Action pending{Action::none};
    Action running{Action::none};
    ScanResult scan;
    VerifyState verify;
    PickupWatch pickup_watch;
    std::vector<std::pair<std::uint64_t, std::string>> entity_class_names;
    std::vector<std::pair<std::uintptr_t, std::ptrdiff_t>> interact_finish_offsets;
    std::vector<std::string> report;
    std::mutex mutex;
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

bool WriteUint32(const Context& context, const std::uintptr_t address, const std::uint32_t value) noexcept {
    if (address == 0 || context.core == nullptr || context.core->write_memory == nullptr) {
        return false;
    }
    AnomalyByteSpanV1 span{
        reinterpret_cast<const std::uint8_t*>(&value), sizeof(value)};
    return context.core->write_memory(context.core->user, address, span).code ==
        ANOMALY_STATUS_V1_OK;
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

// Every probe decision is logged with this prefix so the runtime log shows what the game
// answered, not just what the window shows.
void Log(const Context& context, const std::string_view message) {
    if (context.core == nullptr || context.core->log == nullptr) return;
    context.core->log(
        context.core->user, ANOMALY_CORE_LOG_LEVEL_V1_INFO,
        anomaly::sdk::StringView(message));
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

// True while the actor is still the object its GObjects slot points at: the box being gone
// is the other way an interact shows that it worked.
bool IsObjectAlive(
    const Context& context,
    const std::uintptr_t g_objects,
    const std::uintptr_t actor) noexcept {
    std::int32_t index{};
    if (g_objects == 0 || actor == 0 ||
        !Read(context, actor + kObjectInternalIndexOffset, index) || index < 0) {
        return false;
    }
    return ObjectAt(context, g_objects, static_cast<std::uint32_t>(index)) == actor;
}

std::ptrdiff_t InteractFinishOffset(Context& context, const std::uintptr_t cls) noexcept {
    if (cls == 0) return kInteractFinishOffset;
    for (const auto& [cached_class, cached_offset] : context.interact_finish_offsets) {
        if (cached_class == cls) return cached_offset;
    }
    std::ptrdiff_t resolved = kInteractFinishOffset;
    std::uintptr_t owner = cls;
    for (std::uint32_t depth{}; owner != 0 && depth < 64; ++depth) {
        std::uintptr_t property{};
        Read(context, owner + kUStructPropertyLinkOffset, property);
        for (std::uint32_t count{}; property != 0 && count < 4096; ++count) {
            std::uint32_t name_id{};
            std::int32_t offset{};
            if (Read(context, property + kFFieldNameOffset, name_id) &&
                ResolveName(context, name_id) == "bInteractFinish" &&
                Read(context, property + kFPropertyOffsetInternalOffset, offset) &&
                offset > 0) {
                resolved = offset;
                owner = 0;
                break;
            }
            std::uintptr_t next{};
            if (!Read(context, property + kFPropertyLinkNextOffset, next) || next == property) {
                break;
            }
            property = next;
        }
        if (owner == 0) break;
        std::uintptr_t super{};
        if (!Read(context, owner + kUStructSuperStructOffset, super) || super == 0 ||
            super == owner) {
            break;
        }
        owner = super;
    }
    context.interact_finish_offsets.emplace_back(cls, resolved);
    return resolved;
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

// TriggerInteract is a native RPC reached through ProcessEvent; BoxAuto sets the Native flag
// for the duration of the call and restores it afterwards, and so does this probe.
bool InvokeNative(
    const Context& context,
    void* object,
    void* function,
    void* parameters) noexcept {
    if (object == nullptr || function == nullptr) return false;
    const auto flags_address = reinterpret_cast<std::uintptr_t>(function) + kUFunctionFlagsOffset;
    std::uint32_t original_flags{};
    if (!Read(context, flags_address, original_flags)) return false;
    if (!WriteUint32(context, flags_address, original_flags | kFuncNativeFlag)) return false;
    const bool invoked = InvokeProcessEvent(context, object, function, parameters);
    static_cast<void>(WriteUint32(context, flags_address, original_flags));
    return invoked;
}

// BPGetInteractEntries(controller, out TArray<int32>): the game's own answer to "is there
// an entry here right now". An empty list is why a remote ServerInteract does nothing.
bool ReadInteractChoices(
    const Context& context,
    const std::uintptr_t actor,
    const std::uintptr_t function,
    std::vector<std::int32_t>& choices) noexcept {
    std::uint8_t params[kInteractEntriesParams]{};
    std::memcpy(params + 0, &context.controller, sizeof(context.controller));
    if (!InvokeProcessEvent(
            context, reinterpret_cast<void*>(actor),
            reinterpret_cast<void*>(function), params)) {
        return false;
    }
    std::uintptr_t data{};
    std::int32_t count{};
    std::int32_t capacity{};
    std::memcpy(&data, params + 8, sizeof(data));
    std::memcpy(&count, params + 16, sizeof(count));
    std::memcpy(&capacity, params + 20, sizeof(capacity));
    if (count <= 0 || data == 0 || capacity < count || count > kMaximumInteractEntries) {
        return true;
    }
    for (std::int32_t index{}; index < count; ++index) {
        std::int32_t choice{};
        if (!Read(
                context,
                data + static_cast<std::uintptr_t>(index) * kInteractArrayStride,
                choice)) {
            return false;
        }
        choices.push_back(choice);
    }
    return true;
}

bool CanTryInteract(
    const Context& context,
    const std::uintptr_t actor,
    const std::int32_t choice,
    const std::uintptr_t function,
    bool& can_try) noexcept {
    std::uint8_t params[kCanTryParams]{};
    std::memcpy(params + 0, &context.controller, sizeof(context.controller));
    std::memcpy(params + 8, &choice, sizeof(choice));
    if (!InvokeProcessEvent(
            context, reinterpret_cast<void*>(actor),
            reinterpret_cast<void*>(function), params)) {
        return false;
    }
    can_try = params[12] != 0;
    return true;
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
    std::uintptr_t trigger{};
    if (!FindFunction(context, controller_class, "TriggerInteract", 3, 13, trigger)) {
        trigger = 0;
    }
    context.controller = controller;
    context.server_interact = fn;
    context.trigger_interact = trigger;
    Log(
        context, "probe controller=" + Hex(controller) + " class=" + Hex(controller_class) +
                     " server_interact=" + Hex(fn) + " trigger_interact=" + Hex(trigger));
    return true;
}

bool MatchesLootClass(const std::string_view class_name) noexcept {
    for (const auto prefix : kLootClassPrefixes) {
        if (class_name.find(prefix) != std::string_view::npos) return true;
    }
    return false;
}

// Class names arrive per entity class id; the frame repeats them, so they are cached.
const std::string& EntityClassName(Context& context, const std::uint64_t class_id) {
    static const std::string empty;
    for (const auto& entry : context.entity_class_names) {
        if (entry.first == class_id) return entry.second;
    }
    const auto* service = context.entities;
    if (service == nullptr || service->class_name_utf8 == nullptr) return empty;
    std::size_t size{};
    if (service->class_name_utf8(service->user, class_id, nullptr, &size).code !=
            ANOMALY_STATUS_V1_OK ||
        size <= 1 || size > kMaximumNameBytes) {
        context.entity_class_names.emplace_back(class_id, std::string{});
        return context.entity_class_names.back().second;
    }
    std::string name(size, '\0');
    if (service->class_name_utf8(service->user, class_id, name.data(), &size).code !=
        ANOMALY_STATUS_V1_OK) {
        context.entity_class_names.emplace_back(class_id, std::string{});
        return context.entity_class_names.back().second;
    }
    if (const void* terminator = std::memchr(name.data(), '\0', name.size());
        terminator != nullptr) {
        name.resize(static_cast<const char*>(terminator) - name.data());
    }
    context.entity_class_names.emplace_back(class_id, std::move(name));
    return context.entity_class_names.back().second;
}

// Target acquisition, the way PinkPawHeistESP does it: page the Host's entity frame and keep
// the loot actors it already knows about. No GObjects walk - each match costs one object
// lookup, so a press stays cheap on the game thread.
bool CollectTargets(Context& context) {
    context.scan = ScanResult{};
    const auto* service = context.entities;
    if (service == nullptr || service->frame == nullptr || service->page == nullptr ||
        service->class_name_utf8 == nullptr) {
        Log(context, "probe entity service unavailable");
        return false;
    }
    if (context.g_objects_address == 0 &&
        !ResolveRip(
            context, kGObjectsPattern, kGObjectsAddend, context.g_objects_address)) {
        Log(context, "probe resolve GObjects failed");
        return false;
    }
    AnomalyNteEntityFrameV1 frame{sizeof(frame)};
    if (service->frame(service->user, &frame).code != ANOMALY_STATUS_V1_OK ||
        frame.generation == 0 || frame.entity_count == 0) {
        Log(context, "probe entity frame unavailable");
        return false;
    }
    context.scan.g_objects = context.g_objects_address;
    context.scan.entity_count = frame.entity_count;
    std::array<AnomalyNteEntitySnapshotV1, kEntityPageCapacity> page{};
    std::uint32_t offset{};
    while (offset < frame.entity_count && context.scan.candidates.size() < kMaximumCandidates) {
        for (auto& snapshot : page) snapshot = AnomalyNteEntitySnapshotV1{sizeof(snapshot)};
        AnomalyNteEntityPageRequestV1 request{};
        request.struct_size = sizeof(request);
        request.generation = frame.generation;
        request.offset = offset;
        request.capacity = static_cast<std::uint32_t>(page.size());
        AnomalyNteEntityPageResultV1 result{sizeof(result)};
        if (service->page(service->user, &request, page.data(), &result).code !=
                ANOMALY_STATUS_V1_OK ||
            result.generation != frame.generation || result.returned == 0) {
            break;
        }
        for (std::uint32_t index{}; index < result.returned; ++index) {
            const auto& snapshot = page[index];
            if ((snapshot.flags & ANOMALY_NTE_SNAPSHOT_V1_VALID) == 0 ||
                snapshot.entity_id == 0) {
                continue;
            }
            const std::string& class_name = EntityClassName(context, snapshot.class_id);
            if (class_name.empty() || !MatchesLootClass(class_name)) continue;
            if (context.scan.candidates.size() >= kMaximumCandidates) break;
            // Entity id is the Host object index plus one, so this is a single slot lookup.
            const auto actor = ObjectAt(
                context, context.g_objects_address,
                static_cast<std::uint32_t>(snapshot.entity_id - 1U));
            if (actor == 0) continue;
            const double dx = snapshot.bounds_center[0] - frame.camera_position[0];
            const double dy = snapshot.bounds_center[1] - frame.camera_position[1];
            context.scan.candidates.push_back(
                {actor, class_name, std::sqrt(dx * dx + dy * dy)});
        }
        offset = result.next_offset > offset ? result.next_offset : offset + result.returned;
    }
    // The buttons act on the box the player is standing next to, like BoxAuto does after it
    // has closed the distance, so the nearest candidate has to come first.
    std::sort(
        context.scan.candidates.begin(), context.scan.candidates.end(),
        [](const Candidate& left, const Candidate& right) {
            return left.distance < right.distance;
        });
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

// Localizer::Format consumes string views, so the owning strings stay alive in `values`.
template <std::size_t N>
std::array<std::string_view, N> Views(const std::array<std::string, N>& values) noexcept {
    std::array<std::string_view, N> views{};
    for (std::size_t index = 0; index < N; ++index) {
        views[index] = values[index];
    }
    return views;
}

void AddReportLine(std::vector<std::string>& out, std::string line) {
    out.push_back(std::move(line));
}

void AddError(
    Context& context,
    std::vector<std::string>& out,
    const std::string_view code,
    const std::string& detail) {
    const std::array arguments{code, std::string_view(detail)};
    AddReportLine(out, context.localizer.Format("status.error", "{0} - {1}", arguments));
}

void AddScanLine(
    Context& context,
    std::vector<std::string>& out,
    const ScanResult& scan) {
    const std::array<std::string, 2> arguments{
        std::to_string(scan.entity_count),
        std::to_string(scan.candidates.size())};
    AddReportLine(out, context.localizer.Format(
        "status.scan", "Entities {0}, loot targets {1}", Views(arguments)));
}

// Read-only pass over the class filter, run once when the plugin loads: it calls no BP
// function and interacts with nothing, so the first log line of a session says whether the
// prefix set matches anything in this world at all.
void RunDiagnostic(
    Context& context,
    const ScanResult& scan,
    std::vector<std::string>& out) {
    AddScanLine(context, out, scan);
    std::size_t shown{};
    for (const auto& candidate : scan.candidates) {
        if (shown >= 8) break;
        std::string line = candidate.class_name + " " + Hex(candidate.actor);
        Log(context, "probe diagnostic candidate=" + line);
        AddReportLine(out, std::move(line));
        ++shown;
    }
}

// Snapshots bInteractFinish and schedules the post-interact check, so a press reports what
// the box did rather than what dispatch returned.
void BeginVerify(
    Context& context,
    const std::uintptr_t actor,
    const std::uintptr_t cls,
    const std::string_view class_name) {
    std::uint8_t baseline{};
    Read(context, actor + InteractFinishOffset(context, cls), baseline);
    context.verify.active = true;
    context.verify.actor = actor;
    context.verify.baseline = baseline;
    context.verify.due = std::chrono::steady_clock::now() + kVerifyDelay;
    Log(
        context, "probe interact fired actor=" + Hex(actor) + " class=" +
                     std::string(class_name) + " baseline=" + std::to_string(baseline));
}

// BoxAuto's order: arm the entry through the actor, fire the controller's TriggerInteract,
// and only fall back to ServerInteract when the actor offers no entry at all.
// The box the player is standing next to. BoxAuto closes the distance before it interacts;
// the probe refuses instead of firing at a box across the map, which is why the report says
// "too far" rather than silently doing nothing.
const Candidate* NearestTarget(const ScanResult& scan) noexcept {
    for (const auto& candidate : scan.candidates) {
        if (candidate.distance <= kInteractTargetRadiusCentimeters) return &candidate;
    }
    return nullptr;
}

void ReportTooFar(
    Context& context,
    const ScanResult& scan,
    std::vector<std::string>& out) {
    const std::string nearest = scan.candidates.empty()
        ? std::string("n/a")
        : std::to_string(static_cast<long long>(scan.candidates.front().distance));
    const std::array<std::string, 1> arguments{nearest};
    AddReportLine(out, context.localizer.Format(
        "status.no_target",
        "Nearest loot actor is {0} cm away; stand next to the box and press again",
        Views(arguments)));
    Log(context, "probe no-target nearest=" + nearest);
}

// Method 1 - BoxAuto's open-box call: ServerInteract(actor, 0) on the player controller with
// a twelve byte parameter block that only carries the actor pointer.
void RunServerInteract(
    Context& context,
    const ScanResult& scan,
    std::vector<std::string>& out) {
    AddScanLine(context, out, scan);
    if (scan.candidates.empty()) {
        AddReportLine(
            out, context.localizer.Text("status.no_candidates", "No candidate objects"));
        return;
    }
    if (!GetController(context)) {
        AddError(context, out, "PROFILE", "ServerInteract");
        return;
    }
    const Candidate* target = NearestTarget(scan);
    if (target == nullptr) {
        ReportTooFar(context, scan, out);
        return;
    }
    std::uintptr_t cls{};
    Read(context, target->actor + kObjectClassOffset, cls);
    std::uint8_t params[kServerInteractParams]{};
    std::memcpy(params, &target->actor, sizeof(target->actor));
    const bool dispatched = InvokeProcessEvent(
        context, reinterpret_cast<void*>(context.controller),
        reinterpret_cast<void*>(context.server_interact), params);
    Log(
        context, "probe server-interact actor=" + Hex(target->actor) + " class=" +
                     target->class_name + " cm=" +
                     std::to_string(static_cast<long long>(target->distance)) +
                     " dispatched=" + std::to_string(dispatched ? 1 : 0));
    if (!dispatched) {
        AddError(context, out, "SERVERINTERACT", "dispatch failed");
        return;
    }
    BeginVerify(context, target->actor, cls, target->class_name);
    const std::array<std::string, 2> arguments{
        target->class_name, std::to_string(static_cast<long long>(target->distance))};
    AddReportLine(out, context.localizer.Format(
        "status.server", "ServerInteract sent to {0} ({1} cm)", Views(arguments)));
}

// Method 2 - BoxAuto's TriggerInteractPickup: read the actor's interact entries, ask
// BPCanTryInteract whether a choice is armed, then perform it with
// TriggerInteract(actor, choice, onlyClientSide = 0) on the controller. This is the path the
// Host's own nte.pickup bridge runs internally.
void RunTriggerInteract(
    Context& context,
    const ScanResult& scan,
    std::vector<std::string>& out) {
    AddScanLine(context, out, scan);
    if (scan.candidates.empty()) {
        AddReportLine(
            out, context.localizer.Text("status.no_candidates", "No candidate objects"));
        return;
    }
    if (!GetController(context)) {
        AddError(context, out, "PROFILE", "TriggerInteract");
        return;
    }
    const Candidate* target = NearestTarget(scan);
    if (target == nullptr) {
        ReportTooFar(context, scan, out);
        return;
    }
    const auto actor = target->actor;
    std::uintptr_t cls{};
    Read(context, actor + kObjectClassOffset, cls);
    std::uintptr_t entries_fn{};
    std::uintptr_t can_try_fn{};
    std::vector<std::int32_t> choices;
    const bool has_fns =
        cls != 0 &&
        FindFunction(context, cls, "BPGetInteractEntries", 2, 24, entries_fn) &&
        FindFunction(context, cls, "BPCanTryInteract", 3, 13, can_try_fn);
    const bool has_choices =
        has_fns && ReadInteractChoices(context, actor, entries_fn, choices);
    std::size_t can_try_total{};
    bool fired{};
    std::string choice_used;
    if (has_choices) {
        for (const auto choice : choices) {
            bool can_try{};
            if (!CanTryInteract(context, actor, choice, can_try_fn, can_try) || !can_try) {
                continue;
            }
            ++can_try_total;
            if (context.trigger_interact == 0) continue;
            std::uint8_t params[kTriggerInteractParams]{};
            std::memcpy(params + 0, &actor, sizeof(actor));
            std::memcpy(params + 8, &choice, sizeof(choice));
            params[12] = 0;
            if (InvokeNative(
                    context, reinterpret_cast<void*>(context.controller),
                    reinterpret_cast<void*>(context.trigger_interact), params)) {
                fired = true;
                choice_used = std::to_string(choice);
                break;
            }
        }
    }
    Log(
        context, "probe trigger actor=" + Hex(actor) + " class=" + target->class_name +
                     " cm=" + std::to_string(static_cast<long long>(target->distance)) +
                     " fns=" + std::to_string(has_fns ? 1 : 0) +
                     " entries=" + std::to_string(choices.size()) +
                     " can_try=" + std::to_string(can_try_total) +
                     " trigger_fn=" + Hex(context.trigger_interact) +
                     " fired=" + std::to_string(fired ? 1 : 0));
    if (!fired) {
        const std::array<std::string, 3> arguments{
            std::to_string(has_fns ? 1 : 0), std::to_string(choices.size()),
            std::to_string(can_try_total)};
        AddReportLine(out, context.localizer.Format(
            "status.trigger_miss",
            "Not armed: functions {0}, entries {1}, can-try {2} (trigger {3})",
            Views(arguments)));
        return;
    }
    BeginVerify(context, actor, cls, target->class_name);
    const std::array<std::string, 2> arguments{target->class_name, choice_used};
    AddReportLine(out, context.localizer.Format(
        "status.trigger", "TriggerInteract {1} on {0}", Views(arguments)));
}

// Method 3 - BoxAuto's food path: it never touches the actor for these, it asks the Host for
// request_nearby(radius 600, one item) and reads the confirmation off the pickup snapshot.
void RunHostPickup(
    Context& context,
    const ScanResult& scan,
    std::vector<std::string>& out) {
    AddScanLine(context, out, scan);
    const auto* service = context.pickup;
    if (service == nullptr || service->request_nearby == nullptr ||
        service->snapshot == nullptr) {
        AddError(context, out, "PICKUP", "nte.pickup unavailable");
        return;
    }
    AnomalyNtePickupSnapshotV1 baseline{sizeof(baseline)};
    if (service->snapshot(service->user, &baseline).code != ANOMALY_STATUS_V1_OK) {
        AddError(context, out, "PICKUP", "snapshot failed");
        return;
    }
    AnomalyNtePickupRequestV1 request{sizeof(request)};
    request.flags = ANOMALY_NTE_PICKUP_V1_NONE;
    request.radius = kPickupRadiusCentimeters;
    request.maximum_items = kPickupMaximumItems;
    const AnomalyStatusV1 status = service->request_nearby(service->user, &request);
    Log(
        context, "probe pickup request radius=" +
                     std::to_string(static_cast<int>(kPickupRadiusCentimeters)) +
                     " items=" + std::to_string(kPickupMaximumItems) + " baseline=" +
                     std::to_string(baseline.sequence) + " status=" +
                     std::to_string(status.code));
    if (status.code != ANOMALY_STATUS_V1_OK) {
        AddError(context, out, "PICKUP", "request_nearby rejected");
        return;
    }
    context.pickup_watch.active = true;
    context.pickup_watch.baseline = baseline.sequence;
    context.pickup_watch.deadline = std::chrono::steady_clock::now() + kPickupTimeout;
    AddReportLine(out, context.localizer.Text(
        "status.pickup_waiting", "Pickup requested, waiting for the Host"));
}

// The Host runs a pickup request over several ticks; the verdict only exists once its
// sequence advances, so the probe reads it back instead of assuming the call meant success.
void PollPickup(Context& context) {
    if (!context.pickup_watch.active) return;
    const auto* service = context.pickup;
    if (service == nullptr || service->snapshot == nullptr) {
        context.pickup_watch.active = false;
        return;
    }
    AnomalyNtePickupSnapshotV1 snapshot{sizeof(snapshot)};
    const bool read = service->snapshot(service->user, &snapshot).code == ANOMALY_STATUS_V1_OK;
    const bool valid = read && (snapshot.flags & ANOMALY_NTE_PICKUP_V1_VALID) != 0;
    const bool finished = valid && snapshot.sequence > context.pickup_watch.baseline &&
        snapshot.state == ANOMALY_NTE_PICKUP_V1_COMPLETE;
    const bool expired = std::chrono::steady_clock::now() >= context.pickup_watch.deadline;
    if (!finished && !expired) return;
    context.pickup_watch.active = false;
    const std::array<std::string, 4> arguments{
        std::to_string(snapshot.confirmed), std::to_string(snapshot.triggered),
        std::to_string(snapshot.nearby), std::to_string(snapshot.unconfirmed)};
    const std::string line = finished
        ? context.localizer.Format(
              "status.pickup_done", "Pickup done: confirmed {0}, fired {1}, nearby {2}, open {3}",
              Views(arguments))
        : context.localizer.Format(
              "status.pickup_timeout", "Pickup timed out: confirmed {0}, fired {1}, nearby {2}, open {3}",
              Views(arguments));
    Log(
        context, "probe pickup seq=" + std::to_string(snapshot.sequence) +
                     " state=" + std::to_string(snapshot.state) +
                     " nearby=" + std::to_string(snapshot.nearby) +
                     " triggered=" + std::to_string(snapshot.triggered) +
                     " confirmed=" + std::to_string(snapshot.confirmed) +
                     " unconfirmed=" + std::to_string(snapshot.unconfirmed) +
                     " finished=" + std::to_string(finished ? 1 : 0));
    std::scoped_lock lock(context.mutex);
    context.report.push_back(line);
}


// PinkPawHeistESP's route: the container vtable lives at actor+872 and its slot 3 must still
// hold the resolved pickup entry. The scan is only the fallback for classes that keep the
// interface somewhere else.
void RunVtable(
    Context& context,
    const ScanResult& scan,
    std::vector<std::string>& out) {
    AddScanLine(context, out, scan);
    if (scan.candidates.empty()) {
        AddReportLine(
            out, context.localizer.Text("status.no_candidates", "No candidate objects"));
        return;
    }
    if (!ResolvePickupFunction(context)) {
        AddError(context, out, "SIGNATURE", "pickup");
        return;
    }
    if (!GetController(context)) {
        AddError(context, out, "PROFILE", "ServerInteract");
        return;
    }
    std::size_t tried{};
    std::size_t accepted{};
    std::size_t rejected{};
    std::size_t missing{};
    std::string first_hit;
    for (const auto& candidate : scan.candidates) {
        InterfaceHit hit{};
        const auto known_vtable = ReadPointer(context, candidate.actor + kPinkPawInterfaceOffset);
        if (known_vtable != 0 &&
            ReadPointer(
                context, known_vtable + kPinkPawPickupSlot * sizeof(void*)) ==
                context.pickup_function) {
            hit.offset = kPinkPawInterfaceOffset;
            hit.slot = kPinkPawPickupSlot;
        } else if (!FindInterface(context, candidate.actor, hit)) {
            ++missing;
            Log(
                context, "probe vtable no-interface actor=" + Hex(candidate.actor) +
                             " vtable@872=" + Hex(known_vtable) + " class=" +
                             candidate.class_name);
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
        Log(
            context, "probe vtable actor=" + Hex(candidate.actor) + " class=" +
                         candidate.class_name + " offset=" + Hex(hit.offset) + " slot=" +
                         std::to_string(hit.slot) + " returned=" +
                         std::to_string(returned ? 1 : 0));
        if (first_hit.empty()) {
            const std::array<std::string, 3> arguments{
                candidate.class_name, Hex(hit.offset), std::to_string(hit.slot)};
            first_hit = context.localizer.Format(
                "status.interface", "First interface: {0} at {1} slot {2}", Views(arguments));
        }
        if (returned) break;
    }
    const std::array<std::string, 5> arguments{
        std::to_string(scan.candidates.size()), std::to_string(tried),
        std::to_string(accepted), std::to_string(rejected), std::to_string(missing)};
    AddReportLine(out, context.localizer.Format(
        "status.vtable",
        "Vtable: candidates {0}, tried {1}, true {2}, false {3}, no interface {4}",
        Views(arguments)));
    if (!first_hit.empty()) AddReportLine(out, std::move(first_hit));
}

// The 3-second follow-up: a box that opened either flipped bInteractFinish or left the
// world. Anything else means the call was accepted and then ignored by the game.
void CompleteVerify(Context& context) {
    if (!context.verify.active) return;
    if (std::chrono::steady_clock::now() < context.verify.due) return;
    const auto actor = context.verify.actor;
    const auto baseline = context.verify.baseline;
    context.verify.active = false;
    std::uintptr_t cls{};
    Read(context, actor + kObjectClassOffset, cls);
    std::uint8_t current{};
    const bool read =
        Read(context, actor + InteractFinishOffset(context, cls), current);
    const bool alive = IsObjectAlive(context, context.g_objects_address, actor);
    const bool opened = (read && current != baseline) || !alive;
    const std::string verdict =
        opened ? context.localizer.Text("verify.opened", "opened")
               : context.localizer.Text("verify.unchanged", "unchanged");
    const std::array<std::string, 4> arguments{
        std::to_string(baseline), read ? std::to_string(current) : std::string("n/a"),
        alive ? std::string("1") : std::string("0"), verdict};
    const std::string line = context.localizer.Format(
        "status.verify",
        "After 3s: bInteractFinish {0} -> {1}, alive {2}, verdict {3}",
        Views(arguments));
    Log(
        context, "probe verify actor=" + Hex(actor) + " baseline=" + std::to_string(baseline) +
                     " current=" + (read ? std::to_string(current) : std::string("n/a")) +
                     " alive=" + std::to_string(alive ? 1 : 0) +
                     " opened=" + std::to_string(opened ? 1 : 0));
    std::scoped_lock lock(context.mutex);
    context.report.push_back(line);
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
    context->entities = Query<AnomalyNteEntitiesServiceV1>(
        host, ANOMALY_NTE_ENTITIES_SERVICE_V1_ID, ANOMALY_NTE_ENTITIES_SERVICE_V1_VERSION);
    context->pickup = Query<AnomalyNtePickupServiceV1>(
        host, ANOMALY_NTE_PICKUP_SERVICE_V1_ID, ANOMALY_NTE_PICKUP_SERVICE_V1_VERSION);
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
    // One automatic read-only pass, so a session always leaves a record of what the class
    // filter sees even if nobody presses a button.
    context->pending = Action::diagnostic;
    Log(*context, "probe start");
    return anomaly::sdk::Ok();
}

AnomalyStatusV1 ANOMALY_CALL Stop(void* user, std::uint32_t) {
    auto* context = static_cast<Context*>(user);
    if (context == nullptr) return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT);
    std::scoped_lock lock(context->mutex);
    context->started = false;
    context->pending = Action::none;
    context->running = Action::none;
    context->scan = ScanResult{};
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
    {
        std::scoped_lock lock(context->mutex);
        if (!context->started) return;
    }
    // Both verdicts arrive on a later game tick than the press that started them: the box
    // state check three seconds out, the pickup snapshot once the Host finishes its request.
    // They have to run while the probe is idle, otherwise a press never reports its result.
    CompleteVerify(*context);
    PollPickup(*context);
    {
        std::scoped_lock lock(context->mutex);
        if (context->running == Action::none) {
            if (context->pending == Action::none) return;
            context->running = context->pending;
            context->pending = Action::none;
            context->report.clear();
        }
    }
    Action running{Action::none};
    {
        std::scoped_lock lock(context->mutex);
        running = context->running;
    }
    std::vector<std::string> out;
    if (!CollectTargets(*context)) {
        AddError(*context, out, "ENTITIES", "entity frame");
        Log(*context, "probe collect targets failed");
        std::scoped_lock lock(context->mutex);
        context->running = Action::none;
        context->report = std::move(out);
        return;
    }
    Log(
        *context, "probe collect entities=" + std::to_string(context->scan.entity_count) +
                      " targets=" + std::to_string(context->scan.candidates.size()) +
                      " action=" + std::to_string(static_cast<int>(running)));
    if (running == Action::server_interact) {
        RunServerInteract(*context, context->scan, out);
    } else if (running == Action::trigger_interact) {
        RunTriggerInteract(*context, context->scan, out);
    } else if (running == Action::host_pickup) {
        RunHostPickup(*context, context->scan, out);
    } else if (running == Action::vtable) {
        RunVtable(*context, context->scan, out);
    } else {
        RunDiagnostic(*context, context->scan, out);
    }
    if (out.empty()) {
        AddError(*context, out, "PROBE", "no report");
    }
    std::scoped_lock lock(context->mutex);
    context->running = Action::none;
    context->report = std::move(out);
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
    // One button per pickup implementation BoxAuto reaches for, plus the container call
    // PinkPawHeistESP uses, so a press says which mechanism the game actually honours. The
    // labels are literal calls so the localization check can see every key in use.
    const std::string server_label = context->localizer.Label(
        "action.server", "ServerInteract(actor)", "pickup-probe-server");
    if (ui->button_enabled(
            ui->user, anomaly::sdk::StringView(server_label), 0.0F, 0.0F, 1) != 0) {
        std::scoped_lock lock(context->mutex);
        context->pending = Action::server_interact;
    }
    const std::string trigger_label = context->localizer.Label(
        "action.trigger", "TriggerInteract(entry)", "pickup-probe-trigger");
    if (ui->button_enabled(
            ui->user, anomaly::sdk::StringView(trigger_label), 0.0F, 0.0F, 1) != 0) {
        std::scoped_lock lock(context->mutex);
        context->pending = Action::trigger_interact;
    }
    const std::string pickup_label = context->localizer.Label(
        "action.pickup", "Host pickup (food boxes)", "pickup-probe-pickup");
    if (ui->button_enabled(
            ui->user, anomaly::sdk::StringView(pickup_label), 0.0F, 0.0F, 1) != 0) {
        std::scoped_lock lock(context->mutex);
        context->pending = Action::host_pickup;
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
            "status.idle",
            "Idle. Stand next to a box, then press the method you want to test.");
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
