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

constexpr std::uint32_t kRipDisplacementOffset = 3;
constexpr std::uint32_t kRipInstructionSize = 7;
constexpr std::ptrdiff_t kGObjectsAddend = -16;

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


// `bInteractFinish` moved from 976 to 984 in the 9/26 build; resolve it by name and keep
// the old offset as the fallback, the way BoxAuto does.
constexpr std::ptrdiff_t kInteractFinishOffset = 976;
constexpr auto kVerifyDelay = std::chrono::milliseconds(3000);

constexpr std::size_t kMaximumNameBytes = 1024;
// The actor frame answers in pages of at most this many entries.
constexpr std::size_t kEntityPageCapacity = ANOMALY_NTE_ENTITY_PAGE_V1_MAX_CAPACITY;
// How many entries of a whole-map scan the report lists; the log carries all of them.
constexpr std::size_t kScanReportLines = 12;
// BoxAuto lands its teleports 60 cm above the point so the character drops onto the box
// instead of spawning inside it.
constexpr double kTeleportZOffsetCentimeters = 60.0;

// Class-name fragments a world safe, locker or vault is instantiated under. These are not
// resource boxes, so BoxAuto never touches them and the probe needs its own needle list.
constexpr std::array<std::string_view, 4> kSafeClassNeedles{
    "CabinetKey", "Locker", "SafeBox", "Vault"};
// How many of the closest actors the safe press writes to the log, so a run that finds
// nothing still says what is actually standing around the player.
constexpr std::size_t kNearActorReportLines = 6;
// A world safe is placed against a wall, so its origin sits further from the player than a
// loot box on open ground; the interaction still resolves at this range.
constexpr double kSafeTargetRadiusCentimeters = 1200.0;

enum class Action : std::uint32_t {
    none = 0,
    safe = 1,
    unlock = 2,
    scan = 3,
    teleport = 4,
};


struct Candidate final {
    std::uintptr_t actor{};
    std::string class_name;
    // Actor bounds centre, in world centimetres; a teleport aims at this.
    double position[3]{};
    // Planar distance from the player camera, in centimetres.
    double distance{};
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
    const AnomalyNteActorsServiceV1* actors{};
    const AnomalyNteSessionServiceV1* session{};
    const AnomalyNtePlayerServiceV1* player{};
    const AnomalyNtePlayerTeleportServiceV1* teleport{};
    std::uintptr_t g_objects_address{};
    std::uintptr_t g_world_address{};
    std::uintptr_t controller{};
    std::uintptr_t server_interact{};
    std::uintptr_t trigger_interact{};
    bool started{};
    // One read-only actor pass per session, so the log names what is around the player even
    // before any button is pressed.
    bool actor_probe_done{};
    // `pending` is the render-to-game handoff; `running` and `verify` belong to Update alone.
    Action pending{Action::none};
    Action running{Action::none};
    VerifyState verify;
    // Result of the last whole-map scan, kept so a later teleport can aim at an entry, and the
    // entry index the window's number input selects.
    std::vector<Candidate> safes;
    std::uint32_t teleport_index{};
    std::vector<std::pair<std::uint64_t, std::string>> actor_class_names;
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

// World positions are centimetres, so the report rounds them to whole units.
std::string FormatPosition(const double position[3]) {
    auto whole = [](const double value) {
        return std::to_string(static_cast<long long>(std::llround(value)));
    };
    return "(" + whole(position[0]) + ", " + whole(position[1]) + ", " + whole(position[2]) + ")";
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

// The NTE services only exist once the game world is up: a plugin loaded at boot queries
// nulls and would stay dead for the whole session, so every press retries the query first.
void EnsureServices(Context& context) {
    if (context.actors == nullptr) {
        context.actors = Query<AnomalyNteActorsServiceV1>(
            context.host, ANOMALY_NTE_ACTORS_SERVICE_V1_ID,
            ANOMALY_NTE_ACTORS_SERVICE_V1_VERSION);
    }
    if (context.session == nullptr) {
        context.session = Query<AnomalyNteSessionServiceV1>(
            context.host, ANOMALY_NTE_SESSION_SERVICE_V1_ID,
            ANOMALY_NTE_SESSION_SERVICE_V1_VERSION);
    }
    if (context.player == nullptr) {
        context.player = Query<AnomalyNtePlayerServiceV1>(
            context.host, ANOMALY_NTE_PLAYER_SERVICE_V1_ID,
            ANOMALY_NTE_PLAYER_SERVICE_V1_VERSION);
    }
    if (context.teleport == nullptr) {
        context.teleport = Query<AnomalyNtePlayerTeleportServiceV1>(
            context.host, ANOMALY_NTE_PLAYER_TELEPORT_SERVICE_V1_ID,
            ANOMALY_NTE_PLAYER_TELEPORT_SERVICE_V1_VERSION);
    }
}

bool MatchesSafeClass(const std::string_view class_name) noexcept {
    for (const auto needle : kSafeClassNeedles) {
        if (class_name.find(needle) != std::string_view::npos) return true;
    }
    return false;
}

// Actor discovery is a different Host service from the entity frame: it pages every loaded
// actor, which is what makes a world safe visible at all - being a level actor, it never
// shows up in the loot-oriented entity frame.
const std::string& ActorClassName(Context& context, const std::uint64_t class_id) {
    static const std::string empty;
    for (const auto& entry : context.actor_class_names) {
        if (entry.first == class_id) return entry.second;
    }
    const auto* service = context.actors;
    if (service == nullptr || service->class_name_utf8 == nullptr) return empty;
    std::size_t size{};
    if (service->class_name_utf8(service->user, class_id, nullptr, &size).code !=
            ANOMALY_STATUS_V1_OK ||
        size <= 1 || size > kMaximumNameBytes) {
        context.actor_class_names.emplace_back(class_id, std::string{});
        return context.actor_class_names.back().second;
    }
    std::string name(size, '\0');
    if (service->class_name_utf8(service->user, class_id, name.data(), &size).code !=
        ANOMALY_STATUS_V1_OK) {
        context.actor_class_names.emplace_back(class_id, std::string{});
        return context.actor_class_names.back().second;
    }
    if (const void* terminator = std::memchr(name.data(), '\0', name.size());
        terminator != nullptr) {
        name.resize(static_cast<const char*>(terminator) - name.data());
    }
    context.actor_class_names.emplace_back(class_id, std::move(name));
    return context.actor_class_names.back().second;
}

// One pass over the actor frame fills two lists: every safe-like actor, and the nearest few
// actors of any class so a miss can still name what the player is standing next to.
bool CollectNearbyActors(
    Context& context,
    std::vector<Candidate>& safes,
    std::vector<Candidate>& nearest) {
    safes.clear();
    nearest.clear();
    EnsureServices(context);
    const auto* service = context.actors;
    if (service == nullptr || service->frame == nullptr || service->page == nullptr ||
        service->class_name_utf8 == nullptr) {
        Log(context, "probe actor service unavailable");
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
        Log(context, "probe actor frame unavailable");
        return false;
    }
    std::array<AnomalyNteEntitySnapshotV1, kEntityPageCapacity> page{};
    std::uint32_t offset{};
    std::vector<Candidate> all;
    while (offset < frame.entity_count) {
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
            const std::string& class_name = ActorClassName(context, snapshot.class_id);
            if (class_name.empty()) continue;
            const auto actor = ObjectAt(
                context, context.g_objects_address,
                static_cast<std::uint32_t>(snapshot.entity_id - 1U));
            if (actor == 0) continue;
            const double dx = snapshot.bounds_center[0] - frame.camera_position[0];
            const double dy = snapshot.bounds_center[1] - frame.camera_position[1];
            Candidate candidate{actor, class_name, {}, std::sqrt(dx * dx + dy * dy)};
            candidate.position[0] = snapshot.bounds_center[0];
            candidate.position[1] = snapshot.bounds_center[1];
            candidate.position[2] = snapshot.bounds_center[2];
            all.push_back(candidate);
            if (MatchesSafeClass(class_name)) safes.push_back(candidate);
        }
        offset = result.next_offset > offset ? result.next_offset : offset + result.returned;
    }
    std::sort(
        all.begin(), all.end(),
        [](const Candidate& left, const Candidate& right) {
            return left.distance < right.distance;
        });
    std::sort(
        safes.begin(), safes.end(),
        [](const Candidate& left, const Candidate& right) {
            return left.distance < right.distance;
        });
    const auto keep = std::min(all.size(), kNearActorReportLines);
    nearest.assign(all.begin(), all.begin() + static_cast<std::ptrdiff_t>(keep));
    Log(
        context, "probe actor frame actors=" + std::to_string(frame.entity_count) +
                     " safes=" + std::to_string(safes.size()));
    return true;
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

// Method 5 - a world safe, locker or vault. BoxAuto has no path for these: they are level
// actors, not resource boxes, so neither the table scan nor the entity frame ever sees them.
// The probe finds the closest safe-like actor through the actor service, then tries the two
// calls BoxAuto uses on interactables - the entry chain first, ServerInteract second - and
// reports which one the game answered.
void RunSafe(Context& context, std::vector<std::string>& out) {
    std::vector<Candidate> safes;
    std::vector<Candidate> nearest;
    if (!CollectNearbyActors(context, safes, nearest)) {
        AddError(context, out, "ACTORS", "actor frame");
        return;
    }
    for (const auto& candidate : nearest) {
        Log(
            context, "probe near class=" + candidate.class_name + " cm=" +
                         std::to_string(static_cast<long long>(candidate.distance)));
    }
    const Candidate* target{};
    for (const auto& candidate : safes) {
        if (candidate.distance <= kSafeTargetRadiusCentimeters) {
            target = &candidate;
            break;
        }
    }
    if (target == nullptr) {
        std::string nearest_class = "n/a";
        std::string nearest_distance = "n/a";
        if (!safes.empty()) {
            nearest_class = safes.front().class_name;
            nearest_distance = std::to_string(
                static_cast<long long>(safes.front().distance));
        } else if (!nearest.empty()) {
            nearest_class = nearest.front().class_name;
            nearest_distance = std::to_string(
                static_cast<long long>(nearest.front().distance));
        }
        Log(
            context, "probe safe none safes=" + std::to_string(safes.size()) +
                         " nearest=" + nearest_class + " cm=" + nearest_distance);
        const std::array<std::string, 2> arguments{nearest_class, nearest_distance};
        AddReportLine(out, context.localizer.Format(
            "status.safe_none",
            "No safe within reach; nearest object is {0} at {1} cm",
            Views(arguments)));
        return;
    }
    if (!GetController(context)) {
        AddError(context, out, "PROFILE", "ServerInteract");
        return;
    }
    const auto actor = target->actor;
    std::uintptr_t cls{};
    Read(context, actor + kObjectClassOffset, cls);
    std::uintptr_t entries_fn{};
    std::uintptr_t can_try_fn{};
    std::vector<std::int32_t> choices;
    const bool has_fns = cls != 0 &&
        FindFunction(context, cls, "BPGetInteractEntries", 2, 24, entries_fn) &&
        FindFunction(context, cls, "BPCanTryInteract", 3, 13, can_try_fn);
    const bool has_choices = has_fns && ReadInteractChoices(context, actor, entries_fn, choices);
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
    bool server_fired{};
    if (!fired && context.server_interact != 0) {
        std::uint8_t params[kServerInteractParams]{};
        std::memcpy(params, &actor, sizeof(actor));
        server_fired = InvokeProcessEvent(
            context, reinterpret_cast<void*>(context.controller),
            reinterpret_cast<void*>(context.server_interact), params);
    }
    std::string choice_list;
    for (std::size_t index{}; index < choices.size() && index < 8; ++index) {
        if (!choice_list.empty()) choice_list.push_back(',');
        choice_list += std::to_string(choices[index]);
    }
    Log(
        context, "probe safe actor=" + Hex(actor) + " class=" + target->class_name +
                     " cm=" + std::to_string(static_cast<long long>(target->distance)) +
                     " fns=" + std::to_string(has_fns ? 1 : 0) + " entries=" +
                     std::to_string(choices.size()) + " [" + choice_list + "] can_try=" +
                     std::to_string(can_try_total) + " fired=" +
                     std::to_string(fired ? 1 : 0) + " server=" +
                     std::to_string(server_fired ? 1 : 0));
    if (!fired && !server_fired) {
        const std::array<std::string, 3> arguments{
            std::to_string(has_fns ? 1 : 0), std::to_string(choices.size()),
            std::to_string(can_try_total)};
        AddReportLine(out, context.localizer.Format(
            "status.safe_miss",
            "Safe did not answer: functions {0}, entries {1}, can-try {2}, ServerInteract 0",
            Views(arguments)));
        return;
    }
    BeginVerify(context, actor, cls, target->class_name);
    const std::array<std::string, 2> arguments{
        target->class_name, std::to_string(static_cast<long long>(target->distance))};
    AddReportLine(out, context.localizer.Format(
        "status.safe_sent", "Interacted with {0} ({1} cm), checking in 3 s", Views(arguments)));
}

// Skips the lock-picking minigame. A world safe is not looted by interacting: the interact
// call only opens the minigame, and the safe yields when that minigame reports success. The
// blueprint exposes that report as its own event (BP_ClientUnlockTreasureBox, then
// BP_OnOpenSuccess / BP_OnOpen on the variants that carry them), so calling it directly is
// the same thing the minigame would have done, minus the minigame.
void RunUnlock(Context& context, std::vector<std::string>& out) {
    std::vector<Candidate> safes;
    std::vector<Candidate> nearest;
    if (!CollectNearbyActors(context, safes, nearest)) {
        AddError(context, out, "ACTORS", "actor frame");
        return;
    }
    const Candidate* target{};
    for (const auto& candidate : safes) {
        if (candidate.distance <= kSafeTargetRadiusCentimeters) {
            target = &candidate;
            break;
        }
    }
    if (target == nullptr) {
        std::string nearest_class = "n/a";
        std::string nearest_distance = "n/a";
        if (!safes.empty()) {
            nearest_class = safes.front().class_name;
            nearest_distance = std::to_string(
                static_cast<long long>(safes.front().distance));
        } else if (!nearest.empty()) {
            nearest_class = nearest.front().class_name;
            nearest_distance = std::to_string(
                static_cast<long long>(nearest.front().distance));
        }
        Log(
            context, "probe unlock none safes=" + std::to_string(safes.size()) +
                         " nearest=" + nearest_class + " cm=" + nearest_distance);
        const std::array<std::string, 2> arguments{nearest_class, nearest_distance};
        AddReportLine(out, context.localizer.Format(
            "status.unlock_none",
            "No safe within reach; nearest object is {0} at {1} cm",
            Views(arguments)));
        return;
    }
    const auto actor = target->actor;
    std::uintptr_t cls{};
    Read(context, actor + kObjectClassOffset, cls);
    // The chain the blueprint graph walks once the lock mini-game is won, and only that: the two
    // client events before the multicast only update presentation (measured opened=0), while the
    // multicast is the call that flips the box (measured opened=1). Server_UnLockTreasureBox is
    // what the game's own widget sends, but it is a no-op on a non-authoritative client, so it is
    // not part of this shortcut. Every step is the empty (0 parms / 0 bytes) actor event.
    static constexpr std::array<std::string_view, 3> steps{
        "BP_ClientUnlockTreasureBox",
        "BP_OpenTreasureBox",
        "NetMulticast_NotifyTreasureBoxUnlock",
    };
    // BP_IsTreasureBoxOpened is the flag the box itself reports; read it between steps so the
    // run stops on the event that actually flipped the box instead of firing all of them.
    auto read_opened = [&](bool& known) -> bool {
        known = false;
        std::uintptr_t getter{};
        if (cls == 0 ||
            !FindFunction(context, cls, "BP_IsTreasureBoxOpened", 1, 1, getter)) {
            return false;
        }
        std::uint8_t params[4]{};
        if (!InvokeProcessEvent(
                context, reinterpret_cast<void*>(actor),
                reinterpret_cast<void*>(getter), params)) {
            return false;
        }
        known = true;
        return params[0] != 0;
    };
    std::string found;
    std::string used;
    bool fired{};
    bool opened{};
    for (const auto name : steps) {
        std::uintptr_t function{};
        if (cls == 0 || !FindFunction(context, cls, name, 0, 0, function)) {
            continue;
        }
        if (!found.empty()) found.push_back(',');
        found.append(name);
        std::uint8_t params[8]{};
        const bool ok = InvokeProcessEvent(
            context, reinterpret_cast<void*>(actor), reinterpret_cast<void*>(function), params);
        bool known{};
        const bool open_now = read_opened(known);
        Log(
            context, "probe unlock step=" + std::string(name) + " ok=" +
                         std::to_string(ok ? 1 : 0) +
                         " opened=" + (known ? std::to_string(open_now ? 1 : 0) : std::string("n/a")));
        if (ok) {
            fired = true;
            if (!used.empty()) used.push_back('+');
            used.append(name);
        }
        if (known && open_now) {
            opened = true;
            break;
        }
    }
    Log(
        context, "probe unlock actor=" + Hex(actor) + " class=" + target->class_name +
                     " cm=" + std::to_string(static_cast<long long>(target->distance)) +
                     " found=[" + found + "] fired=" + std::to_string(fired ? 1 : 0) +
                     " used=" + used);
    if (!fired) {
        const std::array<std::string, 2> arguments{
            target->class_name, found.empty() ? std::string("none") : found};
        AddReportLine(out, context.localizer.Format(
            "status.unlock_miss",
            "{0} exposes no unlock event (found {1})", Views(arguments)));
        return;
    }
    if (opened) {
        const std::array<std::string, 2> opened_arguments{target->class_name, used};
        AddReportLine(out, context.localizer.Format(
            "status.unlock_opened", "Opened {0} with {1}", Views(opened_arguments)));
        BeginVerify(context, actor, cls, target->class_name);
        return;
    }
    BeginVerify(context, actor, cls, target->class_name);
    const std::array<std::string, 2> arguments{target->class_name, used};
    AddReportLine(out, context.localizer.Format(
        "status.unlock_sent", "Called {1} on {0}, checking in 3 s", Views(arguments)));
}

// The 3-second follow-up: a box that opened either flipped bInteractFinish or left the
// world. Anything else means the call was accepted and then ignored by the game.
// Whole-map sweep: the actor frame carries every safe actor of the loaded level, so one pass
// lists them all with the position a teleport can aim at.
void RunScanSafes(Context& context, std::vector<std::string>& out) {
    std::vector<Candidate> safes;
    std::vector<Candidate> nearest;
    if (!CollectNearbyActors(context, safes, nearest)) {
        AddError(context, out, "ACTORS", "actor frame");
        return;
    }
    {
        std::scoped_lock lock(context.mutex);
        context.safes = safes;
    }
    Log(context, "probe scan safes=" + std::to_string(safes.size()));
    for (std::size_t index{}; index < safes.size(); ++index) {
        const auto& entry = safes[index];
        Log(
            context, "probe safe id=" + std::to_string(index) + " class=" + entry.class_name +
                         " at " + FormatPosition(entry.position) + " cm=" +
                         std::to_string(static_cast<long long>(entry.distance)));
    }
    const std::array<std::string, 1> total{
        safes.empty() ? std::string("0") : std::to_string(safes.size())};
    AddReportLine(out, context.localizer.Format(
        "status.scan_total", "Found {0} safes; index / class / distance", Views(total)));
    const std::size_t shown = std::min(safes.size(), kScanReportLines);
    for (std::size_t index{}; index < shown; ++index) {
        const auto& entry = safes[index];
        const std::array<std::string, 3> line{
            std::to_string(index), entry.class_name,
            std::to_string(static_cast<long long>(entry.distance / 100.0))};
        AddReportLine(out, context.localizer.Format(
            "status.scan_line", "{0}. {1} - {2} m", Views(line)));
    }
}

// Ask the Host to move the player onto a scanned entry. The Host streams the destination in and
// holds the character across the jump, which is what keeps the arrival from falling through
// unloaded terrain.
void RunTeleportSafe(Context& context, std::vector<std::string>& out) {
    EnsureServices(context);
    std::vector<Candidate> safes;
    std::uint32_t index{};
    {
        std::scoped_lock lock(context.mutex);
        safes = context.safes;
        index = context.teleport_index;
    }
    if (safes.empty()) {
        AddReportLine(out, context.localizer.Text(
            "status.teleport_no_scan", "Scan the map first: no safe is on the list."));
        return;
    }
    if (index >= safes.size()) index = static_cast<std::uint32_t>(safes.size() - 1);
    const auto& entry = safes[index];
    const auto* teleport = context.teleport;
    const auto* session = context.session;
    const auto* player = context.player;
    if (teleport == nullptr || teleport->teleport == nullptr || session == nullptr ||
        session->snapshot == nullptr || player == nullptr || player->snapshot == nullptr) {
        AddError(context, out, "TELEPORT", "teleport service");
        Log(context, "probe teleport service unavailable");
        return;
    }
    AnomalyNteSessionSnapshotV1 session_snapshot{sizeof(session_snapshot)};
    AnomalyNtePlayerSnapshotV1 player_snapshot{sizeof(player_snapshot)};
    if (session->snapshot(session->user, &session_snapshot).code != ANOMALY_STATUS_V1_OK ||
        player->snapshot(player->user, &player_snapshot).code != ANOMALY_STATUS_V1_OK) {
        AddError(context, out, "TELEPORT", "snapshot");
        Log(context, "probe teleport snapshot failed");
        return;
    }
    AnomalyNtePlayerTeleportRequestV1 request{};
    request.struct_size = sizeof(request);
    request.world = session_snapshot.world;
    request.player = player_snapshot.handle;
    request.position[0] = entry.position[0];
    request.position[1] = entry.position[1];
    request.position[2] = entry.position[2] + kTeleportZOffsetCentimeters;
    const auto status = teleport->teleport(teleport->user, &request);
    Log(
        context, "probe teleport id=" + std::to_string(index) + " class=" + entry.class_name +
                     " at " + FormatPosition(entry.position) + " code=" +
                     std::to_string(status.code));
    const std::array<std::string, 3> line{
        std::to_string(index), entry.class_name, std::to_string(status.code)};
    if (status.code == ANOMALY_STATUS_V1_OK) {
        AddReportLine(out, context.localizer.Format(
            "status.teleport_done", "Teleporting to {1} ({0}), code {2}", Views(line)));
    } else {
        AddReportLine(out, context.localizer.Format(
            "status.teleport_failed", "Teleport to {1} ({0}) failed, code {2}", Views(line)));
    }
}

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
    // The treasure box lineage answers this directly, which is far less ambiguous than the
    // interaction bit: it is the flag the game itself uses to hide an already-looted box.
    std::uint8_t opened_flag{};
    bool opened_known{};
    std::uintptr_t getter{};
    if (cls != 0 &&
        FindFunction(context, cls, "BP_IsTreasureBoxOpened", 1, 1, getter)) {
        std::uint8_t params[4]{};
        if (InvokeProcessEvent(
                context, reinterpret_cast<void*>(actor),
                reinterpret_cast<void*>(getter), params)) {
            opened_flag = params[0];
            opened_known = true;
        }
    }
    const bool opened = (read && current != baseline) || !alive ||
        (opened_known && opened_flag != 0);
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
                     " opened=" + std::to_string(opened ? 1 : 0) + " box_open=" +
                     (opened_known ? std::to_string(opened_flag) : std::string("n/a")));
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
    context->actors = Query<AnomalyNteActorsServiceV1>(
        host, ANOMALY_NTE_ACTORS_SERVICE_V1_ID, ANOMALY_NTE_ACTORS_SERVICE_V1_VERSION);
    context->session = Query<AnomalyNteSessionServiceV1>(
        host, ANOMALY_NTE_SESSION_SERVICE_V1_ID, ANOMALY_NTE_SESSION_SERVICE_V1_VERSION);
    context->player = Query<AnomalyNtePlayerServiceV1>(
        host, ANOMALY_NTE_PLAYER_SERVICE_V1_ID, ANOMALY_NTE_PLAYER_SERVICE_V1_VERSION);
    context->teleport = Query<AnomalyNtePlayerTeleportServiceV1>(
        host, ANOMALY_NTE_PLAYER_TELEPORT_SERVICE_V1_ID,
        ANOMALY_NTE_PLAYER_TELEPORT_SERVICE_V1_VERSION);
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
    context->pending = Action::none;
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
    // The verdict arrives on a later game tick than the press that started it, so it has to run
    // while the probe is idle; otherwise a press never reports its result.
    CompleteVerify(*context);
    if (!context->actor_probe_done) {
        context->actor_probe_done = true;
        std::vector<Candidate> safes;
        std::vector<Candidate> nearest;
        if (CollectNearbyActors(*context, safes, nearest)) {
            for (const auto& candidate : nearest) {
                Log(
                    *context, "probe actor near=" + candidate.class_name + " cm=" +
                                  std::to_string(static_cast<long long>(candidate.distance)));
            }
            for (const auto& candidate : safes) {
                Log(
                    *context, "probe actor safe=" + candidate.class_name + " at " +
                                  FormatPosition(candidate.position) + " cm=" +
                                  std::to_string(static_cast<long long>(candidate.distance)));
            }
        }
    }
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
    if (running == Action::safe) {
        RunSafe(*context, out);
    } else if (running == Action::unlock) {
        RunUnlock(*context, out);
    } else if (running == Action::scan) {
        RunScanSafes(*context, out);
    } else if (running == Action::teleport) {
        RunTeleportSafe(*context, out);
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
    // Two presses for the pair under test and two for whole-map work over safes. The labels are
    // literal calls so the localization check can see every key in use.
    const std::string safe_label = context->localizer.Label(
        "action.safe", "Safe / locker interact", "pickup-probe-safe");
    if (ui->button_enabled(
            ui->user, anomaly::sdk::StringView(safe_label), 0.0F, 0.0F, 1) != 0) {
        std::scoped_lock lock(context->mutex);
        context->pending = Action::safe;
    }
    const std::string unlock_label = context->localizer.Label(
        "action.unlock", "Open the safe", "pickup-probe-unlock");
    if (ui->button_enabled(
            ui->user, anomaly::sdk::StringView(unlock_label), 0.0F, 0.0F, 1) != 0) {
        std::scoped_lock lock(context->mutex);
        context->pending = Action::unlock;
    }
    ui->separator(ui->user);
    const std::string scan_label = context->localizer.Label(
        "action.scan", "Scan every safe on the map", "pickup-probe-scan");
    if (ui->button_enabled(
            ui->user, anomaly::sdk::StringView(scan_label), 0.0F, 0.0F, 1) != 0) {
        std::scoped_lock lock(context->mutex);
        context->pending = Action::scan;
    }
    const std::string index_label = context->localizer.Label(
        "setting.index", "Target index (0 = nearest)", "pickup-probe-index");
    std::uint32_t index{};
    {
        std::scoped_lock lock(context->mutex);
        index = context->teleport_index;
    }
    if (ui->input_uint32(ui->user, anomaly::sdk::StringView(index_label), &index, 1, 0) != 0) {
        std::scoped_lock lock(context->mutex);
        context->teleport_index = index;
    }
    const std::string teleport_label = context->localizer.Label(
        "action.teleport", "Teleport to the target", "pickup-probe-teleport");
    if (ui->button_enabled(
            ui->user, anomaly::sdk::StringView(teleport_label), 0.0F, 0.0F, 1) != 0) {
        std::scoped_lock lock(context->mutex);
        context->pending = Action::teleport;
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
