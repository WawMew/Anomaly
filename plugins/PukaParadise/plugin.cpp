// 噗卡星票 · 花篱秘密园自动循环。
//
// 流程（角色不进入迷宫场景，只在 NPC 面前开局）：
//   传送到 NPC → RequestStartMiniGame → 传送到"通关门" → 游戏自己结算 → 票数上涨 → 下一轮
//
// 通关门需要探测：场上有 4 个 BP_Maze_door，只有一个是通关点，且反射层没有任何字段能区分
// （HTPukalandMazeMechanismSystem 的选门逻辑是原生 C++，无 UPROPERTY）。所以首轮逐个试，
// 命中后缓存坐标，之后每轮只传那一个点。
//
// 组件/函数/字段偏移全部在运行期用反射按名字取，不写死版本偏移。
#include "anomaly/sdk/cpp.hpp"
#include "plugins/common/localization.hpp"

#include "reflection.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <new>
#include <string>
#include <string_view>

namespace {

using anomaly::plugins::Localizer;
using anomaly::plugins::pukaland::ReflectionBridge;
using anomaly::sdk::StringView;

using Clock = std::chrono::steady_clock;

// 开局后要经过一段准备/倒计时才进入"进行中"，实测约 25 秒，留足余量。
constexpr auto kStartTimeout = std::chrono::seconds(90);
constexpr auto kRoundCooldown = std::chrono::milliseconds(1500);
// 单个航点等待窗口：传送到位后若没触发结算，很快换下一个。
constexpr auto kProbeTimeout = std::chrono::milliseconds(500);
// 开局后先等小游戏加载完，再开始传送航点。
constexpr auto kEnterDelay = std::chrono::seconds(7);
// 结算界面：每 0.5 秒扫一次按钮，持续 5 秒。
constexpr auto kPollInterval = std::chrono::milliseconds(500);
constexpr auto kPollWindow = std::chrono::seconds(5);
constexpr auto kResolveRetry = std::chrono::seconds(3);

// 会话相位：GameType 的第二个字节。1=进行中，2=提交中，3=结算完成，4=待机。
constexpr std::uint32_t kPhasePlaying = 1;
constexpr std::uint32_t kPhaseSettled = 3;

template <typename Struct, typename Field>
bool HasField(const Struct* value, const std::size_t offset) noexcept {
    return value != nullptr && value->struct_size >= offset + sizeof(Field);
}

AnomalyStatusV1 Status(
    const std::uint32_t code, const std::string_view message = {}) noexcept {
    return {code, 0, {message.data(), message.size()}};
}

bool UiReady(const AnomalyUiServiceV1* ui) noexcept {
    return HasField<AnomalyUiServiceV1, decltype(AnomalyUiServiceV1::begin_window)>(
               ui, offsetof(AnomalyUiServiceV1, begin_window)) &&
        ui->begin_window != nullptr && ui->end_window != nullptr &&
        ui->text != nullptr && ui->button_enabled != nullptr && ui->separator != nullptr;
}

template <typename Service>
const Service* Query(
    const AnomalyHostApiV1* host, const char* id, const std::uint32_t version) noexcept {
    const void* table{};
    if (host == nullptr || host->query_service == nullptr) return nullptr;
    if (host->query_service(host->host_context, StringView(id), version, &table).code !=
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

enum class Phase : std::uint32_t {
    kIdle = 0,
    kResolving,
    kProbing,
    kStarting,
    kCooldown,
    kStopped,
};

struct Context final {
    const AnomalyHostApiV1* host{};
    Localizer localizer;
    const AnomalyCoreServiceV1* core{};
    const AnomalyUiServiceV1* ui{};
    const AnomalyUe5NamesServiceV1* names{};
    const AnomalySignatureServiceV1* signature{};
    const AnomalyNteSessionServiceV1* session{};
    const AnomalyNtePlayerServiceV1* player{};
    const AnomalyNtePlayerTeleportServiceV1* teleport{};
    const AnomalyNteActorsServiceV1* actors{};
    const AnomalyNteUiButtonsServiceV1* buttons{};

    ReflectionBridge bridge;

    std::mutex mutex;
    bool started{};

    // 反射解析结果
    std::uintptr_t component{};
    std::uintptr_t request_start{};
    std::uint32_t session_offset{};
    std::uint32_t ticket_offset{};
    bool offsets_ready{};
    std::uint32_t maze_name_id{};

    // 运行状态
    Phase phase{Phase::kIdle};
    std::uint32_t rounds_target{1};
    std::uint32_t rounds_done{};
    std::int32_t ticket_at_start{-1};
    std::int32_t ticket_now{-1};
    Clock::time_point phase_deadline{};
    Clock::time_point probe_deadline{};
    std::string status;

    // 通关门探测
    std::array<std::array<double, 3>, 8> door_points{};
    std::uint32_t door_count{};
    std::uint32_t probe_index{};
    bool probe_cached{};
    bool probe_waiting{};
    bool game_started{};
    // 结算界面按钮轮询：命中航点后每 0.5 秒扫一次，持续 5 秒。
    bool settlement_polling{};
    bool logged_buttons{};
    std::uint32_t click_attempts{};
    std::uint32_t waypoint_passes{};
    Clock::time_point poll_deadline{};
    Clock::time_point next_poll{};
    std::array<double, 3> clear_point{};
};

void SetStatus(Context& context, std::string text) {
    std::scoped_lock lock(context.mutex);
    context.status = std::move(text);
}

void Log(Context& context, const std::string_view message) {
    if (context.core != nullptr && context.core->log != nullptr) {
        context.core->log(context.core->user, 2U, StringView(message));
    }
}

std::uint32_t ReadU32(const Context& context, const std::uint32_t offset) {
    std::uint32_t value{};
    if (!context.bridge.ReadBytes(context.component + offset, &value, sizeof(value))) {
        return 0;
    }
    return value;
}

std::uint32_t SessionGameId(const Context& context) {
    return ReadU32(context, context.session_offset);
}

std::uint32_t SessionPhase(const Context& context) {
    return (ReadU32(context, context.session_offset + 8) >> 8) & 0xFFU;
}

std::int32_t ReadTicket(const Context& context) {
    std::int32_t value{-1};
    if (!context.bridge.ReadBytes(
            context.component + context.ticket_offset, &value, sizeof(value))) {
        return -1;
    }
    return value;
}

// 组件地址持久化：定位一次后写盘，下次启动直接读；只有校验失败才重新扫描。
std::string StatePath(Context& context) {
    if (context.core == nullptr || context.core->plugin_directory == nullptr) return {};
    char buffer[512]{};
    std::size_t size = sizeof(buffer);
    if (context.core->plugin_directory(context.core->user, buffer, &size).code !=
        ANOMALY_STATUS_V1_OK) {
        return {};
    }
    std::string path(buffer);
    if (!path.empty() && path.back() != '\\' && path.back() != '/') path.push_back('\\');
    path.append("component.txt");
    return path;
}

std::uintptr_t LoadSavedComponent(Context& context) {
    const std::string path = StatePath(context);
    if (path.empty()) return 0;
    std::FILE* file = nullptr;
    if (fopen_s(&file, path.c_str(), "r") != 0 || file == nullptr) return 0;
    unsigned long long value = 0;
    const int read = std::fscanf(file, "%llx", &value);
    std::fclose(file);
    return read == 1 ? static_cast<std::uintptr_t>(value) : 0;
}

void SaveComponent(Context& context, const std::uintptr_t address) {
    const std::string path = StatePath(context);
    if (path.empty()) return;
    std::FILE* file = nullptr;
    if (fopen_s(&file, path.c_str(), "w") != 0 || file == nullptr) return;
    std::fprintf(file, "%llx\n", static_cast<unsigned long long>(address));
    std::fclose(file);
}

// 校验地址仍是一个带 RequestStartMiniGame 的噗卡组件。
bool ValidateComponent(Context& context, const std::uintptr_t address) {
    if (address == 0) return false;
    std::uintptr_t klass{};
    if (!context.bridge.ReadBytes(address + 16, &klass, sizeof(klass)) || klass == 0) {
        return false;
    }
    return context.bridge.FindFunctionInChain(klass, "RequestStartMiniGame") != 0;
}

bool ResolveAll(Context& context) {
    if (context.component == 0) {
        const std::uintptr_t saved = LoadSavedComponent(context);
        if (ValidateComponent(context, saved)) {
            context.component = saved;
            Log(context, "puka: component restored from disk");
        }
    }
    if (context.component == 0) {
        context.component = context.bridge.LocatePukalandComponent();
        if (context.component != 0) {
            SaveComponent(context, context.component);
            Log(context, "puka: component located and saved");
        }
    }
    if (context.component == 0) return false;

    std::uintptr_t klass{};
    if (!context.bridge.ReadBytes(
            context.component + 16, &klass, sizeof(klass)) ||
        klass == 0) {
        return false;
    }
    if (context.request_start == 0) {
        context.request_start =
            context.bridge.FindFunctionInChain(klass, "RequestStartMiniGame");
    }
    if (!context.offsets_ready) {
        context.offsets_ready =
            context.bridge.FindPropertyOffset(klass, "SessionSnapshot", context.session_offset) &&
            context.bridge.FindPropertyOffset(klass, "TicketBalance", context.ticket_offset);
    }
    if (context.maze_name_id == 0 && context.session_offset != 0) {
        context.maze_name_id = SessionGameId(context);
    }
    return context.request_start != 0 && context.offsets_ready &&
        context.maze_name_id != 0;
}

// 枚举 BP_Maze_door 实例，取 bounds_center 作为候选通关点。
void CollectDoors(Context& context) {
    context.door_count = 0;
    if (context.actors == nullptr || context.actors->frame == nullptr ||
        context.actors->page == nullptr || context.names == nullptr ||
        context.names->resolve_utf8 == nullptr) {
        return;
    }
    AnomalyNteEntityFrameV1 frame{};
    frame.struct_size = sizeof(frame);
    if (context.actors->frame(context.actors->user, &frame).code !=
        ANOMALY_STATUS_V1_OK) {
        return;
    }
    constexpr std::uint32_t kPage = 128;
    AnomalyNteEntitySnapshotV1 entities[kPage]{};
    AnomalyNteEntityPageRequestV1 request{};
    request.struct_size = sizeof(request);
    request.generation = frame.generation;
    request.capacity = kPage;
    request.class_name_id = 0;
    std::uint32_t offset = 0;
    while (offset < 8192 && context.door_count < context.door_points.size()) {
        for (auto& entity : entities) entity.struct_size = sizeof(entity);
        request.offset = offset;
        AnomalyNteEntityPageResultV1 result{};
        result.struct_size = sizeof(result);
        if (context.actors->page(context.actors->user, &request, entities, &result).code !=
            ANOMALY_STATUS_V1_OK) {
            return;
        }
        if (result.returned == 0) break;
        for (std::uint32_t i = 0; i < result.returned; ++i) {
            char class_name[96]{};
            std::size_t size = sizeof(class_name);
            if (context.names->resolve_utf8(
                    context.names->user, entities[i].class_name_id, class_name, &size)
                    .code != ANOMALY_STATUS_V1_OK) {
                continue;
            }
            // 迷宫航点是 MazeWaypoint / MazeTrigger（含蓝图子类），不是乐园里的装饰门。
            if (std::strstr(class_name, "MazeWaypoint") == nullptr &&
                std::strstr(class_name, "MazeTrigger") == nullptr) {
                continue;
            }
            Log(context, std::string("puka: hit class=") + class_name);
            const std::uint32_t n = context.door_count;
            context.door_points[n] = {entities[i].bounds_center[0],
                                      entities[i].bounds_center[1],
                                      entities[i].bounds_center[2]};
            context.door_count = n + 1;
            if (context.door_count >= context.door_points.size()) break;
        }
        if (result.next_offset <= offset) break;
        offset = result.next_offset;
    }
    Log(context, "puka: doors=" + std::to_string(context.door_count));
    // 出口航点 = 离玩家最近的那个（玩家进迷宫时被放在出口附近，实测距离约 480，
    // 其余航点都在数千米外）。按距离升序排，首轮就能命中。
    std::array<double, 3> player_pos{};
    bool have_player = false;
    if (context.player != nullptr && context.player->snapshot != nullptr) {
        AnomalyNtePlayerSnapshotV1 snapshot{};
        snapshot.struct_size = sizeof(snapshot);
        if (context.player->snapshot(context.player->user, &snapshot).code ==
            ANOMALY_STATUS_V1_OK) {
            player_pos = {snapshot.position[0], snapshot.position[1], snapshot.position[2]};
            have_player = true;
            char line[160]{};
            std::snprintf(line, sizeof(line), "puka: player = %.1f %.1f %.1f",
                          player_pos[0], player_pos[1], player_pos[2]);
            Log(context, line);
        }
    }
    if (have_player) {
        char line[160]{};
        std::snprintf(line, sizeof(line), "puka: player = %.1f %.1f %.1f",
                      player_pos[0], player_pos[1], player_pos[2]);
        Log(context, line);
    }
    for (std::uint32_t i = 0; i < context.door_count; ++i) {
        char line[160]{};
        std::snprintf(line, sizeof(line), "puka: door[%u] = %.1f %.1f %.1f", i,
                      context.door_points[i][0], context.door_points[i][1],
                      context.door_points[i][2]);
        Log(context, line);
    }
}

bool TeleportTo(Context& context, const std::array<double, 3>& point) {
    if (context.session == nullptr || context.player == nullptr ||
        context.teleport == nullptr || context.teleport->teleport == nullptr) {
        return false;
    }
    AnomalyNteSessionSnapshotV1 session{};
    session.struct_size = sizeof(session);
    if (context.session->snapshot(context.session->user, &session).code !=
        ANOMALY_STATUS_V1_OK) {
        return false;
    }
    AnomalyNtePlayerSnapshotV1 player{};
    player.struct_size = sizeof(player);
    if (context.player->snapshot(context.player->user, &player).code !=
        ANOMALY_STATUS_V1_OK) {
        return false;
    }
    AnomalyNtePlayerTeleportRequestV1 request{};
    request.struct_size = sizeof(request);
    request.world = session.world;
    request.player = player.handle;
    request.position[0] = point[0];
    request.position[1] = point[1];
    request.position[2] = point[2];
    return context.teleport->teleport(context.teleport->user, &request).code ==
        ANOMALY_STATUS_V1_OK;
}

bool RequestStart(Context& context) {
    alignas(16) unsigned char parms[64]{};
    const std::uint32_t id = context.maze_name_id;
    std::memcpy(parms, &id, sizeof(id));
    return context.bridge.Invoke(context.component, context.request_start, parms);
}

// 开一局并传送到指定门，然后等票数变化。
void BeginAttempt(Context& context, const std::array<double, 3>& point,
                  const Clock::time_point now, const std::string_view label) {
    context.ticket_at_start = ReadTicket(context);
    RequestStart(context);
    TeleportTo(context, point);
    context.probe_waiting = true;
    context.phase_deadline = now + kStartTimeout;
    SetStatus(context, std::string(label));
}

// 触发一次按钮扫描（异步，宿主在后续 tick 完成）。
void RequestButtonScan(Context& context) {
    if (context.buttons != nullptr && context.buttons->request_scan != nullptr) {
        AnomalyGenerationHandleV1 handle{};
        context.buttons->request_scan(context.buttons->user, &handle);
    }
}

// 把当前扫描到的按钮全打进日志，用于确认真实按钮名。
void LogButtons(Context& context) {
    if (context.buttons == nullptr || context.buttons->status == nullptr ||
        context.buttons->button_at == nullptr) {
        return;
    }
    AnomalyNteUiButtonsStatusV1 status{};
    status.struct_size = sizeof(status);
    if (context.buttons->status(context.buttons->user, &status).code !=
        ANOMALY_STATUS_V1_OK) {
        return;
    }
    const std::uint32_t total = status.button_count;
    for (std::uint32_t i = 0; i < total && i < 24U; ++i) {
        AnomalyNteUiButtonSnapshotV1 snap{};
        snap.struct_size = sizeof(snap);
        if (context.buttons->button_at(
                context.buttons->user, status.catalog_sequence, i, &snap).code !=
            ANOMALY_STATUS_V1_OK) {
            continue;
        }
        Log(context, std::string("puka: button[") + std::to_string(i) + "] name=" +
                snap.name + " cat=" + std::to_string(snap.category) +
                " text=" + snap.text);
    }
}

// 按钮是否还在（不点击，只查询）。
bool ButtonExists(Context& context, const std::string_view name) {
    if (context.buttons == nullptr || context.buttons->status == nullptr ||
        context.buttons->find == nullptr) {
        return false;
    }
    AnomalyNteUiButtonsStatusV1 status{};
    status.struct_size = sizeof(status);
    if (context.buttons->status(context.buttons->user, &status).code !=
        ANOMALY_STATUS_V1_OK) {
        return false;
    }
    if ((status.flags & ANOMALY_NTE_UI_BUTTONS_STATUS_V1_CATALOG) == 0) return false;
    AnomalyNteUiButtonQueryV1 query{};
    query.struct_size = sizeof(query);
    query.category_mask = ANOMALY_NTE_UI_BUTTON_CATEGORY_V1_CLICKABLE |
        ANOMALY_NTE_UI_BUTTON_CATEGORY_V1_BLOCKED;
    query.catalog_sequence = status.catalog_sequence;
    query.name = StringView(name);
    AnomalyNteUiButtonSnapshotV1 snapshot{};
    snapshot.struct_size = sizeof(snapshot);
    std::uint32_t matches = 0;
    return context.buttons->find(
               context.buttons->user, &query, &snapshot, &matches).code ==
            ANOMALY_STATUS_V1_OK &&
        matches != 0;
}

// 按名字点一个 UI 按钮（结算界面的"再试一次"/"退出"）。
bool ClickButton(Context& context, const std::string_view name) {
    if (context.buttons == nullptr || context.buttons->status == nullptr ||
        context.buttons->find == nullptr || context.buttons->request_click == nullptr) {
        return false;
    }
    AnomalyNteUiButtonsStatusV1 status{};
    status.struct_size = sizeof(status);
    if (context.buttons->status(context.buttons->user, &status).code !=
        ANOMALY_STATUS_V1_OK) {
        return false;
    }
    // 目录未发布完成时查不到任何按钮。
    if ((status.flags & ANOMALY_NTE_UI_BUTTONS_STATUS_V1_CATALOG) == 0) return false;
    AnomalyNteUiButtonQueryV1 query{};
    query.struct_size = sizeof(query);
    query.category_mask = ANOMALY_NTE_UI_BUTTON_CATEGORY_V1_CLICKABLE;
    query.catalog_sequence = status.catalog_sequence;
    query.name = StringView(name);
    AnomalyNteUiButtonSnapshotV1 snapshot{};
    snapshot.struct_size = sizeof(snapshot);
    std::uint32_t matches = 0;
    // 先只认"可点击"的按钮；结算动画没结束时它可能还是 blocked，那就用 FORCE 兜底。
    bool forced = false;
    if (context.buttons->find(context.buttons->user, &query, &snapshot, &matches).code !=
            ANOMALY_STATUS_V1_OK ||
        matches == 0) {
        query.category_mask = ANOMALY_NTE_UI_BUTTON_CATEGORY_V1_CLICKABLE |
            ANOMALY_NTE_UI_BUTTON_CATEGORY_V1_BLOCKED;
        if (context.buttons->find(
                context.buttons->user, &query, &snapshot, &matches).code !=
                ANOMALY_STATUS_V1_OK ||
            matches == 0) {
            return false;
        }
        forced = true;
    }
    AnomalyNteUiButtonClickRequestV1 request{};
    request.struct_size = sizeof(request);
    request.flags = forced ? ANOMALY_NTE_UI_BUTTON_CLICK_V1_FORCE : 0U;
    request.button = snapshot.button;
    AnomalyGenerationHandleV1 handle{};
    const AnomalyStatusV1 clicked =
        context.buttons->request_click(context.buttons->user, &request, &handle);
    Log(context, std::string("puka: click ") + std::string(name) +
            (forced ? "(force) code=" : " code=") + std::to_string(clicked.code));
    return clicked.code == ANOMALY_STATUS_V1_OK;
}

void Advance(Context& context, const Clock::time_point now) {
    if (!context.started) return;
    if (context.phase == Phase::kStopped || context.phase == Phase::kIdle) return;

    switch (context.phase) {
    case Phase::kResolving: {
        if (!ResolveAll(context)) {
            // 组件只在有会话时存在；没定位到就继续等，不阻塞流程。
            SetStatus(context, "等待定位 PukalandComponent（需先进入一局小游戏）");
            return;
        }
        context.phase = Phase::kCooldown;
        context.phase_deadline = now;
        return;
    }
    case Phase::kCooldown: {
        if (now < context.phase_deadline) return;
        if (context.rounds_done >= context.rounds_target) {
            SetStatus(context, "完成轮次 " + std::to_string(context.rounds_done));
            context.phase = Phase::kIdle;
            return;
        }
        // 航点只在进入迷宫后才存在，所以先开局，进迷宫后再采集。
        context.probe_index = 0;
        context.probe_waiting = false;
        context.game_started = false;
        context.door_count = 0;
        context.phase = Phase::kProbing;
        SetStatus(context, "开局中…");
        return;
    }
    case Phase::kProbing: {
        // 结算界面：持续扫描按钮，扫到就点。
        if (context.settlement_polling) {
            const bool finishing = context.rounds_done >= context.rounds_target;
            const char* want =
                finishing ? "Button_CloseSettlement" : "Button_PlayAgainSettlement";
            if (now >= context.next_poll) {
                context.next_poll = now + kPollInterval;
                RequestButtonScan(context);
                if (!context.logged_buttons) {
                    context.logged_buttons = true;
                    LogButtons(context);
                }
                // 点过之后看按钮是否消失：消失即点击生效。
                if (context.click_attempts > 0 && !ButtonExists(context, want)) {
                    context.settlement_polling = false;
                    context.click_attempts = 0;
                    if (finishing) {
                        SetStatus(context, "完成 " + std::to_string(context.rounds_done) +
                                               " 轮，已退出");
                        context.game_started = false;
                        context.phase = Phase::kIdle;
                        return;
                    }
                    context.ticket_at_start = ReadTicket(context);
                    context.door_count = 0;
                    context.probe_index = 0;
                    context.probe_waiting = false;
                    context.waypoint_passes = 0;
                    context.game_started = true;
                    context.phase_deadline = now + kEnterDelay;
                    context.probe_deadline = now + kStartTimeout;
                    SetStatus(context, "已点「再试一次」，等新一局加载…");
                    return;
                }
                if (context.click_attempts >= 3) {
                    // 点了 3 次按钮仍在：不报错、不停止，直接进入下一步。
                    context.settlement_polling = false;
                    context.click_attempts = 0;
                    if (finishing) {
                        SetStatus(context, "完成 " + std::to_string(context.rounds_done) +
                                               " 轮（按钮未消失，直接收尾）");
                        context.game_started = false;
                        context.phase = Phase::kIdle;
                        return;
                    }
                    context.ticket_at_start = ReadTicket(context);
                    context.door_count = 0;
                    context.probe_index = 0;
                    context.probe_waiting = false;
                    context.waypoint_passes = 0;
                    context.game_started = true;
                    context.phase_deadline = now + kEnterDelay;
                    context.probe_deadline = now + kStartTimeout;
                    SetStatus(context, "按钮未消失，继续下一轮");
                    return;
                }
                if (ClickButton(context, want)) ++context.click_attempts;
            }
            if (now >= context.poll_deadline) {
                context.settlement_polling = false;
                SetStatus(context, "结算界面按钮 5 秒内没点到，已停止");
                context.game_started = false;
                context.phase = Phase::kIdle;
            }
            return;
        }
        // 第一步：开局，等玩家真的进到迷宫里。
        if (!context.game_started) {
            context.ticket_at_start = ReadTicket(context);
            RequestStart(context);
            context.game_started = true;
            context.phase_deadline = now + kEnterDelay;
            context.probe_deadline = now + kStartTimeout;
            SetStatus(context, "已开局，等小游戏加载（6 秒）…");
            return;
        }
        // 开局后固定等 6 秒再开始传送航点。
        if (now < context.phase_deadline) return;
        // 进迷宫后航点才存在，这里反复采集直到出现。
        if (context.door_count == 0) {
            CollectDoors(context);
            if (context.door_count == 0) {
                if (now >= context.probe_deadline) {
                    SetStatus(context, "开局后没检测到迷宫航点");
                    context.game_started = false;
                    context.phase = Phase::kIdle;
                }
                return;
            }
        }
        if (!context.probe_waiting) {
            if (context.probe_index >= context.door_count) {
                // 第一遍航点没触发结算，再完整走一遍；还不行就报错停止。
                if (context.waypoint_passes < 1) {
                    ++context.waypoint_passes;
                    context.probe_index = 0;
                    context.probe_waiting = false;
                    SetStatus(context, "第一遍航点未结算，再走一遍");
                    return;
                }
                SetStatus(context, "两遍航点都没触发结算，停止循环");
                context.game_started = false;
                context.phase = Phase::kIdle;
                return;
            }
            TeleportTo(context, context.door_points[context.probe_index]);
            context.probe_waiting = true;
            context.probe_deadline = now + kProbeTimeout;
            SetStatus(context, "试航点 " + std::to_string(context.probe_index + 1) + "/" +
                                   std::to_string(context.door_count) + "…");
            return;
        }
        // 只认票数上涨，避免上一轮残留的相位被误判成本轮已结算。
        const bool settled = context.ticket_at_start >= 0 &&
            ReadTicket(context) > context.ticket_at_start;
        if (settled) {
            context.probe_waiting = false;
            ++context.rounds_done;
            Log(context, "puka: cleared at waypoint " +
                    std::to_string(context.probe_index));
            SetStatus(context, "结算成功，轮次 " + std::to_string(context.rounds_done) +
                                   "，扫描结算界面…");
            context.settlement_polling = true;
            context.logged_buttons = false;
            context.poll_deadline = now + kPollWindow;
            context.next_poll = now;
            return;
        }
        if (now >= context.probe_deadline) {
            ++context.probe_index;
            context.probe_waiting = false;
        }
        return;
    }
    case Phase::kStarting: {
        context.ticket_now = ReadTicket(context);
        const bool settled = SessionPhase(context) == kPhaseSettled ||
            (context.ticket_at_start >= 0 &&
             context.ticket_now > context.ticket_at_start);
        if (settled) {
            ++context.rounds_done;
            context.probe_waiting = false;
            SetStatus(context, "结算成功，轮次 " + std::to_string(context.rounds_done));
            context.phase = Phase::kCooldown;
            context.phase_deadline = now + kRoundCooldown;
            return;
        }
        if (now >= context.phase_deadline) {
            context.probe_waiting = false;
            SetStatus(context, "本轮超时（票数未增加）");
            context.phase = Phase::kIdle;
        }
        return;
    }
    case Phase::kIdle:
    case Phase::kStopped:
    default:
        return;
    }
}

AnomalyStatusV1 ANOMALY_CALL Load(
    const AnomalyHostApiV1* host, void** plugin_context) {
    if (host == nullptr || plugin_context == nullptr) {
        return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT, "host is invalid");
    }
    *plugin_context = nullptr;
    auto* context = new (std::nothrow) Context();
    if (context == nullptr) return Status(ANOMALY_STATUS_V1_FAILED, "allocation failed");
    context->host = host;
    context->localizer = Localizer(host);
    context->core = Query<AnomalyCoreServiceV1>(
        host, ANOMALY_CORE_SERVICE_V1_ID, ANOMALY_CORE_SERVICE_V1_VERSION);
    context->ui = Query<AnomalyUiServiceV1>(
        host, ANOMALY_UI_SERVICE_V1_ID, ANOMALY_UI_SERVICE_V1_VERSION);
    context->names = Query<AnomalyUe5NamesServiceV1>(
        host, ANOMALY_UE5_NAMES_SERVICE_V1_ID, ANOMALY_UE5_NAMES_SERVICE_V1_VERSION);
    context->signature = Query<AnomalySignatureServiceV1>(
        host, ANOMALY_SIGNATURE_SERVICE_V1_ID, ANOMALY_SIGNATURE_SERVICE_V1_VERSION);
    context->session = Query<AnomalyNteSessionServiceV1>(
        host, ANOMALY_NTE_SESSION_SERVICE_V1_ID, ANOMALY_NTE_SESSION_SERVICE_V1_VERSION);
    context->player = Query<AnomalyNtePlayerServiceV1>(
        host, ANOMALY_NTE_PLAYER_SERVICE_V1_ID, ANOMALY_NTE_PLAYER_SERVICE_V1_VERSION);
    context->teleport = Query<AnomalyNtePlayerTeleportServiceV1>(
        host, ANOMALY_NTE_PLAYER_TELEPORT_SERVICE_V1_ID,
        ANOMALY_NTE_PLAYER_TELEPORT_SERVICE_V1_VERSION);
    context->actors = Query<AnomalyNteActorsServiceV1>(
        host, ANOMALY_NTE_ACTORS_SERVICE_V1_ID, ANOMALY_NTE_ACTORS_SERVICE_V1_VERSION);
    context->buttons = Query<AnomalyNteUiButtonsServiceV1>(
        host, ANOMALY_NTE_UI_BUTTONS_SERVICE_V1_ID,
        ANOMALY_NTE_UI_BUTTONS_SERVICE_V1_VERSION);
    if (!UiReady(context->ui)) {
        delete context;
        return Status(ANOMALY_STATUS_V1_UNAVAILABLE, "anomaly.ui is unavailable");
    }
    context->bridge.Attach(context->signature, context->names);
    *plugin_context = context;
    return anomaly::sdk::Ok();
}

AnomalyStatusV1 ANOMALY_CALL Start(void* user) {
    auto* context = static_cast<Context*>(user);
    if (context == nullptr) return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT);
    std::scoped_lock lock(context->mutex);
    if (context->started) return Status(ANOMALY_STATUS_V1_CONFLICT, "already started");
    context->started = true;
    context->phase = Phase::kIdle;
    return anomaly::sdk::Ok();
}

AnomalyStatusV1 ANOMALY_CALL Stop(void* user, std::uint32_t) {
    auto* context = static_cast<Context*>(user);
    if (context == nullptr) return Status(ANOMALY_STATUS_V1_INVALID_ARGUMENT);
    std::scoped_lock lock(context->mutex);
    context->started = false;
    context->phase = Phase::kStopped;
    context->rounds_done = 0;
    context->probe_waiting = false;
    context->status.clear();
    return anomaly::sdk::Ok();
}

void ANOMALY_CALL Unload(void* user) { delete static_cast<Context*>(user); }

void ANOMALY_CALL Update(void* user, double) {
    auto* context = static_cast<Context*>(user);
    if (context == nullptr || !context->started) return;
    Advance(*context, Clock::now());
}

void ANOMALY_CALL Draw(void* user, const AnomalyUiServiceV1* supplied_ui) {
    auto* context = static_cast<Context*>(user);
    if (context == nullptr) return;
    const AnomalyUiServiceV1* ui =
        supplied_ui != nullptr && UiReady(supplied_ui) ? supplied_ui : context->ui;
    if (!UiReady(ui)) return;

    std::uint32_t target{}, done{};
    std::int32_t ticket{-1};
    std::string status;
    Phase phase{};
    bool cached{};
    {
        std::scoped_lock lock(context->mutex);
        target = context->rounds_target;
        done = context->rounds_done;
        ticket = context->ticket_now >= 0 ? context->ticket_now : context->ticket_at_start;
        status = context->status;
        phase = context->phase;
        cached = context->probe_cached;
    }

    int open = 1;
    const std::string title =
        context->localizer.Label("window.title", "噗卡星票", "puka-window");
    anomaly::sdk::UiWindow window(ui, title, &open);
    if (!window) return;

    const auto text = [ui](const std::string& value) {
        ui->text(ui->user, StringView(value));
    };
    text(status.empty() ? std::string("空闲") : status);
    text("星票：" + std::to_string(ticket < 0 ? 0 : ticket));
    text("轮次：" + std::to_string(done) + " / " + std::to_string(target) +
         (cached ? "（通关门已缓存）" : "（首次运行会探测 4 个门）"));
    ui->separator(ui->user);

    if (HasField<AnomalyUiServiceV1, decltype(AnomalyUiServiceV1::input_uint32)>(
            ui, offsetof(AnomalyUiServiceV1, input_uint32)) &&
        ui->input_uint32 != nullptr) {
        std::uint32_t value = target;
        const std::string label =
            context->localizer.Label("setting.rounds", "轮次上限", "puka-rounds");
        if (ui->input_uint32(ui->user, StringView(label), &value, 1, 1) != 0) {
            std::scoped_lock lock(context->mutex);
            context->rounds_target = value < 1 ? 1 : value;
        }
    }

    const bool running = phase != Phase::kIdle && phase != Phase::kStopped;
    const std::string start_label =
        context->localizer.Label("action.start", "开始自动", "puka-start");
    const std::string stop_label =
        context->localizer.Label("action.stop", "停止", "puka-stop");
    if (ui->button_enabled(ui->user, StringView(stop_label), 0.0F, 0.0F, running ? 1 : 0) !=
        0) {
        std::scoped_lock lock(context->mutex);
        context->phase = Phase::kIdle;
        context->probe_waiting = false;
        context->status = "已停止";
    }
    if (ui->button_enabled(ui->user, StringView(start_label), 0.0F, 0.0F, running ? 0 : 1) !=
        0) {
        std::scoped_lock lock(context->mutex);
        context->rounds_done = 0;
        context->phase = Phase::kResolving;
        context->status = "开始";
    }
}

}  // namespace

ANOMALY_SDK_EXPORT AnomalyStatusV1 ANOMALY_CALL AnomalyPluginEntryV1(
    AnomalyPluginDescriptorV1* descriptor) {
    if (descriptor == nullptr || descriptor->struct_size < sizeof(*descriptor)) {
        return {ANOMALY_STATUS_V1_INVALID_ARGUMENT, 0, {"descriptor is invalid", 0}};
    }
    *descriptor = {
        sizeof(*descriptor), ANOMALY_PLUGIN_API_V1_MAJOR, ANOMALY_PLUGIN_API_V1_MINOR,
        anomaly::sdk::StringView("anomaly.local.nte.puka-paradise"),
        anomaly::sdk::StringView("噗卡星票"),
        anomaly::sdk::StringView("WawMew"),
        anomaly::sdk::StringView("0.3.0"),
        Load, Start, Stop, Unload, Update, Draw};
    return anomaly::sdk::Ok();
}
