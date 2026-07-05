/*
 * ============================================================================
 *  HELLO WORLD DISTRIBUTED MICROSERVICE PLATFORM (HWDMP)
 *  "Enterprise Ultra Edition" — Cloud-Native, Event-Driven, AI-Ready*,
 *  Blockchain-Adjacent**, Now With Leader Election(tm)
 *  Version 12.0.0-final-FINAL-v2-RC7-GA
 *
 *  * No AI was involved. We just like the word.
 *  ** No blockchain either. We like that word too.
 *
 *  ARCHITECTURE OVERVIEW:
 *    - In-Process "Network" Simulation Layer (INPNSL)
 *    - Pseudo-Threaded Event Bus (single-threaded, don't tell anyone)
 *    - Finite State Machine Lifecycle Controller
 *    - Plugin Registry with Dynamic Strategy Resolution
 *    - CRC32 Message Integrity Verification
 *    - JSON-ish Serialization Layer
 *    - Structured Logging Subsystem with Severity Levels
 *    - Configuration Management via Fake Environment Parsing
 *    - Retry Policy with Exponential Backoff (simulated)
 *    - Circuit Breaker Pattern (simulated)
 *    - Leader Election Among Simulated Cluster Nodes
 *    - Distributed Lock Manager (simulated, single process)
 *    - Memory Pool Allocator (that just wraps malloc)
 *    - Telemetry / Metrics Exporter
 *    - Internationalization (i18n) Layer for Greetings
 *    - Feature Flag System
 *    - Audit Trail Subsystem
 *    - Embedded "Unit Test" Suite (runs at startup, naturally)
 *    - Graceful Shutdown Coordinator
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#include <stdarg.h>
#include <assert.h>

/* ============================== CONFIG LAYER ============================= */

#define HWDMP_VERSION         "12.0.0-final-FINAL-v2-RC7-GA"
#define MAX_MESSAGE_LENGTH     256
#define MAX_STRATEGIES         4
#define MAX_EVENT_QUEUE        64
#define MAX_PLUGINS            8
#define MAX_LOG_LINE           512
#define ENCODING_SHIFT         3
#define MAX_RETRY_ATTEMPTS     3
#define SIMULATED_NODE_COUNT   3
#define MAX_LOCALES            5
#define MAX_FEATURE_FLAGS      6
#define MAX_AUDIT_ENTRIES      32
#define MAX_METRICS            8
#define MEMORY_POOL_SIZE       4096
#define CIRCUIT_FAILURE_LIMIT  3

typedef enum { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR } LogLevel;

typedef enum {
    STRATEGY_UPPERCASE,
    STRATEGY_LOWERCASE,
    STRATEGY_TITLECASE,
    STRATEGY_IDENTITY
} MessageStrategy;

typedef enum {
    STATUS_OK = 0,
    STATUS_ERR_NULL_POINTER,
    STATUS_ERR_BUFFER_OVERFLOW,
    STATUS_ERR_UNKNOWN_STRATEGY,
    STATUS_ERR_CHECKSUM_MISMATCH,
    STATUS_ERR_QUEUE_FULL,
    STATUS_ERR_NODE_UNREACHABLE,
    STATUS_ERR_CIRCUIT_OPEN,
    STATUS_ERR_LOCK_UNAVAILABLE,
    STATUS_ERR_ALLOC_FAILED,
    STATUS_ERR_UNKNOWN_LOCALE,
    STATUS_ERR_TEST_FAILED
} HwdmpStatus;

typedef enum {
    STATE_BOOTSTRAP,
    STATE_CONFIG_LOADED,
    STATE_TESTS_RUNNING,
    STATE_NODES_REGISTERED,
    STATE_LEADER_ELECTED,
    STATE_MESSAGE_PREPARED,
    STATE_DISPATCHING,
    STATE_RENDERING,
    STATE_SHUTTING_DOWN,
    STATE_TERMINATED
} SystemState;

/* ============================== LOGGING LAYER ============================ */

static const char *log_level_name(LogLevel lvl) {
    switch (lvl) {
        case LOG_TRACE: return "TRACE";
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO:  return "INFO ";
        case LOG_WARN:  return "WARN ";
        case LOG_ERROR: return "ERROR";
        default:        return "?????";
    }
}

static void hwdmp_log(LogLevel lvl, const char *component, const char *fmt, ...) {
    char buffer[MAX_LOG_LINE];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", t);

    printf("[%s] [%s] [%-16s] %s\n", timestamp, log_level_name(lvl), component, buffer);
}

/* ============================== MEMORY POOL LAYER ========================= */

typedef struct {
    unsigned char buffer[MEMORY_POOL_SIZE];
    size_t offset;
} MemoryPool;

static void pool_init(MemoryPool *pool) {
    pool->offset = 0;
    memset(pool->buffer, 0, sizeof(pool->buffer));
}

static void *pool_alloc(MemoryPool *pool, size_t size) {
    /* naive bump allocator, no alignment considerations whatsoever */
    if (pool->offset + size > MEMORY_POOL_SIZE) {
        return NULL;
    }
    void *ptr = &pool->buffer[pool->offset];
    pool->offset += size;
    return ptr;
}

static void pool_reset(MemoryPool *pool) {
    hwdmp_log(LOG_DEBUG, "MEMORY_POOL", "Resetting pool, %zu bytes were in use", pool->offset);
    pool->offset = 0;
}

/* ============================== CRC32 MODULE ============================= */

static uint32_t crc32_compute(const char *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint8_t)data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (~(crc & 1) + 1));
        }
    }
    return ~crc;
}

/* ============================== CRYPTO MODULE ============================= */

typedef struct {
    char encoded[MAX_MESSAGE_LENGTH];
    size_t length;
    uint32_t checksum;
} SecureEnvelope;

static HwdmpStatus envelope_seal(const char *plaintext, SecureEnvelope *out) {
    if (!plaintext || !out) return STATUS_ERR_NULL_POINTER;
    size_t len = strlen(plaintext);
    if (len >= MAX_MESSAGE_LENGTH) return STATUS_ERR_BUFFER_OVERFLOW;
    for (size_t i = 0; i < len; i++) {
        out->encoded[i] = (char)((unsigned char)plaintext[i] + ENCODING_SHIFT);
    }
    out->encoded[len] = '\0';
    out->length = len;
    out->checksum = crc32_compute(out->encoded, len);
    return STATUS_OK;
}

static HwdmpStatus envelope_open(const SecureEnvelope *in, char *plaintext_out) {
    if (!in || !plaintext_out) return STATUS_ERR_NULL_POINTER;
    uint32_t actual = crc32_compute(in->encoded, in->length);
    if (actual != in->checksum) return STATUS_ERR_CHECKSUM_MISMATCH;
    for (size_t i = 0; i < in->length; i++) {
        plaintext_out[i] = (char)((unsigned char)in->encoded[i] - ENCODING_SHIFT);
    }
    plaintext_out[in->length] = '\0';
    return STATUS_OK;
}

/* ============================== SERIALIZATION LAYER ======================= */

static void serialize_to_json_ish(const SecureEnvelope *env, char *out_buf, size_t out_size) {
    snprintf(out_buf, out_size,
        "{\"encoded\":\"%s\",\"length\":%zu,\"checksum\":\"0x%08X\"}",
        env->encoded, env->length, env->checksum);
}

/* ============================== i18n LOCALIZATION LAYER ==================== */

typedef struct {
    const char *locale_code;
    const char *template_fmt; /* %s placeholder for the decoded core message */
} LocaleEntry;

static const LocaleEntry locale_table[MAX_LOCALES] = {
    { "en-US", "%s" },
    { "en-GB", "%s (but spelt properly)" },
    { "pirate", "Ahoy! %s" },
    { "shout",  "%s!!!" },
    { "quiet",  "(%s)" }
};

static HwdmpStatus locale_apply(const char *code, const char *core_msg, char *out, size_t out_size) {
    for (int i = 0; i < MAX_LOCALES; i++) {
        if (strcmp(locale_table[i].locale_code, code) == 0) {
            snprintf(out, out_size, locale_table[i].template_fmt, core_msg);
            return STATUS_OK;
        }
    }
    return STATUS_ERR_UNKNOWN_LOCALE;
}

/* ============================== FEATURE FLAG SYSTEM ======================== */

typedef struct {
    const char *name;
    int enabled;
} FeatureFlag;

static FeatureFlag feature_flags[MAX_FEATURE_FLAGS] = {
    { "ENABLE_LOCALIZATION",      1 },
    { "ENABLE_CIRCUIT_BREAKER",   1 },
    { "ENABLE_LEADER_ELECTION",   1 },
    { "ENABLE_AUDIT_TRAIL",       1 },
    { "ENABLE_TELEMETRY",         1 },
    { "ENABLE_QUANTUM_ENCRYPTION", 0 } /* obviously not implemented */
};

static int feature_is_enabled(const char *name) {
    for (int i = 0; i < MAX_FEATURE_FLAGS; i++) {
        if (strcmp(feature_flags[i].name, name) == 0) {
            return feature_flags[i].enabled;
        }
    }
    return 0;
}

/* ============================== AUDIT TRAIL SUBSYSTEM ====================== */

typedef struct {
    char entries[MAX_AUDIT_ENTRIES][128];
    size_t count;
} AuditTrail;

static void audit_init(AuditTrail *trail) {
    trail->count = 0;
}

static void audit_record(AuditTrail *trail, const char *fmt, ...) {
    if (trail->count >= MAX_AUDIT_ENTRIES) return;
    va_list args;
    va_start(args, fmt);
    vsnprintf(trail->entries[trail->count], sizeof(trail->entries[0]), fmt, args);
    va_end(args);
    trail->count++;
}

static void audit_dump(const AuditTrail *trail) {
    hwdmp_log(LOG_INFO, "AUDIT", "Dumping %zu audit entries:", trail->count);
    for (size_t i = 0; i < trail->count; i++) {
        printf("    [%03zu] %s\n", i + 1, trail->entries[i]);
    }
}

/* ============================== METRICS / TELEMETRY LAYER =================== */

typedef struct {
    char name[64];
    double value;
} Metric;

typedef struct {
    Metric metrics[MAX_METRICS];
    size_t count;
} MetricsRegistry;

static void metrics_init(MetricsRegistry *reg) {
    reg->count = 0;
}

static void metrics_record(MetricsRegistry *reg, const char *name, double value) {
    if (reg->count >= MAX_METRICS) return;
    snprintf(reg->metrics[reg->count].name, sizeof(reg->metrics[reg->count].name), "%s", name);
    reg->metrics[reg->count].value = value;
    reg->count++;
}

static void metrics_export(const MetricsRegistry *reg) {
    hwdmp_log(LOG_INFO, "TELEMETRY", "Exporting %zu metrics to /dev/null (metaphorically):", reg->count);
    for (size_t i = 0; i < reg->count; i++) {
        printf("    hwdmp_%s = %.3f\n", reg->metrics[i].name, reg->metrics[i].value);
    }
}

/* ============================== NETWORK SIMULATION LAYER =================== */

typedef struct {
    int node_id;
    const char *hostname;
    int alive;
    int is_leader;
} SimulatedNode;

static SimulatedNode cluster[SIMULATED_NODE_COUNT] = {
    { 0, "hwdmp-node-alpha.local", 1, 0 },
    { 1, "hwdmp-node-beta.local",  1, 0 },
    { 2, "hwdmp-node-gamma.local", 1, 0 }
};

static HwdmpStatus network_dispatch(const SimulatedNode *node, const char *payload_json) {
    if (!node->alive) return STATUS_ERR_NODE_UNREACHABLE;
    hwdmp_log(LOG_DEBUG, "NETWORK", "Dispatching %zu bytes to %s (node %d)",
              strlen(payload_json), node->hostname, node->node_id);
    volatile long busywork = 0;
    for (long i = 0; i < 100000; i++) busywork += i % 7;
    (void)busywork;
    return STATUS_OK;
}

/* ============================== CIRCUIT BREAKER LAYER ======================= */

typedef enum { CIRCUIT_CLOSED, CIRCUIT_OPEN, CIRCUIT_HALF_OPEN } CircuitState;

typedef struct {
    CircuitState state;
    int consecutive_failures;
} CircuitBreaker;

static void breaker_init(CircuitBreaker *cb) {
    cb->state = CIRCUIT_CLOSED;
    cb->consecutive_failures = 0;
}

static HwdmpStatus breaker_guard(CircuitBreaker *cb) {
    if (cb->state == CIRCUIT_OPEN) {
        return STATUS_ERR_CIRCUIT_OPEN;
    }
    return STATUS_OK;
}

static void breaker_record_result(CircuitBreaker *cb, HwdmpStatus result) {
    if (result == STATUS_OK) {
        cb->consecutive_failures = 0;
        cb->state = CIRCUIT_CLOSED;
    } else {
        cb->consecutive_failures++;
        if (cb->consecutive_failures >= CIRCUIT_FAILURE_LIMIT) {
            cb->state = CIRCUIT_OPEN;
            hwdmp_log(LOG_WARN, "CIRCUIT_BREAKER", "Circuit tripped OPEN after %d failures",
                      cb->consecutive_failures);
        }
    }
}

static HwdmpStatus network_dispatch_with_retry(CircuitBreaker *cb, const SimulatedNode *node,
                                                const char *payload_json) {
    HwdmpStatus guard = breaker_guard(cb);
    if (guard != STATUS_OK) return guard;

    HwdmpStatus status = STATUS_ERR_NODE_UNREACHABLE;
    int attempt = 0;
    int backoff_ms = 10;
    while (attempt < MAX_RETRY_ATTEMPTS) {
        status = network_dispatch(node, payload_json);
        if (status == STATUS_OK) break;
        hwdmp_log(LOG_WARN, "NETWORK", "Attempt %d failed for node %d, backing off %dms",
                  attempt + 1, node->node_id, backoff_ms);
        backoff_ms *= 2;
        attempt++;
    }
    breaker_record_result(cb, status);
    return status;
}

/* ============================== LEADER ELECTION LAYER ======================= */

static HwdmpStatus elect_leader(SimulatedNode *nodes, int count, int *leader_id_out) {
    /* Extremely sophisticated algorithm: highest node_id among the living wins. */
    int best = -1;
    for (int i = 0; i < count; i++) {
        nodes[i].is_leader = 0;
        if (nodes[i].alive && nodes[i].node_id > best) {
            best = nodes[i].node_id;
        }
    }
    if (best < 0) return STATUS_ERR_NODE_UNREACHABLE;
    for (int i = 0; i < count; i++) {
        if (nodes[i].node_id == best) {
            nodes[i].is_leader = 1;
            *leader_id_out = best;
        }
    }
    return STATUS_OK;
}

/* ============================== DISTRIBUTED LOCK MANAGER ==================== */

typedef struct {
    int locked;
    const char *owner;
} DistributedLock;

static void lock_init(DistributedLock *lock) {
    lock->locked = 0;
    lock->owner = NULL;
}

static HwdmpStatus lock_acquire(DistributedLock *lock, const char *requester) {
    if (lock->locked) {
        return STATUS_ERR_LOCK_UNAVAILABLE;
    }
    lock->locked = 1;
    lock->owner = requester;
    hwdmp_log(LOG_DEBUG, "LOCK_MANAGER", "Lock acquired by \"%s\"", requester);
    return STATUS_OK;
}

static void lock_release(DistributedLock *lock) {
    hwdmp_log(LOG_DEBUG, "LOCK_MANAGER", "Lock released by \"%s\"", lock->owner ? lock->owner : "unknown");
    lock->locked = 0;
    lock->owner = NULL;
}

/* ============================== EVENT BUS LAYER ============================ */

typedef enum {
    EVENT_MESSAGE_SEALED,
    EVENT_MESSAGE_DISPATCHED,
    EVENT_MESSAGE_RENDERED,
    EVENT_LEADER_ELECTED,
    EVENT_LOCK_ACQUIRED,
    EVENT_LOCK_RELEASED
} EventType;

typedef struct {
    EventType type;
    char description[128];
} Event;

typedef struct {
    Event queue[MAX_EVENT_QUEUE];
    size_t head;
    size_t tail;
    size_t count;
} EventBus;

static void eventbus_init(EventBus *bus) {
    memset(bus, 0, sizeof(EventBus));
}

static HwdmpStatus eventbus_publish(EventBus *bus, EventType type, const char *desc) {
    if (bus->count >= MAX_EVENT_QUEUE) return STATUS_ERR_QUEUE_FULL;
    Event *e = &bus->queue[bus->tail];
    e->type = type;
    snprintf(e->description, sizeof(e->description), "%s", desc);
    bus->tail = (bus->tail + 1) % MAX_EVENT_QUEUE;
    bus->count++;
    return STATUS_OK;
}

static void eventbus_drain(EventBus *bus) {
    while (bus->count > 0) {
        Event *e = &bus->queue[bus->head];
        hwdmp_log(LOG_INFO, "EVENTBUS", "Consumed event type=%d desc=\"%s\"", e->type, e->description);
        bus->head = (bus->head + 1) % MAX_EVENT_QUEUE;
        bus->count--;
    }
}

/* ============================== STRATEGY / PLUGIN LAYER ==================== */

typedef HwdmpStatus (*StrategyFn)(char *buffer);

static HwdmpStatus strat_upper(char *b) { for (; *b; b++) *b = (char)toupper((unsigned char)*b); return STATUS_OK; }
static HwdmpStatus strat_lower(char *b) { for (; *b; b++) *b = (char)tolower((unsigned char)*b); return STATUS_OK; }
static HwdmpStatus strat_identity(char *b) { (void)b; return STATUS_OK; }
static HwdmpStatus strat_title(char *b) {
    int start = 1;
    for (; *b; b++) {
        if (isspace((unsigned char)*b)) { start = 1; }
        else if (start) { *b = (char)toupper((unsigned char)*b); start = 0; }
        else { *b = (char)tolower((unsigned char)*b); }
    }
    return STATUS_OK;
}

typedef struct {
    const char *name;
    MessageStrategy id;
    StrategyFn fn;
} PluginDescriptor;

typedef struct {
    PluginDescriptor plugins[MAX_PLUGINS];
    size_t count;
} PluginRegistry;

static void registry_init(PluginRegistry *reg) {
    reg->count = 0;
}

static void registry_add(PluginRegistry *reg, const char *name, MessageStrategy id, StrategyFn fn) {
    if (reg->count >= MAX_PLUGINS) return;
    reg->plugins[reg->count].name = name;
    reg->plugins[reg->count].id = id;
    reg->plugins[reg->count].fn = fn;
    reg->count++;
}

static const PluginDescriptor *registry_resolve(const PluginRegistry *reg, MessageStrategy id) {
    for (size_t i = 0; i < reg->count; i++) {
        if (reg->plugins[i].id == id) return &reg->plugins[i];
    }
    return NULL;
}

/* ============================== OUTPUT SINK ABSTRACTION ==================== */

typedef void (*OutputSink)(const char *);

static void console_output_sink(const char *msg) {
    printf(">>> %s\n", msg);
}

/* ============================== EMBEDDED "UNIT TEST" SUITE ================== */
/* Because no enterprise system ships without tests it runs on itself, in prod. */

typedef struct {
    const char *name;
    int passed;
} TestResult;

static int test_crc32_roundtrip(void) {
    const char *msg = "test payload";
    uint32_t a = crc32_compute(msg, strlen(msg));
    uint32_t b = crc32_compute(msg, strlen(msg));
    return a == b;
}

static int test_envelope_roundtrip(void) {
    SecureEnvelope env;
    char decoded[MAX_MESSAGE_LENGTH];
    if (envelope_seal("round trip test", &env) != STATUS_OK) return 0;
    if (envelope_open(&env, decoded) != STATUS_OK) return 0;
    return strcmp(decoded, "round trip test") == 0;
}

static int test_strategy_upper(void) {
    char buf[32];
    snprintf(buf, sizeof(buf), "MixedCase");
    strat_upper(buf);
    return strcmp(buf, "MIXEDCASE") == 0;
}

static int test_locale_pirate(void) {
    char out[64];
    if (locale_apply("pirate", "Hello, world!", out, sizeof(out)) != STATUS_OK) return 0;
    return strstr(out, "Ahoy!") != NULL;
}

static HwdmpStatus run_test_suite(void) {
    TestResult results[4];
    results[0].name = "crc32_roundtrip";
    results[0].passed = test_crc32_roundtrip();
    results[1].name = "envelope_roundtrip";
    results[1].passed = test_envelope_roundtrip();
    results[2].name = "strategy_upper";
    results[2].passed = test_strategy_upper();
    results[3].name = "locale_pirate";
    results[3].passed = test_locale_pirate();

    int all_passed = 1;
    for (int i = 0; i < 4; i++) {
        hwdmp_log(results[i].passed ? LOG_DEBUG : LOG_ERROR, "TEST_RUNNER",
                  "%-24s ... %s", results[i].name, results[i].passed ? "PASS" : "FAIL");
        if (!results[i].passed) all_passed = 0;
    }
    return all_passed ? STATUS_OK : STATUS_ERR_TEST_FAILED;
}

/* ============================== STATE MACHINE CONTROLLER ==================== */

static const char *state_name(SystemState s) {
    switch (s) {
        case STATE_BOOTSTRAP:          return "BOOTSTRAP";
        case STATE_CONFIG_LOADED:      return "CONFIG_LOADED";
        case STATE_TESTS_RUNNING:      return "TESTS_RUNNING";
        case STATE_NODES_REGISTERED:   return "NODES_REGISTERED";
        case STATE_LEADER_ELECTED:     return "LEADER_ELECTED";
        case STATE_MESSAGE_PREPARED:   return "MESSAGE_PREPARED";
        case STATE_DISPATCHING:        return "DISPATCHING";
        case STATE_RENDERING:          return "RENDERING";
        case STATE_SHUTTING_DOWN:      return "SHUTTING_DOWN";
        case STATE_TERMINATED:         return "TERMINATED";
        default:                       return "UNKNOWN";
    }
}

static void transition(SystemState *cur, SystemState next) {
    hwdmp_log(LOG_INFO, "STATE_MACHINE", "%s -> %s", state_name(*cur), state_name(next));
    *cur = next;
}

/* ============================== ORCHESTRATION LAYER ========================= */

typedef struct {
    SecureEnvelope envelope;
    PluginRegistry registry;
    EventBus bus;
    SystemState state;
    MemoryPool pool;
    AuditTrail audit;
    MetricsRegistry metrics;
    CircuitBreaker breaker;
    DistributedLock lock;
    int leader_id;
} HwdmpContext;

static HwdmpStatus context_bootstrap(HwdmpContext *ctx, const char *seed_message) {
    ctx->state = STATE_BOOTSTRAP;
    hwdmp_log(LOG_INFO, "BOOTSTRAP", "Initializing HWDMP v%s", HWDMP_VERSION);

    pool_init(&ctx->pool);
    audit_init(&ctx->audit);
    metrics_init(&ctx->metrics);
    breaker_init(&ctx->breaker);
    lock_init(&ctx->lock);
    audit_record(&ctx->audit, "System bootstrap initiated");

    transition(&ctx->state, STATE_CONFIG_LOADED);
    hwdmp_log(LOG_DEBUG, "CONFIG", "Loaded %d simulated cluster nodes", SIMULATED_NODE_COUNT);
    for (int i = 0; i < MAX_FEATURE_FLAGS; i++) {
        hwdmp_log(LOG_DEBUG, "CONFIG", "Feature flag %-28s = %s",
                  feature_flags[i].name, feature_flags[i].enabled ? "ON" : "off");
    }
    audit_record(&ctx->audit, "Configuration and feature flags loaded");

    transition(&ctx->state, STATE_TESTS_RUNNING);
    HwdmpStatus test_status = run_test_suite();
    audit_record(&ctx->audit, "Embedded test suite executed, result=%d", test_status);
    if (test_status != STATUS_OK) {
        hwdmp_log(LOG_ERROR, "BOOTSTRAP", "Test suite failed, aborting boot sequence");
        return test_status;
    }

    transition(&ctx->state, STATE_NODES_REGISTERED);
    registry_init(&ctx->registry);
    registry_add(&ctx->registry, "TitleCase", STRATEGY_TITLECASE, strat_title);
    registry_add(&ctx->registry, "UPPERCASE", STRATEGY_UPPERCASE, strat_upper);
    registry_add(&ctx->registry, "lowercase", STRATEGY_LOWERCASE, strat_lower);
    registry_add(&ctx->registry, "Identity",  STRATEGY_IDENTITY,  strat_identity);
    hwdmp_log(LOG_DEBUG, "PLUGINS", "Registered %zu strategy plugins", ctx->registry.count);
    audit_record(&ctx->audit, "Registered %zu strategy plugins", ctx->registry.count);

    eventbus_init(&ctx->bus);

    if (feature_is_enabled("ENABLE_LEADER_ELECTION")) {
        transition(&ctx->state, STATE_LEADER_ELECTED);
        HwdmpStatus elect_status = elect_leader(cluster, SIMULATED_NODE_COUNT, &ctx->leader_id);
        if (elect_status != STATUS_OK) return elect_status;
        hwdmp_log(LOG_INFO, "LEADER_ELECTION", "Node %d elected as cluster leader", ctx->leader_id);
        char desc[128];
        snprintf(desc, sizeof(desc), "Node %d elected as leader", ctx->leader_id);
        eventbus_publish(&ctx->bus, EVENT_LEADER_ELECTED, desc);
        audit_record(&ctx->audit, "Leader election completed: node %d", ctx->leader_id);
    }

    transition(&ctx->state, STATE_MESSAGE_PREPARED);
    HwdmpStatus status = envelope_seal(seed_message, &ctx->envelope);
    if (status != STATUS_OK) return status;
    eventbus_publish(&ctx->bus, EVENT_MESSAGE_SEALED, "Payload sealed into SecureEnvelope");
    audit_record(&ctx->audit, "Message sealed into SecureEnvelope, checksum=0x%08X", ctx->envelope.checksum);

    return STATUS_OK;
}

static HwdmpStatus context_dispatch_to_cluster(HwdmpContext *ctx) {
    transition(&ctx->state, STATE_DISPATCHING);

    HwdmpStatus lock_status = lock_acquire(&ctx->lock, "dispatch-coordinator");
    if (lock_status != STATUS_OK) return lock_status;
    eventbus_publish(&ctx->bus, EVENT_LOCK_ACQUIRED, "dispatch-coordinator acquired cluster lock");

    char json_buf[MAX_MESSAGE_LENGTH + 64];
    serialize_to_json_ish(&ctx->envelope, json_buf, sizeof(json_buf));

    int successes = 0;
    for (int i = 0; i < SIMULATED_NODE_COUNT; i++) {
        HwdmpStatus status = network_dispatch_with_retry(&ctx->breaker, &cluster[i], json_buf);
        if (status != STATUS_OK) {
            hwdmp_log(LOG_ERROR, "DISPATCH", "Node %d permanently unreachable", cluster[i].node_id);
            audit_record(&ctx->audit, "Dispatch to node %d FAILED", cluster[i].node_id);
            continue;
        }
        successes++;
        char desc[128];
        snprintf(desc, sizeof(desc), "Payload acknowledged by %s%s", cluster[i].hostname,
                 cluster[i].is_leader ? " (leader)" : "");
        eventbus_publish(&ctx->bus, EVENT_MESSAGE_DISPATCHED, desc);
        audit_record(&ctx->audit, "Dispatch to node %d succeeded", cluster[i].node_id);
    }

    metrics_record(&ctx->metrics, "dispatch_success_count", (double)successes);
    metrics_record(&ctx->metrics, "dispatch_total_nodes", (double)SIMULATED_NODE_COUNT);

    lock_release(&ctx->lock);
    eventbus_publish(&ctx->bus, EVENT_LOCK_RELEASED, "dispatch-coordinator released cluster lock");

    if (successes == 0) return STATUS_ERR_NODE_UNREACHABLE;
    return STATUS_OK;
}

static HwdmpStatus context_render_all_strategies(HwdmpContext *ctx, OutputSink sink) {
    transition(&ctx->state, STATE_RENDERING);
    MessageStrategy order[MAX_STRATEGIES] = {
        STRATEGY_TITLECASE, STRATEGY_UPPERCASE, STRATEGY_LOWERCASE, STRATEGY_IDENTITY
    };

    int rendered_count = 0;
    for (int i = 0; i < MAX_STRATEGIES; i++) {
        const PluginDescriptor *plugin = registry_resolve(&ctx->registry, order[i]);
        if (!plugin) return STATUS_ERR_UNKNOWN_STRATEGY;

        char *decoded = pool_alloc(&ctx->pool, MAX_MESSAGE_LENGTH);
        if (!decoded) return STATUS_ERR_ALLOC_FAILED;

        HwdmpStatus status = envelope_open(&ctx->envelope, decoded);
        if (status != STATUS_OK) return status;

        status = plugin->fn(decoded);
        if (status != STATUS_OK) return status;

        if (feature_is_enabled("ENABLE_LOCALIZATION")) {
            char localized[MAX_MESSAGE_LENGTH];
            HwdmpStatus loc_status = locale_apply("en-US", decoded, localized, sizeof(localized));
            if (loc_status == STATUS_OK) {
                strncpy(decoded, localized, MAX_MESSAGE_LENGTH - 1);
                decoded[MAX_MESSAGE_LENGTH - 1] = '\0';
            }
        }

        hwdmp_log(LOG_INFO, "RENDER", "Applying plugin \"%s\"", plugin->name);
        sink(decoded);
        rendered_count++;

        char desc[128];
        snprintf(desc, sizeof(desc), "Rendered via plugin \"%s\"", plugin->name);
        eventbus_publish(&ctx->bus, EVENT_MESSAGE_RENDERED, desc);
        audit_record(&ctx->audit, "Rendered message using strategy \"%s\"", plugin->name);
    }

    metrics_record(&ctx->metrics, "render_count", (double)rendered_count);
    return STATUS_OK;
}

static HwdmpStatus context_render_localized_variants(HwdmpContext *ctx, OutputSink sink) {
    hwdmp_log(LOG_INFO, "i18n", "Rendering localized greeting variants across %d locales", MAX_LOCALES);
    char base_decoded[MAX_MESSAGE_LENGTH];
    HwdmpStatus status = envelope_open(&ctx->envelope, base_decoded);
    if (status != STATUS_OK) return status;

    for (int i = 0; i < MAX_LOCALES; i++) {
        char localized[MAX_MESSAGE_LENGTH];
        HwdmpStatus loc_status = locale_apply(locale_table[i].locale_code, base_decoded,
                                               localized, sizeof(localized));
        if (loc_status != STATUS_OK) continue;
        hwdmp_log(LOG_DEBUG, "i18n", "Locale \"%s\" resolved", locale_table[i].locale_code);
        sink(localized);
    }
    return STATUS_OK;
}

static void context_shutdown(HwdmpContext *ctx) {
    transition(&ctx->state, STATE_SHUTTING_DOWN);
    eventbus_drain(&ctx->bus);
    metrics_export(&ctx->metrics);
    if (feature_is_enabled("ENABLE_AUDIT_TRAIL")) {
        audit_dump(&ctx->audit);
    }
    pool_reset(&ctx->pool);
    memset(&ctx->envelope, 0, sizeof(ctx->envelope)); /* "secure" wipe */
    transition(&ctx->state, STATE_TERMINATED);
}

/* ============================== BANNER / MAIN ============================== */

static void print_banner(void) {
    printf("================================================================\n");
    printf(" HELLO WORLD DISTRIBUTED MICROSERVICE PLATFORM (HWDMP)\n");
    printf(" \"Enterprise Ultra Edition\"  --  v%s\n", HWDMP_VERSION);
    printf(" Cloud-Native. Event-Driven. Over-Engineered by Design.\n");
    printf("================================================================\n\n");
}

static void print_footer(HwdmpStatus final_status) {
    printf("\n----------------------------------------------------------------\n");
    printf(" Run complete. Final status code: %d (%s)\n",
           final_status, final_status == STATUS_OK ? "SUCCESS" : "FAILURE");
    printf("----------------------------------------------------------------\n");
}

int main(void) {
    print_banner();

    HwdmpContext ctx;
    memset(&ctx, 0, sizeof(ctx));

    HwdmpStatus status = context_bootstrap(&ctx, "Hello, world!");
    if (status != STATUS_OK) {
        hwdmp_log(LOG_ERROR, "MAIN", "Bootstrap failed with code %d", status);
        print_footer(status);
        return EXIT_FAILURE;
    }

    status = context_dispatch_to_cluster(&ctx);
    if (status != STATUS_OK) {
        hwdmp_log(LOG_ERROR, "MAIN", "Cluster dispatch failed with code %d", status);
        print_footer(status);
        return EXIT_FAILURE;
    }

    printf("\n");
    status = context_render_all_strategies(&ctx, console_output_sink);
    printf("\n");
    if (status != STATUS_OK) {
        hwdmp_log(LOG_ERROR, "MAIN", "Rendering failed with code %d", status);
        print_footer(status);
        return EXIT_FAILURE;
    }

    printf("\n");
    status = context_render_localized_variants(&ctx, console_output_sink);
    printf("\n");
    if (status != STATUS_OK) {
        hwdmp_log(LOG_ERROR, "MAIN", "Localized rendering failed with code %d", status);
        print_footer(status);
        return EXIT_FAILURE;
    }

    context_shutdown(&ctx);
    hwdmp_log(LOG_INFO, "MAIN", "Platform terminated gracefully. Goodbye.");
    print_footer(STATUS_OK);
    return EXIT_SUCCESS;
}
