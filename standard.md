
# CEP&CC 0.1

## Cycle-Exact Performance & Clean Code

### Psychopathic Tier

Target dialect: **C++26**  
Version: **0.1**  
Status: **Draft standard**  
---

# 1. Purpose

CEP&CC 0.1 is a coding standard for C++26 codebases that require both of the following properties simultaneously:

1. **Cycle-exact performance discipline**  
   Performance is treated as a correctness requirement, not as a vague goal.

2. **Clean-code discipline**  
   The code must remain explicit, auditable, reviewable, failure-aware, and free of hidden assumptions.

This standard is intended for systems where performance surprises are unacceptable and code clarity is mandatory. Examples include:

- compilers,
- linkers,
- assemblers,
- disassemblers,
- profilers,
- debuggers,
- virtual machines,
- interpreters,
- JIT compilers,
- game engines,
- renderers,
- audio engines,
- video codecs,
- DSP systems,
- embedded firmware,
- deterministic simulators,
- real-time control systems,
- high-performance parsers,
- network data-plane systems,
- low-latency trading systems,
- operating-system-adjacent userland code.

The standard is deliberately strict. It assumes that:

- humans will forget rules,
- reviewers will miss details,
- compilers will change behavior,
- targets will evolve,
- benchmarks will regress,
- assumptions will become stale,
- comments will rot.

Therefore, CEP&CC favors mechanical enforcement, explicit documentation, measured evidence, and compile-time proof wherever possible.

---

# 2. What “CEP&CC” means

## 2.1 CEP: Cycle-Exact Performance

CEP means that the cost of code is explicit, bounded, and measured.

A function is not CEP-compliant merely because it is fast in one test. It is CEP-compliant only if its cost behavior is understood and documented.

A CEP-compliant hot function must be able to answer all of the following questions:

- What does it do?
- What is its worst-case behavior?
- What is its expected-case behavior?
- What branches does it contain?
- What are the branch probabilities?
- What memory does it read?
- What memory does it write?
- Are accesses aligned?
- Are accesses sequential or random?
- Are accesses cache-friendly?
- Does it cause cache pressure?
- Does it cause TLB pressure?
- Does it cause branch mispredictions?
- Does it allocate memory?
- Does it free memory?
- Does it lock anything?
- Does it perform atomic operations?
- Does it perform system calls?
- Does it perform I/O?
- Does it format text?
- Does it throw exceptions?
- Does it rely on RTTI?
- Does it rely on virtual dispatch?
- Does it rely on indirect function calls?
- Does it rely on compiler-generated temporaries?
- Does it rely on compiler-generated initialization?
- Does it rely on target-specific instructions?
- Does it rely on implementation-defined behavior?
- Does it rely on undefined behavior?
- Does it rely on floating-point behavior that is not explicitly controlled?
- Does it rely on input distribution?
- Does it rely on alignment?
- Does it rely on endianness?
- Does it rely on ABI details?
- Does it rely on OS behavior?
- Does it rely on allocator behavior?
- Does it rely on thread scheduling?
- Does it rely on locale?
- Does it rely on filesystem?
- Does it rely on environment variables?
- Does it rely on time?
- Does it rely on randomness?

If the answer to any of these questions is “I don’t know,” then the function is not CEP-compliant.

---

## 2.2 CC: Clean Code

Clean code in CEP&CC does not mean “short code,” “minimal code,” or “elegant code” in a subjective sense.

Clean code means that the code is explicit enough to be reviewed without guessing.

A clean function must make the following obvious:

- what it does,
- why it exists,
- what it assumes,
- what it owns,
- what it borrows,
- what it returns,
- what can fail,
- what cannot fail,
- what its cost class is,
- whether it is complete, partial, stubbed, or placeholder.

Clean code rejects cleverness that hides cost. It rejects abstractions that make control flow, allocation, or failure behavior invisible.

CEP&CC therefore treats the following as clean-code defects when they hide cost:

- clever template metaprogramming,
- macro-generated control flow,
- exception-based control flow,
- virtual dispatch in hot paths,
- type-erased callables in hot paths,
- implicit conversions,
- hidden constructors,
- hidden destructors,
- hidden allocations,
- hidden global initialization,
- hidden thread-local initialization,
- hidden locale behavior,
- hidden I/O,
- hidden formatting,
- hidden synchronization,
- hidden filesystem access,
- hidden random behavior,
- hidden nondeterministic iteration.

---

## 2.3 Psychopathic Tier

“Psychopathic tier” means the standard does not rely on good intentions.

It assumes that violations will occur unless prevented by:

- compiler warnings,
- static analysis,
- lint,
- comment parsers,
- CI checks,
- benchmark gates,
- unit tests,
- property tests,
- sanitizers,
- review checklists,
- signed exceptions,
- explicit waiver notes.

A rule that cannot be enforced is weak. CEP&CC rules are designed to be enforceable.

---

# 3. Normative terms

The following terms have normative meaning in this standard.

- **Must**: mandatory requirement.
- **Must not**: mandatory prohibition.
- **Should**: strong recommendation; deviation requires justification.
- **Should not**: strong discouragement; deviation requires justification.
- **May**: permitted optional behavior.
- **Banned**: forbidden in the specified context.
- **Restricted**: allowed only under explicit conditions.
- **Cold-only**: allowed only outside hot paths.
- **Hot code**: code where cycle cost, latency, jitter, throughput, or memory traffic matters.
- **Cold code**: code where correctness matters but exact cycle cost does not.
- **CEP-0**: cycle-exact hot code class.
- **CEP-1**: deterministic non-hot runtime code class.
- **CEP-2**: offline or non-deterministic tooling code class.
- **Complete**: implementation is finished, tested, documented, and measured if hot.
- **Partial**: implementation is intentionally incomplete for known cases.
- **Stub**: interface exists but behavior is intentionally minimal or absent.
- **Placeholder**: reserved for future implementation; not production behavior.

---

# 4. Core laws

These laws override all other preferences.

---

## Law 1: No hidden cost

Any mechanism that can introduce hidden cost must be explicitly approved and documented.

Hidden cost includes, but is not limited to:

- heap allocation,
- heap deallocation,
- virtual dispatch,
- indirect calls,
- type erasure,
- exception handling,
- RTTI,
- formatting,
- I/O,
- locale,
- filesystem access,
- syscalls,
- locks,
- atomic reference counting,
- thread creation,
- dynamic initialization,
- lazy initialization,
- guard variables,
- coroutine heap frames,
- dynamic library loading,
- nondeterministic hash iteration,
- unpredictable branch generation,
- hidden compiler builtins,
- hidden template instantiation cost,
- hidden code generation from reflection or macros.

If a feature can cause hidden cost, it must be either:

1. banned in the relevant code class,
2. restricted with explicit conditions,
3. measured and documented.

---

## Law 2: No silent assumptions

Every assumption must be explicit.

Assumptions include:

- alignment,
- endianness,
- integer width,
- pointer size,
- cache line size,
- page size,
- ABI,
- OS behavior,
- allocator behavior,
- floating-point rounding,
- floating-point contraction,
- errno behavior,
- thread interleaving,
- input validity,
- input size,
- lifetime,
- ownership,
- reentrancy,
- interrupt safety,
- signal safety,
- compiler optimization behavior.

If an assumption is not written down and enforced, it does not exist.

---

## Law 3: No comment-only invariants

Comments have literal zero runtime cost. That is required. But it also means they cannot enforce anything by themselves.

If a comment says:

```cpp
// Assumes input is sorted.
```

then the code must also have one of:

- a `static_assert` where possible,
- a debug assertion,
- a runtime check,
- a contract,
- a type constraint,
- a documented caller requirement with test coverage,
- a compile-time proof.

A comment alone is not enough.

---

## Law 4: No unmeasured hot code

Hot code must be measured.

Measurement must include at least:

- disassembly,
- benchmark results,
- target description,
- compiler version,
- compile flags,
- input description,
- date or artifact ID.

A performance claim without evidence is invalid.

---

## Law 5: No unreadable hot code

Hot code must be clean enough to be audited.

If a reviewer cannot understand the control flow, memory access pattern, or failure behavior, the code is not acceptable.

---

## Law 6: No unbounded failure

Failure behavior must be explicit.

Every function must declare whether it can fail and how.

Failure includes:

- invalid input,
- resource exhaustion,
- overflow,
- underflow,
- division by zero,
- NaN,
- infinity,
- alignment violation,
- lifetime violation,
- aliasing violation,
- allocation failure,
- syscall failure,
- hardware error,
- interruption,
- cancellation,
- timeout,
- deadlock,
- priority inversion,
- race condition,
- exception,
- assertion,
- contract violation.

If a function cannot fail, the reason must be documented or provable.

---

## Law 7: No hard-coded assumptions

Hard-coded assumptions are banned.

A hard-coded assumption is a literal or implicit belief about the environment that is not named, justified, and enforced.

Examples:

```cpp
constexpr int cache_line = 64;
```

```cpp
if (x < 4096) ...
```

```cpp
reinterpret_cast<std::uintptr_t>(p) & 15
```

```cpp
sizeof(long) == 8
```

```cpp
sizeof(int) == 4
```

```cpp
char is signed
```

```cpp
double is IEEE 754 binary64
```

These may be true on some targets, but they are not allowed as silent assumptions.

They must become named target configuration values, static assertions, debug assertions, or explicit runtime checks.

---

## Law 8: No stale documentation

A comment that no longer matches the code is a defect.

A performance claim that no longer matches the benchmark is a defect.

A status tag that no longer matches the implementation is a defect.

---

# 5. Conformance classes

CEP&CC defines several code classes. Different rules apply to different classes.

---

## 5.1 CEP-0: Cycle-exact hot code

CEP-0 is the strictest class.

CEP-0 code includes:

- inner loops,
- hot compiler passes,
- instruction scheduling,
- register allocation,
- parsing hot paths,
- opcode dispatch,
- render loops,
- audio callbacks,
- interrupt handlers,
- real-time control loops,
- lock-free data structure fast paths.

CEP-0 requirements:

- No dynamic allocation after initialization.
- No exceptions.
- No RTTI.
- No virtual dispatch unless explicitly waived.
- No `std::function` or `std::any`.
- No I/O.
- No formatting.
- No locale.
- No filesystem.
- No regex.
- No random number generation unless deterministic and budgeted.
- No syscalls.
- No locks.
- No blocking.
- No thread creation.
- No coroutine allocation.
- No hidden static initialization.
- No nondeterministic iteration order.
- No unbounded recursion.
- No unbounded loops.
- No uninitialized reads.
- No undefined behavior.
- No implementation-defined behavior unless documented and target-controlled.
- No platform-specific intrinsics unless isolated and documented.
- No inline assembly unless isolated and measured.
- No hidden copies.
- No hidden temporaries.
- No hidden constructors.
- No hidden destructors.
- No hidden exception unwind tables in hot code if exceptions are disabled.

CEP-0 functions must be marked as hot and must have:

- full CEP comment block,
- measured cost,
- evidence artifact,
- explicit failure list,
- explicit assumptions.

---

## 5.2 CEP-1: Deterministic runtime code

CEP-1 code is not cycle-exact, but it must still be deterministic and explicit.

Examples:

- startup code,
- shutdown code,
- configuration loading,
- compilation passes that are not hot,
- diagnostics,
- error reporting,
- file loading,
- module loading,
- test utilities,
- benchmark setup.

CEP-1 may use:

- controlled allocation,
- `std::expected`,
- exceptions if policy allows,
- logging,
- formatting,
- filesystem,
- threading,
- synchronization,

but only if the behavior is bounded and documented.

CEP-1 code still requires clean-code comments and explicit assumptions.

---

## 5.3 CEP-2: Offline or non-deterministic tooling

CEP-2 code includes tools where determinism and cycle-exactness are not required.

Examples:

- documentation generators,
- code generators run at build time,
- test dashboards,
- profiling utilities,
- experimental utilities.

CEP-2 still requires clean code, but performance rules are relaxed.

---

## 5.4 CC: Clean-code class

CC applies to all code, regardless of performance class.

Every file, module, type, function, and nontrivial block must satisfy clean-code rules.

---

# 6. Build and toolchain requirements

## 6.1 C++26 mode

The project must compile in C++26 mode.

Examples:

```text
-std=c++26
```

or compiler equivalent.

If the compiler does not fully support C++26, the project must gate unavailable features and document the minimum required compiler version.

---

## 6.2 Feature gating

Every optional C++26 feature must be gated by its official feature-test macro.

The project should maintain a central header or module:

```cpp
// cep/features.hpp
```

or:

```cpp
export module cep.features;
```

This module must define boolean constants such as:

```cpp
inline constexpr bool cep_has_modules = ...;
inline constexpr bool cep_has_consteval = ...;
inline constexpr bool cep_has_mdspan = ...;
inline constexpr bool cep_has_expected = ...;
```

Do not scatter feature checks across the codebase.

A feature that is not available must either:

1. be excluded cleanly, or
2. cause a compile-time error with a clear diagnostic.

Silent fallback is banned unless the fallback is explicitly documented.

---

## 6.3 Warnings

Warnings must be treated as errors.

Minimum recommended GCC/Clang flags:

```text
-Wall
-Wextra
-Wpedantic
-Wconversion
-Wsign-conversion
-Wshadow
-Wnon-virtual-dtor
-Wold-style-cast
-Woverloaded-virtual
-Wformat=2
-Werror
```

Minimum recommended MSVC flags:

```text
/W4
/WX
/permissive-
/utf-8
/Zc:__cplusplus
```

Additional warnings should be enabled where available.

---

## 6.4 Forbidden compiler options

The following options are banned in CEP-0 unless explicitly waived:

- `-ffast-math`
- `-funsafe-math-optimizations`
- equivalents that change floating-point semantics
- options that remove undefined behavior traps without documentation
- options that make builds nondeterministic
- options that embed local paths unintentionally
- options that depend on machine-specific state without target configuration

Profile-guided optimization may be used only if:

- the profile is checked in,
- the profile generation is reproducible,
- the benchmark suite is deterministic,
- performance regressions are gated.

---

## 6.5 Deterministic builds

Builds must be deterministic.

That means identical source, compiler, flags, and dependencies must produce identical binaries, except for intentionally embedded version metadata.

Builds must not depend on:

- locale,
- timezone,
- environment variables,
- random seed,
- file iteration order,
- hash seed,
- absolute source paths,
- user name,
- machine name,
- current date/time, unless versioning intentionally requires it.

---

## 6.6 Sanitizers

CI must run:

- AddressSanitizer,
- UndefinedBehaviorSanitizer,
- ThreadSanitizer where concurrency exists,
- MemorySanitizer where supported and relevant,
- debug assertions,
- contract checks if available.

CEP-0 code must be clean under all enabled sanitizers.

Sanitizers are not sufficient for cycle-exact verification, but they are necessary for correctness.

---

# 7. Source organization

## 7.1 Hot/cold separation

Hot code and cold code must be separated.

Recommended namespace layout:

```cpp
namespace cep::hot {}
namespace cep::cold {}
namespace cep::target {}
namespace cep::detail {}
```

Hot code should not depend on cold code except through explicit, documented, cold-entry interfaces.

Cold code may call hot code.

Hot code should not call cold code.

Examples of cold calls banned from hot code:

- logging,
- formatting,
- exception throwing,
- file I/O,
- allocation,
- mutex locking,
- dynamic loading,
- environment queries.

---

## 7.2 Target abstraction

Target-specific behavior must be isolated.

Recommended:

```cpp
namespace cep::target {
    inline constexpr std::size_t cache_line_bytes = CEP_TARGET_CACHE_LINE_BYTES;
    inline constexpr std::size_t page_bytes = CEP_TARGET_PAGE_BYTES;
    inline constexpr bool little_endian = CEP_TARGET_LITTLE_ENDIAN;
}
```

Target-specific code must not leak into generic hot code.

Bad:

```cpp
if (is_x86) {
    ...
}
```

Good:

```cpp
target::do_memory_barrier();
```

or:

```cpp
template <Target T>
void lower_instruction(const Instruction& insn);
```

---

## 7.3 Module boundaries

Modules should be used for all first-party code.

Module interfaces should export only stable API.

Implementation details should live in module partitions or implementation units.

Modules must not leak macros.

Modules must not depend on include order.

Modules must not require the consumer to define configuration macros before importing unless documented.

---

# 8. Detailed C++26 language feature policy

This section explains which language features to use, when to use them, why to use them, and when not to use them.

The general rule is:

> If a feature is not explicitly allowed here, it is restricted in CEP-0 until proven safe and measured.

---

## 8.1 Modules

### What they are

Modules replace textual header inclusion with compiled interface units.

### Use

Use modules for all first-party components.

Use modules to:

- define public interfaces,
- hide implementation details,
- reduce accidental macro leakage,
- improve build determinism,
- improve compile-time isolation.

### Why

Modules are cleaner than headers because they:

- avoid repeated textual inclusion,
- avoid include-order bugs,
- reduce macro pollution,
- make dependencies more explicit,
- support better tooling.

### When not to use

Do not use modules as a thin wrapper around chaotic headers.

Do not create module interfaces that re-export everything indiscriminately.

Do not use module interface units for generated code unless the generator is deterministic and reviewed.

### CEP comment requirements

Every module interface should have:

```cpp
// CEP:WHAT: Module interface for ...
// CEP:WHY: Provides ...
// CEP:STATUS: complete
// CEP:FAILURE: none
// CEP:ASSUMES: ...
// CEP:COST: compile-time only
// CEP:EVIDENCE: build graph / review
```

---

## 8.2 Header units

### What they are

Header units allow legacy headers to be imported instead of included.

### Use

Use header units to isolate third-party or legacy C headers.

### Why

They reduce macro leakage and can improve build consistency.

### When not to use

Do not use header units as the primary architecture if native modules are possible.

Do not import unstable generated headers into hot module interfaces.

Do not allow header units to hide missing dependencies.

---

## 8.3 Namespaces

### Use

All project code must be inside namespaces.

Use nested namespaces to express architecture:

```cpp
namespace cep::codegen {}
namespace cep::ir {}
namespace cep::target::arm64 {}
```

### Why

Namespaces prevent name collisions and communicate structure.

### When not to use

Do not use `using namespace` in module interfaces.

Do not use `using namespace std;` anywhere.

Do not use namespace aliases to hide important origin information in public APIs.

### Rules

- No `using namespace` in headers/module interfaces.
- `using namespace` may be allowed inside function bodies in implementation units, but only if it does not hurt clarity.
- `using enum` is allowed in limited scope when it improves clarity.

---

## 8.4 Preprocessor

### Policy

The preprocessor is banned for logic.

Allowed uses:

- include guards only where modules are not used,
- feature-test gating,
- target configuration macros,
- compiler workaround macros if documented,
- version macros.

Banned uses:

- macro-generated control flow,
- macro DSLs,
- macro-based reflection,
- macro-based serialization,
- macro-based loops,
- macro-based function generation,
- macro-based type generation, except where required by compiler bug workarounds.

### Why

Macros hide syntax, defeat type checking, defeat scoping, and make diagnostics worse.

### When macros are allowed

Macros are allowed only when:

- there is no language alternative,
- the macro is isolated,
- the macro has a `CEP_` prefix,
- the macro is documented,
- the macro is tested,
- the macro does not generate hidden control flow.

---

## 8.5 `auto`, `decltype`, and CTAD

### Use

Use `auto` when:

- the type is obvious from context,
- the type is long and does not matter semantically,
- avoiding truncation is important,
- generic programming requires it.

Use `decltype` and `decltype(auto)` when:

- exact type deduction is required,
- writing the type manually would be fragile.

Use class template argument deduction only when:

- the deduced type is obvious,
- there is no surprising ownership change,
- the deduction guide is explicit and reviewed.

### Why

These features reduce verbosity and prevent accidental narrowing.

### When not to use

Do not use `auto` when the exact type matters for:

- ABI,
- serialization,
- binary layout,
- overflow behavior,
- signedness,
- width,
- alignment,
- API clarity.

Do not use CTAD for owning resource types unless the deduction guide is explicit.

Bad:

```cpp
auto x = get_value();
```

Good when type matters:

```cpp
std::uint32_t x = get_value();
```

---

## 8.6 Structured bindings

### Use

Use structured bindings to decompose:

- pairs,
- tuples,
- structs,
- arrays,
- map iteration results.

### Why

They improve readability and reduce accidental misuse of tuple indices.

### When not to use

Do not use structured bindings when:

- they hide copies,
- they bind large objects by value,
- they create unused variables in hot code,
- they obscure lifetimes.

Use reference bindings when needed:

```cpp
auto&& [key, value] = *it;
```

---

## 8.7 Designated initializers

### Use

Use designated initializers for aggregate configuration structs.

Example:

```cpp
struct SchedulerConfig {
    bool enable_ra;
    bool enable_ls;
    std::size_t max_pressure;
};

constexpr SchedulerConfig cfg{
    .enable_ra = true,
    .enable_ls = false,
    .max_pressure = 64,
};
```

### Why

Designated initializers prevent positional mistakes and make configuration explicit.

### When not to use

Do not use them for:

- non-aggregates,
- types with hidden constructors,
- types where initialization order has side effects.

---

## 8.8 Aggregate initialization

### Use

Use aggregate initialization for plain data structures.

### Why

It is explicit, simple, and avoids constructor overhead.

### When not to use

Do not use aggregate initialization when:

- invariants must be enforced,
- construction can fail,
- resource ownership must be validated,
- initialization order is subtle.

If a type has invariants, give it a constructor or factory function.

---

## 8.9 `std::initializer_list`

### Use

Use `std::initializer_list` only in cold code or convenience APIs.

### Why

It is readable for small literal lists.

### When not to use

Do not use it in CEP-0 unless the generated code is measured.

Do not use it for large data.

Do not use it where allocation or temporary array creation is unacceptable.

---

## 8.10 `constexpr`

### Use

Use `constexpr` for:

- constants,
- lookup tables,
- compile-time computation,
- configuration values,
- math that can be done at compile time.

### Why

`constexpr` moves cost to compile time and can produce literal zero runtime cost.

### When not to use

Do not mark functions `constexpr` as decoration.

Do not use `constexpr` functions that perform dynamic allocation at compile time unless the compiler and library support it and the compile-time cost is controlled.

Do not rely on constant evaluation if the function can also run at runtime unless behavior is identical.

---

## 8.11 `consteval`

### Use

Use `consteval` for functions that must only run at compile time.

### Why

It guarantees no runtime residue.

### When not to use

Do not use `consteval` for functions that may need to run at runtime.

Do not use `consteval` if the function depends on runtime configuration.

---

## 8.12 `constinit`

### Use

Use `constinit` for global variables that are initialized at compile time but may be mutable.

### Why

It prevents dynamic initialization order bugs.

### When not to use

Do not use `constinit` for variables that can be `constexpr`.

Do not use `constinit` for variables with nontrivial destructors unless justified.

---

## 8.13 `if consteval`

### Use

Use `if consteval` to separate compile-time and runtime behavior.

### Why

It is clearer than older constant-evaluation checks.

### When not to use

Do not use it to create different observable semantics without documentation.

If compile-time and runtime behavior differ, the difference must be explained in comments.

---

## 8.14 Concepts

### Use

Use concepts to constrain templates.

Use concepts to express:

- numeric requirements,
- iterator requirements,
- callable requirements,
- layout requirements,
- target requirements,
- compile-time configuration requirements.

### Why

Concepts improve diagnostics and prevent invalid instantiations.

They are zero runtime cost.

### When not to use

Do not create overly complex concept chains that explode compile time.

Do not use concepts to encode runtime policy unless the policy is compile-time decidable.

Do not use concepts as a substitute for runtime validation.

---

## 8.15 Templates

### Use

Use templates for static polymorphism in hot code.

Templates are preferred over virtual dispatch in CEP-0.

### Why

Templates can inline and remove indirect dispatch.

### When not to use

Do not allow template instantiation explosion.

Do not use deeply recursive template metaprogramming in hot compile paths unless compile-time cost is measured.

Do not hide control flow in template specialization unless documented.

Template instantiations must be auditable.

---

## 8.16 Fold expressions

### Use

Use fold expressions for variadic operations where the operation is obvious.

### Why

They are concise and often generate good code.

### When not to use

Do not use fold expressions for complex control flow.

Do not use them when evaluation order matters and is not obvious.

---

## 8.17 Lambdas

### Use

Use lambdas for local function objects.

Use stateless lambdas in hot code when possible.

### Why

Lambdas inline well and avoid named function clutter.

### When not to use

Do not use lambdas with:

- complex captures,
- mutable hidden state,
- references with unclear lifetimes,
- large captures,
- runtime polymorphism,
- side effects in hot loops, unless explicitly documented.

Avoid:

```cpp
auto f = [x, y, z]() mutable { ... };
```

in CEP-0 unless the state machine is explicit.

---

## 8.18 Generic lambdas and template lambdas

### Use

Use generic lambdas for local generic algorithms.

### Why

They reduce boilerplate.

### When not to use

Do not use them if they obscure the exact type being processed.

Do not use them if they cause excessive instantiation.

---

## 8.19 Deducing this / explicit object parameters

### Use

Use deducing this when:

- recursive lambdas are needed,
- overload sets are simplified,
- explicit object parameter improves clarity.

### Why

It can reduce boilerplate and make overload control cleaner.

### When not to use

Do not use it in hot code without inspecting generated code.

Do not use it if it makes call semantics unclear.

---

## 8.20 Attributes

Attributes must be used carefully.

### `[[nodiscard]]`

Required for:

- error types,
- status types,
- factory functions,
- resource handles,
- validation functions.

Do not remove `[[nodiscard]]` to silence warnings.

### `[[fallthrough]]`

Required when switch cases intentionally fall through.

Do not rely on comments alone.

### `[[maybe_unused]]`

Allowed for intentionally unused variables in templates or debug-only code.

Do not use it to hide dead code.

### `[[deprecated]]`

Use for deprecated APIs with a message.

Do not allow deprecated APIs in CEP-0.

### `[[likely]]` and `[[unlikely]]`

Restricted.

Use only when profiling evidence exists.

Do not use them as aesthetic hints.

### `[[assume]]`

Restricted.

Use only when:

- the assumption is proven,
- debug assertion checks it,
- the assumption is documented,
- failure behavior is defined.

Never use `[[assume]]` as validation.

### `[[no_unique_address]]`

Conditional.

Use for empty allocator/tag members when ABI impact is understood.

Do not use in shared libraries without ABI review.

---

## 8.21 `static_assert`

### Use

Use `static_assert` for every compile-time assumption.

Examples:

- type width,
- alignment,
- endianness,
- layout,
- ABI compatibility,
- enum values,
- feature availability.

### Why

`static_assert` is literal zero runtime cost and makes assumptions visible.

### Rules

Every `static_assert` must have a meaningful message.

Bad:

```cpp
static_assert(sizeof(T) == 4);
```

Good:

```cpp
static_assert(sizeof(T) == 4, "T must be exactly 32 bits for binary format compatibility");
```

---

## 8.22 Contracts

If your C++26 toolchain provides contracts, use them.

### Use

Use contracts for:

- preconditions,
- postconditions,
- invariants.

### Why

Contracts make assumptions explicit and can be checked in debug or audit builds.

### When not to use

Do not use contracts for:

- side effects,
- logging in hot code,
- allocation,
- runtime error handling,
- replacing proper validation,
- changing observable behavior.

Contract checking must be configurable.

For CEP-0 release builds, contracts must either:

- be compiled out, or
- trap deterministically.

They must not allocate, format, or throw.

---

## 8.23 Static reflection

If your C++26 toolchain provides static reflection, treat it as a powerful but dangerous feature.

### Use

Use static reflection for:

- compile-time code generation,
- enum-to-string tables,
- serialization metadata,
- visitor generation,
- invariant checking,
- documentation generation,
- compile-time validation.

### Why

Static reflection can be zero runtime cost if it generates compile-time tables or inline functions.

### When not to use

Do not use static reflection if:

- generated code is not reviewed,
- generated code is not tested,
- generated code introduces hidden branches,
- generated code explodes compile time,
- generated code is difficult to debug,
- generated code depends on nondeterministic reflection ordering.

Generated code is not exempt from CEP&CC. It must satisfy the same rules as handwritten code.

---

## 8.24 Pattern matching

If your C++26 toolchain provides pattern matching, use it conditionally.

### Use

Use pattern matching for:

- closed state machines,
- tagged unions,
- opcode dispatch,
- IR node classification,
- exhaustive enum handling.

### Why

Pattern matching can improve clarity and generate jump tables.

### When not to use

Do not use pattern matching when:

- patterns allocate,
- patterns call opaque predicates,
- patterns hide side effects,
- patterns create temporary copies,
- pattern guards make branch prediction unclear,
- codegen is worse than explicit switch.

For CEP-0, inspect generated assembly.

---

## 8.25 Coroutines

### Policy

Coroutines are restricted.

### Use

Use coroutines only for:

- asynchronous orchestration,
- generator-like cold pipelines,
- state machines where clarity outweighs cost.

### Why

Coroutines can make asynchronous control flow easier to read.

### When not to use

Do not use coroutines in CEP-0 unless all of the following are true:

- no heap allocation occurs,
- promise type is explicit,
- allocator behavior is deterministic,
- resume points are deterministic,
- destruction is deterministic,
- generated state machine is measured,
- no hidden locking occurs.

Coroutines often hide:

- allocation,
- indirect resume,
- heap frames,
- destructor ordering,
- cancellation behavior.

Therefore they are banned by default in hot code.

---

## 8.26 Exceptions

### Policy

Exceptions are restricted.

### Use

Exceptions may be used in CEP-1 if:

- the project explicitly enables exceptions,
- exceptions are not used for control flow,
- destructors are noexcept,
- exception objects are small and non-allocating,
- hot boundaries are exception-free.

### Why

Exceptions can simplify cold error handling.

### When not to use

Exceptions are banned in CEP-0.

Do not use exceptions for:

- expected failures,
- parsing failures,
- validation failures,
- resource exhaustion,
- control flow,
- hot-path diagnostics,
- destructors,
- move constructors that must not fail,
- allocator failure in hot code.

Use `std::expected`, status codes, or result types instead.

---

## 8.27 RTTI

### Policy

RTTI is banned in hot code.

### Use

RTTI may be used in cold diagnostic or serialization code if required.

### Why

RTTI can simplify dynamic type queries in cold code.

### When not to use

Do not use RTTI in CEP-0.

Do not use `dynamic_cast` in hot paths.

Do not use `typeid` for dispatch in hot paths.

Use static dispatch, tagged enums, or concepts instead.

---

## 8.28 Virtual functions

### Policy

Virtual functions are banned in CEP-0 unless waived.

### Use

Use virtual functions for:

- plugin interfaces,
- cold abstraction boundaries,
- replaceable tools,
- diagnostic hooks.

### Why

Virtual functions provide runtime polymorphism.

### When not to use

Do not use virtual functions in:

- inner loops,
- dispatch loops,
- IR traversal hot paths,
- instruction selection,
- register allocation,
- renderer hot paths,
- audio callbacks.

Virtual dispatch hides indirect branch cost and prevents inlining.

Preferred alternatives:

- templates,
- concepts,
- CRTP,
- tagged unions,
- enums,
- function pointer tables,
- compile-time dispatch.

---

## 8.29 `new` and `delete`

### Policy

`new` and `delete` are banned in CEP-0.

### Use

Use `new` only in initialization phases or allocator implementations.

### Why

Dynamic allocation is expensive and nondeterministic.

### When not to use

Do not allocate after initialization in hot code.

Use:

- stack allocation,
- arena allocation,
- fixed buffers,
- `std::inplace_vector`,
- static storage.

---

## 8.30 Move semantics

### Use

Use move semantics for transferring ownership of resources.

### Why

Move semantics avoid unnecessary copies.

### Rules

- Move constructors should be `noexcept` when possible.
- Move assignment should leave objects in a valid but unspecified state.
- Moved-from objects must not be used except to destroy or reassign.
- Hot code should avoid move operations that hide deallocation.

---

## 8.31 Perfect forwarding

### Use

Use perfect forwarding in factory functions and emplacement APIs.

### Why

It avoids copies and preserves value category.

### When not to use

Do not use perfect forwarding when:

- the forwarded type is unclear,
- diagnostics become unreadable,
- hot code becomes dependent on template instantiation,
- forwarding hides allocation.

---

## 8.32 Operator overloading

### Use

Overload operators only when the operator meaning is conventional.

Examples:

- arithmetic types,
- iterators,
- mathematical vectors,
- strongly typed units.

### Why

Natural operator use can improve clarity.

### When not to use

Do not overload operators to create DSLs.

Do not overload operators that hide:

- allocation,
- I/O,
- locking,
- formatting,
- network calls,
- filesystem calls.

Do not overload `&&`, `||`, or `,`.

---

## 8.33 User-defined literals

### Use

User-defined literals may be used for strongly typed units:

- bytes,
- cycles,
- hertz,
- milliseconds,
- degrees.

### Why

They improve expressiveness and prevent unit mistakes.

### When not to use

Do not use them if they hide runtime work.

Do not use them for parsing complex strings.

Do not use them in hot code if they allocate.

---

## 8.34 Enumerations

### Use

Use `enum class` for all enumerations.

Do not use unscoped enums unless interfacing with C.

### Why

Scoped enums prevent implicit conversion and name pollution.

### Rules

- Give enums explicit underlying type if binary size matters.
- Use `std::to_underlying` for conversion.
- Do not cast raw integers to enums without validation.

---

## 8.35 `using enum`

### Use

Use `using enum` in local scopes where it improves readability.

### When not to use

Do not use `using enum` in module interfaces.

Do not use it in large scopes where it creates ambiguity.

---

## 8.36 Three-way comparison

### Use

Use `operator<=>` when:

- ordering is meaningful,
- the type is value-like,
- comparison is simple.

### Why

It reduces boilerplate.

### When not to use

Do not use three-way comparison if:

- comparison is expensive,
- comparison is nondeterministic,
- comparison depends on locale,
- comparison depends on uninitialized memory,
- comparison is not total.

For hot code, compare only fields that matter and document cost.

---

## 8.37 `noexcept`

### Use

Mark functions `noexcept` when they truly cannot throw.

Use `noexcept` for:

- move constructors,
- move assignment,
- destructors,
- swap,
- low-level accessors,
- hot functions when exceptions are disabled.

### Why

`noexcept` improves optimization and exception safety.

### Rules

Do not lie.

If a function can throw, do not mark it `noexcept`.

If a function is `noexcept` but calls potentially throwing code, that is a defect.

---

## 8.38 `volatile`

### Policy

`volatile` is restricted.

### Use

Use `volatile` only for memory-mapped I/O or hardware registers.

### When not to use

Do not use `volatile` for:

- concurrency,
- atomics,
- timing,
- preventing optimization of benchmarks,
- preventing compiler reordering in lock-free code.

Use `std::atomic` for concurrency.

---

## 8.39 Inline assembly

### Policy

Inline assembly is restricted and must be isolated.

### Use

Use inline assembly only when:

- a required instruction is not exposed by the compiler,
- exact instruction sequence is required,
- performance-critical sequence cannot be generated reliably.

### Why

Inline assembly gives exact control.

### When not to use

Do not use inline assembly in generic code.

Do not use it for trivial operations the compiler can do well.

Do not use it without documenting:

- clobbers,
- inputs,
- outputs,
- alignment,
- side effects,
- target constraints,
- cycle cost.

Inline assembly must live in target-specific modules.

---

## 8.40 Alignment

### Use

Use `alignas` to enforce alignment.

Use alignment for:

- SIMD,
- cache-line separation,
- DMA buffers,
- lock-free structures.

### Why

Alignment affects performance and correctness.

### Rules

Do not assume alignment.

Prove alignment with:

- `alignas`,
- allocator guarantees,
- static assertions,
- debug checks.

Do not use `reinterpret_cast` to infer alignment without checks.

---

## 8.41 `std::assume_aligned` equivalent

If using aligned pointer hints:

### Use

Use only when alignment is proven.

### Why

It can improve vectorization.

### When not to use

Do not use alignment hints without debug assertion or static proof.

An incorrect alignment hint is undefined behavior.

---

## 8.42 `thread_local`

### Policy

`thread_local` is restricted.

### Use

Use `thread_local` for:

- per-thread arenas,
- per-thread buffers,
- per-thread diagnostic state.

### Why

It can avoid false sharing and locks.

### When not to use

Do not use `thread_local` in CEP-0 unless:

- initialization cost is known,
- access cost is measured,
- destruction cost is known,
- TLS model is understood.

Do not use `thread_local` for hidden lazy initialization.

---

## 8.43 Atomics

### Use

Use atomics for concurrency.

Use explicit memory orders.

### Why

Atomics prevent data races.

### When not to use

Do not use atomics in hot code unless necessary.

Do not use default `std::memory_order_seq_cst` in hot code without justification.

Do not use atomics for:

- logging counters that can be batched,
- metrics that can be thread-local,
- reference counting in hot loops unless measured.

Every atomic operation must document:

- memory order,
- ordering rationale,
- failure points,
- ABA considerations,
- lifetime assumptions.

---

## 8.44 Source character set and string literals

### Use

Use UTF-8 source encoding.

Use `u8`, `u`, `U` string literals only when encoding matters.

### Why

Text encoding assumptions are a common portability defect.

### When not to use

Do not assume `char` is signed.

Do not assume `char` can hold arbitrary Unicode.

Do not use narrow strings for user-visible text without explicit encoding policy.

---

# 9. Detailed C++26 standard library policy

This section covers major standard library feature classes.

General rule:

> If a library feature is not explicitly allowed here, it is restricted in CEP-0 until proven safe and measured.

---

## 9.1 `std::array`

### Use

Use `std::array` for fixed-size arrays.

### Why

It provides bounds-aware access without heap allocation.

### When not to use

Do not use it for runtime-sized data.

Do not use it for large objects on small stacks.

---

## 9.2 `std::vector`

### Use

Use `std::vector` in CEP-1 for dynamic storage.

Use `reserve` when final size is known.

### Why

It is the default dynamic sequence container.

### When not to use

Do not use `std::vector` in CEP-0 unless:

- capacity is reserved before entering hot code,
- no reallocation occurs,
- no exceptions are used,
- element type is trivially relocatable or proven safe.

Do not use `std::vector<bool>` in performance-sensitive code.

---

## 9.3 `std::inplace_vector` or equivalent bounded vector

### Use

Use bounded inline vectors for small collections that must not allocate.

### Why

They avoid heap allocation while retaining vector-like API.

### When not to use

Do not use them when maximum capacity is unknown.

Do not use them for large objects.

Document behavior on overflow.

---

## 9.4 `std::span`

### Use

Use `std::span` for non-owning contiguous views.

### Why

It makes bounds explicit and avoids raw pointer/size pairs.

### When not to use

Do not use `std::span` for ownership.

Do not store spans to temporaries.

Do not use dynamic-extent spans in CEP-0 if static extent is possible.

---

## 9.5 `std::mdspan`

### Use

Use `std::mdspan` for multidimensional non-owning views.

### Why

It makes layout and stride explicit.

### When not to use

Do not use dynamic layout objects in hot code unless measured.

Do not allow hidden bounds checks in CEP-0 release builds.

---

## 9.6 `std::mdspan` subview facilities

If available, use subviews carefully.

### Use

Use subviews for slicing matrices or tensors without copying.

### Why

They avoid allocation.

### When not to use

Do not use subviews if they create hidden temporaries or complex stride calculations in hot code.

---

## 9.7 `std::string`

### Use

Use `std::string` for owning text in cold code.

### Why

It is convenient and safe compared to raw C strings.

### When not to use

Do not use `std::string` in CEP-0.

Do not use it for:

- hot parsing,
- hot formatting,
- hot logging,
- hot diagnostics.

Use `std::string_view` for read-only text.

---

## 9.8 `std::string_view`

### Use

Use `std::string_view` for non-owning read-only text.

### Why

It avoids allocation and copying.

### When not to use

Do not store string views to temporaries.

Do not assume null termination.

Do not use string views for text that may be mutated.

---

## 9.9 `std::optional`

### Use

Use `std::optional` for values that may be absent.

### Why

It makes absence explicit without using pointers.

### When not to use

Do not use `std::optional` when:

- absence is an error,
- absence requires allocation,
- the contained type is large and hot,
- the optional branch is unpredictable and costly.

Do not use `std::optional` as a substitute for proper initialization.

---

## 9.10 `std::optional` reference-like facilities

If C++26 provides optional references:

### Use

Use optional references for nullable reference semantics.

### Why

They can be clearer than raw pointers.

### When not to use

Do not use them if they hide nullability.

Do not use them if pointer codegen is better and the pointer is already non-owning.

---

## 9.11 `std::expected`

### Use

Use `std::expected` for recoverable errors.

### Why

It avoids exceptions and makes failure explicit.

### Rules

- Error type must be small.
- Error type must not allocate.
- Error type must not throw.
- Error construction must be cheap.
- Error paths must be documented.

### When not to use

Do not use `std::expected` for impossible failures.

Do not use it for control flow that is expected in the normal path unless performance is measured.

---

## 9.12 `std::variant`

### Use

Use `std::variant` for closed sum types.

### Why

It is type-safe compared to unions.

### When not to use

Do not use `std::variant` in CEP-0 unless:

- discriminant access is measured,
- visitation codegen is inspected,
- no allocation occurs,
- no exceptions occur,
- active index changes are controlled.

Do not use recursive variants in hot code.

---

## 9.13 `std::any`

### Policy

Banned in hot code.

### Use

Only allowed in cold reflective tooling if absolutely necessary.

### Why banned

It hides type erasure, allocation, and indirect access.

---

## 9.14 `std::function`

### Policy

Banned in hot code.

### Use

Allowed only in cold callback registration.

### Why banned

It hides:

- type erasure,
- allocation,
- indirect calls,
- possible virtual-like dispatch.

Use templates, concepts, or function pointers instead.

---

## 9.15 `std::bind`

### Policy

Banned.

Use lambdas instead.

---

## 9.16 `std::reference_wrapper`

### Use

Use for containers of references or temporary reference wrappers.

### When not to use

Do not use it to hide lifetime problems.

Do not use it in public APIs unless reference semantics are obvious.

---

## 9.17 `std::tuple` and `std::pair`

### Use

Use for simple heterogeneous aggregates.

### Why

They avoid boilerplate for small return types.

### When not to use

Do not use large tuples in hot code.

Do not use tuple indices when named struct fields would be clearer.

If a tuple has semantic meaning, create a struct.

---

## 9.18 `std::bitset`

### Use

Use for fixed-size bit flags.

### Why

It is explicit and compact.

### When not to use

Do not use it when dynamic size is needed.

Do not use it for performance-critical bitmask operations if generated code is worse than manual integers.

---

## 9.19 `std::vector<bool>`

### Policy

Banned in performance-sensitive code.

Use `std::vector<std::uint8_t>` or custom bitmask with explicit layout.

---

## 9.20 Associative containers

### `std::map` / `std::set`

Use only when ordered tree semantics are required.

Avoid in hot code due to pointer chasing.

### `std::unordered_map` / `std::unordered_set`

Restricted.

Use only when:

- hash is deterministic,
- bucket count is fixed,
- rehashing is disabled or budgeted,
- collision behavior is documented,
- iteration order is not relied upon.

Banned in CEP-0 unless fully measured.

### `std::flat_map` / `std::flat_set` if available

Use for read-mostly sorted associative data.

Avoid for high mutation.

Document insertion and deletion cost.

---

## 9.21 `std::list` and `std::forward_list`

### Policy

Banned in hot code.

### Use

Only for rare cases requiring stable iterators and node-based insertion in cold code.

### Why banned

Pointer chasing and allocation are poor for performance.

---

## 9.22 `std::deque`

### Use

Use for double-ended queues in cold or CEP-1 code.

### When not to use

Avoid in CEP-0 due to chunked layout and indirect access.

---

## 9.23 `std::hive` or equivalent stable container

If available:

### Use

Use when element stability is required and allocation is controlled.

### When not to use

Do not use in CEP-0 unless:

- chunk layout is measured,
- pointer chasing is acceptable,
- allocation is bounded.

---

## 9.24 Algorithms

### Use

Use standard algorithms when their behavior is clear.

Examples:

- `std::copy`,
- `std::fill`,
- `std::move`,
- `std::transform`,
- `std::find`,
- `std::sort` in cold code.

### Why

They are well-tested and often optimized.

### When not to use

Do not use algorithms with capturing lambdas if they prevent inlining.

Do not use parallel algorithms in CEP-0.

Do not use algorithms that hide allocation or comparison cost.

---

## 9.25 Ranges

### Policy

Restricted.

### Use

Use ranges in CEP-1 or CEP-2 for readable transformations.

### Why

Ranges can express pipelines cleanly.

### When not to use

Do not use ranges in CEP-0 unless:

- generated assembly is inspected,
- no hidden temporaries exist,
- no hidden allocations exist,
- no hidden branches exist,
- no indirect calls exist.

Prefer explicit loops in hot code when performance matters.

---

## 9.26 Views

### Use

Use views for non-owning transformations in cold code.

### When not to use

Do not use complex view adaptors in hot code.

Do not use filters with expensive predicates in hot code unless measured.

---

## 9.27 Execution policies

### Policy

Banned in CEP-0.

### Use

Use only for offline batch processing where nondeterminism and scheduling are acceptable.

### Why banned

Execution policies introduce scheduling, synchronization, and nondeterminism.

---

## 9.28 `std::execution` senders/receivers if available

### Policy

Restricted.

### Use

Use for structured asynchronous orchestration outside hot paths.

### Why restricted

Async frameworks hide scheduling, allocation, and cancellation behavior.

### When not to use

Do not use in CEP-0.

Do not use for deterministic frame loops or interrupt paths.

---

## 9.29 Threads

### Use

Use `std::thread` or `std::jthread` for control-plane concurrency.

### When not to use

Do not create threads in hot code.

Do not use threads for short work unless measured.

Use `std::jthread` for scoped lifetime and cancellation where appropriate.

---

## 9.30 Mutexes and locks

### Policy

Banned in CEP-0.

### Use

Use mutexes for coarse-grained protection in cold code.

### Why banned

Locks introduce priority inversion, cache contention, and nondeterministic latency.

### When allowed

Allowed in CEP-1 if:

- lock scope is documented,
- deadlock analysis exists,
- lock ordering is documented,
- contention is bounded.

---

## 9.31 Condition variables

### Use

Use for thread coordination in cold or control-plane code.

### When not to use

Do not use in real-time hot paths.

Document spurious wakeup handling.

---

## 9.32 Latches, barriers, semaphores

### Use

Use for synchronization patterns where their semantics fit.

### When not to use

Do not use in CEP-0.

Document memory ordering and lifetime assumptions.

---

## 9.33 `std::atomic`

Already covered in language section, but library rules:

- Use explicit memory orders.
- Use `std::atomic_ref` only when necessary.
- Avoid atomic reference counting in hot code.
- Avoid atomic arithmetic for metrics in hot loops; use thread-local accumulation.

---

## 9.34 Hazard pointers and RCU if available

### Policy

Restricted.

### Use

Use only for specialized lock-free reclamation.

### When not to use

Do not use without rigorous proof and measurement.

Do not use in CEP-0 unless reclamation cost is budgeted.

---

## 9.35 `std::chrono`

### Use

Use for timing, clocks, and durations in cold or measurement code.

### Why

Portable time representation.

### When not to use

Do not call clock functions inside CEP-0 unless the clock source is budgeted and deterministic.

Do not use `std::chrono` for per-frame hot timestamps without measuring overhead.

---

## 9.36 `std::format`

### Policy

Banned in hot code.

### Use

Use for cold diagnostics and logs.

### Why banned

Formatting is expensive and often allocates.

---

## 9.37 `std::print` / `std::println`

### Policy

Banned in hot code.

### Use

Use for cold output.

### Why banned

I/O is expensive and nondeterministic.

---

## 9.38 Iostreams

### Policy

Banned in hot code.

### Use

Use only for legacy or cold diagnostics.

### Why banned

Iostreams can be heavy, locale-sensitive, and synchronized.

Prefer explicit binary I/O or cold logging interfaces.

---

## 9.39 `std::filesystem`

### Policy

Banned in hot code.

### Use

Use for file operations in cold code.

### Why banned

Filesystem operations involve syscalls, allocations, and nondeterminism.

---

## 9.40 `std::regex`

### Policy

Banned in hot code.

### Use

Use only for cold text processing if absolutely necessary.

### Why banned

Regex engines are expensive and often nondeterministic in performance.

Prefer explicit parsers.

---

## 9.41 Locale facilities

### Policy

Banned in hot code.

### Use

Use only when user-facing localization is required.

### Why banned

Locale behavior is expensive, stateful, and nondeterministic for performance.

---

## 9.42 Random number generation

### Policy

Restricted.

### Use

Use deterministic engines with explicit seeds for testing or simulation.

### When not to use

Do not use random number generation in CEP-0 unless:

- deterministic,
- bounded,
- measured,
- required by algorithm.

Do not use nondeterministic random devices in hot code.

---

## 9.43 Numeric facilities

Use:

- `std::bit_cast`,
- `std::byteswap`,
- `std::countl_zero`,
- `std::countr_zero`,
- `std::popcount`,
- `std::rotl`,
- `std::rotr`,
- `std::bit_ceil`,
- `std::bit_floor`,
- `std::bit_width`,
- `std::midpoint`,
- `std::numbers`.

### Why

These are explicit, portable, and often map to hardware.

### When not to use

Do not assume hardware support.

Gate target-specific intrinsics and provide fallbacks.

---

## 9.44 Math functions

### Use

Use math functions only when needed.

### Why restricted

Math functions may:

- allocate,
- set errno,
- have target-specific behavior,
- have unpredictable latency.

### Rules

- Document required precision.
- Document NaN/Inf behavior.
- Document errno behavior.
- Use `std::fma` only when intended.
- Avoid transcendental functions in CEP-0 unless budgeted.

---

## 9.45 Floating-point types

### Use

Use fixed-width floating-point types if available:

- `std::float32_t`
- `std::float64_t`
- `std::bfloat16_t`

### Why

They make precision explicit.

### When not to use

Do not use `long double` unless target support is documented.

Do not assume `float` or `double` sizes in binary formats.

---

## 9.46 `std::complex`

### Use

Use for complex arithmetic in cold or measured numeric code.

### When not to use

Do not use in CEP-0 unless codegen is measured.

---

## 9.47 `std::valarray`

### Policy

Should not be used.

Use explicit arrays, spans, or numeric libraries instead.

---

## 9.48 `std::linalg` if available

### Policy

Restricted.

### Use

Use only if backend kernels are audited.

### Why restricted

Linear algebra libraries can hide allocation, threading, and blocking behavior.

### When not to use

Do not use in CEP-0 without inspecting generated kernels.

---

## 9.49 Type traits

### Use

Use type traits for compile-time decisions.

### Why

Zero runtime cost.

### Rules

Use `std::is_trivially_copyable`, `std::is_nothrow_move_constructible`, etc., to enforce assumptions.

Do not use type traits to silently select dangerous behavior without comments.

---

## 9.50 `std::source_location`

### Use

Use for diagnostics and assertions.

### Why

Better than macros.

### When not to use

Do not store source locations in hot structures.

Do not pass them through CEP-0 inner loops.

---

## 9.51 `std::stacktrace`

### Policy

Cold-only.

### Use

Use for crash reporting.

### Why banned in hot code

Stacktrace capture is expensive.

---

## 9.52 Error handling facilities

Use:

- `std::error_code`,
- `std::error_category`,
- `std::system_error` in cold code,
- `std::expected` for recoverable errors.

Avoid exceptions in hot code.

---

## 9.53 Memory facilities

### Use

- `std::allocator` only in generic containers where unavoidable.
- `std::pmr` only with explicit arenas.
- `std::addressof` when overloading `&` is possible.
- `std::construct_at` / `std::destroy_at` in allocator-aware code.

### When not to use

Do not use polymorphic allocators in CEP-0 unless the resource is fixed and allocation is budgeted.

---

## 9.54 Smart pointers

### `std::unique_ptr`

Use for unique ownership.

Allowed in CEP-1.

Restricted in CEP-0 because deletion may be hidden.

### `std::shared_ptr`

Banned in hot code.

Atomic reference counting is expensive.

### `std::weak_ptr`

Banned in hot code.

Use only in cold ownership graphs.

### Intrusive reference counting

Allowed only if measured and explicitly implemented.

---

## 9.55 `std::function` and callable wrappers

Already covered, but important:

- Banned in CEP-0.
- Use templates/concepts in hot code.
- Use function pointers only when indirect call is budgeted.

---

## 9.56 `std::invoke`

### Use

Use for generic invocation in cold code.

### When not to use

Do not use if it obscures call target in hot code.

---

## 9.57 `std::mem_fn`

Banned.

Use lambdas.

---

## 9.58 `std::not_fn`

Use sparingly.

Do not use if it harms clarity.

---

## 9.59 `std::bind_front` / `std::bind_back`

Conditional.

Use only if clearer than lambda and no hidden allocation.

---

## 9.60 `std::integer_sequence`

Use for compile-time integer sequences.

Why: zero runtime cost.

Do not use to generate huge instantiation chains without compile-time budget.

---

## 9.61 `std::spanstream` or equivalent if available

### Use

Use for buffered text over fixed spans in cold or measured code.

### When not to use

Do not use for hot formatting.

---

## 9.62 `std::charconv`

### Use

Use for fast integer and floating-point conversion when needed.

### Why

It is generally faster than iostreams.

### When not to use

Do not use in CEP-0 unless measured.

Do not assume all formats are supported.

---

# 10. Comment standard

This is one of the most important parts of CEP&CC.

Comments must be:

- zero runtime cost,
- machine-parseable,
- maintained,
- explicit,
- failure-aware,
- assumption-aware,
- cost-aware,
- status-aware.

---

## 10.1 Literal zero-cost requirement

Comments must have literal zero runtime cost.

That means:

- comments are removed by the compiler,
- comments do not create runtime strings,
- comments do not create debug strings unless explicitly intended,
- comments do not affect ABI,
- comments do not affect code generation,
- comments do not create reflection metadata at runtime,
- comments do not create log messages by themselves.

If a comment is parsed by a tool, the generated artifact is not a comment. The generated artifact must satisfy all CEP&CC rules.

---

## 10.2 Required comment fields

Every nontrivial file, module, type, function, hot loop, unsafe block, stub, placeholder, partial implementation, and target-specific block must include these fields:

```cpp
// CEP:WHAT:
// CEP:WHY:
// CEP:STATUS:
// CEP:FAILURE:
// CEP:ASSUMES:
// CEP:COST:
// CEP:EVIDENCE:
```

Optional fields:

```cpp
// CEP:OWNER:
// CEP:TICKET:
// CEP:TARGET:
// CEP:SECURITY:
// CEP:PORTABILITY:
// CEP:REVIEW:
```

---

## 10.3 `CEP:WHAT`

This field describes what the entity is.

It must be a clear noun phrase or short paragraph.

Good:

```cpp
// CEP:WHAT: Decodes a 32-bit instruction into an opcode descriptor.
```

Bad:

```cpp
// decode
```

The WHAT field must not merely repeat the name.

Bad:

```cpp
// CEP:WHAT: decode_instruction function
```

Good:

```cpp
// CEP:WHAT: Decodes a 32-bit RISC instruction into opcode, operand, and privilege metadata.
```

---

## 10.4 `CEP:WHY`

This field explains why the entity exists and why this approach was chosen.

Good:

```cpp
// CEP:WHY: Table lookup is faster than nested switches for the 7-bit opcode space and keeps dispatch data-driven.
```

Bad:

```cpp
// CEP:WHY: fast
```

The WHY field must include rejected alternatives when the choice is non-obvious.

Example:

```cpp
// CEP:WHY: A sorted vector is used instead of unordered_map because the table is read-mostly and cache locality dominates lookup cost.
```

---

## 10.5 `CEP:STATUS`

This field must be one of:

```text
complete
partial
stub
placeholder
```

### Complete

```cpp
// CEP:STATUS: complete
```

Means:

- implemented,
- tested,
- documented,
- reviewed,
- measured if hot.

### Partial

```cpp
// CEP:STATUS: partial
```

Means:

- implemented for a known subset,
- missing cases are listed,
- owner/ticket exists.

Example:

```cpp
// CEP:STATUS: partial
// CEP:TODO(alice): CEP-314: Handle vector predicated instructions.
```

### Stub

```cpp
// CEP:STATUS: stub
```

Means:

- interface exists,
- body is intentionally minimal,
- behavior is not production-complete.

Stubs must fail loudly in debug.

Example:

```cpp
// CEP:STATUS: stub
// CEP:FAILURE: Debug assertion fires if called.
```

### Placeholder

```cpp
// CEP:STATUS: placeholder
```

Means:

- reserved for future implementation,
- should not be used in production paths,
- may not have meaningful behavior.

Placeholders must not be callable in release builds without explicit error handling.

---

## 10.6 `CEP:FAILURE`

This field lists failure points.

If there are no failure points, write:

```cpp
// CEP:FAILURE: none
```

Do not write vague phrases like:

```cpp
// should not fail
```

Good:

```cpp
// CEP:FAILURE: Returns parse_error::bad_opcode if opcode is outside the valid range. No allocation. No throw.
```

Good for hot loop:

```cpp
// CEP:FAILURE: none; input size is bounded and arithmetic uses wrapping u32 by design.
```

Failure points to consider:

- invalid input,
- empty input,
- oversized input,
- overflow,
- underflow,
- NaN,
- infinity,
- division by zero,
- misalignment,
- aliasing,
- dangling reference,
- allocation failure,
- syscall failure,
- timeout,
- interruption,
- race condition,
- deadlock,
- priority inversion,
- unsupported target,
- compiler divergence,
- hardware fault,
- contract violation.

---

## 10.7 `CEP:ASSUMES`

This field lists assumptions.

If there are no assumptions, write:

```cpp
// CEP:ASSUMES: none
```

Do not allow hard-coded assumptions.

Bad:

```cpp
// CEP:ASSUMES: x86-64, little endian
```

Good:

```cpp
// CEP:ASSUMES: target endianness is little; enforced by static_assert in cep::target.
```

Good:

```cpp
// CEP:ASSUMES: data is 4-byte aligned; checked by debug assertion.
```

Every assumption must be enforced by one of:

- `static_assert`,
- debug assertion,
- runtime check,
- contract,
- type constraint,
- target configuration,
- documented caller contract with tests.

---

## 10.8 `CEP:COST`

This field describes performance cost.

For cold code:

```cpp
// CEP:COST: cold; not performance-critical.
```

For compile-time code:

```cpp
// CEP:COST: compile-time only; no runtime instructions.
```

For hot code:

```cpp
// CEP:COST: 3 cycles/element on target cortex-m7, -O3, measured 2026-09-01.
```

Or:

```cpp
// CEP:COST: 12 cycles expected, 18 cycles worst-case on target arm64-a78, artifact bench-193.
```

If cost is not measured:

```cpp
// CEP:COST: not measured; not valid for CEP-0.
```

A CEP-0 function cannot be `complete` without measured cost.

---

## 10.9 `CEP:EVIDENCE`

This field points to proof.

Evidence may be:

- benchmark ID,
- unit test ID,
- fuzz test ID,
- disassembly artifact,
- compiler explorer link hash,
- review record,
- ticket ID.

Examples:

```cpp
// CEP:EVIDENCE: bench CEP-0019, asm artifact a41c9e2.
```

```cpp
// CEP:EVIDENCE: unit test cep::decode::test_opcode_table.
```

```cpp
// CEP:EVIDENCE: review 2026-09-12 by alice.
```

If there is no evidence, the code cannot be marked complete for hot paths.

---

## 10.10 `CEP:OWNER` and `CEP:TICKET`

Required for:

- partial,
- stub,
- placeholder,
- known defects,
- waivers.

Example:

```cpp
// CEP:OWNER: alice
// CEP:TICKET: CEP-512
```

Do not allow anonymous TODOs.

Bad:

```cpp
// TODO: fix later
```

Good:

```cpp
// CEP:TODO(alice): CEP-512: Handle predicated vector encodings.
```

---

## 10.11 `CEP:TARGET`

Use when code is target-specific.

Example:

```cpp
// CEP:TARGET: arm64
```

or:

```cpp
// CEP:TARGET: riscv64
```

This field must exist for:

- inline assembly,
- intrinsics,
- target-specific alignment,
- target-specific cache assumptions,
- target-specific instruction latency.

---

## 10.12 `CEP:SECURITY`

Use when security-sensitive behavior exists.

Examples:

- parsing untrusted input,
- handling secrets,
- cryptographic operations,
- privilege transitions,
- memory safety boundaries.

Example:

```cpp
// CEP:SECURITY: Input may be untrusted; all bounds are checked before read.
```

---

## 10.13 `CEP:PORTABILITY`

Use when behavior depends on portability concerns.

Examples:

- endianness,
- ABI,
- floating-point format,
- character encoding,
- file path semantics.

---

## 10.14 Comment anti-patterns

The following are defects:

### Repeating code

Bad:

```cpp
// increment i
++i;
```

### Vague performance claims

Bad:

```cpp
// fast path
```

Required:

```cpp
// CEP:COST: ...
// CEP:EVIDENCE: ...
```

### Comment-only assumptions

Bad:

```cpp
// assumes aligned
```

Required:

```cpp
// CEP:ASSUMES: aligned to 16 bytes; enforced by CEP_ASSERT.
```

### Commented-out code

Banned.

Use version control.

### Stale comments

Defect.

### Jokes or personal notes

Banned in normative code comments.

### Secrets

Banned.

### TODO without owner/ticket

Banned.

---

# 11. Hard-coded assumptions ban

This section expands the hard-coded assumption rule.

---

## 11.1 What counts as a hard-coded assumption?

Any literal or implicit belief that is not named and enforced.

Examples:

```cpp
if (size > 4096)
```

```cpp
alignas(64)
```

if 64 is not a named target constant.

```cpp
x & 63
```

if 63 assumes 64-byte cache line.

```cpp
sizeof(int) == 4
```

```cpp
sizeof(void*) == 8
```

```cpp
std::endian::native == std::endian::little
```

without static assertion.

---

## 11.2 Required handling

Every assumption must be handled in one of these ways.

### 1. Named constant

```cpp
namespace cep::target {
    inline constexpr std::size_t page_bytes = CEP_TARGET_PAGE_BYTES;
}
```

### 2. Static assertion

```cpp
static_assert(sizeof(std::uint32_t) == 4, "u32 must be exactly 4 bytes");
```

### 3. Debug assertion

```cpp
CEP_ASSERT(is_aligned(ptr, 16));
```

### 4. Runtime check

```cpp
if (!is_aligned(ptr, 16)) return error::misaligned;
```

### 5. Contract

If C++26 contracts are available:

```cpp
pre(is_aligned(ptr, 16));
```

### 6. Type constraint

Use types that make invalid states unrepresentable.

Example:

```cpp
template <std::size_t Alignment>
class AlignedPtr;
```

---

## 11.3 Magic numbers

Magic numbers are banned except for trivial arithmetic identities where meaning is obvious.

Even then, prefer named constants.

Bad:

```cpp
if (opcode == 0x7F)
```

Good:

```cpp
inline constexpr Opcode kVectorOpcode = static_cast<Opcode>(0x7F);
```

Better:

```cpp
enum class Opcode : std::uint8_t {
    vector = 0x7F,
};
```

---

# 12. Failure-point documentation

Every function must document failure behavior.

---

## 12.1 Failure classes

The comment must identify relevant classes:

- input validation failure,
- resource exhaustion,
- arithmetic overflow,
- arithmetic underflow,
- NaN,
- infinity,
- misalignment,
- aliasing violation,
- lifetime violation,
- allocation failure,
- syscall failure,
- concurrency race,
- deadlock,
- timeout,
- cancellation,
- interruption,
- unsupported feature,
- target mismatch,
- compiler divergence,
- hardware fault.

---

## 12.2 Failure behavior

For each failure, state what happens:

- returns error,
- traps,
- asserts,
- throws (if allowed),
- logs cold,
- aborts,
- retries,
- ignores safely.

Do not leave failure behavior implicit.

---

# 13. Cycle-exact measurement requirements

## 13.1 Measurement artifacts

For every CEP-0 function, store:

- source revision,
- compiler version,
- compiler flags,
- target CPU,
- target frequency state,
- input dataset,
- benchmark harness version,
- measured cycles,
- measured instructions,
- disassembly excerpt or hash.

---

## 13.2 Benchmark environment

Benchmarks should:

- pin threads,
- disable turbo where possible,
- use fixed frequency,
- isolate CPUs,
- disable background work,
- use huge pages if relevant,
- lock memory if relevant,
- warm caches if measuring steady state,
- flush caches if measuring cold behavior.

The benchmark configuration must be documented.

---

## 13.3 Cost categories

Cost comments should distinguish:

- best case,
- expected case,
- worst case,
- cache miss case,
- branch mispredict case,
- fault case.

Example:

```cpp
// CEP:COST: expected 14 cycles, worst 34 cycles with L1 miss, artifact bench-201.
```

---

## 13.4 Regression gates

CI must fail if:

- CEP-0 benchmark regresses beyond allowed threshold,
- disassembly changes unexpectedly,
- branch count changes unexpectedly,
- allocation appears in hot code,
- exceptions appear in hot code,
- virtual calls appear in hot code.

---

# 14. Clean-code requirements

## 14.1 Naming

Use one consistent style.

Recommended:

```cpp
namespace cep::codegen {}

class InstructionScheduler {};

struct RegisterMask {};

constexpr std::size_t kMaxOpcodeTableEntries = 512;

auto schedule_instruction() -> ScheduleResult;

std::int32_t frame_index;
```

Rules:

- types: `PascalCase`,
- functions/variables: `snake_case`,
- constants: `kPascalCase`,
- macros: `CEP_UPPER_SNAKE_CASE`,
- namespaces: `snake_case`.

No single-letter names except loop indices, template parameters, and mathematical conventions.

---

## 14.2 Ownership

Ownership must be explicit.

| Type | Meaning |
|---|---|
| `T` | value ownership |
| `T*` | non-owning, nullable |
| `T&` | non-owning, non-null |
| `std::unique_ptr<T>` | exclusive ownership |
| `std::shared_ptr<T>` | shared ownership, banned in hot code |
| `std::span<T>` | non-owning contiguous mutable view |
| `std::span<const T>` | non-owning contiguous read-only view |
| `std::string_view` | non-owning read-only text view |

Raw pointers must not own resources.

---

## 14.3 Const correctness

Default to `const`.

Use `constexpr` for compile-time constants.

Use `constinit` for global variables that are not `constexpr`.

Use `mutable` only with a comment explaining why mutation is logically const.

---

## 14.4 Explicitness

Required:

- `explicit` constructors unless copy/move,
- explicit integer widths,
- explicit casts,
- `noexcept` where guaranteed,
- `[[nodiscard]]` on status/error/factory functions.

Banned:

- C-style casts,
- implicit narrowing,
- implicit signed/unsigned comparisons,
- implicit conversion constructors,
- implicit exception paths in hot code.

Use:

```cpp
static_cast<T>
```

or named conversion functions.

---

## 14.5 Functions

Every function must answer:

1. What does it do?
2. What does it assume?
3. What can fail?
4. What is its cost?
5. Is it complete?

Recommended limits:

- one function, one responsibility,
- avoid functions over ~80 lines unless hot-loop structure requires it,
- avoid deep nesting,
- prefer early returns for error handling,
- no output parameters where a return is clearer,
- no in/out parameters unless required by performance and documented.

---

## 14.6 Headers and modules

Module interfaces must not:

- export macros,
- include unnecessary implementation details,
- leak private implementation types,
- depend on include order.

Use partitions for large components.

Use implementation units for non-public code.

---

# 15. Compiler-specific additions

If the codebase is itself a compiler, these additional rules apply.

---

## 15.1 Deterministic diagnostics

Diagnostics must not depend on:

- pointer addresses,
- hash iteration order,
- locale,
- time,
- environment,
- unstable file ordering.

Diagnostic output must be stable across runs.

---

## 15.2 Pass ordering

Compiler passes must be explicit and versioned.

No pass may silently depend on another pass’s output unless documented.

Pass pipelines must be testable in isolation.

---

## 15.3 IR stability

Intermediate representations must:

- be printable,
- be hashable deterministically,
- have stable IDs,
- avoid hidden target assumptions.

IR must not rely on pointer values for semantic identity.

---

## 15.4 Target hooks

All target-specific behavior must go through explicit target hooks.

No generic backend code may contain:

```cpp
if (is_x86) ...
```

Use target policy objects or concept-constrained target interfaces.

---

## 15.5 Compiler memory

Compiler allocations must use arena/pool allocators per compilation phase.

Do not use global `new` in passes.

---

# 16. Enforcement and CI

CI must enforce:

- C++26 mode,
- warnings as errors,
- sanitizer cleanliness,
- comment schema presence,
- no TODO without owner/ticket,
- no stub in CEP-0 without waiver,
- no placeholder in production hot path,
- benchmark regression gates,
- disassembly golden checks,
- no magic constants lint,
- no banned features in hot code,
- no hard-coded assumptions lint.

---

# 17. Review checklist

A change is compliant only if all are true.

## Build

- [ ] Compiles as C++26.
- [ ] All optional features are feature-test gated.
- [ ] Warnings as errors.
- [ ] Sanitizers clean.
- [ ] No undefined behavior.

## Performance

- [ ] No hidden allocation in hot code.
- [ ] No exceptions in hot code.
- [ ] No RTTI in hot code.
- [ ] No virtual dispatch in hot code.
- [ ] No I/O in hot code.
- [ ] No formatting in hot code.
- [ ] No locks in hot code.
- [ ] All hot branches documented.
- [ ] All hot loops have measured cost.

## Clean code

- [ ] Ownership is explicit.
- [ ] Lifetimes are explicit.
- [ ] Error handling is explicit.
- [ ] No magic constants.
- [ ] No commented-out code.
- [ ] No stale comments.
- [ ] All public APIs are `[[nodiscard]]` where appropriate.

## Comments

- [ ] `CEP:WHAT` present.
- [ ] `CEP:WHY` present.
- [ ] `CEP:STATUS` present.
- [ ] `CEP:FAILURE` present.
- [ ] `CEP:ASSUMES` present.
- [ ] `CEP:COST` present for performance-relevant code.
- [ ] `CEP:EVIDENCE` present for measured claims.

## Assumptions

- [ ] No hard-coded endianness.
- [ ] No hard-coded alignment.
- [ ] No hard-coded cache line size.
- [ ] No hard-coded page size.
- [ ] No hard-coded ABI assumptions.
- [ ] No hard-coded floating-point behavior.
- [ ] All assumptions are enforced or cited.

---

# 18. Example: compliant CEP&CC function

```cpp
// CEP:WHAT: Computes a 64-bit additive checksum over a contiguous u32 buffer.
// CEP:WHY: Control-plane validation needs a cheap, allocation-free checksum.
// CEP:STATUS: complete
// CEP:FAILURE: Returns kChecksumEmpty for empty input. No allocation. No UB.
// CEP:ASSUMES: data.data() is 4-byte aligned; enforced by debug assert.
// CEP:COST: 1 cycle/element on target cortex-m7, -O3, measured 2026-09-01.
// CEP:EVIDENCE: bench CEP-0019, asm artifact a41c9e2.
[[nodiscard]]
constexpr auto compute_checksum(std::span<const std::uint32_t> data) noexcept
    -> std::uint64_t
{
    // CEP:WHAT: Empty-input sentinel.
    // CEP:WHY: Lets caller distinguish empty buffer from zero checksum.
    // CEP:STATUS: complete
    // CEP:FAILURE: none
    // CEP:ASSUMES: none
    // CEP:COST: constant
    // CEP:EVIDENCE: unit test cep::checksum::empty
    if (data.empty()) {
        return kChecksumEmpty;
    }

    CEP_ASSERT(
        (reinterpret_cast<std::uintptr_t>(data.data()) % alignof(std::uint32_t)) == 0
    );

    std::uint64_t sum = 0;

    // CEP:WHAT: Main accumulation loop.
    // CEP:WHY: 64-bit accumulator prevents overflow for any bounded input size.
    // CEP:STATUS: complete
    // CEP:FAILURE: none
    // CEP:ASSUMES: data.size() <= kMaxChecksumElements; checked by caller.
    // CEP:COST: 1 cycle/element measured.
    // CEP:EVIDENCE: bench CEP-0019
    for (std::size_t i = 0; i != data.size(); ++i) {
        sum += data[i];
    }

    return sum;
}
```

---

# 19. Example: stub

```cpp
// CEP:WHAT: Lowers target-specific vector intrinsics.
// CEP:WHY: Required for vector codegen, not yet implemented.
// CEP:STATUS: stub
// CEP:FAILURE: Debug assertion fires if called in debug. Release returns unsupported error.
// CEP:ASSUMES: only called from cold lowering phase.
// CEP:COST: not applicable; stub.
// CEP:EVIDENCE: ticket CEP-512.
[[nodiscard]]
auto lower_vector_intrinsics([[maybe_unused]] const VectorOp& op) noexcept
    -> std::expected<LoweredOp, LowerError>
{
    CEP_ASSERT(false && "vector lowering stub");
    return std::unexpected(LowerError::unsupported);
}
```

---

# 20. Example: placeholder

```cpp
// CEP:WHAT: Reserved hook for future register pressure feedback.
// CEP:WHY: Scheduler API must remain stable while allocator integration is designed.
// CEP:STATUS: placeholder
// CEP:FAILURE: static_assert if instantiated in production build.
// CEP:ASSUMES: no production call sites.
// CEP:COST: zero; not emitted.
// CEP:EVIDENCE: design doc CEP-ARCH-009.
```

---

Added. The following are new normative chapters to append to **CEP&CC 0.1**.

These additions introduce:

1. **Security requirements**.
2. **Literal optimal code definition**.
3. **Multi-language companion policy** for:
   - Rust,
   - C,
   - Zig,
   - Python/Lua tooling.

These chapters are written as direct additions to the existing standard.

---

# 22. Security

Security is a first-class correctness requirement in CEP&CC.

A function is not compliant if it is fast but exploitable.

Security rules apply to all code classes, with stricter rules for CEP-0 and FFI boundaries.

---

## 22.1 Security objective

The security objective is:

> No input, environment state, toolchain artifact, or FFI boundary may cause undefined behavior, memory unsafety, privilege escalation, secret leakage, denial of service, or silent corruption beyond the documented failure policy.

Security defects include:

- buffer overflow,
- out-of-bounds read,
- use-after-free,
- double-free,
- uninitialized read,
- uninitialized write,
- integer overflow,
- signed overflow,
- unchecked truncation,
- stack overflow,
- uncontrolled recursion,
- format string injection,
- path traversal,
- command injection,
- deserialization attack,
- TOCTOU race,
- side-channel leakage,
- secret leakage in logs,
- secret leakage in error messages,
- untrusted allocator control,
- untrusted code generation,
- supply-chain compromise,
- compiler/toolchain tampering.

---

## 22.2 Threat model requirement

Every component must have a threat model.

At minimum, the component must answer:

- What input is trusted?
- What input is untrusted?
- What boundaries exist?
- What privileges does the component have?
- What secrets does the component touch?
- What resources can be exhausted?
- What failure mode is acceptable under attack?
- What failure mode is forbidden under attack?

If no threat model exists, the component must treat all external input as untrusted.

---

## 22.3 Trust boundaries

Trust boundaries must be explicit.

Examples of trust boundaries:

- user input,
- network input,
- file input,
- IPC input,
- environment variables,
- command-line arguments,
- configuration files,
- plugin APIs,
- FFI calls,
- kernel interfaces,
- hypervisor interfaces,
- hardware registers,
- generated code,
- toolchain output,
- third-party libraries.

Data crossing a trust boundary must be validated before use.

Validation must include:

- size bounds,
- type bounds,
- alignment,
- encoding,
- lifetime,
- ownership,
- permissions,
- resource limits,
- semantic invariants.

A trust boundary must not be crossed by raw pointers, raw lengths, or unchecked enums without validation.

---

## 22.4 Memory safety

Memory safety is mandatory.

CEP&CC memory-safety rules:

- No out-of-bounds access.
- No use-after-free.
- No double-free.
- No uninitialized reads.
- No uninitialized writes.
- No dangling references.
- No dangling spans.
- No dangling string views.
- No hidden lifetime extension.
- No unsafe pointer arithmetic without bounds proof.
- No aliasing violations.
- No type punning through invalid casts.
- No stack overflow from recursion.
- No unbounded alloca-like behavior.
- No variable-length arrays.

In C++, use:

- `std::span` for contiguous views,
- `std::string_view` only with lifetime proof,
- `std::expected` for recoverable errors,
- RAII for resource ownership,
- static assertions for layout assumptions,
- sanitizers in CI.

In unsafe languages, unsafe blocks must be isolated and documented.

---

## 22.5 Input validation

All external input is untrusted until validated.

Input validation must be explicit.

Validation must answer:

- What is the minimum size?
- What is the maximum size?
- What is the required alignment?
- What is the required encoding?
- What is the required lifetime?
- What resource limits apply?
- What happens if validation fails?
- Does failure leak information?

Bad:

```cpp
parse_packet(data);
```

Good:

```cpp
auto packet = validate_packet(data);
if (!packet) return packet.error();
process_packet(*packet);
```

Validation functions must be documented with:

```cpp
// CEP:SECURITY: Validates untrusted network input.
// CEP:FAILURE: Returns error on malformed bounds. No allocation. No throw.
```

---

## 22.6 Integer safety

Integer misuse is a security defect.

Required rules:

- Use fixed-width integer types.
- Do not allow silent narrowing.
- Do not allow silent signed/unsigned mixing.
- Do not allow unchecked overflow.
- Do not allow unchecked underflow.
- Do not allow unchecked multiplication used for allocation sizing.
- Do not allow unchecked array index calculation.
- Do not allow unchecked pointer arithmetic.

Use:

- `std::uint8_t`,
- `std::uint16_t`,
- `std::uint32_t`,
- `std::uint64_t`,
- `std::int8_t`,
- `std::int16_t`,
- `std::int32_t`,
- `std::int64_t`,
- `std::size_t` for sizes,
- `std::ptrdiff_t` for differences.

Use safe comparison helpers:

- `std::cmp_less`,
- `std::cmp_equal`,
- `std::cmp_greater`,
- `std::in_range`.

If wrapping is intentional, it must be documented:

```cpp
// CEP:ASSUMES: u32 wrapping is intentional and part of checksum semantics.
```

If overflow is impossible, prove it:

```cpp
static_assert(kMaxEntries <= SIZE_MAX / sizeof(Entry));
```

---

## 22.7 Unsafe code

Unsafe code is restricted.

Unsafe code includes:

C++:

- raw pointer arithmetic,
- `reinterpret_cast`,
- union type punning where not permitted,
- inline assembly,
- `volatile` hardware access,
- manual lifetime management,
- placement new,
- custom allocator code.

Rust:

- `unsafe` blocks,
- raw pointers,
- FFI declarations,
- manual layout assumptions,
- `MaybeUninit`,
- inline assembly.

C:

- all pointer arithmetic,
- casts,
- unions,
- volatile,
- inline assembly.

Zig:

- pointer casts,
- `@ptrCast`,
- `@bitCast`,
- `@intFromPtr`,
- volatile loads/stores,
- inline assembly.

Unsafe code must have:

```cpp
// CEP:SECURITY: unsafe block
// CEP:WHAT:
// CEP:WHY:
// CEP:FAILURE:
// CEP:ASSUMES:
// CEP:COST:
// CEP:EVIDENCE:
```

Unsafe code must be isolated in small modules.

Unsafe code must not leak unsafe invariants into safe APIs.

---

## 22.8 FFI security

FFI is a security boundary.

FFI rules:

- Every FFI type must have explicit layout.
- Every FFI pointer must be validated where possible.
- Every FFI length must be validated.
- Every FFI enum must be validated before conversion.
- Every FFI callback must be documented.
- Every FFI error contract must be documented.
- Every FFI allocation ownership must be documented.
- Every FFI deallocation owner must be documented.
- Every FFI string encoding must be documented.
- Every FFI struct must be `repr(C)` or equivalent.
- Every FFI function must specify calling convention.
- Every FFI function must be `noexcept`/`extern "C"` or equivalent unless intentionally propagating exceptions, which is banned in CEP-0.

Do not assume safety guarantees cross language boundaries.

Rust references, C pointers, Zig slices, and C++ spans all lose validity guarantees at FFI boundaries unless explicitly checked.

---

## 22.9 Secrets and side channels

Secrets require special treatment.

Secrets include:

- cryptographic keys,
- passwords,
- tokens,
- session identifiers,
- private user data,
- hardware secrets,
- signing keys,
- decrypt keys,
- authentication material.

Rules:

- Secrets must not be logged.
- Secrets must not be formatted into error messages.
- Secrets must not appear in crash dumps unless redacted.
- Secrets must not be copied unnecessarily.
- Secrets must be zeroized according to policy if required.
- Secret-dependent branches are banned in cryptographic hot paths unless explicitly allowed.
- Secret-dependent memory indexing is banned in constant-time paths.
- Timing side channels must be documented.
- Cache side channels must be considered.
- Speculative execution side channels must be considered for security-critical targets.

Security-sensitive code must state:

```cpp
// CEP:SECURITY: constant-time path; no secret-dependent branches.
```

or:

```cpp
// CEP:SECURITY: not constant-time; must not process secret material.
```

---

## 22.10 Denial of service

CEP&CC security treats resource exhaustion as a security defect.

Components must define limits for:

- input size,
- recursion depth,
- allocation count,
- allocation size,
- file descriptors,
- threads,
- stack usage,
- CPU time,
- memory usage,
- open handles,
- queue depth,
- timeout behavior.

Hot paths must not allow untrusted input to cause unbounded work.

Banned:

- unbounded recursion,
- unbounded loop over untrusted length,
- unbounded allocation,
- unbounded string construction,
- unbounded container growth,
- unbounded regex matching,
- unbounded parsing depth,
- unbounded deserialization nesting.

If limits are enforced, the limit value must not be hard-coded without justification.

Bad:

```cpp
if (size > 4096) return error::too_large;
```

Good:

```cpp
if (size > cep::limit::max_packet_bytes) return error::too_large;
```

---

## 22.11 Supply-chain security

Dependencies must be controlled.

Required:

- pinned dependency versions,
- dependency lockfiles,
- dependency hashes,
- vendored third-party code where practical,
- SBOM generation,
- review of new dependencies,
- no network fetch during deterministic release builds unless explicitly approved.

Banned:

- unpinned dependencies,
- mutable dependency tags,
- build scripts that fetch arbitrary remote code in release builds,
- telemetry in build tools,
- undocumented post-install scripts,
- dependency code that violates CEP&CC security rules.

Generated code from dependencies is subject to the same review as handwritten code.

---

## 22.12 Toolchain security

The compiler toolchain is part of the trusted computing base.

Required:

- pinned compiler version,
- compiler hash or signature,
- reproducible builds,
- deterministic flags,
- no hidden environment dependence,
- no telemetry in release builds,
- audited linker behavior,
- audited standard library version.

If a compiler plugin is used, it is security-critical.

Compiler plugins must be:

- reviewed,
- versioned,
- deterministic,
- sandboxed where possible,
- documented.

---

## 22.13 Logging and diagnostics security

Logs are a security surface.

Rules:

- Logs must not contain secrets.
- Logs must not contain unvalidated user-controlled format strings.
- Logs must not contain unbounded user input.
- Logs must be rate-limited where appropriate.
- Error messages must not leak sensitive internal state.
- Stack traces must be disabled or redacted in production where required.
- Debug assertions must not expose secrets.

In CEP-0, logging is banned unless:

- logging is cold,
- logging is lock-free where required,
- logging cannot block the hot path,
- logging cannot allocate in the hot path.

---

## 22.14 Security comment fields

Security-sensitive code must include additional comment fields.

Required where relevant:

```cpp
// CEP:SECURITY:
// CEP:TRUST:
// CEP:THREAT:
// CEP:UNSAFE:
```

### `CEP:SECURITY`

Describes security role.

Examples:

```cpp
// CEP:SECURITY: Parses untrusted binary input.
```

```cpp
// CEP:SECURITY: constant-time comparison of authentication tags.
```

### `CEP:TRUST`

Describes input trust level.

Allowed values:

```text
trusted
validated
untrusted
```

Example:

```cpp
// CEP:TRUST: untrusted until validate_packet returns success.
```

### `CEP:THREAT`

Describes threats considered.

Example:

```cpp
// CEP:THREAT: malformed length, integer overflow, out-of-bounds read.
```

### `CEP:UNSAFE`

Describes unsafe operations.

Example:

```cpp
// CEP:UNSAFE: pointer arithmetic bounded by checked length.
```

If no unsafe behavior exists:

```cpp
// CEP:UNSAFE: none
```

---

## 22.15 Security checklist

A change is security-compliant only if:

- [ ] Threat model is documented.
- [ ] Trust boundaries are explicit.
- [ ] All untrusted input is validated.
- [ ] Integer operations are safe or explicitly documented.
- [ ] Memory safety is enforced.
- [ ] Unsafe code is isolated and documented.
- [ ] FFI boundaries validate all inputs.
- [ ] No secrets appear in logs or errors.
- [ ] Side-channel policy is documented.
- [ ] Resource limits are explicit.
- [ ] Dependencies are pinned and reviewed.
- [ ] Toolchain is pinned and reproducible.
- [ ] Sanitizers pass.
- [ ] Fuzz tests pass where input is untrusted.

---

# 23. Optimal code

This chapter defines what CEP&CC means by “optimal code.”

The term “optimal” must not be used as a vague compliment.

In CEP&CC, optimality is a normative claim with evidence.

---

## 23.1 Literal optimal code definition

CEP&CC defines three optimality classes.

### OPT-0: Locally optimal

A function is locally optimal if, under the documented target and cost model, no known implementation satisfying the same observable behavior has lower measured cost.

This is the minimum required claim for CEP-0 hot code.

### OPT-1: Lower-bound optimal

A function is lower-bound optimal if the implementer provides a lower-bound argument showing that the function cannot be faster under the documented cost model.

Examples of lower-bound arguments:

- must read N bytes,
- must write M bytes,
- must execute at least K dependent operations,
- must perform at least one branch due to input-dependent control flow,
- must call a hardware instruction with known latency,
- must touch at least P cache lines.

### OPT-2: Provably optimal

A function is provably optimal if a formal or exhaustive proof shows optimality under a precise cost model.

This is rare and only required where justified.

---

## 23.2 Practical meaning of “literally optimal”

For CEP&CC, “literally optimal” means:

> The implementation performs no instruction, memory access, branch, allocation, synchronization, or hidden work that is not required by the observable specification, target cost model, and chosen failure policy.

This means optimal code must not contain:

- redundant loads,
- redundant stores,
- redundant branches,
- redundant copies,
- hidden temporaries,
- hidden allocations,
- hidden synchronization,
- hidden initialization,
- hidden exception machinery,
- hidden type erasure,
- hidden virtual dispatch,
- hidden formatting,
- hidden logging,
- hidden locale behavior,
- hidden I/O,
- hidden allocator calls,
- hidden bounds checks in release unless required by security policy,
- hidden compiler runtime calls,
- hidden dynamic initialization,
- hidden destructor work,
- hidden cleanup paths that are semantically unnecessary.

---

## 23.3 Optimality is target-relative

There is no universal optimal code.

Optimality is always relative to:

- target ISA,
- target microarchitecture,
- compiler version,
- compile flags,
- memory hierarchy,
- branch predictor state,
- cache state,
- input distribution,
- failure policy,
- security policy,
- determinism policy.

Therefore every optimality claim must specify the target.

Bad:

```cpp
// optimal
```

Good:

```cpp
// CEP:OPTIMAL: target-optimal on arm64-a78 for aligned 64-byte cache-line inputs.
```

---

## 23.4 Optimality evidence

An optimality claim requires evidence.

Evidence may include:

- disassembly,
- instruction count,
- dependency-chain analysis,
- measured cycles,
- measured uops,
- measured cache misses,
- measured branch mispredictions,
- lower-bound argument,
- exhaustive search,
- compiler output comparison,
- handwritten assembly comparison,
- benchmark suite artifact.

Required comment fields:

```cpp
// CEP:OPTIMAL:
// CEP:OPTPROOF:
```

Examples:

```cpp
// CEP:OPTIMAL: target-optimal
// CEP:OPTPROOF: bench CEP-201; minimum required loads = 8; measured loads = 8.
```

```cpp
// CEP:OPTIMAL: lower-bound optimal
// CEP:OPTPROOF: function must read 32 bytes and write 16 bytes; measured memory ops match lower bound.
```

---

## 23.5 Optimality requirements for CEP-0

CEP-0 hot code must be at least OPT-0.

To claim OPT-0, the following must be true:

1. The function is measured.
2. The target is documented.
3. The input classes are documented.
4. The cost model is documented.
5. Alternatives were considered.
6. Disassembly was reviewed.
7. No hidden work exists.
8. No cheaper known implementation exists.
9. The claim is reviewed.
10. The evidence is stored.

A CEP-0 function cannot be marked:

```cpp
// CEP:STATUS: complete
```

unless it also has either:

```cpp
// CEP:OPTIMAL: target-optimal
```

or:

```cpp
// CEP:OPTIMAL: not-optimal
```

with an optimization ticket if performance matters.

If the function is not optimal but acceptable, it must say:

```cpp
// CEP:OPTIMAL: not-optimal
// CEP:OPTNOTE: acceptable due to maintainability; see CEP-771.
```

Do not lie about optimality.

---

## 23.6 Code-level optimality criteria

Optimal code should satisfy the following where applicable.

### 23.6.1 Minimal work

The function must not do unnecessary work.

Banned examples:

- recomputing invariant values inside loops,
- copying values that could be moved or referenced,
- formatting strings that are not used,
- checking conditions that are already proven,
- initializing memory that will be immediately overwritten,
- calling destructors for trivial objects unnecessarily,
- performing virtual dispatch where static dispatch is possible.

### 23.6.2 Minimal memory traffic

Optimal code minimizes memory traffic.

Required considerations:

- read each required input once,
- write each required output once,
- avoid false sharing,
- avoid cache-line splitting,
- avoid misaligned access,
- avoid unnecessary cache invalidation,
- avoid pointer chasing where contiguous layout is possible,
- prefer structure-of-arrays where vectorization matters.

### 23.6.3 Minimal branching

Optimal code avoids unnecessary branches.

Branch reduction requires:

- profile evidence,
- branchless alternatives considered,
- predication considered,
- lookup tables considered,
- jump tables considered,
- switch lowering inspected.

Do not remove branches if they are required for:

- security checks,
- overflow checks,
- bounds checks,
- failure handling,
- correctness.

Security checks are not “unnecessary work” unless proven redundant.

### 23.6.4 Minimal indirection

Optimal code avoids unnecessary indirection.

Banned in hot optimal code unless required:

- virtual functions,
- function pointers,
- `std::function`,
- type-erased iterators,
- dynamic dispatch,
- pointer-to-pointer chains,
- polymorphic allocators,
- runtime polymorphic containers.

### 23.6.5 Minimal allocation

Optimal hot code does not allocate.

Allocation is hidden work and usually nondeterministic.

Allowed allocation only if:

- done before entering hot path,
- arena-based,
- bounded,
- measured,
- documented.

### 23.6.6 Minimal compile-time residue

Optimal code should not leave unnecessary compile-time residue.

Prefer:

- `constexpr`,
- `consteval`,
- compile-time tables,
- template specialization only where necessary,
- static reflection only if generated code is audited.

Compile-time work is not free. It must be budgeted.

---

## 23.7 Optimality and security

Security checks may prevent some forms of micro-optimization.

CEP&CC rule:

> Security correctness beats micro-optimality.

A function that is faster but exploitable is not optimal.

If a security check costs cycles, it must be documented as required cost.

Example:

```cpp
// CEP:OPTNOTE: bounds check retained; required for untrusted input security.
```

Do not remove bounds checks to claim optimality unless the input is trusted or proven safe.

---

## 23.8 Optimality and clean code

Clean code is required for optimality because hidden cost hides in unclear code.

A reviewer cannot certify optimal code if:

- ownership is unclear,
- lifetimes are unclear,
- assumptions are unclear,
- failure behavior is unclear,
- branch probabilities are unclear,
- memory layout is unclear,
- target dependencies are unclear.

Therefore clean-code violations are optimality blockers.

---

## 23.9 Optimality comment examples

Good:

```cpp
// CEP:OPTIMAL: target-optimal
// CEP:OPTPROOF: bench CEP-301; 16 loads, 16 stores, 0 branches; matches required memory lower bound.
```

Good:

```cpp
// CEP:OPTIMAL: not-optimal
// CEP:OPTNOTE: uses scalar loop; vectorization blocked by target errata; see CEP-402.
```

Bad:

```cpp
// optimal
```

Bad:

```cpp
// fastest possible
```

Bad:

```cpp
// should inline well
```

---

# 24. Multi-language companion policy

CEP&CC recognizes that real systems are rarely pure C++.

However, the standard remains C++26-primary unless otherwise stated.

Companion languages are allowed only when their role is explicit and their code is adapted to CEP&CC rules.

The companion languages defined here are:

1. Rust — safe systems alternative / FFI boundary.
2. C — legacy/hardware interface.
3. Zig — modern low-level alternative.
4. Python / Lua — CEP-2 tooling only.

---

## 24.1 General companion-language rules

All companion-language code must obey the same high-level CEP&CC laws:

- no hidden cost,
- no silent assumptions,
- no comment-only invariants,
- no unmeasured hot code,
- no unreadable hot code,
- no unbounded failure,
- no hard-coded assumptions,
- no stale documentation,
- explicit security policy,
- explicit optimality policy.

Companion-language code must use the same CEP comment schema:

```text
CEP:WHAT
CEP:WHY
CEP:STATUS
CEP:FAILURE
CEP:ASSUMES
CEP:COST
CEP:EVIDENCE
CEP:SECURITY
CEP:OPTIMAL
CEP:OPTPROOF
```

If the language comment syntax differs, use the closest line-comment form.

---

# 25. Rust companion policy

## 25.1 Role

Rust is the primary safe-systems companion language.

Its role is:

- safe systems alternative,
- FFI boundary language,
- memory-safe component language,
- tool for isolating unsafe logic behind safe APIs.

Rust is allowed where:

- memory safety is critical,
- FFI boundaries require safer ownership,
- components can be built deterministically,
- runtime cost is compatible with CEP requirements.

---

## 25.2 Why Rust is allowed

Rust is allowed because it provides:

- zero-cost abstractions comparable to C++,
- memory safety without garbage collection,
- strong type system,
- explicit lifetimes,
- explicit ownership,
- explicit mutability,
- `no_std` support,
- explicit unsafe boundaries.

However, Rust is not automatically safe in performance-critical code. Rust can still hide:

- allocation,
- panics,
- dynamic dispatch,
- drop glue,
- formatting,
- iterator overhead,
- atomics,
- synchronization,
- FFI undefined behavior.

Therefore CEP&CC adapts Rust rules as follows.

---

## 25.3 Rust CEP-0 rules

For Rust CEP-0 hot code:

### 25.3.1 Runtime

Banned:

- `std` runtime dependence in hot code,
- `Box`,
- `Vec`,
- `String`,
- `format!`,
- `println!`,
- `eprintln!`,
- `panic!`,
- `unwrap`,
- `expect`,
- `todo!`,
- `unimplemented!`,
- `unreachable!` unless proven and documented,
- `Rc`,
- `Arc`,
- `Mutex`,
- `RwLock`,
- channels,
- thread spawning,
- dynamic allocation,
- `async` runtime dependence,
- `Future` allocation in hot paths,
- trait objects via `dyn`,
- dynamic dispatch,
- formatting machinery,
- `std::io`,
- `std::fs`,
- `std::net`,
- `std::env`,
- `std::time` in hot paths unless budgeted.

Required:

- use `core::` over `std::` for hot code,
- use fixed-size slices `&[T]` and `&mut [T]`,
- use references with explicit lifetimes,
- use explicit integer types,
- use explicit error enums or result types that do not allocate,
- use `#[inline]` only where justified,
- use `#[repr(C)]` or explicit layout for FFI types,
- use `#[no_mangle]` only for FFI exports,
- use `extern "C"` or explicit ABI for FFI functions.

---

## 25.4 Rust panic policy

CEP-0 Rust functions must be panic-free or have proof that panic cannot occur.

Use one of:

- `#![no_std]`,
- `panic = "abort"` in release profile,
- static analysis,
- review,
- tests,
- contracts,
- `#[should_panic]` banned in CEP-0 tests unless testing failure behavior.

Banned in CEP-0:

```rust
.unwrap()
.expect("...")
panic!("...")
```

Allowed only if proof exists:

```rust
// CEP:ASSUMES: index is checked immediately above.
// CEP:SECURITY: bounds check retained.
```

If a panic is possible, the function is not CEP-0-complete.

---

## 25.5 Rust allocation policy

Allocation is banned in Rust CEP-0.

Banned:

- `Box::new`,
- `Vec::new`,
- `Vec::push`,
- `String::new`,
- `String::push_str`,
- `alloc::vec::Vec` in hot paths,
- any global allocator dependence.

Allowed:

- stack allocation,
- fixed arrays,
- slices,
- caller-provided buffers,
- arena allocation if the arena is initialized before hot path and deterministic.

---

## 25.6 Rust trait object policy

Trait objects are banned in CEP-0.

Banned:

```rust
&dyn Trait
Box<dyn Trait>
Arc<dyn Trait>
```

Reason:

Trait objects introduce dynamic dispatch, which is equivalent to hidden virtual dispatch.

Allowed alternatives:

- generics,
- static dispatch,
- enums,
- function pointer tables if measured,
- compile-time polymorphism.

---

## 25.7 Rust unsafe policy

Unsafe Rust is restricted.

Allowed only when:

- safe Rust cannot express the operation,
- the unsafe block is isolated,
- invariants are documented,
- FFI requires it,
- hardware access requires it.

Every unsafe block must have:

```rust
// CEP:UNSAFE: pointer arithmetic bounded by checked slice length.
// CEP:ASSUMES: ptr is aligned to 4 bytes; checked above.
// CEP:SECURITY: input is untrusted; bounds validated.
```

Unsafe code must not leak invariants.

A safe function wrapping unsafe code must uphold all safe guarantees.

---

## 25.8 Rust FFI policy

Rust FFI types must have explicit layout.

Required:

```rust
#[repr(C)]
```

or:

```rust
#[repr(transparent)]
```

where appropriate.

FFI functions must specify ABI:

```rust
pub extern "C" fn cep_decode(...)
```

FFI functions must not unwind across the boundary.

Use:

```rust
#[no_mangle]
pub extern "C" fn ...
```

only when required.

FFI inputs must be validated:

- pointers checked for null if nullable,
- lengths checked,
- alignment checked,
- enum values checked,
- lifetimes cannot be assumed from C/C++.

---

## 25.9 Rust comment example

```rust
// CEP:WHAT: Decodes a fixed-size 32-bit opcode table entry.
// CEP:WHY: Table lookup is faster than match for hot decoder path.
// CEP:STATUS: complete
// CEP:FAILURE: Returns DecodeError::BadOpcode for invalid opcode.
// CEP:ASSUMES: opcode < 128; checked by caller.
// CEP:COST: 3 cycles expected on arm64-a78, artifact bench-rs-19.
// CEP:EVIDENCE: bench CEP-RS-0019
// CEP:SECURITY: opcode may come from untrusted input.
// CEP:OPTIMAL: target-optimal
// CEP:OPTPROOF: one table load, one branch, no allocation.
#[no_mangle]
pub extern "C" fn cep_decode_opcode(opcode: u8) -> DecodeResult {
    if opcode >= 128 {
        return DecodeResult::err(DecodeError::BadOpcode);
    }

    // CEP:WHAT: Safe table access.
    // CEP:WHY: Bounds check ensures no out-of-bounds read.
    // CEP:SECURITY: bounds check retained for untrusted input.
    let entry = OPCODE_TABLE[opcode as usize];
    DecodeResult::ok(entry)
}
```

---

# 26. C companion policy

## 26.1 Role

C is allowed for:

- ABI stability,
- kernel interfaces,
- hypervisor interfaces,
- embedded bare-metal code,
- hardware registers,
- legacy firmware interfaces,
- stable C ABI boundaries.

C is unavoidable in OS-adjacent and hardware-adjacent code.

However, C is unsafe by default and must be restricted.

---

## 26.2 C standard subset

C code must follow a strict subset.

Acceptable baseline:

- MISRA-C:2023, or
- CERT-C, or
- a project-defined subset that is at least as strict.

If MISRA-C and CEP&CC conflict, the stricter rule applies unless waived.

---

## 26.3 C language restrictions

For CEP-0 C code:

Banned:

- dynamic allocation,
- `malloc`,
- `calloc`,
- `realloc`,
- `free`,
- `alloca`,
- variable-length arrays,
- recursion,
- varargs,
- floating point unless required,
- standard library calls unless intrinsic-like and target-approved,
- implicit integer promotion surprises,
- implicit narrowing,
- implicit signed/unsigned mixing,
- macro logic,
- undefined behavior,
- uninitialized reads,
- out-of-bounds access,
- non-reentrant library functions,
- locale-dependent functions,
- I/O functions,
- formatted printing,
- file operations,
- environment access.

Required:

- fixed-width types only,
- explicit casts where conversion is intentional,
- explicit bounds checks,
- explicit alignment checks,
- explicit volatile only for MMIO,
- `_Static_assert` for compile-time assumptions,
- `static inline` for small hot functions where appropriate,
- deterministic failure behavior.

---

## 26.4 Fixed-width types

C code must use fixed-width types exclusively for binary, hardware, ABI, and performance-critical code.

Required headers:

```c
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
```

Use:

```c
uint8_t
uint16_t
uint32_t
uint64_t
int8_t
int16_t
int32_t
int64_t
uintptr_t
size_t
ptrdiff_t
```

Banned as primary types in hot or ABI code:

```c
int
long
unsigned
unsigned long
short
char
```

unless required by a documented C ABI.

---

## 26.5 C macro policy

Macros are treated as defects unless justified.

Allowed macros:

- include guards,
- feature gates,
- target configuration,
- compiler workaround macros,
- `CEP_` prefixed constants.

Banned macros:

- macro-generated control flow,
- macro-generated loops,
- macro-generated types,
- macro-generated functions,
- macro DSLs,
- macro-based reflection,
- macro-based serialization.

If a macro is required, it must have:

```c
// CEP:WHAT:
// CEP:WHY:
// CEP:STATUS:
// CEP:FAILURE:
// CEP:ASSUMES:
// CEP:COST:
// CEP:EVIDENCE:
```

---

## 26.6 C standard library policy

CEP-0 C code must not call the standard library except for:

- compiler intrinsics,
- inline assembly wrappers,
- freestanding headers,
- target-specific runtime hooks explicitly approved.

Banned:

- `printf`,
- `fprintf`,
- `snprintf`, unless cold and bounded,
- `memcpy`? Conditional.

Important note: `memcpy`, `memset`, `memcmp` may be acceptable if target libc implementations are deterministic and measured. However, in strict CEP-0, even these must be approved because they may call optimized library routines with variable behavior.

If `memcpy` is used, document:

```c
// CEP:ASSUMES: memcpy is inline or deterministic for size <= 64 bytes.
```

---

## 26.7 C pointer rules

Pointers must be explicit.

Rules:

- pointer arithmetic only within known bounds,
- no NULL dereference,
- no dangling pointers,
- no aliasing violations,
- no casts that violate alignment,
- no casts that violate strict aliasing,
- no pointer-to-integer assumptions unless target-defined.

Use `uintptr_t` only for target-specific proven cases.

---

## 26.8 C volatile rules

`volatile` is only for hardware registers and MMIO.

Do not use `volatile` for:

- locks,
- atomics,
- timing,
- preventing optimization of benchmarks,
- thread communication.

---

## 26.9 C comment example

```c
// CEP:WHAT: Reads a 32-bit MMIO register.
// CEP:WHY: Hardware register must not be reordered or cached.
// CEP:STATUS: complete
// CEP:FAILURE: none if address is target-valid.
// CEP:ASSUMES: addr is 4-byte aligned and target-mapped.
// CEP:COST: one volatile load; target-specific latency.
// CEP:EVIDENCE: target manual section 12.4, bench C-011.
// CEP:SECURITY: MMIO input may be untrusted; caller validates value.
// CEP:OPTIMAL: target-optimal
// CEP:OPTPROOF: single required load.
static inline uint32_t cep_mmio_read_u32(volatile uint32_t const* addr)
{
    return *addr;
}
```

---

# 27. Zig companion policy

## 27.1 Role

Zig is allowed as a modern low-level alternative.

Its role is:

- explicit allocator control,
- comptime metaprogramming,
- C-ABI interoperability,
- embedded code,
- explicit error handling,
- replacement for some C/C++ template patterns.

Zig is allowed where its explicitness improves CEP&CC compliance.

---

## 27.2 Why Zig is allowed

Zig provides:

- explicit allocators,
- comptime evaluation,
- no hidden function calls in many contexts,
- explicit error unions,
- straightforward C ABI interop,
- packed/extern structs,
- compile-time generics without C++ template syntax.

However, Zig can still hide cost through:

- allocator choice,
- runtime safety checks,
- comptime explosion,
- `anytype` instantiation,
- error handling paths,
- standard library dependencies.

Therefore CEP&CC adapts Zig rules as follows.

---

## 27.3 Zig CEP-0 rules

For Zig CEP-0 hot code:

Banned:

- default allocator dependence,
- heap allocation in hot paths,
- `std.debug.print`,
- `std.io`,
- `std.fs`,
- `std.Thread`,
- `std.Mutex` in hot paths unless justified,
- `panic` in hot paths,
- `unreachable` unless proven and documented,
- runtime recursion,
- unbounded comptime expansion,
- hidden error handling allocation,
- dynamic dispatch in hot paths,
- opaque interface-style dynamic dispatch unless measured.

Required:

- explicit allocator parameter where allocation is possible,
- fixed buffer allocator or arena allocator for bounded allocation,
- explicit error unions for recoverable errors,
- explicit alignment checks,
- explicit packed/extern structs for ABI,
- explicit target configuration,
- deterministic comptime output.

---

## 27.4 Zig allocator policy

Zig’s explicit allocator model is a CEP&CC strength.

Use it strictly.

Banned in CEP-0:

- `std.heap.page_allocator`,
- `std.heap.c_allocator`,
- `std.heap.wasm_allocator`,
- any default allocator that may perform hidden OS allocation.

Allowed:

- stack allocation,
- fixed buffer allocator,
- caller-provided arena,
- static arena initialized before hot path.

Example:

```zig
// CEP:ASSUMES: allocator is a fixed buffer allocator initialized before hot path.
```

---

## 27.5 Zig `anytype` policy

`anytype` is restricted.

Allowed:

- compile-time-only contexts,
- generic utilities with explicit instantiation list,
- code where all instantiations are reviewed.

Banned:

- runtime-polymorphic use,
- unbounded generic instantiation,
- hidden dynamic behavior,
- hot code where the concrete type is not obvious.

`anytype` is analogous to C++ templates and generic lambdas. It must not hide cost.

---

## 27.6 Zig error policy

CEP-0 Zig functions must use explicit error unions for recoverable failure.

Required:

```zig
!ReturnType
```

or explicit error enum.

Banned as primary failure mechanism in CEP-0:

- `panic`,
- `unreachable`,
- `std.debug.assert` as release validation,
- crash-on-error unless the failure policy is fatal.

If `unreachable` is used, it must be proven:

```zig
// CEP:ASSUMES: state enum is exhaustive; invalid state prevented by type.
// CEP:FAILURE: unreachable in valid builds.
```

---

## 27.7 Zig comptime policy

Comptime is powerful and must be controlled.

Allowed:

- compile-time tables,
- compile-time validation,
- compile-time code generation,
- layout computation,
- constant folding.

Banned:

- comptime code that produces unreadable generated code,
- comptime code with nondeterministic output,
- comptime code that explodes compile time,
- comptime code that hides runtime branches,
- comptime code that depends on unstable environment.

Generated Zig code is subject to CEP&CC review.

---

## 27.8 Zig ABI and FFI

FFI types must use explicit layout.

Use:

```zig
extern struct
```

or:

```zig
packed struct
```

depending on ABI requirement.

FFI functions must specify calling convention:

```zig
extern "C"
```

or Zig equivalent.

FFI boundaries must validate:

- pointers,
- lengths,
- alignment,
- enum values,
- error codes.

---

## 27.9 Zig comment example

```zig
// CEP:WHAT: Computes bounded checksum over u32 slice.
// CEP:WHY: Validation requires allocation-free checksum.
// CEP:STATUS: complete
// CEP:FAILURE: Returns error.Empty for empty slice.
// CEP:ASSUMES: slice pointer is 4-byte aligned; Zig slice guarantees non-null.
// CEP:COST: 1 cycle/element on target, bench ZIG-010.
// CEP:EVIDENCE: bench CEP-ZIG-0010
// CEP:SECURITY: input may be untrusted; length bounded by caller.
// CEP:OPTIMAL: target-optimal
// CEP:OPTPROOF: one load and one add per element.
pub fn checksum(items: []const u32) !u64 {
    if (items.len == 0) return error.Empty;

    var sum: u64 = 0;
    for (items) |x| {
        sum += x;
    }
    return sum;
}
```

---

# 28. Python and Lua companion policy

## 28.1 Role

Python and Lua are allowed only for CEP-2 tooling.

Allowed roles:

- build scripts,
- code generators,
- test harnesses,
- benchmark orchestration,
- report generation,
- configuration validation,
- tooling glue.

They are not allowed for CEP-0 or CEP-1 runtime components unless a separate waiver is granted.

---

## 28.2 Why Python/Lua are allowed

They are useful for:

- rapid tooling,
- orchestration,
- test automation,
- code generation,
- benchmark control,
- report generation.

Their runtime performance is usually irrelevant to CEP-0 because they operate offline.

However, their output is security-critical and performance-critical.

Therefore:

> Python/Lua tool performance is not important. Tool determinism and output compliance are mandatory.

---

## 28.3 Determinism requirement

Python/Lua tooling must be deterministic.

Required:

- stable iteration order,
- sorted output where order is not semantic,
- fixed seeds,
- fixed locale,
- fixed timezone if time is used,
- no dependence on environment unless explicit,
- no dependence on current working directory unless explicit,
- no dependence on file iteration order,
- no dependence on hash randomization,
- no nondeterministic parallelism unless output is deterministic.

Python-specific:

- set `PYTHONHASHSEED` to fixed value,
- sort directory listings,
- use `pathlib` with explicit normalization,
- avoid `set` iteration for output order,
- avoid `dict` insertion-order nondeterminism if input order varies,
- pin dependency versions.

Lua-specific:

- avoid `pairs` for output where order matters,
- use sorted keys,
- pin Lua version,
- avoid OS-dependent behavior unless configured.

---

## 28.4 Generated code rule

Generated C++, Rust, C, or Zig code is fully subject to CEP&CC.

The generator is not exempt because it is written in Python or Lua.

Generated code must include CEP comments or the generator must emit them.

Generated code must not contain:

- hard-coded assumptions,
- magic numbers,
- commented-out code,
- unvalidated FFI,
- unsafe constructs without comments,
- nondeterministic layout,
- unstable ordering,
- hidden allocation in CEP-0.

Generated code must be reviewed either as source or via golden-file tests.

---

## 28.5 Tool security

Python/Lua tools are a supply-chain attack surface.

Required:

- pinned dependencies,
- lockfiles,
- no arbitrary network fetch during release builds,
- no telemetry,
- no secrets in scripts,
- no undocumented subprocess execution,
- sandboxed code generation where possible,
- validated input files,
- validated output paths.

Banned:

- `eval` of untrusted input,
- `exec` of untrusted input,
- dynamic import of untrusted modules,
- shell injection,
- path traversal,
- unpickling untrusted data in Python,
- loading untrusted Lua bytecode.

---

## 28.6 Python example: deterministic generator

```python
# CEP:WHAT: Generates opcode table header.
# CEP:WHY: Keeps opcode metadata synchronized with specification.
# CEP:STATUS: complete
# CEP:FAILURE: Exits with error if spec file is malformed.
# CEP:ASSUMES: spec file is UTF-8 and sorted by opcode value.
# CEP:COST: offline tool; runtime cost irrelevant.
# CEP:EVIDENCE: golden test cep_opcode_table.hpp.golden.
# CEP:SECURITY: input is trusted repository file; no network.

def generate_opcode_table(spec: list[OpcodeSpec]) -> str:
    lines = []
    lines.append("// Generated by cep_gen_opcode_table.py")
    lines.append("// Do not edit manually.")
    lines.append("")
    lines.append("inline constexpr std::array<OpcodeInfo, 128> kOpcodeTable{{")

    for entry in sorted(spec, key=lambda e: e.value):
        lines.append(f"    OpcodeInfo{{ .opcode = {entry.value}, .flags = {entry.flags} }},")

    lines.append("};")
    lines.append("")
    return "\n".join(lines)
```

---

# 29. FFI and cross-language integration

FFI is both a security boundary and a performance boundary.

Therefore FFI receives special rules.

---

## 29.1 FFI ownership rules

Every FFI API must answer:

- Who allocates?
- Who frees?
- Who owns pointers?
- Who owns buffers?
- Who owns error strings?
- Who owns callbacks?
- What happens on error?
- What is the alignment?
- What is the lifetime?
- What is the calling convention?
- What is the threading policy?
- What is the reentrancy policy?
- What is the signal-safety policy?
- What is the interrupt-safety policy?

If any answer is unknown, the FFI API is incomplete.

---

## 29.2 FFI layout rules

FFI structs must use explicit layout.

C++:

- use standard-layout types,
- avoid virtual functions,
- avoid exceptions in ABI,
- avoid `std::vector`, `std::string`, `std::optional`, etc., in stable ABI unless private implementation is controlled.

Rust:

- use `#[repr(C)]`,
- use explicit integer types,
- avoid `Vec`, `String`, `Box` in ABI unless ownership is documented.

Zig:

- use `extern struct` or `packed struct`,
- explicit integer types.

C:

- fixed-width types,
- no bitfields unless target-defined,
- no flexible array members unless reviewed.

---

## 29.3 FFI error rules

Do not propagate exceptions across FFI.

C++ FFI functions should be `extern "C"` and `noexcept`.

Rust FFI functions must not unwind.

Zig FFI functions must not panic across boundary.

C FFI functions must return error codes.

Error codes must be documented.

---

## 29.4 FFI validation

All FFI inputs must be validated on entry.

Even if the caller is trusted, validate where feasible because FFI callers may be wrong.

Validation includes:

- null checks,
- alignment checks,
- length checks,
- enum range checks,
- flag checks,
- callback validity,
- ownership validity.

FFI validation is security work, not optional performance overhead.

---

# 30. Updated review checklist

Add the following to the existing review checklist.

## Security

- [ ] Threat model documented.
- [ ] Trust boundaries explicit.
- [ ] Untrusted input validated.
- [ ] Integer safety checked.
- [ ] Memory safety checked.
- [ ] Unsafe code isolated.
- [ ] FFI boundary validated.
- [ ] No secrets in logs.
- [ ] Side-channel policy documented.
- [ ] Resource limits explicit.
- [ ] Supply chain pinned.
- [ ] Toolchain pinned.

## Optimality

- [ ] Optimality class declared.
- [ ] Target specified.
- [ ] Cost model specified.
- [ ] Evidence attached.
- [ ] Disassembly reviewed.
- [ ] Alternatives considered.
- [ ] Lower-bound argument provided if claimed.
- [ ] No hidden work.
- [ ] Security checks not removed without proof.
- [ ] Optimality comment present.

## Companion languages

- [ ] Language role justified.
- [ ] CEP comment schema present.
- [ ] Hot-path bans respected.
- [ ] FFI layout explicit.
- [ ] FFI errors explicit.
- [ ] Allocator policy explicit.
- [ ] Panic/abort policy explicit.
- [ ] Generated code reviewed.
- [ ] Tooling deterministic.

---

Added. Below are the new normative chapters for **file structure**, **naming**, and **violation handling**.

This includes the requested extermination policy.

The rule is simple:

> Non-compliant code is not merged.  
> If non-compliant code is discovered after merge, it is quarantined, reverted, or deleted.  
> We exterminate the code, not the person.

---

# 32. File structure

File structure is part of the standard because bad structure hides cost, ownership, assumptions, and security boundaries.

A compliant repository must make the following obvious from the directory tree alone:

- what is hot,
- what is cold,
- what is target-specific,
- what is generated,
- what is third-party,
- what is test code,
- what is benchmark code,
- what is tooling,
- what is configuration,
- what is security-sensitive,
- what is FFI,
- what is documentation.

If a reviewer cannot determine these from the layout, the repository structure is non-compliant.

---

## 32.1 Top-level repository layout

Recommended layout:

```text
repo/
├── modules/
├── source/
├── include/
├── target/
├── hot/
├── cold/
├── ffi/
├── generated/
├── tests/
├── benches/
├── tools/
├── config/
├── security/
├── docs/
├── scripts/
├── third_party/
├── quarantine/
└── .cep/
```

Meaning:

| Directory | Purpose |
|---|---|
| `modules/` | First-party C++26 module interface units |
| `source/` | First-party C++ implementation units |
| `include/` | Public headers only when headers are unavoidable |
| `target/` | Target-specific code: ISA, OS, ABI, hardware |
| `hot/` | CEP-0 hot code only |
| `cold/` | CEP-1/CEP-2 cold code |
| `ffi/` | FFI boundaries for C, Rust, Zig, C++ |
| `generated/` | Machine-generated code |
| `tests/` | Unit, property, contract, and integration tests |
| `benches/` | Benchmarks and cycle-cost evidence |
| `tools/` | Build tools, generators, harnesses |
| `config/` | Target configuration, feature configuration |
| `security/` | Threat models, security policies, audits |
| `docs/` | Human documentation |
| `scripts/` | Python/Lua tooling scripts |
| `third_party/` | Vendored third-party code |
| `quarantine/` | Non-compliant code awaiting deletion or repair |
| `.cep/` | CEP&CC lint config, waivers, evidence metadata |

---

## 32.2 Hot and cold separation

Hot and cold code must not live in the same file unless absolutely unavoidable.

Preferred:

```text
hot/decoder/opcode_decoder.cppm
hot/decoder/opcode_decoder.cpp
cold/decoder/opcode_decoder_diagnostics.cpp
```

Bad:

```text
decoder.cpp
```

where hot decoding, logging, file I/O, and diagnostics are mixed together.

Why:

- hot code must be auditable,
- cold code must not accidentally enter hot paths,
- benchmarking becomes easier,
- security boundaries become clearer,
- compile-time isolation improves.

---

## 32.3 Module directory rules

C++ modules should mirror architecture.

Example:

```text
modules/
├── cep/
│   ├── core/
│   │   ├── core.cppm
│   │   ├── types.cppm
│   │   ├── result.cppm
│   │   └── limits.cppm
│   ├── hot/
│   │   ├── decoder.cppm
│   │   ├── checksum.cppm
│   │   └── dispatch.cppm
│   ├── cold/
│   │   ├── diagnostics.cppm
│   │   └── config_parser.cppm
│   ├── target/
│   │   ├── arm64.cppm
│   │   ├── riscv64.cppm
│   │   └── x86_64.cppm
│   └── ffi/
│       ├── c_abi.cppm
│       └── rust_abi.cppm
```

Module names should use dotted form:

```cpp
export module cep.core.types;
export module cep.hot.decoder;
export module cep.target.arm64;
```

Namespace names should mirror module names:

```cpp
namespace cep::core::types {}
namespace cep::hot::decoder {}
namespace cep::target::arm64 {}
```

---

## 32.4 Source directory rules

Implementation units mirror module units.

Example:

```text
source/
├── cep/
│   ├── core/
│   │   ├── types.cpp
│   │   └── result.cpp
│   ├── hot/
│   │   ├── decoder.cpp
│   │   └── checksum.cpp
│   ├── cold/
│   │   └── config_parser.cpp
│   └── target/
│       └── arm64/
│           ├── cache.cpp
│           └── barriers.cpp
```

Rules:

- One primary component per file.
- No file may contain both CEP-0 and CEP-1 code unless separated by explicit sections and approved.
- No target-specific code may live in generic source directories.
- No generated code may live in handwritten source directories.
- No third-party code may live in first-party source directories.

---

## 32.5 Target directory rules

Target-specific code must be isolated.

Example:

```text
target/
├── arm64/
│   ├── cache.cppm
│   ├── barriers.cppm
│   └── intrinsics.cppm
├── riscv64/
│   ├── cache.cppm
│   └── barriers.cppm
├── x86_64/
│   ├── cache.cppm
│   ├── barriers.cppm
│   └── inline_asm.cppm
└── generic/
    └── fallback.cppm
```

Allowed inside target directories:

- inline assembly,
- intrinsics,
- cache-line constants,
- memory barriers,
- MMIO helpers,
- target-specific alignment rules,
- target-specific performance counters.

Forbidden outside target directories:

- inline assembly,
- target intrinsics,
- target-specific `if` checks,
- target-specific constants.

Bad:

```cpp
#if defined(__x86_64__)
...
#endif
```

inside generic hot code.

Good:

```cpp
#include <cep/target/barriers.hpp>
```

or:

```cpp
import cep.target.barriers;
```

---

## 32.6 FFI directory rules

FFI code must live in dedicated FFI directories.

Example:

```text
ffi/
├── cpp/
│   ├── decoder_api.cppm
│   └── decoder_api.cpp
├── c/
│   ├── cep_decoder.h
│   └── cep_decoder.c
├── rust/
│   ├── decoder_ffi.rs
│   └── Cargo.toml
└── zig/
    └── decoder_ffi.zig
```

FFI directories must contain:

- ABI definitions,
- validation code,
- layout tests,
- ownership documentation,
- error-code documentation.

FFI directories must not contain business logic.

FFI should be thin.

Good FFI:

```text
validate -> convert -> call internal API -> convert result -> return
```

Bad FFI:

```text
parse -> allocate -> optimize -> lower -> emit -> log
```

---

## 32.7 Generated code rules

Generated code must be isolated.

Example:

```text
generated/
├── opcode_table.hpp
├── opcode_table.cpp
├── error_codes.rs
├── ir_nodes.zig
└── diagnostics.c
```

Every generated file must begin with a generator comment.

Example:

```cpp
// GENERATED FILE
// Generator: tools/gen_opcode_table.py
// Generator CEP:STATUS: complete
// Generator CEP:EVIDENCE: golden test opcode_table.golden
// Do not edit manually.
```

Rules:

- generated files must not be manually edited,
- generated files must be reproducible,
- generated files must have golden tests,
- generated files must include generator identity,
- generated files must include CEP comments or emit them,
- generated files must not introduce hard-coded assumptions.

If a generator emits CEP-0 code, the generator itself is performance-critical and security-critical.

---

## 32.8 Test directory rules

Tests must mirror source and modules.

Example:

```text
tests/
├── unit/
│   ├── core/
│   │   ├── result_test.cpp
│   │   └── limits_test.cpp
│   ├── hot/
│   │   ├── decoder_test.cpp
│   │   └── checksum_test.cpp
│   └── ffi/
│       └── c_abi_test.cpp
├── property/
├── contract/
├── fuzz/
├── security/
└── golden/
```

Rules:

- every CEP-0 function requires tests,
- every security validation function requires adversarial tests,
- every FFI boundary requires layout tests,
- every generated file requires golden tests,
- every stub requires a test proving it fails loudly in debug,
- every placeholder requires a test proving it is not used in release.

---

## 32.9 Benchmark directory rules

Benchmarks are evidence, not decoration.

Example:

```text
benches/
├── hot/
│   ├── decoder_bench.cpp
│   └── checksum_bench.cpp
├── target/
│   ├── arm64/
│   └── x86_64/
└── artifacts/
```

Benchmark artifacts must include:

- compiler version,
- flags,
- target CPU,
- input data,
- date or artifact ID,
- measured cycles,
- disassembly hash,
- regression threshold.

Benchmarks must be deterministic.

---

## 32.10 Tools directory rules

Tooling lives here:

```text
tools/
├── gen_opcode_table.py
├── gen_error_codes.py
├── lint_comments.py
├── check_assumptions.py
├── bench_gate.py
└── exterminate.py
```

Python/Lua tools are CEP-2, but their output must be CEP-compliant.

Tools must be deterministic.

---

## 32.11 Config directory rules

Configuration values must live here:

```text
config/
├── target_arm64.hpp
├── target_riscv64.hpp
├── limits.hpp
├── feature_gates.hpp
└── security_policy.hpp
```

Config files must define named constants.

Bad:

```cpp
constexpr int cache_line = 64;
```

Good:

```cpp
namespace cep::target {
    inline constexpr std::size_t cache_line_bytes = CEP_TARGET_CACHE_LINE_BYTES;
}
```

All config constants must have comments:

```cpp
// CEP:WHAT: Target cache line size.
// CEP:WHY: Used for alignment and false-sharing avoidance.
// CEP:STATUS: complete
// CEP:FAILURE: static_assert if target config missing.
// CEP:ASSUMES: provided by target manifest.
// CEP:COST: compile-time only.
// CEP:EVIDENCE: target manual / bench config.
```

---

## 32.12 Security directory rules

Security documentation is normative.

Example:

```text
security/
├── threat_model.md
├── trust_boundaries.md
├── ffi_security.md
├── unsafe_audit.md
├── side_channels.md
└── supply_chain.md
```

Security documents must be versioned and reviewed.

---

## 32.13 Quarantine directory

Non-compliant code may be moved to:

```text
quarantine/
```

Quarantine code:

- is not compiled by default,
- is not linked,
- is not shipped,
- is not benchmarked,
- is not treated as compliant,
- must contain a quarantine manifest.

Quarantine manifest example:

```text
quarantine/
└── old_decoder/
    ├── QUARANTINE.md
    ├── decoder.cpp
    └── decoder.cppm
```

`QUARANTINE.md` must contain:

```text
Reason: hidden allocation in CEP-0
Violation: CEP&CC 9.2
Owner: alice
Ticket: CEP-901
Deadline: 2026-10-15
Disposition: repair or exterminate
```

Quarantine is temporary.

Quarantine is not storage.

If quarantine code is not repaired by its deadline, it is exterminated.

---

# 33. Naming

Naming is normative.

Bad names hide intent. Hidden intent hides cost. Hidden cost violates CEP&CC.

---

## 33.1 General naming principles

Names must be:

- explicit,
- searchable,
- pronounceable,
- consistent,
- non-clever,
- non-ambiguous,
- stable where ABI-stable,
- reflective of cost class where useful.

Avoid:

- jokes,
- puns,
- obscure abbreviations,
- temporary names,
- duplicated names across unrelated concepts,
- names that lie,
- names that imply speed without evidence,
- names that imply safety without proof.

Bad:

```cpp
fast_thing
```

Bad:

```cpp
do_it
```

Bad:

```cpp
helper2
```

Bad:

```cpp
optimized_parser
```

Good:

```cpp
decode_opcode
```

Good:

```cpp
validate_packet_bounds
```

Good:

```cpp
compute_checksum_u32
```

---

## 33.2 File names

Use lowercase snake_case.

Examples:

```text
opcode_decoder.cppm
opcode_decoder.cpp
packet_validator.cpp
arm64_barriers.cppm
checksum_bench.cpp
decoder_test.cpp
```

Rules:

- no spaces,
- no uppercase,
- no version numbers in file names unless ABI versioning requires it,
- no dates in file names,
- no “final”, “new”, “old”, “fixed”,
- no duplicated names in different layers unless intentional and documented.

Bad:

```text
DecoderFinal.cpp
```

Bad:

```text
parser_new.cpp
```

Bad:

```text
checksum2.cpp
```

---

## 33.3 Hot file names

CEP-0 files should be obviously hot.

Recommended:

```text
hot/decoder/opcode_decoder.cppm
hot/checksum/checksum_u32.cppm
```

or file-level tag:

```cpp
// CEP:CLASS: CEP-0
```

If a file contains hot code, the file header must say so.

Example:

```cpp
// CEP:FILE: hot/decoder/opcode_decoder.cppm
// CEP:CLASS: CEP-0
```

---

## 33.4 Cold file names

Cold files should be obviously cold.

Examples:

```text
cold/diagnostics/log_sink.cpp
cold/config/config_parser.cpp
```

File header:

```cpp
// CEP:FILE: cold/config/config_parser.cpp
// CEP:CLASS: CEP-1
```

---

## 33.5 Target file names

Target files must include target identity.

Examples:

```text
target/arm64/barriers.cppm
target/x86_64/cache.cppm
target/riscv64/mmio.cppm
```

Bad:

```text
target/barriers.cppm
```

unless generic.

Good generic fallback:

```text
target/generic/fallback_barriers.cppm
```

---

## 33.6 Test file names

Test files must state what they test.

Pattern:

```text
<component>_test.cpp
```

Examples:

```text
opcode_decoder_test.cpp
checksum_u32_test.cpp
ffi_c_abi_test.cpp
```

For property tests:

```text
opcode_decoder_property_test.cpp
```

For fuzz tests:

```text
packet_validator_fuzz_test.cpp
```

For security tests:

```text
packet_validator_security_test.cpp
```

---

## 33.7 Benchmark file names

Pattern:

```text
<component>_bench.cpp
```

Examples:

```text
opcode_decoder_bench.cpp
checksum_u32_bench.cpp
```

For target-specific benches:

```text
opcode_decoder_arm64_bench.cpp
```

---

## 33.8 Generated file names

Generated files should state their origin.

Examples:

```text
generated/opcode_table.hpp
generated/error_codes.rs
generated/ir_nodes.zig
```

Generated file header:

```cpp
// GENERATED FILE
// Generator: tools/gen_opcode_table.py
// Do not edit manually.
```

---

## 33.9 Namespace names

Namespaces must be lowercase and architectural.

Pattern:

```cpp
namespace cep::<layer>::<component> {}
```

Examples:

```cpp
namespace cep::core {}
namespace cep::hot::decoder {}
namespace cep::cold::config {}
namespace cep::target::arm64 {}
namespace cep::ffi::c {}
namespace cep::detail {}
```

Rules:

- no namespace aliases in public APIs unless stable,
- no `using namespace` in module interfaces,
- no namespace pollution,
- no one-letter namespaces except local lambda/template scope.

---

## 33.10 Module names

Use dotted module names.

Examples:

```cpp
export module cep.core.types;
export module cep.hot.decoder;
export module cep.target.arm64.barriers;
export module cep.ffi.c.decoder;
```

Module names must match directory and namespace structure.

---

## 33.11 Type names

Types use `PascalCase`.

Examples:

```cpp
struct OpcodeInfo {};
class InstructionDecoder {};
enum class DecodeError : std::uint8_t {};
using Checksum = std::uint64_t;
```

Rules:

- no Hungarian notation,
- no `C` prefix,
- no `I` interface prefix unless required by legacy policy,
- no abbreviations unless project-wide glossary defines them.

Bad:

```cpp
struct OpInfo {};
```

unless `Op` is a defined term.

Good:

```cpp
struct OpcodeInfo {};
```

---

## 33.12 Enum names

Enums use `enum class` and `PascalCase` names.

Enumerator names use `snake_case` or `PascalCase` depending on project choice, but one style must be chosen.

Recommended:

```cpp
enum class DecodeError : std::uint8_t {
    none = 0,
    bad_opcode = 1,
    bad_operand = 2,
    unsupported_extension = 3,
};
```

Or:

```cpp
enum class DecodeError : std::uint8_t {
    None = 0,
    BadOpcode = 1,
    BadOperand = 2,
    UnsupportedExtension = 3,
};
```

Do not mix styles.

Rules:

- enums must have explicit underlying type if ABI-stable,
- enums must not be implicitly converted to integers,
- use `std::to_underlying` when conversion is required.

---

## 33.13 Function names

Functions use `snake_case`.

Function names should describe the action.

Examples:

```cpp
auto decode_opcode(std::uint8_t opcode) noexcept -> DecodeResult;
auto validate_packet(PacketView packet) noexcept -> std::expected<Packet, PacketError>;
auto compute_checksum_u32(std::span<const std::uint32_t> data) noexcept -> std::uint64_t;
```

Use verb-first names:

- `decode_`
- `validate_`
- `parse_`
- `compute_`
- `lower_`
- `emit_`
- `schedule_`
- `allocate_`
- `reserve_`
- `flush_`
- `finish_`

Predicates use:

- `is_`
- `has_`
- `can_`
- `should_`

Examples:

```cpp
auto is_aligned(const void* ptr, std::size_t alignment) noexcept -> bool;
auto has_overflow(std::uint32_t a, std::uint32_t b) noexcept -> bool;
```

Factories use:

- `make_`
- `create_`

Examples:

```cpp
auto make_decoder_config() noexcept -> DecoderConfig;
```

Conversions use:

- `to_`
- `as_`
- `into_`

Examples:

```cpp
auto to_wire_format(const Packet& packet) noexcept -> WirePacket;
```

---

## 33.14 Variable names

Variables use `snake_case`.

Examples:

```cpp
std::uint32_t opcode;
std::size_t frame_index;
PacketError parse_error;
```

Rules:

- no single-letter variables except loops, math, template parameters,
- no abbreviations without glossary,
- loop indices may be `i`, `j`, `k` only when conventional,
- iterator names should describe the element.

Bad:

```cpp
auto x = decode();
```

Good:

```cpp
auto decoded_insn = decode();
```

---

## 33.15 Constant names

Constants use `kPascalCase`.

Examples:

```cpp
inline constexpr std::size_t kMaxPacketBytes = CEP_LIMIT_MAX_PACKET_BYTES;
inline constexpr std::uint32_t kInvalidOpcode = 0xFFFFFFFFu;
```

Magic constants are banned.

Bad:

```cpp
constexpr int kMax = 4096;
```

Good:

```cpp
inline constexpr std::size_t kMaxPacketBytes = CEP_LIMIT_MAX_PACKET_BYTES;
```

and the limit itself is documented.

---

## 33.16 Macro names

Macros are discouraged, but if used, they must be prefixed.

Required prefix:

```text
CEP_
```

Examples:

```cpp
#define CEP_TARGET_CACHE_LINE_BYTES 64
#define CEP_HAS_MDSPAN 1
```

Banned:

```cpp
#define MAX 4096
```

Banned:

```cpp
#define DO_DECODE() ...
```

---

## 33.17 Template parameter names

Template parameters use `PascalCase`.

Examples:

```cpp
template <typename Decoder>
auto decode_all(Decoder& decoder) -> DecodeStatus;

template <std::size_t Alignment>
class AlignedBuffer;
```

Concepts use `PascalCase`.

Examples:

```cpp
template <typename T>
concept ContiguousBuffer = requires(T buffer) {
    { buffer.data() } -> std::same_as<std::uint8_t*>;
    { buffer.size() } -> std::convertible_to<std::size_t>;
};
```

---

## 33.18 Error type names

Error types must be explicit.

Patterns:

```cpp
enum class <component>_error;
struct <component>_error;
using <component>_result = std::expected<T, <component>_error>;
```

Examples:

```cpp
enum class DecodeError : std::uint8_t;
using DecodeResult = std::expected<OpcodeInfo, DecodeError>;

enum class PacketError : std::uint8_t;
using PacketParseResult = std::expected<Packet, PacketError>;
```

Do not use generic `Error` unless the scope is tiny.

Bad:

```cpp
enum class Error {};
```

Good:

```cpp
enum class DecoderError {};
```

---

## 33.19 FFI names

FFI symbols must be stable and explicit.

C ABI example:

```c
extern "C" int cep_decode_opcode(uint8_t opcode, cep_opcode_info* out);
```

Rules:

- prefix all public C symbols with project prefix,
- use lowercase snake_case,
- use fixed-width types,
- avoid C++ types in C ABI,
- avoid exceptions,
- avoid allocation,
- document ownership.

Good:

```c
int32_t cep_decoder_validate(const uint8_t* data, size_t size);
```

Bad:

```c
int decode(const char* data, int len);
```

---

## 33.20 Rust naming

Rust follows standard Rust style, but CEP&CC additions apply.

Use:

```rust
snake_case
```

for functions and variables.

Use:

```rust
PascalCase
```

for types.

Use:

```rust
SCREAMING_SNAKE_CASE
```

for constants and statics.

FFI functions must be explicit:

```rust
#[no_mangle]
pub extern "C" fn cep_decode_opcode(opcode: u8) -> DecodeResult
```

Unsafe modules should be named clearly:

```rust
mod unsafe_decoder;
```

or:

```rust
mod ffi;
```

Do not hide unsafe in generic utility modules.

---

## 33.21 C naming

C uses lowercase snake_case.

Public symbols must have project prefix.

Example:

```c
uint32_t cep_mmio_read_u32(volatile uint32_t const* addr);
```

Internal functions may be `static`.

Bad:

```c
uint32_t read_reg(volatile uint32_t* p);
```

Good:

```c
uint32_t cep_mmio_read_u32(volatile uint32_t const* addr);
```

---

## 33.22 Zig naming

Zig uses standard Zig style.

Functions:

```zig
camelCase
```

Types:

```zig
PascalCase
```

Constants:

```zig
camelCase
```

or project-chosen stable style.

FFI functions should use C-compatible names:

```zig
export fn cep_decode_opcode(opcode: u8) callconv(.C) DecodeResult
```

Do not use ambiguous names.

Bad:

```zig
pub fn doThing(...)
```

Good:

```zig
pub fn decodeOpcode(...)
```

---

## 33.23 Python/Lua tool naming

Python:

```python
snake_case
```

for functions and variables.

```python
PascalCase
```

for classes.

```python
UPPER_SNAKE_CASE
```

for constants.

Files:

```text
gen_opcode_table.py
lint_comments.py
bench_gate.py
```

Lua:

```lua
snake_case
```

recommended.

Tool names must describe the tool.

Bad:

```text
gen.py
```

Good:

```text
gen_opcode_table.py
```

---

# 34. Violation handling and extermination

CEP&CC is not advisory.

Violations are defects.

Some defects are style issues.

Some defects are security hazards.

Some defects are performance hazards.

Some defects are all three.

The response is proportional to severity, but the default action for non-compliant code is rejection.

---

## 34.1 Prime extermination rule

> Non-compliant code is not allowed to enter the mainline.  
> If it is detected before merge, it is blocked.  
> If it is detected after merge, it is quarantined, reverted, or deleted.  
> The code is exterminated. The person is not.

This standard is about code hygiene, not punishment.

But code that violates security, cycle-exactness, or assumption rules is not allowed to remain alive in the tree.

---

## 34.2 Violation severity classes

### Severity 0: Exterminate immediately

Severity 0 violations are unacceptable.

Examples:

- undefined behavior,
- memory safety bug,
- buffer overflow,
- use-after-free,
- uninitialized read,
- uninitialized write,
- secret leakage,
- FFI boundary without validation,
- exception crossing FFI,
- panic crossing FFI,
- hidden allocation in CEP-0,
- hidden locking in CEP-0,
- hidden I/O in CEP-0,
- hot-path virtual dispatch,
- hot-path `dyn Trait` in Rust,
- hot-path `std::function`,
- hot-path `std::any`,
- hot-path macro-generated control flow,
- hard-coded target assumption,
- missing layout on FFI type,
- generated code without golden test,
- untrusted input parsed without validation,
- security check removed without proof,
- benchmark evidence falsified,
- stale optimality claim knowingly retained.

Response:

1. Block merge.
2. If already merged, revert or quarantine immediately.
3. Add regression test.
4. Add lint rule if possible.
5. Perform root-cause analysis.

---

### Severity 1: Exterminate unless emergency waiver

Severity 1 violations are serious but may have rare waivers.

Examples:

- missing CEP comment block on hot function,
- missing `CEP:COST` on CEP-0 function,
- missing `CEP:FAILURE` on security-sensitive function,
- missing `CEP:ASSUMES` where assumption exists,
- TODO without owner and ticket,
- stub used in production path without ticket,
- placeholder callable from release path,
- benchmark missing artifact,
- non-deterministic Python/Lua generator output,
- unsafe block without `CEP:UNSAFE`,
- target-specific code outside target directory,
- mixed hot/cold file without waiver.

Response:

1. Block merge.
2. Require repair or deletion.
3. If emergency waiver is granted, record it in `.cep/waivers/`.

Waivers must include:

```text
violation
reason
owner
ticket
security review
performance review
expiration date
```

Waivers without expiration are banned.

---

### Severity 2: Reject and request repair

Severity 2 violations are clean-code violations.

Examples:

- bad naming,
- missing file header,
- missing namespace structure,
- mixed directory placement,
- vague comment,
- stale comment,
- commented-out code,
- missing `[[nodiscard]]`,
- missing explicit constructor,
- magic number in cold code,
- missing test for cold utility.

Response:

1. CI may warn or fail depending on project strictness.
2. Reviewer should reject.
3. Author repairs.

If repeated, code may be quarantined.

---

### Severity 3: Warn and educate

Severity 3 violations are minor style or documentation issues.

Examples:

- inconsistent formatting where formatter is missing,
- minor comment wording issue,
- non-blocking naming preference,
- documentation typo.

Response:

- warn,
- request cleanup,
- do not block unless repeated.

---

## 34.3 Automated extermination pipeline

CI must enforce extermination.

Pipeline stages:

1. **Parse**
   - Check file structure.
   - Check file headers.
   - Check CEP comment tags.
   - Check status tags.
   - Check TODO owner/ticket.

2. **Compile**
   - C++26 mode.
   - Warnings as errors.
   - Feature gates.
   - No banned features in hot code.

3. **Static analysis**
   - Banned functions.
   - Banned types.
   - Banned macros.
   - Hard-coded constants.
   - Missing static assertions.
   - Unsafe block comments.

4. **Sanitizers**
   - ASan.
   - UBSan.
   - TSan.
   - MSan where relevant.

5. **Security**
   - Fuzz tests.
   - FFI validation tests.
   - Secret scanning.
   - Dependency pinning.
   - Supply-chain checks.

6. **Performance**
   - Benchmark gate.
   - Disassembly diff.
   - Allocation check.
   - Virtual call check.
   - Indirect call check.
   - Branch regression check.

7. **Determinism**
   - Generated code reproducibility.
   - Python/Lua tool determinism.
   - Golden file tests.

8. **Verdict**
   - PASS,
   - WARN,
   - FAIL,
   - EXTERMINATE.

If verdict is `EXTERMINATE`, merge is blocked.

---

## 34.4 Extermination actions

When code is exterminated, one of the following actions occurs.

### 34.4.1 Reject

For unmerged code.

The merge request is closed or marked blocked.

Reason must be recorded:

```text
EXTERMINATED: hidden allocation in CEP-0
Rule: CEP&CC 9.2
Evidence: CI run 2026-09-28-1432
```

### 34.4.2 Revert

For merged code that violates Severity 0 or Severity 1.

Revert commit message:

```text
Exterminate commit 8f3a2c1

Reason: hidden allocation in CEP-0 hot decoder.
Rule: CEP&CC 9.2
Ticket: CEP-901
Owner: alice
```

The revert is not optional.

The revert happens before repair if the violation is severe.

### 34.4.3 Quarantine

For code that may be repairable but must not remain active.

Move code to:

```text
quarantine/
```

Add manifest:

```text
QUARANTINE.md
```

Quarantined code is excluded from build.

### 34.4.4 Delete

For code that is not worth repairing.

Delete:

- dead code,
- obsolete stubs,
- expired quarantine,
- repeated violations,
- unowned code,
- code with no tests,
- code with no evidence,
- code with stale security claims.

Deletion is a valid maintenance action.

Dead code is a security liability and a performance lie.

---

## 34.5 Human handling

Do not attack people.

Attack the defect.

Good review comment:

```text
This violates CEP&CC 9.2: hidden allocation in CEP-0.
The code must be quarantined or repaired before merge.
```

Bad review comment:

```text
You wrote terrible code.
```

Repeated violations by a contributor should trigger:

- additional review,
- pairing,
- training,
- reduced merge privileges,
- mandatory CEP&CC checklist sign-off.

But the immediate object of extermination is the code.

---

## 34.6 Violation examples and required responses

### Example 1: Hidden allocation in CEP-0

Violation:

```cpp
auto decode_packet(PacketView view) -> Packet {
    std::vector<std::uint8_t> buffer;
    ...
}
```

Response:

```text
EXTERMINATE
Reason: std::vector allocation in CEP-0.
Rule: CEP&CC 9.2.
Action: revert or replace with caller-provided fixed buffer.
```

---

### Example 2: Missing CEP comments on hot function

Violation:

```cpp
auto decode_opcode(std::uint8_t opcode) noexcept -> OpcodeInfo;
```

No CEP block.

Response:

```text
FAIL
Reason: missing CEP comment block.
Rule: CEP&CC 10.2.
Action: repair before merge.
```

If function is already in CEP-0 and comments are missing after review, quarantine.

---

### Example 3: Hard-coded cache line size

Violation:

```cpp
alignas(64) struct Counter {};
```

No named constant.

Response:

```text
FAIL
Reason: hard-coded cache-line assumption.
Rule: CEP&CC 11.
Action: use cep::target::cache_line_bytes.
```

---

### Example 4: FFI without layout

Rust violation:

```rust
pub struct DecoderState {
    ...
}
```

exported through FFI without `#[repr(C)]`.

Response:

```text
EXTERMINATE
Reason: FFI type lacks explicit layout.
Rule: CEP&CC 25.8.
Action: add #[repr(C)] and layout tests.
```

---

### Example 5: Rust panic in hot path

Violation:

```rust
let value = table[index].unwrap();
```

Response:

```text
EXTERMINATE
Reason: possible panic in CEP-0.
Rule: CEP&CC 25.4.
Action: replace with explicit error handling or proof.
```

---

### Example 6: Zig default allocator in hot path

Violation:

```zig
var list = std.ArrayList(u8).init(std.heap.page_allocator);
```

Response:

```text
EXTERMINATE
Reason: heap allocation in CEP-0.
Rule: CEP&CC 27.4.
Action: replace with fixed buffer or arena.
```

---

### Example 7: C macro logic

Violation:

```c
#define DECODE(x) do { ... } while (0)
```

Response:

```text
EXTERMINATE
Reason: macro-generated control flow.
Rule: CEP&CC 26.5.
Action: replace with static inline function.
```

---

### Example 8: Python generator nondeterminism

Violation:

```python
for key in table.keys():
    emit(key)
```

Output depends on unstable order.

Response:

```text
FAIL
Reason: nondeterministic generated output.
Rule: CEP&CC 28.3.
Action: sort keys or use stable order.
```

If generated code already merged, regenerate golden files or revert.

---

## 34.7 Waiver process

Waivers are rare, temporary, and documented.

Waivers are stored in:

```text
.cep/waivers/
```

Example waiver file:

```text
.cep/waivers/CEP-901.yaml
```

Contents:

```yaml
id: CEP-901
rule: CEP&CC 9.2
component: hot/decoder/opcode_decoder.cpp
violation: inline assembly required due to target errata
owner: alice
security_review: bob
performance_review: carol
created: 2026-09-28
expires: 2026-12-31
status: active
```

Waivers must not:

- be verbal,
- be permanent,
- cover security vulnerabilities without security review,
- cover undefined behavior unless hardware errata is documented,
- apply to generated code without generator fix ticket.

Expired waivers automatically trigger extermination.

---

## 34.8 Extermination report

Every extermination produces a report.

Report location:

```text
.cep/exterminations/
```

Example:

```text
.cep/exterminations/2026-09-28-CEP-901.md
```

Report contents:

```markdown
# Extermination Report CEP-901

Date: 2026-09-28
Component: hot/decoder/opcode_decoder.cpp
Violation: hidden allocation in CEP-0
Rule: CEP&CC 9.2
Severity: 0
Detected by: CI benchmark gate
Action: reverted commit 8f3a2c1
Owner: alice
Follow-up: CEP-902
Regression test: tests/unit/hot/decoder_allocation_test.cpp
```

Extermination reports are not optional.

They are institutional memory.

---

## 34.9 Post-extermination process

After extermination, the team must:

1. Identify the root cause.
2. Add a regression test.
3. Add lint or CI rule if possible.
4. Update documentation.
5. Repair or delete quarantined code.
6. Close the ticket.

If the same violation recurs three times in the same component, the component is considered structurally non-compliant.

Structural non-compliance requires redesign or deletion.

---

# 35. File header requirements

Every first-party source file must begin with a file-level CEP block.

C++ example:

```cpp
// CEP:FILE: hot/decoder/opcode_decoder.cppm
// CEP:WHAT: Module interface for the hot opcode decoder.
// CEP:WHY: Provides allocation-free opcode decoding for CEP-0 dispatch.
// CEP:CLASS: CEP-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns DecodeError for invalid opcodes. No allocation. No throw.
// CEP:ASSUMES: Input opcode is a raw untrusted byte; validated inside.
// CEP:COST: 3 cycles expected on arm64-a78, bench CEP-0019.
// CEP:EVIDENCE: bench CEP-0019, asm artifact a41c9e2.
// CEP:SECURITY: Handles untrusted opcode input.
```

C example:

```c
// CEP:FILE: target/arm64/mmio.c
// CEP:WHAT: MMIO access helpers for arm64 target.
// CEP:WHY: Hardware registers require volatile accesses with explicit ordering.
// CEP:CLASS: CEP-0
// CEP:STATUS: complete
// CEP:FAILURE: none if caller provides valid aligned target address.
// CEP:ASSUMES: address is 4-byte aligned and target-mapped.
// CEP:COST: one volatile load/store per access.
// CEP:EVIDENCE: target manual section 12.4.
// CEP:SECURITY: MMIO values are untrusted and must be validated by caller.
```

Rust example:

```rust
// CEP:FILE: ffi/decoder_ffi.rs
// CEP:WHAT: C ABI FFI for opcode decoder.
// CEP:WHY: Provides stable C interface to Rust decoder.
// CEP:CLASS: FFI
// CEP:STATUS: complete
// CEP:FAILURE: Returns error code; does not panic.
// CEP:ASSUMES: C caller validates pointer validity where possible.
// CEP:COST: one table lookup after validation.
// CEP:EVIDENCE: bench CEP-RS-0019.
// CEP:SECURITY: FFI boundary; all inputs validated.
```

Zig example:

```zig
// CEP:FILE: ffi/decoder_ffi.zig
// CEP:WHAT: C ABI FFI for opcode decoder.
// CEP:WHY: Exposes deterministic decoder to C/C++.
// CEP:CLASS: FFI
// CEP:STATUS: complete
// CEP:FAILURE: Returns error enum; no panic.
// CEP:ASSUMES: caller provides valid slice bounds.
// CEP:COST: one table lookup after validation.
// CEP:EVIDENCE: bench CEP-ZIG-0019.
// CEP:SECURITY: FFI boundary; inputs validated.
```

Python tool example:

```python
# CEP:FILE: tools/gen_opcode_table.py
# CEP:WHAT: Generates opcode table from opcode specification.
# CEP:WHY: Keeps opcode metadata synchronized and deterministic.
# CEP:CLASS: CEP-2
# CEP:STATUS: complete
# CEP:FAILURE: Exits with error if spec is malformed.
# CEP:ASSUMES: spec file is UTF-8 and repository-trusted.
# CEP:COST: offline tool; runtime cost irrelevant.
# CEP:EVIDENCE: golden test generated/opcode_table.hpp.golden.
# CEP:SECURITY: no network; no untrusted input.
```

---

# 36. Updated repository compliance checklist

A repository is compliant only if:

## Structure

- [ ] Hot and cold code are separated.
- [ ] Target-specific code is isolated.
- [ ] FFI code is isolated.
- [ ] Generated code is isolated.
- [ ] Tests mirror source.
- [ ] Benchmarks mirror hot code.
- [ ] Third-party code is vendored and separated.
- [ ] Quarantine exists and is excluded from builds.
- [ ] Config constants are centralized.

## Naming

- [ ] Files use lowercase snake_case.
- [ ] Modules match namespaces and directories.
- [ ] Types use PascalCase.
- [ ] Functions use snake_case.
- [ ] Constants use kPascalCase or equivalent.
- [ ] Macros use CEP_ prefix.
- [ ] FFI symbols use stable project prefix.
- [ ] No clever or misleading names.
- [ ] No dead names like `old`, `new`, `final`.

## Violation handling

- [ ] CI can block non-compliant merges.
- [ ] CI can detect banned hot-path constructs.
- [ ] CI can detect missing CEP comments.
- [ ] CI can detect missing evidence.
- [ ] CI can detect nondeterministic generators.
- [ ] Waivers are written, temporary, and reviewed.
- [ ] Extermination reports exist.
- [ ] Quarantine has deadlines.
- [ ] Expired quarantine is deleted.

---

# 37. Final extermination clause

The final rule is:

> CEP&CC does not negotiate with non-compliant code.

If code cannot prove:

- what it is,
- why it exists,
- what it assumes,
- how it fails,
- what it costs,
- whether it is secure,
- whether it is optimal,
- whether it is complete,

then it does not belong in the codebase.

It is either fixed, quarantined, or exterminated.


Add this as a new normative chapter.

I am using **HPC** here as **High-Performance Compiler**. If you meant **High-Performance Computing**, the chapter can be renamed and retargeted, but the strictness model stays the same.

---

# 38. HPC: High-Performance Compiler Conformance

This chapter extends CEP&CC for compilers, linkers, assemblers, JIT compilers, IR transformers, profile-guided optimizers, code generators, and binary instrumentation tools.

This chapter is normative.

A compiler is not compliant merely because it produces fast output. A compiler is compliant only if its translation behavior is correct, deterministic, measurable, secure, auditable, and reproducible.

For HPC compilers, the following are first-class correctness requirements:

1. semantic correctness,
2. deterministic translation,
3. bounded compile time,
4. bounded compile memory,
5. explicit optimization legality,
6. explicit target assumptions,
7. measurable codegen quality,
8. reproducible artifacts,
9. secure handling of untrusted input,
10. provable or evidence-backed optimality claims.

This chapter does not replace CEP&CC. It extends it. Where this chapter is stricter, this chapter wins. Where this chapter is silent, the rest of CEP&CC applies.

---

## 38.1 Scope

This chapter applies to all of the following:

- ahead-of-time compilers,
- JIT compilers,
- interpreters with optimizing tiers,
- IR-to-IR transformers,
- linkers,
- LTO pipelines,
- assemblers,
- disassemblers used as verification tools,
- binary rewriting tools,
- profile-guided optimization pipelines,
- code generators,
- instruction schedulers,
- register allocators,
- vectorizers,
- loop transformers,
- target-specific backends,
- compiler plugins,
- compiler driver pipelines,
- build-time code generators that emit compiler-relevant artifacts.

If a tool can change observable program semantics, it is inside the HPC boundary.

If a tool can affect generated machine code quality, it is inside the HPC boundary.

If a tool can affect compile-time performance determinism, it is inside the HPC boundary.

---

## 38.2 HPC prime law

The HPC prime law is:

> A compiler must never silently change the meaning of a program.
> A compiler must never silently trade correctness for performance.
> A compiler must never silently introduce nondeterministic translation.
> A compiler must never silently exceed compile-time budgets.
> A compiler must never silently exploit an assumption that is not documented and enforced.

Violations of the HPC prime law are Severity 0 unless proven otherwise by an explicit, reviewed, temporary waiver.

---

## 38.3 HPC conformance classes

HPC defines compiler component classes. These map onto CEP classes but add compiler-specific meaning.

### 38.3.1 HPC-0: Compiler-critical hot code

HPC-0 is the strictest compiler class.

HPC-0 code includes:

- lexer hot paths,
- parser hot paths,
- preprocessor hot paths,
- module import hot paths,
- AST lowering,
- IR construction,
- IR verification,
- IR normalization,
- optimization passes,
- alias analysis,
- value tracking,
- dependence analysis,
- loop analysis,
- vectorization,
- instruction selection,
- register allocation,
- instruction scheduling,
- machine IR lowering,
- emission,
- relocation handling,
- JIT patching,
- runtime code generation,
- deoptimization,
- binary hot rewriting.

HPC-0 components must satisfy all CEP-0 requirements unless explicitly waived.

HPC-0 components must additionally satisfy this chapter.

### 38.3.2 HPC-1: Deterministic compiler support code

HPC-1 includes compiler code that must be deterministic but is not necessarily cycle-exact.

Examples:

- diagnostics,
- configuration loading,
- target description loading,
- symbol table management,
- debug info construction,
- LTO merging,
- serialization,
- module cache handling,
- profile ingestion,
- remark generation,
- compile orchestration,
- linker script parsing,
- archive handling.

HPC-1 must be deterministic unless explicitly documented otherwise.

HPC-1 must satisfy CEP-1 requirements.

### 38.3.3 HPC-2: Offline compiler tooling

HPC-2 includes offline tools where runtime determinism is less important, but output correctness remains mandatory.

Examples:

- table generators,
- opcode generators,
- diagnostic generators,
- target description generators,
- benchmark harnesses,
- fuzz harness generators,
- documentation generators,
- compile-database tools.

HPC-2 tools must produce deterministic outputs if those outputs enter the compiler build.

Generated code is subject to the same rules as handwritten code.

---

## 38.4 Compiler correctness hierarchy

HPC compilers must obey the following correctness hierarchy.

Highest priority:

1. semantic correctness,
2. memory safety,
3. deterministic translation,
4. security,
5. compile-time boundedness,
6. generated-code performance,
7. compile-time speed,
8. compiler maintainability,
9. compiler convenience.

A lower-priority goal must never defeat a higher-priority requirement.

Examples:

- Faster compilation must not cause miscompilation.
- Better optimization must not break determinism.
- Better diagnostics must not change codegen silently.
- Smaller binaries must not remove required security checks.
- Simpler pass code must not rely on silent IR assumptions.

---

## 38.5 Miscompilation policy

Miscompilation is a Severity 0 defect.

A miscompilation exists if the compiler emits code that violates the observable behavior of the source program under the documented language standard, target ABI, and selected compiler options.

Miscompilation includes:

- incorrect control flow,
- incorrect data flow,
- incorrect memory ordering,
- incorrect floating-point behavior under selected flags,
- incorrect exception behavior,
- incorrect lifetime handling,
- incorrect initialization,
- incorrect destructor ordering,
- incorrect volatile behavior,
- incorrect atomic behavior,
- incorrect thread-local behavior,
- incorrect inline assembly handling,
- incorrect relocation,
- incorrect debug info that changes codegen semantics,
- incorrect profile-guided transformation,
- incorrect LTO merging,
- incorrect JIT patching,
- incorrect deoptimization state.

A miscompilation discovered after merge requires:

1. immediate revert or quarantine,
2. regression test,
3. minimal reproducer,
4. root-cause analysis,
5. lint or CI rule where possible,
6. extermination report.

---

## 38.6 Internal compiler error policy

An internal compiler error is a compiler crash, assertion failure, abort, or uncontrolled diagnostic failure.

### 38.6.1 Valid input

An internal compiler error on valid input is Severity 0.

Valid input means source code, IR, profile data, object files, or link inputs accepted by the documented compiler interface.

### 38.6.2 Invalid input

An internal compiler error on invalid input is Severity 1 unless it is exploitable.

For invalid input, the compiler should emit:

- clear diagnostics,
- source location where possible,
- no secret leakage,
- no unbounded resource usage,
- no memory unsafety.

### 38.6.3 Compiler robustness

The compiler must not:

- crash on malformed but syntactically bounded input without diagnostics,
- hang indefinitely,
- consume unbounded memory,
- emit partial invalid artifacts silently,
- continue translation after unrecoverable semantic failure.

If compilation cannot continue, the compiler must fail loudly and deterministically.

---

## 38.7 Language conformance requirements

An HPC compiler must document its language conformance state.

Required documentation:

- supported language standard,
- unsupported language features,
- partially supported features,
- implementation-defined behavior catalog,
- target-specific behavior catalog,
- ABI assumptions,
- library assumptions,
- feature-test macro behavior,
- module support status,
- contract support status,
- reflection support status,
- floating-point model,
- exception model,
- thread model,
- atomic model.

For C++26 compilers, the compiler must maintain a feature matrix.

Example:

```text
docs/compiler/cxx26_feature_matrix.md
```

The feature matrix must include:

```text
feature | status | gate | notes | tests | evidence
```

Silent language-feature fallback is banned.

If a feature is unavailable, the compiler must either:

1. reject the code with a clear diagnostic, or
2. gate the feature through an explicit documented mechanism.

---

## 38.8 Implementation-defined behavior policy

Implementation-defined behavior is allowed only if it is:

- named,
- documented,
- target-controlled,
- tested,
- visible in diagnostics where relevant.

The compiler must provide an implementation-defined behavior catalog.

The catalog must include:

- type sizes,
- signedness of `char`,
- alignment rules,
- endianness,
- floating-point model,
- exception ABI,
- name mangling rules,
- TLS model,
- attribute behavior,
- pragma behavior,
- diagnostic behavior,
- module cache behavior,
- initialization order rules,
- linkage rules,
- visibility rules.

Undocumented implementation-defined behavior is a Severity 1 defect.

If implementation-defined behavior affects security or optimization legality, it is Severity 0 until documented.

---

## 38.9 Undefined behavior policy

Compilers must not use undefined behavior as a silent optimization license.

Allowed optimization based on undefined behavior is only permitted if all of the following are true:

1. The language standard permits the assumption.
2. The compiler option explicitly enables the behavior.
3. The behavior is documented.
4. The optimization is diagnosable where possible.
5. The optimization does not break security-critical bounds checks unless explicitly allowed.
6. The optimization is testable.
7. The optimization can be disabled.

Banned:

- silently removing security checks because of UB assumptions,
- silently deleting overflow checks,
- silently removing bounds checks,
- silently assuming unreachable code is dead,
- silently transforming suspicious code into faster but semantically different code.

If a compiler exploits UB, the pass must state:

```cpp
// CEP:HPC-UB: Uses strict-aliasing UB assumption.
// CEP:HPC-UB-GATE: -fstrict-aliasing.
// CEP:HPC-UB-PROOF: no type-punning across analyzed region.
```

---

## 38.10 Deterministic translation

HPC compilers must be deterministic by default.

Deterministic translation means:

> Same source + same compiler version + same flags + same target configuration + same dependencies + same profile data + same environment contract = same diagnostics, same IR, same object output, same disassembly, same remarks, same debug artifacts.

Allowed exceptions must be explicit and documented.

Examples of allowed intentional variation:

- embedded build timestamp if enabled by explicit option,
- embedded source path if enabled by explicit option,
- randomized ASLR-related runtime behavior not present in object output.

Banned sources of nondeterminism:

- pointer address hashing,
- unordered container iteration order,
- hash map iteration order,
- file iteration order,
- directory iteration order,
- environment variables unless explicitly declared,
- locale,
- timezone,
- current time,
- random seeds,
- thread scheduling order,
- unstable module cache keys,
- unstable pass IDs,
- unstable symbol ordering,
- unstable diagnostic ordering,
- unstable temporary file names embedded into output,
- unstable build paths embedded into output unless remapped.

Parallel compilation must produce deterministic output.

If parallel compilation cannot be made deterministic, parallelism must be disabled by default or explicitly gated.

---

## 38.11 Compile-time performance class

Compile time is a performance cost.

HPC compilers must treat compile-time and compile-memory as CEP costs.

Every HPC-0 component must document:

- expected compile time,
- worst-case compile time,
- expected memory usage,
- worst-case memory usage,
- input-size complexity,
- IR-node complexity,
- token complexity,
- instantiation complexity,
- pass repetition behavior,

Required comment fields:

```cpp
// CEP:HPC-COMPILE-COST:
// CEP:HPC-COMPILE-MEM:
// CEP:HPC-COMPLEXITY:
```

Example:

```cpp
// CEP:HPC-COMPILE-COST: 18 ms for 10k IR nodes on reference machine.
// CEP:HPC-COMPILE-MEM: 96 MB peak for 10k IR nodes.
// CEP:HPC-COMPLEXITY: O(N) expected, O(N log N) worst-case.
```

Unbounded compile-time behavior is banned in HPC-0.

Quadratic or worse behavior is allowed only if:

- it is documented,
- input bounds exist,
- evidence exists,
- regression gates exist.

---

## 38.12 Compile-time budgets

HPC compiler projects must define compile-time budgets.

Recommended budget categories:

- lexer,
- parser,
- preprocessor,
- module import,
- template instantiation,
- `constexpr` evaluation,
- reflection expansion,
- AST lowering,
- IR construction,
- IR verification,
- optimization pipeline,
- target lowering,
- register allocation,
- scheduling,
- emission,
- debug info,
- link,
- LTO,
- JIT compilation,
- profile loading.

Budgets must be named constants, not magic numbers.

Bad:

```cpp
if (pass_time > 500) fail();
```

Good:

```cpp
if (pass_time > cep::limit::hpc_pass_max_ms) fail();
```

Budget violations are CI failures unless waived.

---

## 38.13 Compiler input trust model

Compiler input is untrusted until validated.

Compiler inputs include:

- source code,
- headers,
- modules,
- precompiled headers,
- IR,
- bitcode,
- object files,
- archives,
- linker scripts,
- profiles,
- configuration files,
- target descriptions,
- plugin binaries,
- debug info,
- symbol files.

The compiler must define trust boundaries for each input class.

Required questions:

- What input is trusted?
- What input is untrusted?
- What input can be malicious?
- What input can be huge?
- What input can be recursive?
- What input can exhaust memory?
- What input can exhaust compile time?
- What input can trigger code generation?
- What input can trigger plugin loading?
- What input can affect codegen legality?

If no trust model exists, all compiler input is treated as untrusted.

---

## 38.15 Diagnostics

Diagnostics are compiler output and therefore subject to determinism and security rules.

Diagnostics must be:

- stable across runs,
- deterministic in order,
- source-location accurate,
- machine-parseable where possible,
- free of pointer addresses,
- free of hash seeds,
- free of environment leaks,
- free of secret data,
- bounded in count,
- bounded in size.

Diagnostics must not affect codegen unless explicitly documented.

If diagnostics affect codegen, the effect must be gated and tested.

Required diagnostic metadata:

```text
diagnostic ID
severity
source location
component
message
suggestion
note
```

Diagnostic IDs must be stable.

Diagnostic text may change, but diagnostic meaning must not silently change.

---

## 38.16 Optimization remarks

Optimization remarks are evidence of compiler behavior.

HPC compilers should emit machine-readable remarks for:

- inlining,
- vectorization,
- loop unrolling,
- loop interchange,
- loop fusion,
- loop distribution,
- LICM,
- common subexpression elimination,
- dead code elimination,
- function specialization,
- register allocation spills,
- scheduling changes,
- branch elimination,
- profile use,
- PGO mismatches,
- target-specific lowering.

Remarks must be deterministic.

Remarks must not leak:

- secrets,
- environment paths unless remapped,
- unstable IDs,
- nondeterministic ordering.

Remarks are not a substitute for evidence, but they are useful evidence.

---

## 38.17 IR contract

The intermediate representation is a contract.

An HPC compiler IR must be:

- printable,
- hashable,
- versioned,
- verifiable,
- stable,
- canonicalizable,
- target-aware but not target-contaminated,
- serializable if used across stages,
- round-trippable if text IR is normative,
- documented with semantic invariants.

IR must not rely on:

- pointer identity,
- address order,
- hash iteration order,
- uninitialized metadata,
- hidden target assumptions,
- hidden pass ordering,
- hidden global state.

IR nodes must have stable identity within a compilation unit unless identity is explicitly documented as unstable.

---

## 38.18 IR verification

Every IR mutation must be verified.

Required verifier checks:

- type correctness,
- use-def validity,
- dominance validity,
- terminator validity,
- block linkage validity,
- metadata validity,
- target constraint validity,
- alignment validity,
- attribute validity,
- linkage validity,
- calling convention validity,
- debug info consistency if debug info is IR-visible.

IR verification must run:

- after parsing/lowering,
- after each HPC-0 pass,
- before target lowering,
- before emission,
- after JIT patching where feasible.

If verification is too expensive for a hot pass, the verifier may be split into cheap and full modes, but the full verifier must run in CI.

Skipping IR verification in release is allowed only if:

- the verifier cost is measured,
- the safety argument is documented,
- CI still runs full verification.

---

## 38.19 IR determinism

IR must be deterministic.

IR printing must use stable ordering:

- stable function order,
- stable block order,
- stable instruction order,
- stable metadata order,
- stable attribute order,
- stable debug order.

IR hashing must not depend on:

- pointer values,
- allocation order,
- hash seed,
- map iteration order,
- thread order.

If IR is serialized, serialization must be deterministic.

Serialized IR must include:

- IR version,
- compiler version,
- target configuration hash,
- pass pipeline hash,
- feature gate hash.

---

## 38.20 Pass pipeline contract

The pass pipeline must be explicit.

Required pipeline documentation:

- pass order,
- pass version,
- pass dependencies,
- pass options,
- pass enable/disable gates,
- pass cost model,
- pass target restrictions,
- pass required analyses,
- pass invalidated analyses,
- pass preserved invariants,
- pass evidence.

The pass pipeline must be versioned.

Bad:

```text
run optimizer
```

Good:

```text
pipeline: hpc-opt-2026-09
passes: verify, canonicalize, inline, licm, gv, dce, lower-target
```

Changing pass order is a semantic event.

Pass-order changes require:

- review,
- benchmark evidence,
- golden IR update,
- disassembly review,
- regression test.

---

## 38.21 Pass certification

Every HPC-0 pass must be certified.

A pass is certified only if it has:

1. purpose,
2. legality conditions,
3. input requirements,
4. output guarantees,
5. preserved invariants,
6. invalidated analyses,
7. cost model,
8. failure policy,
9. target dependencies,
10. tests,
11. golden IR,
12. benchmark evidence,
13. fuzz evidence where applicable.

Required pass comment fields:

```cpp
// CEP:HPC-PASS:
// CEP:HPC-PASS-KIND:
// CEP:HPC-PASS-INPUT:
// CEP:HPC-PASS-OUTPUT:
// CEP:HPC-PASS-ANALYSIS-REQUIRED:
// CEP:HPC-PASS-ANALYSIS-PRODUCED:
// CEP:HPC-PASS-ANALYSIS-INVALIDATED:
// CEP:HPC-PASS-LEGALITY:
// CEP:HPC-PASS-PRESERVES:
// CEP:HPC-PASS-COST:
// CEP:HPC-PASS-FAILURE:
// CEP:HPC-PASS-TARGET:
// CEP:HPC-PASS-EVIDENCE:
```

Example:

```cpp
// CEP:HPC-PASS: licm
// CEP:HPC-PASS-KIND: loop transformation
// CEP:HPC-PASS-INPUT: SSA IR with loop info
// CEP:HPC-PASS-OUTPUT: SSA IR with hoisted invariant operations
// CEP:HPC-PASS-ANALYSIS-REQUIRED: loop, dominance, alias, side-effect
// CEP:HPC-PASS-ANALYSIS-PRODUCED: updated loop invariants
// CEP:HPC-PASS-ANALYSIS-INVALIDATED: dominance, scalar evolution
// CEP:HPC-PASS-LEGALITY: no side effects, no alias conflict, no control dependence change
// CEP:HPC-PASS-PRESERVES: program semantics, memory ordering, exception behavior
// CEP:HPC-PASS-COST: O(N) expected, O(N log N) worst-case
// CEP:HPC-PASS-FAILURE: aborts transformation if legality cannot be proven
// CEP:HPC-PASS-TARGET: target-independent
// CEP:HPC-PASS-EVIDENCE: golden IR licm_01, fuzz licm_fuzz_04, bench HPC-113
```

---

## 38.22 Pass legality

A pass must not transform code unless legality is proven.

Legality proof may include:

- type rules,
- alias analysis,
- dependence analysis,
- control-flow analysis,
- memory-order analysis,
- overflow analysis,
- alignment analysis,
- initialization analysis,
- exception analysis,
- target constraint analysis.

If legality cannot be proven, the pass must not perform the transformation.

Silent conservative fallback is allowed only if documented.

Banned:

- transforming because it is usually safe,
- transforming because no test failed,
- transforming because profiling suggests it,
- transforming because target prefers it,
- transforming because another compiler does it.

Every transformation must answer:

> Under what exact conditions is this transformation legal?

If the answer is unknown, the transformation is not allowed.

---

## 38.23 Optimization assumption policy

Optimizations often rely on assumptions.

All optimization assumptions must be explicit.

Examples:

- no aliasing,
- aligned access,
- no overflow,
- no NaN,
- no side effects,
- no exception,
- no atomic synchronization,
- no volatile access,
- no signal interaction,
- no interrupt interaction,
- no concurrent mutation,
- initialized memory,
- finite loop,
- known trip count,
- known function visibility,
- no interposition,
- no dynamic loading interference.

Each assumption must be one of:

1. proven statically,
2. enforced by runtime check,
3. documented and gated by compiler option,
4. documented as target-specific,
5. rejected.

Comment-only assumptions are banned.

---

## 38.24 Floating-point optimization policy

Floating-point transformations are restricted.

HPC compilers must not change floating-point semantics unless explicitly enabled.

Banned by default:

- reassociation,
- contraction unless allowed,
- fast-math behavior,
- NaN elimination,
- infinity elimination,
- signed-zero elimination,
- reciprocal transformation,
- division-to-multiplication transformation,
- vectorization that changes rounding,
- errno behavior changes,
- math library substitution without proof.

Allowed floating-point optimizations must document:

- rounding mode assumptions,
- exception assumptions,
- NaN assumptions,
- infinity assumptions,
- errno assumptions,
- contraction policy,
- vector-width impact,
- target FMA behavior.

If floating-point behavior is target-specific, it must live in target policy.

---

## 38.25 Loop transformation policy

Loop transformations require dependence proof.

Loop transformations include:

- unrolling,
- peeling,
- fusion,
- fission,
- interchange,
- reversal,
- tiling,
- vectorization,
- parallelization,
- invariant code motion,
- induction variable simplification,
- bound strengthening,
- loop deletion,
- loop rotation.

Each loop transformation must document:

- loop bounds,
- trip count,
- dependence proof,
- alignment proof,
- side-effect proof,
- exit condition proof,
- overflow proof,
- exception behavior,
- floating-point behavior,
- vector legality,
- scalar fallback behavior.

Loop deletion is especially dangerous.

A loop may be deleted only if the compiler proves:

- no side effects,
- no observable memory effects,
- no volatile effects,
- no atomic effects,
- no exception effects,
- no observable control-flow effects,
- bounded or irrelevant execution.

---

## 38.26 Vectorization policy

Vectorization is allowed only when legality is proven.

Vectorizer must prove:

- data dependence safety,
- alignment,
- trip count,
- masked remainder handling,
- scalar fallback,
- memory ordering,
- exception behavior,
- floating-point semantics,
- target vector ABI,
- target register pressure,
- target cost benefit.

Vectorizer must not vectorize if:

- dependence is unknown,
- alignment is unknown and target requires alignment,
- floating-point semantics would change,
- exceptions would change,
- atomics are present,
- volatile accesses are present,
- target cost model predicts regression,
- code size regression exceeds budget.

Vectorization evidence must include:

- vector width,
- vector instruction used,
- scalar fallback path,
- remainder handling,
- alignment assumption,
- measured performance,
- disassembly hash.

---

## 38.27 Inlining policy

Inlining is an optimization with semantic and compile-time consequences.

Inlining decisions must be explainable.

Required inlining data:

- caller,
- callee,
- inlining cost,
- inlining benefit,
- code size impact,
- compile time impact,
- register pressure impact,
- recursion safety,
- exception safety,
- debug impact,
- target constraints.

Inlining must not:

- cause unbounded compile-time growth,
- cause unbounded code size growth,
- change observable initialization order,
- change exception semantics,
- change linkage semantics,
- expose private symbols incorrectly,
- break determinism.

Inline heuristics must be versioned.

---

## 38.28 Interprocedural optimization policy

Interprocedural optimization requires explicit visibility and linkage analysis.

IPO includes:

- cross-module inlining,
- constant propagation across modules,
- dead argument elimination,
- function specialization,
- global value numbering,
- LTO optimization,
- cross-TU alias analysis,
- cross-TU devirtualization,
- cross-TU whole-program analysis.

IPO must prove:

- linkage,
- visibility,
- interposition rules,
- dynamic loading constraints,
- symbol resolution rules,
- initialization order constraints,
- thread visibility constraints,
- exception ABI constraints.

If whole-program assumptions are used, they must be documented.

Banned:

- assuming no interposition without evidence,
- assuming no dynamic loading without evidence,
- assuming symbol visibility without checking,
- assuming no concurrent access without proof.

---

## 38.29 Profile-guided optimization policy

Profile data is compiler input.

Profile data is untrusted until validated.

Required profile validation:

- schema version,
- compiler version,
- target hash,
- binary hash,
- source revision,
- function ID validity,
- counter validity,
- checksum,
- timestamp policy,
- path normalization,
- size bounds,
- counter bounds.

PGO must not change program semantics.

PGO may influence:

- inlining order,
- block layout,
- branch prediction hints,
- function order,
- cold/hot splitting,
- register allocation heuristics,
- unrolling thresholds.

PGO must not:

- remove required checks,
- change memory ordering,
- change floating-point semantics,
- change exception behavior,
- change observable initialization,
- change diagnostics semantics.

Profile mismatch must be detected.

If profile mismatch is detected, the compiler must either:

1. fail,
2. ignore profile with diagnostic,
3. fall back to non-PGO pipeline.

Silent use of stale profile is banned.

---

## 38.30 Target hooks

All target-specific compiler behavior must go through explicit target hooks.

Banned in generic compiler code:

```cpp
if (is_arm64) ...
```

```cpp
if (is_x86_64) ...
```

```cpp
#if defined(__riscv)
...
#endif
```

Allowed:

```cpp
target.hook.lower_instruction(insn);
```

or:

```cpp
target_policy.schedule(instruction);
```

Target hooks must be:

- versioned,
- documented,
- deterministic,
- tested,
- measured,
- isolated in target directories.

Target hooks must declare:

- target name,
- target revision,
- ISA level,
- ABI,
- endianness,
- pointer width,
- register file,
- alignment rules,
- vector width,
- cache parameters,
- latency model,
- cost model version.

---

## 38.31 Target cost model

A target cost model is mandatory for HPC compilers.

The cost model must include:

- instruction latency,
- instruction throughput,
- issue width,
- register pressure,
- spill cost,
- branch cost,
- misprediction cost,
- memory latency,
- cache behavior,
- alignment cost,
- vector operation cost,
- scalar-to-vector transition cost,
- relocation cost,
- call cost,
- return cost,
- exception cost,
- TLS access cost,
- atomic cost,
- barrier cost.

Cost model values must not be magic numbers.

They must be named and sourced.

Good:

```cpp
// CEP:HPC-TARGET-COST: arm64-a78 load latency = 4 cycles, target manual rev B.
```

Bad:

```cpp
constexpr int load_latency = 4;
```

Cost model changes require evidence.

---

## 38.32 Register allocation policy

Register allocation is HPC-0.

Register allocator must document:

- register classes,
- allocation order,
- spill policy,
- eviction policy,
- coalescing policy,
- rematerialization policy,
- live range splitting,
- interference graph construction,
- target constraints,
- debug behavior.

Register allocation must be deterministic.

Required evidence:

- register pressure,
- spill count,
- spill code size,
- rematerialization count,
- copy count,
- coalescing success rate,
- allocation time,
- allocation memory.

Register allocator heuristics must be versioned.

---

## 38.33 Instruction scheduling policy

Instruction scheduling is HPC-0.

Scheduler must document:

- dependence graph,
- latency model,
- issue model,
- hazard model,
- register pressure feedback,
- branch handling,
- memory ordering constraints,
- target barriers,
- anti-dependence handling,
- output-dependence handling.

Scheduler must preserve:

- program order where required,
- memory ordering,
- volatile semantics,
- atomic semantics,
- exception semantics,
- signal/interrupt constraints where documented.

Scheduler must be deterministic.

If scheduling is target-specific, it must be isolated in target code.

---

## 38.34 Emission policy

Object emission is HPC-0.

Emitter must guarantee:

- deterministic object layout,
- deterministic section order,
- deterministic symbol order,
- deterministic relocation order,
- deterministic debug info order,
- deterministic exception table order,
- deterministic unwind info,
- deterministic note sections.

Emitter must not embed:

- absolute source paths unless remapped,
- user names,
- host names,
- timestamps unless explicitly enabled,
- environment variables,
- random values,
- unstable temporary identifiers.

Emitter evidence must include:

- object hash,
- section list,
- symbol table hash,
- relocation table hash,
- disassembly hash.

---

## 38.35 Codegen evidence

HPC compilers must provide codegen evidence for hot paths.

Required evidence categories:

- disassembly,
- instruction count,
- branch count,
- call count,
- indirect call count,
- memory load count,
- memory store count,
- alignment behavior,
- vector usage,
- spill count,
- stack usage,
- code size,
- relocation count,
- exception table size,
- debug info impact,
- target cost estimate.

For HPC-0 emitted functions, the compiler should provide:

```cpp
// CEP:HPC-CODEGEN:
// CEP:HPC-CODEGEN-PROOF:
```

Example:

```cpp
// CEP:HPC-CODEGEN: target-optimal scalar loop for checksum on arm64-a78.
// CEP:HPC-CODEGEN-PROOF: bench HPC-201, 1 load/add per element, 0 spills.
```

---

## 38.36 Debug info policy

Debug info must not silently change codegen.

If debug info affects codegen, the effect must be documented.

Examples:

- debug intrinsics affecting scheduling,
- debug variables affecting register allocation,
- line tables affecting block layout,
- debug labels affecting symbol order.

Debug info must be deterministic.

Debug info must not contain:

- secrets,
- environment variables,
- absolute paths unless remapped,
- unstable IDs,
- nondeterministic ordering.

Debug info generation must be budgeted.

---

## 38.37 Linker and LTO policy

Linking is part of the compiler translation system.

Linker requirements:

- deterministic symbol resolution,
- deterministic archive member order,
- deterministic section placement,
- deterministic relocation processing,
- deterministic output hash,
- no environment dependence,
- no time dependence,
- no locale dependence.

LTO requirements:

- deterministic bitcode merging,
- deterministic partitioning,
- deterministic optimization order,
- deterministic symbol internalization,
- deterministic dead stripping,
- deterministic profile use.

ThinLTO or equivalent parallel LTO must produce deterministic final output.

If deterministic parallel LTO is impossible, it must be disabled by default or gated.

---

## 38.38 Binary layout policy

Binary layout must be explicit.

Required documentation:

- section layout,
- segment permissions,
- alignment,
- page size assumptions,
- relocation types,
- symbol visibility,
- export table,
- import table,
- exception tables,
- unwind tables,
- TLS model,
- note sections,
- debug sections.

Executable stack is banned unless explicitly required and documented.

Writable and executable memory is banned unless required by JIT policy and security-reviewed.

---

## 38.39 JIT policy

JIT compilers are HPC-0 when they generate executable code at runtime.

JIT compilation must have explicit budgets:

- compile latency,
- compile memory,
- code cache size,
- patch time,
- invalidation time,
- deoptimization time,
- relocation time,
- symbol resolution time.

JIT must enforce:

- W^X,
- code cache bounds,
- relocation correctness,
- patchpoint validity,
- instruction alignment,
- target hazard constraints,
- thread synchronization during patching,
- safe publication of generated code.

JIT must be deterministic for the same:

- input IR,
- runtime configuration,
- target state,
- profile data,
- patchpoint state.

If deterministic JIT is impossible due to runtime state, the nondeterminism must be documented and bounded.

JIT deoptimization must preserve program semantics.

JIT must not execute untrusted generated code without:

- validation,
- sandboxing,
- capability limits,
- security review.

---

## 38.40 Runtime patching policy

Runtime code patching is Severity 0 territory.

Patching must prove:

- target instruction sequence is safe to modify,
- no thread can observe a partially patched state,
- instruction boundaries are valid,
- relocations are valid,
- branch targets are valid,
- cache coherency is handled,
- pipeline hazards are handled,
- rollback is possible if required.

Patching must be logged or diagnosable in debug builds.

Patching must not leak secrets.

Patching failures must fail safely.

---

## 38.41 Compiler plugin policy

Compiler plugins are security-critical.

Plugins must be:

- versioned,
- reviewed,
- deterministic,
- sandboxed where possible,
- explicitly loaded,
- documented,
- tested,
- hash-pinned.

Plugins must not:

- silently change codegen,
- silently change diagnostics,
- silently change pass ordering,
- introduce nondeterminism,
- access network without approval,
- access environment without approval,
- leak source code,
- leak secrets.

A plugin that affects HPC-0 behavior is itself HPC-0-relevant.

---

## 38.42 Compiler supply chain

Compiler supply chain is part of HPC security.

Required:

- pinned compiler version,
- pinned assembler version,
- pinned linker version,
- pinned standard library version,
- pinned runtime library version,
- pinned target description version,
- pinned pass pipeline version,
- pinned cost model version,
- pinned profile schema version,
- artifact hashes,
- reproducible builds.

Banned:

- fetching arbitrary compiler plugins during release builds,
- fetching arbitrary target descriptions during release builds,
- telemetry in release compiler builds,
- nondeterministic package resolution,
- mutable compiler toolchain tags,
- unsigned compiler artifacts where signature policy exists.

Self-hosted compilers must have bootstrap validation.

Bootstrap validation should include:

- stage comparison,
- artifact hash comparison,
- behavioral test suite,
- benchmark comparison,
- diagnostics comparison.

---

## 38.43 Compiler testing requirements

HPC compilers require aggressive testing.

Required test classes:

1. language conformance tests,
2. unit tests,
3. IR golden tests,
4. disassembly golden tests,
5. diagnostic golden tests,
6. pass legality tests,
7. pass negative tests,
8. target-specific tests,
9. ABI tests,
10. layout tests,
11. exception tests,
12. floating-point tests,
13. atomic tests,
14. concurrency tests,
15. linker tests,
16. LTO tests,
17. PGO tests,
18. JIT tests,
19. deoptimization tests,
20. fuzz tests,
21. differential tests,
22. miscompilation regression tests,
23. compile-time benchmark tests,
24. code-quality benchmark tests,
25. determinism tests.

A compiler change that cannot be tested is not mergeable.

---

## 38.44 Fuzzing requirements

HPC compilers must fuzz:

- lexer,
- parser,
- preprocessor,
- module importer,
- IR parser,
- object parser,
- linker input parser,
- profile parser,
- debug info parser,
- target description parser,
- plugin interface where possible.

Fuzzing must detect:

- crashes,
- hangs,
- memory safety bugs,
- unbounded recursion,
- unbounded memory,
- unbounded compile time,
- invalid diagnostics,
- invalid IR generation,
- invalid codegen,
- assertion failures.

Fuzz failures must be reducible.

Every fuzz regression must have:

- minimal reproducer,
- test,
- severity classification,
- extermination report if merged previously.

---

## 38.45 Differential testing

Differential testing is required where feasible.

Differential testing compares compiler behavior against:

- reference interpreter,
- older stable compiler version,
- alternative optimization level,
- alternative backend,
- sanitized execution,
- formal model,
- target simulator,
- known-good disassembly.

Differential testing must not assume the newer compiler is correct.

When differential disagreement occurs, the compiler team must determine:

- which behavior is standard-correct,
- which behavior is target-correct,
- which behavior is option-correct,
- which compiler is defective.

Differential mismatches are Severity 0 if they indicate miscompilation.

---

## 38.46 Translation validation

Translation validation is strongly recommended.

Where possible, HPC compilers should use:

- SMT-based equivalence checking,
- alive-style transformation validation,
- IR invariant checking,
- symbolic execution,
- property-based testing,
- proof-producing optimizers.

Translation validation is not required for every pass, but passes with high miscompilation risk should prefer it.

High-risk passes:

- alias-based transformations,
- loop transformations,
- vectorization,
- memory reordering,
- dead code elimination,
- speculative devirtualization,
- profile-guided transformations,
- floating-point transformations,
- link-time optimizations.

---

## 38.47 Benchmarking HPC compilers

HPC compiler benchmarking must measure both compiler cost and output quality.

Required compiler-cost metrics:

- wall compile time,
- CPU time,
- peak memory,
- pass time,
- pass memory,
- template instantiation time,
- constexpr evaluation time,
- module import time,
- LTO time,
- link time,
- JIT compile time.

Required output-quality metrics:

- runtime performance,
- code size,
- static object size,
- instruction count,
- branch count,
- load/store count,
- vectorization rate,
- spill count,
- stack usage,
- relocation count,
- debug info size.

Benchmarks must be deterministic.

Benchmark artifacts must include:

- compiler version,
- flags,
- target,
- input,
- profile data hash,
- environment contract,
- artifact hashes,
- measured results.

---

## 38.48 HPC CI gates

CI must enforce HPC requirements.

Required gates:

1. C++26 or relevant language standard mode.
2. Warnings as errors.
3. Sanitizers clean.
4. Determinism check.
5. Golden IR check.
6. Golden disassembly check.
7. Diagnostic stability check.
8. Pass legality test.
9. Miscompilation regression suite.
10. Fuzz suite.
11. Compile-time benchmark gate.
12. Compile-memory benchmark gate.
13. Output-size gate.
14. Runtime benchmark gate.
15. Target matrix tests.
16. PGO profile validation.
17. LTO determinism check.
18. JIT safety tests where applicable.
19. Plugin policy check where applicable.
20. Supply-chain pinning check.

If any Severity 0 gate fails, merge is blocked.

---

## 38.49 HPC comment fields

The following comment fields are added for HPC compilers.

Required where relevant:

```cpp
// CEP:HPC-CLASS:
// CEP:HPC-PASS:
// CEP:HPC-PASS-KIND:
// CEP:HPC-PASS-INPUT:
// CEP:HPC-PASS-OUTPUT:
// CEP:HPC-PASS-ANALYSIS-REQUIRED:
// CEP:HPC-PASS-ANALYSIS-PRODUCED:
// CEP:HPC-PASS-ANALYSIS-INVALIDATED:
// CEP:HPC-PASS-LEGALITY:
// CEP:HPC-PASS-PRESERVES:
// CEP:HPC-PASS-COST:
// CEP:HPC-PASS-FAILURE:
// CEP:HPC-PASS-TARGET:
// CEP:HPC-PASS-EVIDENCE:
// CEP:HPC-IR:
// CEP:HPC-TRANSFORM:
// CEP:HPC-UB:
// CEP:HPC-UB-GATE:
// CEP:HPC-UB-PROOF:
// CEP:HPC-COMPILE-COST:
// CEP:HPC-COMPILE-MEM:
// CEP:HPC-COMPLEXITY:
// CEP:HPC-TARGET-MODEL:
// CEP:HPC-CODEGEN:
// CEP:HPC-CODEGEN-PROOF:
// CEP:HPC-PGO:
// CEP:HPC-JIT:
// CEP:HPC-DETERMINISM:
```

---

## 38.50 `CEP:HPC-CLASS`

Use this field to identify HPC class.

Allowed values:

```text
HPC-0
HPC-1
HPC-2
```

Example:

```cpp
// CEP:HPC-CLASS: HPC-0
```

---

## 38.51 `CEP:HPC-IR`

Use this field to describe IR role.

Examples:

```cpp
// CEP:HPC-IR: Builds target-independent SSA from lowered AST.
```

```cpp
// CEP:HPC-IR: Verifies dominance and use-def chains after optimization.
```

---

## 38.52 `CEP:HPC-TRANSFORM`

Use this field to describe transformation role.

Examples:

```cpp
// CEP:HPC-TRANSFORM: Hoists loop-invariant memory loads.
```

```cpp
// CEP:HPC-TRANSFORM: Vectorizes aligned fixed-trip-count loops.
```

---

## 38.53 `CEP:HPC-DETERMINISM`

Use this field to state deterministic behavior.

Examples:

```cpp
// CEP:HPC-DETERMINISM: deterministic; no hash-order dependence.
```

```cpp
// CEP:HPC-DETERMINISM: deterministic if parallelism disabled.
```

If nondeterminism exists:

```cpp
// CEP:HPC-DETERMINISM: nondeterministic due to optional parallel LTO; disabled by default.
```

---

## 38.54 HPC review checklist

A compiler change is HPC-compliant only if all relevant items are true.

### Correctness

- [ ] No miscompilation.
- [ ] No silent semantic change.
- [ ] No UB exploitation without gate.
- [ ] No floating-point semantic change without gate.
- [ ] No memory-order change.
- [ ] No exception behavior change.
- [ ] No initialization order change.
- [ ] No ABI break.

### Determinism

- [ ] Diagnostics deterministic.
- [ ] IR deterministic.
- [ ] Object output deterministic.
- [ ] Disassembly deterministic.
- [ ] Remarks deterministic.
- [ ] LTO deterministic.
- [ ] PGO pipeline deterministic.
- [ ] Parallel compilation deterministic or gated.

### Compile-time performance

- [ ] Compile-time budget documented.
- [ ] Compile-memory budget documented.
- [ ] Complexity documented.
- [ ] No unbounded recursion.
- [ ] No unbounded instantiation.
- [ ] No unbounded pass repetition.
- [ ] Benchmark evidence present.

### Pass certification

- [ ] Pass contract present.
- [ ] Legality conditions present.
- [ ] Analyses documented.
- [ ] Invalidations documented.
- [ ] Failure policy documented.
- [ ] Target dependence documented.
- [ ] Evidence present.

### Target

- [ ] No target checks in generic code.
- [ ] Target hooks explicit.
- [ ] Target cost model documented.
- [ ] Target assumptions enforced.
- [ ] Target changes measured.

### Codegen

- [ ] Disassembly reviewed.
- [ ] Instruction count reviewed.
- [ ] Spills reviewed.
- [ ] Stack usage reviewed.
- [ ] Relocations reviewed.
- [ ] Code size reviewed.
- [ ] Debug impact reviewed.

### Security

- [ ] Untrusted input validated.
- [ ] Resource limits enforced.
- [ ] No secret leakage.
- [ ] No unsafe plugin behavior.
- [ ] No executable writable memory outside policy.
- [ ] Profile data validated.
- [ ] Supply chain pinned.

---

## 38.55 HPC violation severity

### Severity 0 HPC violations

Examples:

- miscompilation,
- nondeterministic object output,
- invalid IR accepted silently,
- pass transforms without legality proof,
- UB-based optimization without gate,
- floating-point semantic change without gate,
- profile silently stale,
- JIT patch race,
- W^X violation,
- compiler crash on valid input,
- secret leakage in diagnostics,
- hard-coded target assumption in generic code,
- target hook missing layout proof,
- linker nondeterminism,
- LTO semantic change without evidence,
- untrusted input causing unbounded compile time,
- generated compiler table without golden test.

Response:

1. Block merge.
2. Revert or quarantine if merged.
3. Add regression test.
4. Add minimal reproducer.
5. Add extermination report.
6. Add lint or CI rule if possible.

### Severity 1 HPC violations

Examples:

- missing pass evidence,
- missing compile-time budget,
- missing IR verifier in non-critical path,
- missing deterministic remark ordering,
- missing target cost source,
- missing diagnostic ID stability,
- missing PGO schema documentation,
- missing JIT budget documentation.

Response:

1. Block merge unless emergency waiver.
2. Require repair.
3. Waiver must expire.

### Severity 2 HPC violations

Examples:

- poor pass naming,
- vague compiler comment,
- stale remark text,
- missing optional HPC comment field,
- unclear target documentation.

Response:

- reject or request repair.

---

## 38.56 HPC extermination examples

### Example 1: Silent vectorization with unknown dependence

Violation:

```cpp
// Vectorize loop.
for (...)
```

No dependence proof.

Response:

```text
EXTERMINATE
Reason: vectorization without dependence proof.
Rule: CEP&CC 38.26
Action: disable vectorization or add legality proof.
```

### Example 2: Nondeterministic pass order

Violation:

```cpp
for (auto& pass : pass_map) run(pass);
```

`pass_map` iteration order is unstable.

Response:

```text
EXTERMINATE
Reason: nondeterministic pass execution order.
Rule: CEP&CC 38.20
Action: use explicit ordered pipeline.
```

### Example 3: PGO uses stale profile silently

Violation:

Compiler ignores profile version mismatch.

Response:

```text
EXTERMINATE
Reason: stale profile used silently.
Rule: CEP&CC 38.29
Action: fail or fall back with diagnostic.
```

### Example 4: Generic backend contains target if

Violation:

```cpp
if (target == Target::arm64) {
  emit_arm64_sequence();
}
```

Response:

```text
FAIL
Reason: target-specific logic in generic backend.
Rule: CEP&CC 38.30
Action: move to target hook.
```

### Example 5: JIT patch without synchronization

Violation:

JIT patches live code without safe publication.

Response:

```text
EXTERMINATE
Reason: unsafe runtime patching.
Rule: CEP&CC 38.40
Action: revert and implement safe patch protocol.
```

---

## 38.57 HPC example: compliant optimization pass

```cpp
// CEP:WHAT: Hoists loop-invariant scalar loads from inner loops.
// CEP:WHY: Reduces redundant memory traffic in hot compiler IR transformations.
// CEP:STATUS: complete
// CEP:FAILURE: Returns PassError::unsupported if legality cannot be proven.
// CEP:ASSUMES: SSA form, loop info, alias analysis available.
// CEP:COST: O(N) expected, O(N log N) worst-case on IR nodes.
// CEP:EVIDENCE: golden IR licm_01, fuzz licm_fuzz_04, bench HPC-113.
// CEP:SECURITY: IR input may be untrusted; verifier runs before pass.
// CEP:HPC-CLASS: HPC-0
// CEP:HPC-PASS: licm
// CEP:HPC-PASS-KIND: loop transformation
// CEP:HPC-PASS-INPUT: SSA IR with loop and alias analysis
// CEP:HPC-PASS-OUTPUT: SSA IR with hoisted invariant loads
// CEP:HPC-PASS-ANALYSIS-REQUIRED: loop, dominance, alias, side-effect
// CEP:HPC-PASS-ANALYSIS-PRODUCED: updated invariant set
// CEP:HPC-PASS-ANALYSIS-INVALIDATED: dominance, scalar evolution
// CEP:HPC-PASS-LEGALITY: no side effects, no alias conflict, no control dependence change
// CEP:HPC-PASS-PRESERVES: semantics, memory order, exception behavior
// CEP:HPC-PASS-COST: 14 ms for 10k IR nodes on reference machine
// CEP:HPC-PASS-FAILURE: aborts transformation conservatively
// CEP:HPC-PASS-TARGET: target-independent
// CEP:HPC-PASS-EVIDENCE: bench HPC-113
// CEP:HPC-COMPILE-COST: 14 ms / 10k IR nodes
// CEP:HPC-COMPILE-MEM: 64 MB peak
// CEP:HPC-COMPLEXITY: O(N) expected
// CEP:HPC-DETERMINISM: deterministic; pass iterates stable IR order
```

---

## 38.58 HPC example: compliant JIT patchpoint

```cpp
// CEP:WHAT: Patches a direct call site to a validated runtime stub.
// CEP:WHY: Runtime specialization requires replacing a call target safely.
// CEP:STATUS: complete
// CEP:FAILURE: Returns PatchError::unsafe if instruction boundaries are invalid.
// CEP:ASSUMES: patchpoint is quiescent; no thread observes partial patch.
// CEP:COST: bounded patch latency; measured HPC-JIT-201.
// CEP:EVIDENCE: jit_patch_test_07, disassembly artifact jit-9921.
// CEP:SECURITY: target stub is validated; W^X enforced.
// CEP:HPC-CLASS: HPC-0
// CEP:HPC-JIT: runtime patching
// CEP:HPC-DETERMINISM: deterministic for same patchpoint state
// CEP:HPC-CODEGEN: direct call replacement with target-safe sequence
// CEP:HPC-CODEGEN-PROOF: golden disassembly jit_patch_07
```

---

## 38.59 HPC release qualification

A compiler release is HPC-qualified only if it provides:

1. language conformance report,
2. target matrix report,
3. implementation-defined behavior catalog,
4. pass pipeline manifest,
5. target cost model version,
6. profile schema version,
7. deterministic build evidence,
8. compile-time benchmark report,
9. code-quality benchmark report,
10. miscompilation regression suite,
11. fuzz report,
12. security threat model,
13. supply-chain manifest,
14. toolchain hashes,
15. known defect list,
16. waiver list,
17. extermination report summary.

If any required artifact is missing, the compiler release is not HPC-qualified.

---

## 38.60 Final HPC clause

An HPC compiler must prove itself before it is trusted to transform code.

If a compiler component cannot show:

- what it transforms,
- why the transformation is legal,
- what assumptions it uses,
- what target it assumes,
- what cost it imposes,
- what evidence supports it,
- how it fails,
- how it remains deterministic,
- how it remains secure,

then it is not HPC-compliant.

It must be repaired, quarantined, or exterminated.

---

# 39. Resource-Constrained Systems (RCS) Overview

This chapter extends CEP&CC for systems where resources are not merely limited, but are part of the correctness contract. A resource-constrained system is not compliant because it runs. It is compliant only if every resource is bounded, owned, measured, documented, monitored, and failure-handled.

This chapter applies whenever any of the following are true:
- RAM is limited,
- flash or ROM is limited,
- stack is limited,
- heap is absent or constrained,
- CPU time is budgeted,
- deadlines exist,
- WCET (Worst-Case Execution Time) matters,
- energy is budgeted,
- battery capacity is finite,
- thermal envelope is bounded,
- storage endurance is finite,
- I/O bandwidth is bounded,
- queue capacity is bounded,
- safe-state reachability is required,
- radiation tolerance is required,
- deterministic recovery is required.

Target domains include:
- spacecraft avionics,
- flight controllers,
- satellite subsystems,
- radiation-tolerant CPUs,
- industrial controllers,
- medical embedded controllers,
- automotive ECUs,
- bare-metal firmware,
- RTOS-based control systems,
- sensor nodes,
- motor controllers,
- power converters,
- battery-powered devices,
- safety-critical actuators,
- deterministic network endpoints,
- bootloaders,
- secure elements.

Where this chapter is stricter than the general CEP&CC rules, this chapter wins. Where this chapter is silent, the rest of CEP&CC applies.

---

## 39.1 RCS prime law

The RCS prime law is:

> No resource may be hidden, unbounded, unmeasured, or silently exhaustible.
> Every resource must have a budget, an owner, evidence, and a failure policy.
> Resource exhaustion is not a surprise condition. It must be predicted, prevented, detected, contained, and handled through a documented safe-state or degraded-mode transition.

This law has five binding clauses.

### 39.1.1 No hidden resource
Every resource consumer must be identifiable.
Banned:
- hidden allocation,
- hidden stack growth,
- hidden queue growth,
- hidden retry,
- hidden lock wait,
- hidden flash write,
- hidden log write,
- hidden peripheral access,
- hidden power-state transition,
- hidden thermal throttle,
- hidden cache maintenance,
- hidden DMA transfer.

If a resource consumer cannot be named, it is not allowed.

### 39.1.2 No unbounded resource
Every resource consumer must have a bound.
Banned:
- unbounded loops,
- unbounded recursion,
- unbounded retry,
- unbounded queue depth,
- unbounded log size,
- unbounded stack usage,
- unbounded heap usage,
- unbounded flash writes,
- unbounded blocking,
- unbounded ISR execution,
- unbounded interrupt disable time.

If a bound cannot be proven, the feature is not allowed in RCS-0.

### 39.1.3 No unmeasured resource
Every bounded resource must be measured or analyzed.
Required evidence:
- static analysis,
- high-water measurement,
- WCET analysis,
- utilization analysis,
- endurance estimate,
- energy measurement,
- thermal measurement,
- queue high-water measurement.

A budget without evidence is a wish, not a constraint.

### 39.1.4 No resource without an owner
Every resource region, pool, queue, task, interrupt, and fault must have an owner.
Owner means:
- a named component,
- a named module,
- a named team,
- a named review authority.

Unowned resources are defects.

### 39.1.5 No resource exhaustion without a failure policy
Every resource must define what happens when its budget is exhausted.
Allowed failure policies:
- return explicit error,
- drop non-critical item,
- enter degraded mode,
- enter safe state,
- reset subsystem,
- escalate fault,
- trigger watchdog.

Banned:
- silent continuation,
- undefined behavior,
- crash without diagnostics,
- partial artifact emission,
- hidden corruption.

Violations of the RCS prime law are Severity 0 in RCS-0 code.

---

## 39.2 RCS conformance classes

RCS defines three system classes.

### 39.2.1 RCS-0: Hard real-time or safety-critical constrained code
RCS-0 is the strictest class.
RCS-0 applies when any of the following are true:
- missing a deadline can cause hazard,
- resource exhaustion can cause unsafe behavior,
- power loss can cause unsafe behavior,
- storage corruption can cause unsafe behavior,
- watchdog failure can cause unsafe behavior,
- radiation upset can cause unsafe behavior,
- the system must enter a safe state on fault,
- the system is certifiable or safety-related,
- the system controls actuators,
- the system controls power delivery,
- the system controls propulsion,
- the system controls life-critical functions.

RCS-0 requirements:
- static allocation by default,
- no general-purpose heap after initialization,
- bounded stacks,
- bounded execution paths,
- WCET evidence,
- schedulability evidence,
- energy budget evidence,
- storage endurance evidence,
- explicit failure policy,
- explicit safe-state policy,
- watchdog policy,
- degraded-mode policy,
- recovery policy,
- deterministic I/O queue policy,
- fault table,
- fault injection evidence,
- memory protection where safety demands it.

RCS-0 code must not throw exceptions.
RCS-0 code must not panic.
RCS-0 code must not abort without a documented fault path.
RCS-0 code must not rely on operating-system convenience services unless those services are proven deterministic and bounded.

### 39.2.2 RCS-1: Soft real-time constrained code
RCS-1 applies to embedded or constrained systems where deadlines matter but are not safety-critical.
Examples:
- telemetry aggregators,
- user-interface controllers,
- data loggers,
- non-critical sensor hubs,
- diagnostics panels,
- non-safety gateways.

RCS-1 requirements:
- bounded memory,
- bounded CPU time,
- bounded queues,
- bounded retries,
- explicit timeout policy,
- explicit failure policy,
- measured or estimated WCET where practical,
- log quotas,
- storage budgets,
- watchdog where practical.

RCS-1 may use controlled dynamic allocation if the allocator is deterministic and documented.

### 39.2.3 RCS-2: Offline or support tooling for constrained systems
RCS-2 applies to:
- host tools,
- firmware generators,
- image builders,
- flash tools,
- telemetry analyzers,
- test harnesses,
- simulation tools,
- configuration generators,
- linker script generators,
- table generators.

RCS-2 is not runtime constrained code, but its outputs must not violate RCS rules.

---

## 39.3 Resource budget document

Every RCS project must maintain a resource budget.
The resource budget is a normative artifact.
It is not a comment. It is not a wiki page. It is a versioned, reviewed, enforced artifact.

### 39.3.1 Required budget categories
The resource budget must include:
- RAM regions,
- ROM/flash regions,
- static object sizes,
- stack budgets,
- heap pools,
- queue capacities,
- buffer sizes,
- CPU utilization,
- WCET budgets,
- ISR latency budgets,
- energy budgets,
- thermal thresholds,
- storage write budgets,
- log quotas,
- watchdog deadlines,
- timeout constants,
- safe-state requirements,
- recovery budgets,
- degraded-mode budgets.

### 39.3.2 Budget entry format
Each budget entry must include:
- name,
- unit,
- value,
- owner,
- source,
- evidence ID,
- margin,
- last verified date,
- verification method.

Example:
```text
name: control_pool
unit: bytes
value: 4096
owner: control-team
source: system configuration table v7
evidence: RCS-MEM-014
margin: 768 bytes
last_verified: 2026-09-10
method: static analysis + runtime high-water
```

---

# 40. RCS Memory and Allocation Policy

Memory is a first-class constrained resource.
RCS code must know:
- where every byte lives,
- who owns it,
- when it is initialized,
- when it is freed,
- how much margin remains,
- what happens on exhaustion,
- what happens on corruption,
- what happens on power loss.

---

## 40.1 RAM usage

All RAM usage must be classified.

### 40.1.1 Required RAM categories
- code resident in RAM,
- constants copied to RAM,
- static data,
- zero-initialized data,
- stacks,
- interrupt stacks,
- heap pools,
- DMA buffers,
- peripheral buffers,
- communication buffers,
- log buffers,
- diagnostic buffers,
- storage cache,
- filesystem buffers,
- scratch memory,
- secure memory,
- retention memory,
- ECC/parity overhead,
- MPU/MMU table memory,
- vector table memory.

### 40.1.2 RAM region contract
Every RAM region must have:
- name,
- size,
- owner,
- alignment,
- cacheability,
- initialization policy,
- access policy,
- high-water mark,
- margin,
- evidence,
- corruption policy,
- power-loss policy.

Unowned RAM is a defect.
Uninitialized RAM is a defect unless explicitly documented as scratch.

---

## 40.2 Static allocation

Static allocation is the default for RCS-0.

### 40.2.1 Allowed static allocation uses
- fixed control blocks,
- fixed task stacks,
- fixed message buffers,
- fixed I/O queues,
- fixed DMA descriptors,
- fixed lookup tables,
- fixed state machines,
- fixed log ring buffers,
- fixed configuration objects,
- fixed calibration tables,
- fixed fault records.

### 40.2.2 Static sizing rules
Static allocation must be sized by named constants.
Bad:
```cpp
ControlBlock blocks[64];
```
Good:
```cpp
ControlBlock blocks[cep::rcs::kMaxControlBlocks];
```
and:
```cpp
// CEP:WHAT: Maximum number of simultaneous control blocks.
// CEP:WHY: Derived from system configuration and actuator count.
// CEP:ASSUMES: kMaxControlBlocks matches hardware configuration table.
// CEP:EVIDENCE: config review RCS-CFG-007.
inline constexpr std::size_t kMaxControlBlocks = 12;
```

### 40.2.3 Static overflow rules
Static allocation must not silently exceed its region.
Required:
- static assertions on size,
- linker map analysis,
- region boundary checks,
- high-water instrumentation where practical.

Example:
```cpp
static_assert(
    sizeof(ControlBlock) * cep::rcs::kMaxControlBlocks
        <= cep::rcs::limit::control_pool_bytes,
    "control pool overflow");
```

---

## 40.3 Heap policy

General-purpose heap is banned in RCS-0 after initialization unless explicitly waived.

### 40.3.1 Allowed allocator types
If heap is used, it must be one of:
- fixed-size pool allocator,
- arena allocator,
- slab allocator,
- static buffer allocator,
- project-approved deterministic allocator.

### 40.3.2 Banned heap patterns in RCS-0
Banned:
- global `new` in control paths,
- global `delete` in control paths,
- `malloc` in control paths,
- `free` in control paths,
- `realloc`,
- unbounded container growth,
- exception-based allocation failure handling,
- hidden allocator callbacks,
- polymorphic allocators without review,
- `std::vector` growth in control paths,
- `std::string` growth in control paths,
- `std::function` capture allocation,
- `std::shared_ptr` control block allocation in hot paths,
- iostream allocation,
- formatting allocation.

---

## 40.4 Bounded stacks

Every thread, task, interrupt handler, and exception context must have a bounded stack.

### 40.4.1 Banned stack patterns in RCS-0
- no unbounded recursion,
- no direct recursion unless bounded and proven,
- no indirect recursion,
- no `alloca`,
- no variable-length arrays,
- no large automatic aggregates unless budgeted,
- no deep call chains without evidence,
- no exception unwind stacks,
- no coroutine heap frames,
- no hidden compiler-generated temporaries on the stack,
- no large by-value parameters,
- no large by-value returns,
- no formatted output on stack buffers without bound.

### 40.4.2 Stack overflow response
Stack overflow detection must not silently continue.
Allowed responses:
- safe-state transition,
- fatal fault,
- subsystem reset,
- watchdog escalation.

Banned:
- logging and continuing,
- ignoring overflow flag,
- resetting high-water mark without analysis.

---

# 41. RCS CPU, WCET, and Execution Paths

CPU time is a constrained resource.
RCS code must not merely be fast on average. It must be bounded in the worst case.
Average performance is irrelevant. Worst-case performance is the contract.

---

## 41.1 WCET requirement

Every RCS-0 task, control loop, interrupt handler, and time-critical function must have a WCET estimate.
WCET means worst-case execution time.

### 41.1.1 WCET evidence contents
WCET evidence must include:
- target CPU,
- target frequency,
- cache state,
- flash wait states,
- RAM/ROM placement,
- branch prediction state,
- interrupt exposure,
- preemption exposure,
- memory contention,
- peripheral latency,
- compiler version,
- compile flags,
- analysis method,
- measurement method,
- artifact ID,
- worst-case input,
- worst-case path.

### 41.1.2 WCET comment
WCET claims require:
```cpp
// CEP:RCS-WCET:
```
Example:
```cpp
// CEP:RCS-WCET: 210 us on leon3-gr712 at 200 MHz, worst-case I-cache miss,
// artifact RCS-WCET-014.
```

---

## 41.2 Bounded execution paths

All execution paths in RCS-0 must be bounded.

### 41.2.1 Banned unbounded patterns
- unbounded loops,
- unbounded recursion,
- unbounded retry loops,
- unbounded spin waits,
- unbounded search over dynamically growing data,
- unbounded queue traversal,
- unbounded linked-list traversal,
- unbounded tree traversal,
- unbounded dynamic dispatch chains,
- unbounded state machine cycles.

### 41.2.2 Retry policy
Every bounded retry policy must have:
- max attempts,
- delay policy,
- timeout policy,
- failure action,
- evidence.

Bad:
```cpp
while (!ready()) {
    retry();
}
```
Good:
```cpp
for (std::uint32_t attempt = 0; attempt < cep::rcs::limit::max_device_retries;
     ++attempt) {
    if (ready()) return std::expected<void, DeviceError>{};
    wait_one_tick();
}
return std::unexpected(DeviceError::timeout);
```

---

## 41.3 Interrupt latency

Interrupt latency must be bounded.

### 41.3.1 ISR rules
ISRs must be short and bounded.
ISRs must not:
- allocate,
- block,
- wait on locks,
- wait on queues without bounded timeout,
- perform filesystem operations,
- perform flash writes unless explicitly budgeted,
- perform formatting,
- perform logging beyond bounded trace buffers,
- perform long computation,
- perform recovery,
- perform network operations.

ISRs should:
- acknowledge hardware,
- capture minimal state,
- post to bounded queue,
- schedule deferred work,
- return.

### 41.3.2 Interrupt disable time
Interrupt disable time must be bounded.
Required:
- maximum disable time,
- named constant,
- evidence,
- review.

Banned:
- disabling interrupts around long operations,
- disabling interrupts around flash writes,
- disabling interrupts around formatting,
- disabling interrupts around allocation.

---

# 42. RCS Storage, Flash, and Persistence

Storage is not infinite, not infinitely fast, and not infinitely durable.
RCS storage must be bounded, predictable, corruption-aware, and power-loss-aware.

---

## 42.1 Bounded logs

Logs must be bounded.

### 42.1.1 Banned log patterns
- unbounded log files,
- unbounded fault histories,
- unbounded debug traces,
- unbounded telemetry buffers,
- logs that allocate without quota,
- logs that block control loops,
- logs that cause flash wear without budget,
- logs that contain secrets,
- logs that contain unbounded formatted strings.

### 42.1.2 Allowed log designs
- fixed ring buffer in RAM,
- selective persistence,
- severity-based throttling,
- fault-only persistent logs,
- circular fault history with fixed record count.

---

## 42.2 Flash wear management

Flash wear is a reliability constraint.
Every flash write must be justified.

### 42.2.1 Banned flash patterns
- writing logs every tick without budget,
- rewriting unchanged data,
- unbounded journal growth,
- unbalanced erase cycles,
- ignoring wear counters,
- ignoring bad-block detection,
- writing during hard real-time paths without budget.

### 42.2.2 Flash latency rules
Flash write operations in hard real-time paths must be budgeted.
If flash write latency can violate a deadline, the write must be deferred or partitioned.

---

## 42.3 Power-loss atomicity

Persistent writes must survive power loss.

### 42.3.1 Required properties
- writes are atomic or journaled,
- partially written records are detectable,
- old valid state remains reachable,
- commit points are explicit,
- rollback is possible,
- metadata consistency is validated at boot.

### 42.3.2 Banned power-loss patterns
- in-place multi-sector updates without journaling,
- assuming power will remain stable during write,
- writing configuration directly without commit marker,
- corrupting golden image during update.

---

# 43. RCS Power, Energy, and Thermal

Power is a correctness constraint.
A system that violates its energy budget may fail even if its code is functionally correct.

---

## 43.1 Sleep and wake behavior

Sleep states must be explicit.

### 43.1.1 Required sleep-state table
- state name,
- power draw,
- entry latency,
- exit latency,
- retained memory,
- lost state,
- wake sources,
- peripheral availability,
- clock behavior,
- interrupt behavior,
- brownout behavior,
- watchdog behavior,
- security behavior.

### 43.1.2 Banned sleep patterns
- hidden sleep state transitions,
- sleep entry with interrupts unsafely enabled,
- sleep entry with peripherals left in unsafe state,
- sleep entry with pending DMA,
- wake sources undocumented,
- wake latency omitted from deadline analysis.

---

## 43.2 Brownout and power rail behavior

The system must define behavior for:
- undervoltage,
- overvoltage,
- brownout,
- power rail droop,
- power-good loss,
- battery exhaustion,
- capacitor holdup exhaustion.

### 43.2.1 Power-fault safety
Power-fault handling must not rely on uninitialized memory.
Power-fault handling must not rely on heap.
Power-fault handling must be reachable from any state.

---

# 44. RCS I/O, DMA, and Peripherals

I/O is where resource constraints meet the physical world.
I/O must be bounded, timeout-aware, and failure-aware.

---

## 44.1 Bounded queues

Every queue must have a capacity.

### 44.1.1 Banned queue patterns
- unbounded queues,
- dynamically growing mailboxes,
- queues with no overflow policy,
- queues that block ISR without bounded timeout,
- queues that hide allocation,
- queues with no high-water tracking.

### 44.1.2 Queue overflow policy
Queue overflow policy must be one of:
- reject new item,
- drop newest,
- drop oldest,
- overwrite critical-safe item,
- escalate fault,
- apply backpressure.

The policy must be documented.

---

## 44.2 Timeout behavior

Every blocking I/O operation in RCS-1 and RCS-0 must have a timeout unless proven unnecessary.

### 44.2.1 Banned timeout patterns
- infinite waits in control paths,
- waits without timeout constants,
- timeouts hard-coded without rationale,
- timeouts that allow deadline violation,
- timeouts that hide hardware faults.

Good:
```cpp
// CEP:RCS-TIMEOUT: sensor read timeout 2 ms; retry 3 times; then sensor fault.
```
Bad:
```cpp
wait_forever();
```

---

## 44.3 DMA rules

DMA is powerful and dangerous.

### 44.3.1 DMA safety rules
DMA must not access memory outside its approved window.
DMA must not corrupt static data.
DMA must not introduce nondeterministic memory latency unless WCET includes it.
DMA must not be configured by untrusted input without validation.

---

# 45. RCS Concurrency and Interrupts

Concurrency must be bounded and analyzable.
RCS concurrency is not about throughput alone. It is about predictable, safe completion.

---

## 45.1 Deadlock analysis

Deadlocks must be prevented by design.

### 45.1.1 Banned deadlock patterns
- circular lock dependencies,
- unbounded lock nesting,
- lock acquisition in ISR,
- lock acquisition with interrupts disabled unless budgeted,
- recursive mutexes without proof,
- hidden lock acquisition through callbacks.

### 45.1.2 Lock-order table
If locks are used, the project must maintain a lock-order table.
Example:
```text
lock order:
1. system_state_lock
2. telemetry_lock
3. storage_lock
```
Any code acquiring locks out of order is a Severity 0 defect.

---

## 45.2 Priority inversion

Priority inversion must be bounded.

### 45.2.1 Banned priority inversion patterns
- unbounded priority inversion,
- priority donation cycles,
- priority inversion through long flash writes,
- priority inversion through I/O calls,
- priority inversion through logging.

---

# 46. RCS Failure, Watchdogs, and Safe States

RCS systems must assume failure.
Failure is not exceptional. It is part of the environment.

---

## 46.1 Watchdogs

Watchdogs are mandatory for RCS-0 unless explicitly waived with a safety argument.

### 46.1.1 Banned watchdog patterns
- blindly kicking the watchdog,
- kicking the watchdog inside a timer ISR without health validation,
- disabling the watchdog without review,
- extending watchdog timeout to hide deadline misses,
- allowing one failed component to keep the system alive falsely.

### 46.1.2 Good watchdog policy
```text
Kick watchdog only if:
- control loop completed within deadline,
- no fatal fault active,
- stack watermark valid,
- queue overflow counter below threshold,
- power state valid,
- storage health valid.
```

---

## 46.2 Safe-state transitions

Safe state is mandatory for RCS-0 systems that can cause hazard.

### 46.2.1 Safe-state reachability
Safe-state transitions must be reachable even if:
- control task missed deadline,
- watchdog expired,
- stack overflow detected,
- memory corruption detected,
- configuration invalid,
- sensor invalid,
- communication lost,
- power droop occurred,
- thermal limit exceeded.

Example:
```cpp
// CEP:RCS-SAFE-STATE: De-energize actuators within 5 ms of fatal fault.
// CEP:EVIDENCE: fault injection test RCS-FI-031.
```

---

# 47. RCS C++26 Language and Library Restrictions

This section defines how C++26 features apply to RCS environments.

---

## 47.1 `std::expected` in RCS
### Use
Use `std::expected` for recoverable errors in RCS-1.
In RCS-0, use `std::expected` only if:
- the error type is trivially destructible,
- the error type requires no allocation,
- the return value optimization (RVO) is guaranteed or measured,
- the unwrapping does not introduce hidden branches that violate WCET.
### When not to use
Do not use `std::expected` if the error payload contains `std::string` or `std::vector`.

---

## 47.2 `std::inplace_vector` in RCS
### Use
Use `std::inplace_vector` for bounded, stack-allocated dynamic sequences in RCS-0.
### Why
It provides vector-like semantics without heap allocation.
### Rules
- Capacity must be a named constant.
- Overflow behavior must be documented (e.g., `bad_alloc` equivalent or assert).
- Do not use it if the capacity exceeds the stack budget.

---

## 47.3 `std::mdspan` in RCS
### Use
Use `std::mdspan` for mapping hardware buffers, DMA regions, and memory-mapped I/O.
### Why
It provides bounds-checked, layout-aware access without allocation.
### When not to use
Do not use dynamic extents in RCS-0 if static extents can be proven.
Do not use complex layout policies that hide stride calculations in hot loops.

---

## 47.4 Coroutines in RCS
### Policy
Banned in RCS-0.
### Why
Coroutines inherently require heap allocation for the coroutine frame unless a custom, deterministic, bounded allocator is provided and proven. Even with custom allocators, the state machine resumption cost and hidden branches make WCET analysis extremely difficult.
### Allowed
Only in RCS-1 if the promise type, allocator, and resumption overhead are fully measured and bounded.

---

## 47.5 `std::print` and `std::format` in RCS
### Policy
Banned in RCS-0 and RCS-1 control paths.
### Why
Formatting allocates, locks, and performs I/O.
### Allowed
Only in RCS-2 tooling or cold diagnostic dumps where CPU and memory budgets are explicitly reserved.

---

# 48. RCS Comment Standard

RCS requires specific comment fields to document resource constraints.

---

## 48.1 Required RCS comment fields
```cpp
// CEP:RCS-CLASS:
// CEP:RCS-MEM:
// CEP:RCS-STACK:
// CEP:RCS-HEAP:
// CEP:RCS-WCET:
// CEP:RCS-SCHEDULE:
// CEP:RCS-FLASH:
// CEP:RCS-POWER:
// CEP:RCS-THERMAL:
// CEP:RCS-QUEUE:
// CEP:RCS-TIMEOUT:
// CEP:RCS-WATCHDOG:
// CEP:RCS-SAFE-STATE:
```

---

## 48.2 RCS comment example
```cpp
// CEP:FILE: hot/control/motor_control.cpp
// CEP:WHAT: Periodic motor control task for RCS-0 actuator loop.
// CEP:WHY: Maintains bounded, deterministic actuator response.
// CEP:CLASS: CEP-0, RCS-0
// CEP:STATUS: complete
// CEP:FAILURE: Returns ControlError on sensor timeout, queue overflow, or
//              safe-state request. No allocation. No throw.
// CEP:ASSUMES: sensor queue is bounded; actuator table is static.
// CEP:COST: WCET 210 us on leon3-gr712, artifact RCS-WCET-014.
// CEP:EVIDENCE: bench RCS-CTRL-011, fault injection RCS-FI-031.
// CEP:SECURITY: sensor input untrusted; range checked before use.
// CEP:RCS-CLASS: RCS-0
// CEP:RCS-MEM: static motor_pool only; no heap after boot.
// CEP:RCS-STACK: 1024 bytes budget; high-water 640 bytes; margin 384 bytes.
// CEP:RCS-WCET: 210 us worst-case, artifact RCS-WCET-014.
// CEP:RCS-SCHEDULE: 10 ms period; 8 ms deadline; max blocking 90 us.
// CEP:RCS-QUEUE: sensor queue depth 4; overflow rejects newest sample.
// CEP:RCS-TIMEOUT: sensor read timeout 2 ms; retry 3 times.
// CEP:RCS-WATCHDOG: contributes control heartbeat each successful period.
// CEP:RCS-SAFE-STATE: actuator de-energized within 5 ms on fatal fault.
```

---

# 49. RCS Review Checklist and Extermination

---

## 49.1 RCS Review Checklist

### Memory
- [ ] RAM regions documented.
- [ ] Static allocation used where required.
- [ ] Heap policy explicit.
- [ ] No hidden allocation.
- [ ] Stack budget documented.
- [ ] Stack high-water measured.
- [ ] Stack margin sufficient.
- [ ] Fragmentation analyzed if dynamic allocation exists.
- [ ] Memory protection configured where required.
- [ ] Linker map reviewed.

### CPU and scheduling
- [ ] WCET documented.
- [ ] Execution paths bounded.
- [ ] No unbounded loops.
- [ ] No unbounded retries.
- [ ] CPU budget documented.
- [ ] Schedulability evidence present.
- [ ] Interrupt latency bounded.
- [ ] Blocking time bounded.
- [ ] Priority inversion controlled.
- [ ] Task table updated.

### Storage
- [ ] Persistent data bounded.
- [ ] Logs bounded.
- [ ] Flash wear budget documented.
- [ ] Corruption detection present.
- [ ] Power-loss recovery tested.
- [ ] Rollback path documented.
- [ ] Update failure path tested.

### Failure
- [ ] Fault table updated.
- [ ] Watchdog policy valid.
- [ ] Degraded mode documented.
- [ ] Recovery path documented.
- [ ] Safe-state transition tested.
- [ ] Fault injection evidence present.

---

## 49.2 RCS Extermination Examples

### Example 1: Hidden allocation in control loop
Violation:
```cpp
void control_tick() {
    auto buffer = std::vector<std::uint8_t>(256);
    ...
}
```
Response:
```text
EXTERMINATE
Reason: heap allocation in RCS-0 control loop.
Rule: CEP&CC 40.3
Action: replace with static buffer or pool.
```

### Example 2: Unbounded retry
Violation:
```cpp
while (!sensor_ready()) {
    wait();
}
```
Response:
```text
EXTERMINATE
Reason: unbounded retry loop in RCS-0.
Rule: CEP&CC 41.2
Action: bound retries and add timeout fault path.
```

### Example 3: Blind watchdog kick
Violation:
```cpp
void timer_isr() {
    kick_watchdog();
}
```
Response:
```text
EXTERMINATE
Reason: watchdog kicked without health validation.
Rule: CEP&CC 46.1
Action: gate kick on health checks.
```

### Example 4: In-place config update
Violation:
```cpp
write_config_in_place(new_config);
```
Response:
```text
EXTERMINATE
Reason: persistent write without power-loss atomicity.
Rule: CEP&CC 42.3
Action: use A/B or journaled write.
```

### Example 5: Lock acquired in ISR
Violation:
```cpp
void isr() {
    std::lock_guard lock(state_mutex);
    ...
}
```
Response:
```text
EXTERMINATE
Reason: lock acquisition in ISR.
Rule: CEP&CC 41.3 / 45.1
Action: post to bounded queue; defer locking.
```

---

# 50. Mechanical enforcement: cep_lint

This chapter is normative.

CEP&CC requires mechanical enforcement (section 16) and reserves `.cep/` for lint configuration (section 32.1). This chapter defines the repository's enforcement tool, its rule catalog, and the contract that keeps this document synchronized with the lint configuration.

The tool is `tools/cep_lint`:

- written in C++26, compiled with the minimum warning set of section 6.3 with warnings as errors,
- classified CEP-2 (offline tooling, section 5.3),
- itself subject to CEP&CC: its own source must lint to zero severity-0 and severity-1 violations before every change (the self-lint gate),
- driven entirely by data: every pattern, threshold, severity, message, and option lives in `.cep/cep_lint.json`; the engine contains mechanism only.

The linter does not negotiate with non-compliant code (section 37). It exits non-zero when any severity-0 or severity-1 finding exists, or when the rule catalog below drifts out of sync with this document.

---

## 50.1 Invocation

```text
tools/cep_lint/build/cep_lint [options] <files or directories>
```

Options (defined in configuration, not code):

- `--config, -c <path>`: lint configuration JSON. Default: `.cep/cep_lint.json`. Environment override: `CEP_LINT_CONFIG`.
- `--self-test, -t`: run the self-test manifest (`tools/cep_lint/tests/manifest.json`) and exit.
- `--help, -h`: show usage.
- `--version, -v`: print tool and standard versions.

Exit codes (configuration data):

| Code | Meaning |
|---|---|
| 0 | No failing findings. |
| 1 | Findings at a severity listed in `fail_on` (default: severity 0 and 1), or a failed self-test scenario. |
| 2 | Bootstrap failure before or during configuration, scan, or document loading (coded `CEP-LINT-BOOT-<n>`, see 50.5). |
| 3 | Command-line usage error. |

Determinism: directory traversal is sorted, issues are sorted by file, line, rule, and message, and no output depends on locale, time, environment, or iteration order (sections 6.5 and 38.10).

---

## 50.2 Severity mapping

Lint severities are the violation classes of section 34.2:

| Lint severity | Class | Default response |
|---|---|---|
| 0 | Exterminate immediately | Exit 1; block merge |
| 1 | Exterminate unless emergency waiver | Exit 1; block merge |
| 2 | Reject and request repair | Reported; exit 0 unless `fail_on` is widened |
| 3 | Warn and educate | Reported only |

Waivers, when introduced, must follow section 34.7 (written, temporary, expiring) and live in `.cep/waivers/`.

---

## 50.3 Rule catalog

Every rule below is a key in `.cep/cep_lint.json` under `rules` and must have a `### Rule` heading in this chapter. The `CEP-LINT-DOC-SYNC` rule enforces this contract mechanically: a rule without a section here is a lint failure, and a documented rule without configuration is a lint failure (Law 8: no stale documentation).

### Rule CEP-LINT-FILE-HEADER

**Severity 1. Sections: 35, 10.2. Check: `comment_block_schema` (file header mode).**

Every first-party `.cpp` and `.hpp` file must begin with a CEP file header block containing `CEP:FILE`, `CEP:WHAT`, `CEP:WHY`, `CEP:CLASS`, `CEP:STATUS`, `CEP:FAILURE`, `CEP:ASSUMES`, `CEP:COST`, and `CEP:EVIDENCE`. The declared class must be one of the defined conformance classes (`CEP-0`, `CEP-1`, `CEP-2`, `CC`, `FFI`, `HPC-0`, `HPC-1`, `HPC-2`, `RCS-0`, `RCS-1`, `RCS-2`).

Parameters: `max_start_line`, `required_fields`, `class_field`, `allowed_classes`.

Limits: the header is the first contiguous full-line comment block; content above it (license text, shebang) is a violation by design.

### Rule CEP-LINT-FUNC-BLOCK

**Severity 1. Sections: 10.2, 10.3 through 10.9. Check: `function_policy` (block mode).**

Every function definition whose body contains at least `min_body_statements` statements (default 2) must have a preceding CEP comment block containing `CEP:WHAT`, `CEP:WHY`, `CEP:STATUS`, `CEP:FAILURE`, `CEP:ASSUMES`, `CEP:COST`, and `CEP:EVIDENCE`. Between the block and the definition only punctuation-free lines (attributes, template headers, trailing declarations) are allowed.

Parameters: `required_fields`, `min_body_statements`, `gap_pattern`, `require_block_for_lambdas`.

Limits: "nontrivial" is approximated mechanically as two or more statements; trivial one-statement accessors rely on their enclosing block. File header blocks are never accepted as function blocks. Lambdas are exempt unless `require_block_for_lambdas` is set; document nontrivial lambdas in the enclosing function's block. Definitions with default arguments in the parameter list are not recognized by the extractor.

### Rule CEP-LINT-STATUS-VALUE

**Severity 2. Section: 10.5. Check: `comment_block_schema` (status value mode).**

Every `CEP:STATUS` value must be one of `complete`, `partial`, `stub`, `placeholder`.

Parameters: `status_field`, `allowed_values`.

### Rule CEP-LINT-TODO-OWNER

**Severity 1. Section: 10.10. Check: `comment_regex` (line scoped).**

The markers `TODO`, `FIXME`, `XXX`, and `HACK` (case-insensitive) are violations unless written in the sanctioned form `CEP:TODO(owner): CEP-<ticket>: text`. Anonymous work markers are banned.

Parameters: `pattern`, `icase`, `suppression_pattern`.

### Rule CEP-LINT-STUB-DECL

**Severity 1. Sections: 10.5, 10.10. Check: `comment_block_schema` (stub requirements mode).**

Any comment block declaring `CEP:STATUS: stub`, `partial`, or `placeholder` must contain `CEP:OWNER` and `CEP:TICKET` in the same block. Unowned stubs and placeholders are banned.

Parameters: `status_field`, `statuses`, `required_fields`.

### Rule CEP-LINT-PLACEHOLDER-COMMENT

**Severity 1. Sections: 3, 10.5. Check: `comment_regex` (line scoped).**

Marker text (`not implemented`, `unimplemented`, `placeholder`, `fixme`, `tbd`, `wip`, case-insensitive) in comments is a violation unless the line is a `CEP:` field line (declared status is the sanctioned form).

Parameters: `pattern`, `icase`, `suppression_pattern`.

### Rule CEP-LINT-PLACEHOLDER-TEXT

**Severity 1. Sections: 3, 10.5. Check: `string_literal_regex`.**

Marker text in string literals is a violation. Placeholders must fail loudly (section 19), not leak into runtime messages.

Parameters: `pattern`, `icase`.

### Rule CEP-LINT-MAGIC-NUMBER

**Severity 2. Sections: Law 7, 11.1 through 11.3, 33.15. Check: `numeric_literal_policy`.**

Numeric literals other than the allow-list (default: 0 and 1) are violations unless the enclosing statement is a sanctioned form: a `constexpr` or `const` declaration, an `enum`, a `static_assert`, or a preprocessor line. Sanctioned constants must still follow the constant handling rules of section 11.2.

Parameters: `allowed_values`, `exempt_contexts`.

Limits: the exemption context is the joined statement text, bounded to twelve lines, stopping at statement boundaries; literals split from their declaration across many lines rely on review. Value comparison is numeric, so `0x0` equals `0`.

### Rule CEP-LINT-MACRO-PREFIX

**Severity 2. Sections: 33.16, 8.4. Check: `macro_prefix_policy`.**

Object-like macro names must match the `CEP_` prefix pattern or the include-guard pattern. All other macro definitions are violations.

Parameters: `name_pattern`, `guard_pattern`.

Limits: function-like macro logic is banned by section 8.4 but is not yet detected mechanically; review remains required.

### Rule CEP-LINT-HOT-BANNED

**Severity 0. Sections: 5.1, 8.25 through 8.29, 9.2 through 9.41, 40.3. Check: `banned_token_policy`.**

In files whose declared `CEP:CLASS` is `CEP-0`, `HPC-0`, or `RCS-0`, the following tokens are exterminated on sight: `new`, `delete`, `throw`, `try`, `catch`, `dynamic_cast`, `typeid`, `virtual`, coroutine keywords, `std::function`, `std::any`, `std::shared_ptr`, `std::weak_ptr`, `std::bind`, `std::regex`, `std::format`, `std::print`, `std::println`, stream objects, `std::filesystem`, synchronization primitives, `std::thread`, `std::async`, `std::sort`, `std::stable_sort`, C I/O and allocation functions, and the allocating containers `std::vector`, `std::string`, `std::list`, `std::map`, `std::set`, and their unordered variants.

Parameters: `applies_to_classes`, `class_field`, `tokens`.

Limits: tokens are matched in code after comment and string removal, so banned names inside comments or messages are not violations. Legitimate hot-path use requires an emergency waiver (section 34.7).

### Rule CEP-LINT-STUB-BODY

**Severity 1. Sections: 10.5, 19, 20. Check: `function_policy` (stub body mode).**

A function definition with an empty body is a violation unless its associated comment block declares `CEP:STATUS: stub`, `partial`, or `placeholder` (which then requires `CEP:OWNER` and `CEP:TICKET` per `CEP-LINT-STUB-DECL`). Empty special member functions should use `= default` or `= delete`.

Parameters: `suppress_statuses`, `suppress_status_field`.

Limits: immediately-invoked lambdas inside expressions are not recognized by the extractor and rely on review.

### Rule CEP-LINT-EMPTY-CATCH

**Severity 1. Sections: Law 6, 12.2. Check: `flat_code_regex`.**

A `catch` handler with an empty body is a violation. Handle the failure or propagate it.

Parameters: `pattern`.

### Rule CEP-LINT-EMPTY-BRANCH

**Severity 2. Section: 14.5. Check: `flat_code_regex`.**

`if`, `else`, `for`, `while`, `do`, `switch`, and `try` guarding an empty block is a violation: the branch does nothing.

Parameters: `pattern`.

### Rule CEP-LINT-CONSTANT-RETURN

**Severity 2. Section: 14.5. Check: `function_policy` (constant return mode).**

A function whose body is a single `return true;`, `return false;`, or `return nullptr;` statement is a violation: the result is not computed from inputs.

Parameters: `pattern`.

Limits: guard clauses inside larger bodies are not violations by design; `return 0;` and `return 1;` are conventional exit codes and are not flagged.

### Rule CEP-LINT-NAMING-TYPE

**Severity 2. Section: 33.11. Check: `flat_code_regex` with name validation.**

Type names introduced by `struct`, `class`, `enum class`, `enum struct`, and `using` must be PascalCase without underscores.

Parameters: `pattern`, `line_group`, `name_pattern`.

Limits: template parameters and concept names are not checked; the standard already requires PascalCase (33.17) and review covers them.

### Rule CEP-LINT-NAMING-FUNC

**Severity 2. Section: 33.13. Check: `function_policy` (naming mode).**

Function names must be snake_case. Destructors, operators, and lambdas are exempt from this check.

Parameters: `name_pattern`.

Limits: same extractor limits as `CEP-LINT-FUNC-BLOCK`.

### Rule CEP-LINT-COMMENTED-CODE

**Severity 2. Section: 10.14. Check: `comment_regex` (line scoped).**

Comment lines that parse as code statements (keyword-led statements ending in a terminator, assignments, calls, or preprocessor directives) are violations. Use version control.

Parameters: `pattern`, `suppression_pattern`.

Limits: prose comments that merely mention code words are not flagged unless they end with a terminator character; keep comment lines terminated with prose punctuation.

### Rule CEP-LINT-DOC-SYNC

**Severity 1. Sections: Law 8, 16, 34.3. Check: `doc_rule_coverage`.**

This document and the lint configuration must agree: every configured rule must have a `### Rule` heading in this chapter, every documented rule must exist in the configuration, rule headings must be unique, and the document's `Version:` line must equal the configuration's `standard.version`. Any drift is a lint failure, which is the mechanical enforcement of Law 8 for this tool.

Parameters: `doc_path`, `heading_pattern`, `version_pattern`.

---

## 50.4 Bootstrap error codes

Failures that occur before message templates are loaded print `CEP-LINT-BOOT-<n>` with a detail string:

| Code | Meaning |
|---|---|
| 1 | File I/O failure: unreadable configuration, include, manifest, target, or standard document. |
| 2 | JSON parse failure with file, line, and column. |
| 3 | Include cycle or excessive include depth in layered configurations. |
| 4 | Missing key: configuration schema violation or missing message template. |
| 5 | Wrong type for a key or element. |
| 6 | Unknown check primitive name. |
| 7 | Severity out of the 0 through 3 range. |
| 8 | Invalid regular expression in any pattern parameter. |

---

## 50.5 Known limits

Mechanical enforcement is lexical and structural, not semantic. The following require review, sanitizers, benchmarks, and the CI gates of sections 16 and 34.3:

- allocation and cost behavior beyond token bans (section 13 evidence),
- ignored return values and `[[nodiscard]]` discipline (8.20),
- constant naming style: section 6.2's feature-gate constants (`cep_has_modules`) conflict with section 33.15's `kPascalCase` rule; the linter deliberately does not check constant names until the standard resolves the conflict,
- macro-generated control flow (8.4),
- target-specific code outside target directories (32.5),
- optimality claims and evidence (23).

---

## 50.6 Self-verification gate

A change to the tool, the configuration, or this chapter is compliant only if all of the following pass:

1. `tools/cep_lint/build.sh` compiles with the section 6.3 warning set and `-Werror`.
2. `cep_lint tools/cep_lint/src` reports zero severity-0 and severity-1 findings (the self-lint gate required by section 16).
3. `cep_lint --self-test` passes every scenario in `tools/cep_lint/tests/manifest.json`, including exact expected violation counts per rule.
4. A sanitizer build (`MODE=asan`) passes the self-test clean (section 6.6).
5. `CEP-LINT-DOC-SYNC` passes, proving this chapter and `.cep/cep_lint.json` agree.

Adding or changing a rule requires updating the configuration and this chapter in the same change; the tool refuses the split.
