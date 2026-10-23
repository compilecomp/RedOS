theory Mem
  imports Main
begin

section \<open>Memory physics (twin of kernel/src/mm/phys.rs)\<close>

text \<open>
  The Ephemeral Page Allocator is modeled as a total function over an
  explicit command language: the allocator performs exactly the commands
  of \<^bold>\<open>alloc_cmd\<close> -- allocation and free -- and nothing else. Three
  guarantees are proved sorry-free:

  \<^item> \<open>wipe_before_reuse\<close> -- a frame granted by an allocation was wiped
    since its last occupant (the guard demands it); no allocation can
    expose a previous occupant's bytes.
  \<^item> \<open>locked_stable\<close> / \<open>locked_never_reused\<close> -- a locked frame (Key
    Material / FHE State, the mlock mandate) keeps its class under every
    command and can never re-enter the free pool.
  \<^item> \<open>anti_swap\<close> -- the allocator's I/O alphabet contains no storage
    event: the I/O function is total over the closed command type and
    every constructor maps to a RAM event. (The kernel-level complement:
    no block-device driver is linked; @{text phys::anti_swap_audit}
    refuses to boot if one ever appears -- together, RAM-only keys stay
    in RAM.)
\<close>

datatype fclass = FFree | FGeneral | FLocked | FShared | FReserved

type_synonym fid = nat

record pool =
  pcls   :: "fid \<Rightarrow> fclass"     \<comment> \<open>per-frame class\<close>
  pwiped :: "fid set"            \<comment> \<open>wiped since last occupant\<close>

subsection \<open>The allocator command language (closed model)\<close>

datatype alloc_cmd =
  AAlloc fid fclass    \<comment> \<open>grant a frame with a class\<close>
| AFree fid            \<comment> \<open>wipe + release a frame\<close>

text \<open>The I/O alphabet. Closed-world: @{text io_of} is total over
      \<^bold>\<open>alloc_cmd\<close> and has exactly two cases -- both RAM. A storage
      write is not expressible.\<close>

datatype io_ev = IoRam | IoStorage fid

fun io_of :: "alloc_cmd \<Rightarrow> io_ev" where
  "io_of (AAlloc _ _) = IoRam"
| "io_of (AFree _) = IoRam"

subsection \<open>The allocator transition (total, deterministic, guarded)\<close>

text \<open>Allocation demands a wiped Free frame; free demands General or
      Shared and records the wipe BEFORE the frame re-enters the pool --
      the exact order of phys.rs @{text free} (wipe_noise, zero, mark
      Free). Malformed commands are refused (state unchanged): the named
      errors of the Rust implementation.\<close>

fun epool :: "pool \<Rightarrow> alloc_cmd \<Rightarrow> pool" where
  "epool p (AAlloc f c) =
     (if pcls p f = FFree \<and> f \<in> pwiped p \<and> c \<noteq> FFree \<and> c \<noteq> FReserved
      then p\<lparr> pcls := (pcls p)(f := c) \<rparr>
      else p)"
| "epool p (AFree f) =
     (if pcls p f = FGeneral \<or> pcls p f = FShared
      then p\<lparr> pcls := (pcls p)(f := FFree),
              pwiped := pwiped p \<union> {f} \<rparr>
      else p)"

fun epools :: "pool \<Rightarrow> alloc_cmd list \<Rightarrow> pool" where
  "epools p [] = p"
| "epools p (c # cs) = epools (epool p c) cs"

subsection \<open>The pool invariant and wipe-before-reuse\<close>

definition pool_inv :: "pool \<Rightarrow> bool" where
  "pool_inv p \<equiv> \<forall>f. pcls p f = FFree \<longrightarrow> f \<in> pwiped p"

lemma epool_preserves_inv:
  assumes "pool_inv p"
  shows "pool_inv (epool p c)"
  using assms by (cases c) (auto simp: pool_inv_def)

lemma epools_preserve_inv:
  assumes "pool_inv p0"
  shows "pool_inv (epools p0 cs)"
  using assms by (induct cs arbitrary: p0) (auto intro: epool_preserves_inv)

text \<open>THEOREM (wipe before reuse): a frame granted by an allocation has
      been wiped since its last occupant. The content half of the
      protocol (the noise is genuinely unrelated to the old pattern) is
      enforced empirically by the boot test's 256-window sweep; this
      theorem is the structural half.\<close>

theorem wipe_before_reuse:
  assumes changed: "pcls (epool p (AAlloc f c)) \<noteq> pcls p"
  shows "f \<in> pwiped p"
proof -
  have guard: "pcls p f = FFree \<and> f \<in> pwiped p \<and> c \<noteq> FFree \<and> c \<noteq> FReserved"
    using changed by (cases c) (auto split: if_splits)
  then show ?thesis by blast
qed

text \<open>Corollary: allocations from a pool satisfying the invariant never
      expose a stale occupant, because the granted frame was wiped.\<close>

theorem alloc_no_stale_occupant:
  assumes inv: "pool_inv p"
    and granted: "pcls (epool p (AAlloc f c)) \<noteq> pcls p"
  shows "f \<in> pwiped p"
  using wipe_before_reuse[OF granted] .

subsection \<open>The mlock mandate\<close>

text \<open>A locked frame is untouched by every command: allocation demands a
      Free frame, free demands General or Shared -- FLocked satisfies
      neither guard, so its class is stable.\<close>

theorem locked_stable:
  assumes lk: "pcls p f = FLocked"
  shows "pcls (epool p c) f = FLocked"
  using lk by (cases c) auto

theorem locked_never_reused:
  assumes lk: "pcls p0 f = FLocked"
  shows "pcls (epools p0 cs) f \<noteq> FFree"
  using lk by (induct cs arbitrary: p0) (auto simp: locked_stable)

theorem locked_forever:
  assumes lk: "pcls p0 f = FLocked"
  shows "pcls (epools p0 cs) f = FLocked"
  using lk by (induct cs arbitrary: p0) (auto simp: locked_stable)

subsection \<open>Anti-swap (closed-world I/O argument)\<close>

text \<open>THEOREM (anti-swap): every allocator command emits a RAM event.
      Since the command type is closed and the I/O function is total,
      no execution of the allocator -- of any length -- can produce a
      storage write.\<close>

theorem anti_swap:
  "\<forall>c. io_of c = IoRam"
  by (cases) simp

theorem anti_swap_seq:
  "\<forall>c \<in> set cs. io_of c = IoRam"
  by (induct cs) auto

subsection \<open>Free implies wiped (the test's structural half)\<close>

text \<open>Every frame released by a free command is recorded as wiped -- the
      boot test's 256-window sweep checks the CONTENT half (noise
      quality).\<close>

theorem free_marks_wiped:
  assumes changed: "pcls (epool p (AFree f)) \<noteq> pcls p"
  shows "f \<in> pwiped (epool p (AFree f))"
proof -
  have guard: "pcls p f = FGeneral \<or> pcls p f = FShared"
    using changed by (cases "pcls p f = FGeneral \<or> pcls p f = FShared")
      (auto split: if_splits)
  then show ?thesis by auto
qed

end
