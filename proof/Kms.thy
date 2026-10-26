theory Kms
  imports Main
begin

section \<open>RAM-only KMS vault (twin of kernel/src/kms.rs)\<close>

text \<open>
  The vault is modeled as a total, deterministic transition system over
  an explicit command language. Guarantees proved sorry-free, mirroring
  the v0.6.0 exit criteria:

  \<^item> \<open>attempts_monotone\<close> -- the wrong-PIN counter never decreases, not
    even across a successful unlock (documented policy: a boot is the
    vault's lifetime).
  \<^item> \<open>duress_destroys\<close> / \<open>dead_terminal\<close> -- the attempt that reaches
    the budget destroys the vault (keys absent, leases inactive), and
    \<^bold>\<open>no command whatsoever\<close> brings it back: Dead is terminal, so
    every later operation fails closed.
  \<^item> \<open>lease_expiry_wipes\<close> + \<open>no_grant_no_serve\<close> -- a use at or after
    the expiry tick deactivates the lease and wipes its key; without an
    explicit re-grant it never serves again, and every (ttl-guarded)
    re-grant sets a strictly-future expiry.
  \<^item> \<open>no_key_use_outside_unlock\<close> -- disk I/O and lease use succeed
    only in the Unlocked state: sealed (before unlock) and dead (after
    duress) both refuse. The QEMU scenario asserts the empirical half
    (the VaultDead error after the duress banner).

  v0.7.0 additions: the entropy policy (\<open>rng_admits\<close>) and the terminal
  \<open>VRefused\<close> state -- a vault sealed under a Strict RNG policy with
  non-RDRAND entropy never generates a master key at all; it refuses
  every command exactly like a dead vault (\<open>refused_terminal\<close>,
  \<open>refused_never_serves\<close>), and no command can ENTER the state (it is
  an initial-state-only outcome of init, never of a transition).

  Model simplifications are recorded in proof/TODO.md (items 9--13 and
  17); the load-bearing one is that PIN correctness is an authenticated
  unwrap (GCM tag under the Argon2id KEK), so a ``correct PIN'' command
  is by construction the only command that can move Sealed to Unlocked.
\<close>

subsection \<open>States and commands\<close>

datatype vstate = VSealed | VUnlocked | VWiping | VDead | VRefused

datatype kms_cmd =
  KUnlock bool           \<comment> \<open>attempt unlock; True = correct PIN\<close>
| KGrant nat nat         \<comment> \<open>grant lease id with ttl (ticks; ttl > 0)\<close>
| KUse nat               \<comment> \<open>use lease id (lazy expiry check)\<close>
| KDiskRead              \<comment> \<open>XTS RAM-disk read (consumes derived key)\<close>
| KDiskWrite             \<comment> \<open>XTS RAM-disk write (consumes derived key)\<close>
| KTick                  \<comment> \<open>scheduler context switch (the only clock)\<close>

record vault =
  vst    :: vstate
  vatt   :: nat                  \<comment> \<open>attempts consumed (monotone)\<close>
  vtick  :: nat                  \<comment> \<open>scheduler ticks (monotone)\<close>
  vkeys  :: bool                 \<comment> \<open>key material resident (master live)\<close>
  vlact  :: "nat \<Rightarrow> bool"        \<comment> \<open>lease id active?\<close>
  vlkey  :: "nat \<Rightarrow> bool"        \<comment> \<open>lease key resident?\<close>
  vlexp  :: "nat \<Rightarrow> nat"         \<comment> \<open>lease expiry tick (meaningful if active)\<close>

definition BUDGET :: nat where
  "BUDGET = 3"   \<comment> \<open>MAX_ATTEMPTS in kms.rs\<close>

subsection \<open>The transition (total, deterministic, guarded)\<close>

text \<open>Malformed commands leave the vault unchanged -- the named errors
      of the Rust implementation (KmsError/UnlockError). The budget
      check precedes everything: the counter-satisfying attempt never
      runs the crypto, whatever PIN it carries (kms.rs unlock ordering).
      VWiping is a guard state only (the implementation's transient
      duress marker); no command targets it, and it refuses like Dead.\<close>

fun ev :: "vault \<Rightarrow> kms_cmd \<Rightarrow> vault" where
  "ev v (KUnlock pin) =
     (if vst v = VDead \<or> vst v = VWiping \<or> vst v = VRefused then v
      else if vatt v + 1 \<ge> BUDGET
      then v\<lparr> vst := VDead, vkeys := False,
              vlact := (\<lambda>_. False), vlkey := (\<lambda>_. False) \<rparr>
      else if vst v = VUnlocked then v\<lparr> vatt := vatt v + 1 \<rparr>
      else if pin
      then v\<lparr> vst := VUnlocked, vatt := vatt v + 1, vkeys := True \<rparr>
      else v\<lparr> vatt := vatt v + 1 \<rparr>)"
| "ev v (KGrant i t) =
     (if vst v = VUnlocked \<and> t > 0
      then v\<lparr> vlact := (vlact v)(i := True),
              vlkey := (vlkey v)(i := True),
              vlexp := (vlexp v)(i := vtick v + t) \<rparr>
      else v)"
| "ev v (KUse i) =
     (if vst v = VUnlocked \<and> vlact v i \<and> vlexp v i \<le> vtick v
      then v\<lparr> vlact := (vlact v)(i := False),
              vlkey := (vlkey v)(i := False) \<rparr>
      else v)"
| "ev v KTick = v\<lparr> vtick := vtick v + 1 \<rparr>"
| "ev v _ = v"   \<comment> \<open>disk I/O is not a state change (outcome below)\<close>

fun evs :: "vault \<Rightarrow> kms_cmd list \<Rightarrow> vault" where
  "evs v [] = v"
| "evs v (c # cs) = evs (ev v c) cs"

subsection \<open>Command outcomes (the fail-closed surface)\<close>

text \<open>Whether a command SUCCEEDS in the given (pre-transition) state.
      Disk I/O and lease use are the key-consuming operations: they are
      refused outside Unlocked, and expired leases refuse their key.\<close>

fun ok :: "vault \<Rightarrow> kms_cmd \<Rightarrow> bool" where
  "ok v (KUse i) = (vst v = VUnlocked \<and> vlact v i \<and> vtick v < vlexp v i)"
| "ok v KDiskRead  = (vst v = VUnlocked \<and> vkeys v)"
| "ok v KDiskWrite = (vst v = VUnlocked \<and> vkeys v)"
| "ok v (KUnlock _) = (vst v \<noteq> VDead \<and> vst v \<noteq> VWiping \<and> vst v \<noteq> VRefused)"
| "ok v (KGrant _ _) = (vst v = VUnlocked)"
| "ok v KTick = True"

subsection \<open>Invariants (reachability discipline)\<close>

text \<open>Two structural invariants hold along every transition:
      \<^item> \<open>dead_inv\<close> -- a dead vault carries no key material and no
        live lease (so terminality arguments below need reachability,
        not blind faith in record literals);
      \<^item> \<open>key_inv\<close> -- resident keys imply the Unlocked state (keys are
        installed only by a successful unlock and removed by duress).\<close>

definition dead_inv :: "vault \<Rightarrow> bool" where
  "dead_inv v \<equiv> vst v = VDead \<longrightarrow>
     (\<not> vkeys v \<and> (\<forall>i. \<not> vlact v i \<and> \<not> vlkey v i))"

definition key_inv :: "vault \<Rightarrow> bool" where
  "key_inv v \<equiv> vkeys v \<longrightarrow> vst v = VUnlocked"

theorem ev_preserves_dead_inv:
  assumes "dead_inv v"
  shows "dead_inv (ev v c)"
  using assms by (cases c) (auto simp: dead_inv_def BUDGET_def
    split: vstate.splits)

theorem evs_preserves_dead_inv:
  assumes "dead_inv v"
  shows "dead_inv (evs v cs)"
  using assms by (induct cs arbitrary: v)
    (auto intro: ev_preserves_dead_inv)

theorem ev_preserves_key_inv:
  assumes "key_inv v"
  shows "key_inv (ev v c)"
  using assms by (cases c) (auto simp: key_inv_def BUDGET_def
    split: vstate.splits if_splits)

theorem evs_preserves_key_inv:
  assumes "key_inv v"
  shows "key_inv (evs v cs)"
  using assms by (induct cs arbitrary: v)
    (auto intro: ev_preserves_key_inv)

subsection \<open>Monotonicity\<close>

theorem attempts_monotone:
  "vatt (ev v c) \<ge> vatt v"
  by (cases c; simp add: BUDGET_def split: vstate.splits)

theorem attempts_monotone_seq:
  "vatt (evs v cs) \<ge> vatt v"
  by (induct cs arbitrary: v) (auto intro: le_trans attempts_monotone)

theorem ticks_monotone:
  "vtick (ev v c) \<ge> vtick v"
  by (cases c) auto

theorem ticks_monotone_seq:
  "vtick (evs v cs) \<ge> vtick v"
  by (induct cs arbitrary: v) (auto intro: le_trans ticks_monotone)

subsection \<open>Duress: the budget destroys the vault, and Dead is terminal\<close>

text \<open>THEOREM (duress destroys): the budget-satisfying unlock attempt
      wipes the key material and every lease, regardless of the PIN it
      carries and regardless of which live state it hits. This is the
      roadmap exit criterion ``wrong-PIN counter destroys the vault''.\<close>

theorem duress_destroys:
  assumes live: "vst v = VSealed \<or> vst v = VUnlocked"
    and budget: "vatt v + 1 \<ge> BUDGET"
  shows "vst (ev v (KUnlock pin)) = VDead
     \<and> \<not> vkeys (ev v (KUnlock pin))
     \<and> \<not> vlact (ev v (KUnlock pin)) i
     \<and> \<not> vlkey (ev v (KUnlock pin)) i"
  using live budget by (cases "vst v"; auto simp: BUDGET_def
    split: vstate.splits)

text \<open>Terminality, in three mechanical steps: the state never leaves
      VDead; the key material never comes back; the counter freezes.\<close>

theorem dead_state_stable:
  assumes dead: "vst v = VDead"
  shows "vst (ev v c) = VDead"
  using dead by (cases c) (auto split: vstate.splits)

theorem dead_material_stable:
  assumes inv: "dead_inv v"
    and dead: "vst v = VDead"
  shows "\<not> vkeys (ev v c)
     \<and> \<not> vlact (ev v c) i
     \<and> \<not> vlkey (ev v c) i"
  using inv dead by (cases c) (auto simp: dead_inv_def
    split: vstate.splits)

theorem dead_counter_frozen:
  assumes dead: "vst v = VDead"
  shows "vatt (ev v c) = vatt v"
  using dead by (cases c) (auto split: vstate.splits)

theorem dead_terminal:
  assumes inv: "dead_inv v"
    and dead: "vst v = VDead"
  shows "vst (ev v c) = VDead
     \<and> \<not> vkeys (ev v c)
     \<and> \<not> vlact (ev v c) i
     \<and> \<not> vlkey (ev v c) i
     \<and> vatt (ev v c) = vatt v"
  using assms dead_state_stable dead_material_stable dead_counter_frozen
  by blast

lemma dead_seq_aux:
  assumes inv: "dead_inv v"
    and dead: "vst v = VDead"
  shows "vst (evs v cs) = VDead \<and> dead_inv (evs v cs)"
  using assms
proof (induct cs arbitrary: v)
  case Nil then show ?case by (simp add: dead_inv_def)
next
  case (Cons c cs)
  have st: "vst (ev v c) = VDead" using Cons.prems dead_state_stable by blast
  have inv': "dead_inv (ev v c)" using Cons.prems ev_preserves_dead_inv by blast
  from Cons.hyps[of "ev v c"] inv' st show ?case by simp
qed

theorem dead_terminal_seq:
  assumes inv: "dead_inv v"
    and dead: "vst v = VDead"
  shows "vst (evs v cs) = VDead
     \<and> \<not> vkeys (evs v cs)
     \<and> \<not> vlact (evs v cs) i
     \<and> \<not> vlkey (evs v cs) i"
proof -
  from dead_seq_aux[OF assms] have st: "vst (evs v cs) = VDead"
    and dinv: "dead_inv (evs v cs)" by auto
  from dinv st show ?thesis by (simp add: dead_inv_def)
qed

text \<open>Corollary (fail-closed forever): after duress, NO operation that
      consumes key material ever succeeds again -- the exact state the
      QEMU scenario asserts with the VaultDead error.\<close>

theorem dead_never_serves:
  assumes dead: "vst v = VDead"
  shows "\<not> ok v KDiskRead \<and> \<not> ok v KDiskWrite \<and> \<not> ok v (KUse i)"
  using dead by simp

subsection \<open>Entropy policy and the Refused state (v0.7.0)\<close>

text \<open>The compile-time policy switch (kernel/src/kms.rs RngPolicy) and
      the entropy sources the seal path can report. Strict builds admit
      only hardware RDRAND; the weak TSC fallback is admitted only under
      Lenient (and must be surfaced honestly in the boot log).\<close>

datatype rng_policy = RLenient | RStrict
datatype rng_source = SRdrand | SWeak

definition rng_admits :: "rng_policy \<Rightarrow> rng_source \<Rightarrow> bool" where
  "rng_admits p s \<equiv> p = RLenient \<or> s = SRdrand"

theorem strict_refuses_weak:
  "\<not> rng_admits RStrict SWeak"
  by (simp add: rng_admits_def)

theorem strict_admits_rdrand:
  "rng_admits RStrict SRdrand"
  by (simp add: rng_admits_def)

theorem lenient_admits_all:
  "rng_admits RLenient s"
  by (simp add: rng_admits_def)

text \<open>VRefused: entered only by init (before the first command), never
      by a transition. It is terminal like VDead: every command leaves
      it (and its zeroed key material) untouched, and nothing serves.
      Terminality needs the same reachability discipline as Dead
      (refused_inv: a refused vault carries no key material and no live
      leases -- init wipes the drawn key and zeroizes the blob before
      entering the state, and nothing else can create keys there).\<close>

definition refused_inv :: "vault \<Rightarrow> bool" where
  "refused_inv v \<equiv> vst v = VRefused \<longrightarrow>
     (\<not> vkeys v \<and> (\<forall>i. \<not> vlact v i \<and> \<not> vlkey v i))"

theorem ev_preserves_refused_inv:
  assumes "refused_inv v"
  shows "refused_inv (ev v c)"
  using assms by (cases c) (auto simp: refused_inv_def BUDGET_def
    split: vstate.splits)

theorem ev_never_enters_refused:
  assumes "vst v \<noteq> VRefused"
  shows "vst (ev v c) \<noteq> VRefused"
  using assms by (cases c) (auto split: vstate.splits)

theorem refused_state_stable:
  assumes refused: "vst v = VRefused"
  shows "vst (ev v c) = VRefused"
  using refused by (cases c) (auto split: vstate.splits)

theorem refused_terminal:
  assumes inv: "refused_inv v"
    and refused: "vst v = VRefused"
  shows "vst (ev v c) = VRefused
     \<and> \<not> vkeys (ev v c)
     \<and> \<not> vlact (ev v c) i
     \<and> \<not> vlkey (ev v c) i"
proof -
  have st: "vst (ev v c) = VRefused"
    using refused refused_state_stable by blast
  have inv': "refused_inv (ev v c)"
    using assms ev_preserves_refused_inv by blast
  from inv' st show ?thesis by (simp add: refused_inv_def)
qed

theorem refused_never_serves:
  assumes refused: "vst v = VRefused"
  shows "\<not> ok v KDiskRead \<and> \<not> ok v KDiskWrite \<and> \<not> ok v (KUse i) \<and> \<not> ok v (KUnlock p)"
  using refused by simp

subsection \<open>Leases: lazy expiry, refuse-after-expiry, fresh re-grant\<close>

text \<open>THEOREM (lease expiry wipes): a use at or after the expiry tick
      deactivates the lease and wipes its key. Lazy expiry is the only
      expiry (no timer interrupt exists in Phase 2).\<close>

theorem lease_expiry_wipes:
  assumes granted: "vst v = VUnlocked \<and> vlact v i \<and> vlexp v i \<le> vtick v"
  shows "vlact (ev v (KUse i)) i = False \<and> vlkey (ev v (KUse i)) i = False"
  using granted by auto

text \<open>Without a re-grant of the same slot, an inactive lease can never
      serve: activation happens only in KGrant.\<close>

theorem no_grant_no_serve:
  assumes inactive: "vlact v i = False"
    and grant_free: "\<forall>c \<in> set cs. \<forall>t. c \<noteq> KGrant i t"
  shows "\<not> ok (evs v cs) (KUse i)"
  using assms
proof (induct cs arbitrary: v)
  case Nil then show ?case by simp
next
  case (Cons c cs)
  have not_grant: "\<forall>t. c \<noteq> KGrant i t" using Cons.prems(2) by simp
  have inact': "vlact (ev v c) i = False"
    using not_grant Cons.prems(1)
    by (cases c) (auto split: vstate.splits)
  have "\<not> ok (evs (ev v c) cs) (KUse i)"
  proof (rule Cons.hyps)
    show "vlact (ev v c) i = False" using inact' by simp
  next
    show "\<forall>c' \<in> set cs. \<forall>t. c' \<noteq> KGrant i t" using Cons.prems(2) by simp
  qed
  then show ?case by simp
qed

text \<open>Every effective re-grant sets a strictly-future expiry (ttl > 0
      guard; ticks do not move during a grant), so a re-granted lease
      starts its budget honestly.\<close>

theorem regrant_sets_future_expiry:
  assumes granted: "vst v = VUnlocked \<and> t > 0"
  shows "vlexp (ev v (KGrant i t)) i = vtick v + t
     \<and> vlexp (ev v (KGrant i t)) i > vtick (ev v (KGrant i t))"
  using granted by simp

subsection \<open>Fail-closed outside Unlocked, and the unlock outcome\<close>

text \<open>Before unlock (Sealed) and after duress (Dead), no key-consuming
      operation succeeds. Together with @{text dead_terminal} this is
      the vault's whole fail-closed story: keys serve only in Unlocked,
      and Unlocked is reachable only through a budget-respecting,
      tag-authenticated unlock.\<close>

theorem sealed_never_serves:
  assumes sealed: "vst v = VSealed"
  shows "\<not> ok v KDiskRead \<and> \<not> ok v KDiskWrite \<and> \<not> ok v (KUse i)"
  using sealed by simp

theorem keys_imply_unlocked:
  assumes inv: "key_inv v"
    and keys: "vkeys v"
  shows "vst v = VUnlocked"
  using inv keys by (simp add: key_inv_def)

text \<open>A correct-PIN attempt on a live sealed vault under budget opens
      it, installs the keys, and counts the attempt.\<close>

theorem unlock_opens_under_budget:
  assumes sealed: "vst v = VSealed"
    and under: "vatt v + 1 < BUDGET"
  shows "vst (ev v (KUnlock True)) = VUnlocked
     \<and> vkeys (ev v (KUnlock True))
     \<and> vatt (ev v (KUnlock True)) = vatt v + 1"
  using sealed under by (auto simp: BUDGET_def split: vstate.splits if_splits)

text \<open>A wrong-PIN attempt (tag failure) leaves the vault sealed and
      only advances the counter. Key-freedom of the result needs the
      reachability invariant (a sealed vault carries no keys -- the
      state alone cannot exclude a nonsense record literal with
      vkeys=True): key_inv supplies exactly that.\<close>

theorem wrong_pin_stays_sealed:
  assumes sealed: "vst v = VSealed"
    and under: "vatt v + 1 < BUDGET"
    and kinv: "key_inv v"
  shows "vst (ev v (KUnlock False)) = VSealed
     \<and> \<not> vkeys (ev v (KUnlock False))
     \<and> vatt (ev v (KUnlock False)) = vatt v + 1"
proof -
  from kinv sealed have nokeys: "\<not> vkeys v"
    by (auto simp: key_inv_def)
  from sealed under nokeys show ?thesis by (simp add: BUDGET_def)
qed
end
