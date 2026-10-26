theory Ident
  imports Main
begin

section \<open>Zero-ID identity: manifests, sandbox spawner, Permission
Tracker (twin of kernel/src/identity.rs)\<close>

text \<open>
  Authority without identity. There are no usernames, no UIDs, no
  certificate chains in this model -- the same as in the kernel. The
  trust anchor is the RAM-only vault: manifests carry a MAC under a
  vault-derived key, so a closed vault refuses every spawn (the model
  guards every spawn on \<^verbatim>\<open>ivault\<close>). Guarantees proved sorry-free,
  mirroring the v0.7.0 exit criteria:

  \<^item> \<open>spawn_refuses_mac\<close> / \<open>spawn_refuses_hash\<close> -- a forged manifest
    (MAC failure) or a substituted binary (content-hash mismatch) is
    INERT: nothing in the state changes. This is the roadmap exit
    criterion ``spawner refuses hash mismatch''.
  \<^item> \<open>spawn_default_grant\<close> -- an admitted spawn creates the task with
    exactly one authority (the prompt channel) and records the grant in
    the tracker in the same atomic step (record-then-mint ordering).
  \<^item> \<open>tracked_caps\<close> (the no-cap-without-record invariant) -- a live
    authority always has a Granted record behind it; every path that
    sets a capability appends its record first. Preservation is proved
    for every command, and by induction for every command sequence.
  \<^item> \<open>policy_refusal_records\<close> / \<open>strict_caps_ttl\<close> -- the STRICT
    profile's TTL ceiling is mechanical: a request beyond the cap is
    denied and recorded without any operator involvement, and the cap
    is untouched.
  \<^item> \<open>operator_denial_no_grant\<close> -- an operator refusal never changes
    the capability state (denials are recorded, never enforced silently).
  \<^item> \<open>expiry_clears_lease\<close> / \<open>exit_clears_all_caps\<close> +
    \<open>exit_records_revocation\<close> -- lease-scoped authority dies at the
    expiry report; session-scoped authority dies with the task, and the
    ledger records the revocation.

  Model simplifications are recorded in proof/TODO.md (items 14--16);
  the load-bearing ones: MAC and content hash are abstract values
  (the concrete BLAKE2b bindings are pinned by KATs in the C core and
  the kernel's own spawn refusals in QEMU), and the operator's decision
  is an input to the request commands (the prompt handshake is the
  human half, outside the TCB by design).
\<close>

subsection \<open>Types and state\<close>

datatype profile = PStd | PStrict
datatype auth = ALease | ADisk | APrompt

record manifest =
  mprofile :: profile
  mttl     :: nat                \<comment> \<open>requested max lease TTL (ticks)\<close>
  mhash    :: nat                \<comment> \<open>abstract binary content hash\<close>
  mmac_ok  :: bool               \<comment> \<open>abstract MAC validity\<close>

record prog =
  phash :: nat                   \<comment> \<open>abstract content hash of the binary\<close>

definition STRICT_TTL_MAX :: nat where
  "STRICT_TTL_MAX = 64"

definition ttl_admitted :: "profile \<Rightarrow> nat \<Rightarrow> bool" where
  "ttl_admitted p t \<equiv> p \<noteq> PStrict \<or> t \<le> STRICT_TTL_MAX"

definition mac_ok :: "manifest \<Rightarrow> bool" where
  "mac_ok m \<equiv> mmac_ok m"

definition hash_ok :: "manifest \<Rightarrow> prog \<Rightarrow> bool" where
  "hash_ok m b \<equiv> mhash m = phash b"

type_synonym task = nat

datatype decision = DGranted | DDenied | DRevoked | DExpired

record entry =
  e_task :: task
  e_auth :: auth
  e_dec  :: decision
  e_tick :: nat

record istate =
  ivault   :: bool                     \<comment> \<open>vault Unlocked? (anchor of trust)\<close>
  itracker :: "entry list"             \<comment> \<open>append-only ledger (newest first)\<close>
  icaps    :: "task \<Rightarrow> auth \<Rightarrow> bool"   \<comment> \<open>live authorities per task\<close>
  ialive   :: "task \<Rightarrow> bool"           \<comment> \<open>task slot currently running\<close>
  iprof    :: "task \<Rightarrow> profile"        \<comment> \<open>sandbox profile of the spawned task\<close>
  itick    :: nat

subsection \<open>Commands and the transition\<close>

text \<open>The operator's decision is a parameter of the request commands
      (the prompt handshake is the human half). Everything BEFORE the
      operator -- MAC, hash, profile validity, TTL policy cap, task
      aliveness, vault state -- is mechanical, and every refusal is
      recorded in the ledger.\<close>

datatype ident_cmd =
  ISpawn task manifest prog    \<comment> \<open>spawn task t from manifest m over prog b\<close>
| ILeaseReq task nat bool      \<comment> \<open>lease request: ttl, operator decision\<close>
| IDiskReq task bool           \<comment> \<open>disk request: operator decision\<close>
| IExpire task nat             \<comment> \<open>lease-expiry report (lease id)\<close>
| IExit task                   \<comment> \<open>task exit (session death)\<close>

fun ev :: "istate \<Rightarrow> ident_cmd \<Rightarrow> istate" where
  "ev s (ISpawn t m b) =
     (if ivault s \<and> mac_ok m \<and> hash_ok m b \<and> \<not> ialive s t
      then s\<lparr> ialive := (ialive s)(t := True),
              icaps := (icaps s)(t := \<lambda>a. a = APrompt),
              iprof := (iprof s)(t := mprofile m),
              itracker :=
                \<lparr> e_task = t, e_auth = APrompt, e_dec = DGranted,
                  e_tick = itick s \<rparr> # itracker s \<rparr>
      else s)"
| "ev s (ILeaseReq t ttl granted) =
     (if ialive s t \<and> ivault s \<and> ttl_admitted (iprof s t) ttl
      then if granted
      then s\<lparr> icaps := (icaps s)(t := (icaps s t)(ALease := True)),
              itracker :=
                \<lparr> e_task = t, e_auth = ALease, e_dec = DGranted,
                  e_tick = itick s \<rparr> # itracker s \<rparr>
      else s\<lparr> itracker :=
                \<lparr> e_task = t, e_auth = ALease, e_dec = DDenied,
                  e_tick = itick s \<rparr> # itracker s \<rparr>
      else s\<lparr> itracker :=
                \<comment> \<open>mechanical refusal (policy cap / dead task / closed
                   vault): recorded, never granted, never silent\<close>
                \<lparr> e_task = t, e_auth = ALease, e_dec = DDenied,
                  e_tick = itick s \<rparr> # itracker s \<rparr>)"
| "ev s (IDiskReq t granted) =
     (if ialive s t \<and> ivault s
      then if granted
      then s\<lparr> icaps := (icaps s)(t := (icaps s t)(ADisk := True)),
              itracker :=
                \<lparr> e_task = t, e_auth = ADisk, e_dec = DGranted,
                  e_tick = itick s \<rparr> # itracker s \<rparr>
      else s\<lparr> itracker :=
                \<lparr> e_task = t, e_auth = ADisk, e_dec = DDenied,
                  e_tick = itick s \<rparr> # itracker s \<rparr>
      else s\<lparr> itracker :=
                \<lparr> e_task = t, e_auth = ADisk, e_dec = DDenied,
                  e_tick = itick s \<rparr> # itracker s \<rparr>)"
| "ev s (IExpire t i) =
     (if ialive s t \<and> icaps s t ALease
      then s\<lparr> icaps := (icaps s)(t := (icaps s t)(ALease := False)),
              itracker :=
                \<lparr> e_task = t, e_auth = ALease, e_dec = DExpired,
                  e_tick = itick s \<rparr> # itracker s \<rparr>
      else s)"
| "ev s (IExit t) =
     (if ialive s t
      then s\<lparr> ialive := (ialive s)(t := False),
              icaps := (icaps s)(t := \<lambda>_. False),
              itracker :=
                (if icaps s t ALease
                 then [\<lparr> e_task = t, e_auth = ALease, e_dec = DRevoked,
                          e_tick = itick s \<rparr>]
                 else [])
                @ (if icaps s t ADisk
                 then [\<lparr> e_task = t, e_auth = ADisk, e_dec = DRevoked,
                          e_tick = itick s \<rparr>]
                 else [])
                @ (if icaps s t APrompt
                 then [\<lparr> e_task = t, e_auth = APrompt, e_dec = DRevoked,
                          e_tick = itick s \<rparr>]
                 else [])
                @ itracker s \<rparr>
      else s)"

fun evs :: "istate \<Rightarrow> ident_cmd list \<Rightarrow> istate" where
  "evs s [] = s"
| "evs s (c # cs) = evs (ev s c) cs"

subsection \<open>Spawn refusals are inert, admission is recorded\<close>

text \<open>THEOREM (spawner refuses): a forged manifest and a substituted
      binary change NOTHING. The refusal is a named outcome at a pure
      function boundary -- no state is touched on the way out.\<close>

theorem spawn_refuses_mac:
  assumes "\<not> mac_ok m"
  shows "ev s (ISpawn t m b) = s"
  using assms by auto

theorem spawn_refuses_hash:
  assumes "\<not> hash_ok m b"
  shows "ev s (ISpawn t m b) = s"
  using assms by (auto simp: hash_ok_def)

theorem spawn_refuses_closed_vault:
  assumes "\<not> ivault s"
  shows "ev s (ISpawn t m b) = s"
  using assms by auto

text \<open>THEOREM (admission): a valid manifest over matching content spawns
      the task alive, grants exactly the prompt authority, and appends
      the default-grant record in the same atomic step.\<close>

theorem spawn_admits:
  assumes "ivault s" "mac_ok m" "hash_ok m b" "\<not> ialive s t"
  shows "ialive (ev s (ISpawn t m b)) t
     \<and> icaps (ev s (ISpawn t m b)) t APrompt
     \<and> (\<forall>a. a \<noteq> APrompt \<longrightarrow> \<not> icaps (ev s (ISpawn t m b)) t a)
     \<and> iprof (ev s (ISpawn t m b)) t = mprofile m"
  using assms by (auto simp: hash_ok_def mac_ok_def)

theorem spawn_records_default_grant:
  assumes "ivault s" "mac_ok m" "hash_ok m b" "\<not> ialive s t"
  shows "\<exists>e \<in> set (itracker (ev s (ISpawn t m b))).
           e_task e = t \<and> e_auth e = APrompt \<and> e_dec e = DGranted"
  using assms by (auto simp: hash_ok_def mac_ok_def)

subsection \<open>The no-cap-without-record invariant\<close>

text \<open>THE tracked invariant: a live authority always has a Granted
      record behind it. Every cap-setting transition appends its record
      in the SAME step (record-then-mint in identity.rs); nothing ever
      deletes records. This is the mechanical direction of the
      Permission Tracker's contract.\<close>

definition tracked :: "istate \<Rightarrow> task \<Rightarrow> auth \<Rightarrow> bool" where
  "tracked s t a \<equiv> \<exists>e \<in> set (itracker s).
     e_task e = t \<and> e_auth e = a \<and> e_dec e = DGranted"

theorem ev_preserves_tracked_caps:
  assumes inv: "\<forall>t a. icaps s t a \<longrightarrow> tracked s t a"
  shows "\<forall>t a. icaps (ev s c) t a \<longrightarrow> tracked (ev s c) t a"
  using inv
proof (cases c)
  case (ISpawn t m b)
  then show ?thesis
    by (auto simp: tracked_def split: if_splits)
next
  case (ILeaseReq t ttl granted)
  then show ?thesis
    by (auto simp: tracked_def split: if_splits)
next
  case (IDiskReq t granted)
  then show ?thesis
    by (auto simp: tracked_def split: if_splits)
next
  case (IExpire t i)
  then show ?thesis
    by (auto simp: tracked_def split: if_splits)
next
  case (IExit t)
  then show ?thesis
    by (auto simp: tracked_def split: if_splits)
qed

theorem evs_preserves_tracked_caps:
  assumes inv: "\<forall>t a. icaps s t a \<longrightarrow> tracked s t a"
  shows "\<forall>t a. icaps (evs s cs) t a \<longrightarrow> tracked (evs s cs) t a"
  using assms
proof (induct cs arbitrary: s)
  case Nil then show ?case by simp
next
  case (Cons c cs)
  from Cons.prems have step: "\<forall>t a. icaps (ev s c) t a \<longrightarrow> tracked (ev s c) t a"
    using ev_preserves_tracked_caps by blast
  from Cons.hyps[of "ev s c"] step show ?case by simp
qed

text \<open>The ledger never shrinks (append-only; IExit appends the
      revocations of whatever was still live -- possibly none).\<close>

theorem tracker_append_only:
  "length (itracker s) \<le> length (itracker (ev s c))"
  by (cases c) (auto simp: length_append)

theorem tracker_append_only_seq:
  "length (itracker s) \<le> length (itracker (evs s cs))"
  by (induct cs arbitrary: s)
    (auto intro: le_trans tracker_append_only)

subsection \<open>Requests: policy caps, operator decisions, expiry\<close>

text \<open>THEOREM (mechanical policy cap): the STRICT profile's TTL ceiling
      denies and records BEFORE any operator involvement, and the
      capability state is untouched.\<close>

theorem strict_caps_ttl:
  assumes "ttl_admitted PStrict t"
  shows "t \<le> STRICT_TTL_MAX"
  using assms by (simp add: ttl_admitted_def)

theorem policy_refusal_records:
  assumes "ialive s t" "ivault s" "\<not> ttl_admitted (iprof s t) ttl"
  shows "itracker (ev s (ILeaseReq t ttl g)) =
           \<lparr> e_task = t, e_auth = ALease, e_dec = DDenied,
             e_tick = itick s \<rparr> # itracker s
     \<and> icaps (ev s (ILeaseReq t ttl g)) = icaps s"
  using assms by (auto simp: ttl_admitted_def)

theorem policy_refusal_no_cap:
  assumes "ialive s t" "ivault s" "\<not> ttl_admitted (iprof s t) ttl"
  shows "icaps (ev s (ILeaseReq t ttl g)) t ALease = icaps s t ALease"
  using assms by (auto simp: ttl_admitted_def)

text \<open>THEOREM (operator denial never grants -- and never revokes): the
      decision is the operator's; the capability state is the kernel's.
      A refusal changes nothing but the ledger.\<close>

theorem operator_denial_no_grant:
  assumes "ialive s t" "ivault s" "ttl_admitted (iprof s t) ttl"
  shows "icaps (ev s (ILeaseReq t ttl False)) t ALease = icaps s t ALease
     \<and> icaps (ev s (IDiskReq t False)) t ADisk = icaps s t ADisk"
  using assms by (auto simp: ttl_admitted_def)

theorem operator_grant_sets_cap:
  assumes "ialive s t" "ivault s" "ttl_admitted (iprof s t) ttl"
  shows "icaps (ev s (ILeaseReq t ttl True)) t ALease
     \<and> tracked (ev s (ILeaseReq t ttl True)) t ALease"
  using assms by (auto simp: ttl_admitted_def tracked_def)

text \<open>THEOREM (lease expiry clears the authority and records it): the
      owner's expiry report mirrors the KMS's lazy wipe into the ledger
      and removes the authority in the same step.\<close>

theorem expiry_clears_lease:
  assumes "ialive s t" "icaps s t ALease"
  shows "\<not> icaps (ev s (IExpire t i)) t ALease
     \<and> (\<exists>e \<in> set (itracker (ev s (IExpire t i))).
           e_task e = t \<and> e_auth e = ALease \<and> e_dec e = DExpired)"
  using assms by auto

subsection \<open>Session death: authority cannot outlive its holder\<close>

text \<open>THEOREM (exit clears everything): a dying task's authority set
      goes to empty -- mechanically, in the same transition that marks
      the slot dead (task.rs task_exit: tracker records, then the table
      clear).\<close>

theorem exit_clears_all_caps:
  assumes "ialive s t"
  shows "icaps (ev s (IExit t)) = (icaps s)(t := \<lambda>_. False)"
  using assms by auto

theorem exit_dead_not_alive:
  assumes "ialive s t"
  shows "\<not> ialive (ev s (IExit t)) t"
  using assms by auto

text \<open>THEOREM (revocation recorded): every authority that was live at
      exit gets its Revoked record -- the ledger reflects what
      happened. (Authorities already expired or denied stay as they
      are; the ledger records events, not absences.)\<close>

theorem exit_records_revocation:
  assumes "ialive s t" "icaps s t a"
  shows "\<exists>e \<in> set (itracker (ev s (IExit t))).
           e_task e = t \<and> e_auth e = a \<and> e_dec e = DRevoked"
  using assms by (cases a) auto

end
