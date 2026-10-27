theory Fastpath
  imports Cap IPC
begin

section \<open>Register-path IPC fast path, TLB obligation, glass wall
          (twin of kernel/src/fastpath.rs, mm/pagemap.rs, glass.rs)\<close>

text \<open>
  v0.8.0's formal surfaces, one theory:

  \<^item> \<open>Register rendezvous control-blindness\<close> -- the fast path's
    send/recv move a five-register payload between saved frames; the
    CONTROL state (parked / staged-occupancy / blocked) and the result
    code evolve independently of the payload VALUES. The staged path
    stores the payload in the stage slot (as the byte router stores a
    staged message) -- the kernel-side copy is the identity on values,
    and no control decision reads a payload word. Twin of fastpath.rs.

  \<^item> \<open>Exactly-once delivery\<close> -- a parked receiver consumes its
    registration exactly once; reachable states never hold a parked
    receiver AND a staged sender simultaneously; a second staged sender
    is a named rejection, never a silent overwrite.

  \<^item> \<open>TLB invalidation obligation (PCID model)\<close> -- with PCID active,
    CR3 loads may retain translations (noflush); revocation safety
    rests on an explicit invalidation after every unmap, BEFORE any
    admitted access through that page. Root switches do NOT clean the
    obligation (that is the hazard being formalized); only the
    invalidation command does.

  \<^item> \<open>Glass wall visibility\<close> -- the compositor's pane set grows only
    through grants from the app; a page the app holds private can never
    become an admitted pane; panes are read-only by construction; pane
    revocation denies until a fresh grant.

  \<^item> \<open>Ring-3 containment scope\<close> -- a contained fault kills exactly
    the faulting task.

  Model simplifications (proof/TODO.md items 19+): payloads are
  polymorphic opaque values; PCID tags are abstract (the obligation is
  stated per (root, page)); glass page sets are abstract at page
  granularity.
\<close>

subsection \<open>Fast-path endpoint state\<close>

text \<open>A five-word register payload; the kernel treats it as opaque.\<close>
type_synonym 'p regs = "'p \<times> 'p \<times> 'p \<times> 'p \<times> 'p"

record 'p fast_ep =
  fparked :: bool                    \<comment> \<open>a receiver is parked (frame registered)\<close>
  fstaged :: "('p regs) option"      \<comment> \<open>a blocked sender's staged registers\<close>
  fblocked :: bool                   \<comment> \<open>a sender is blocked on staging\<close>

definition fep_empty :: "'p fast_ep" where
  "fep_empty \<equiv> \<lparr> fparked = False, fstaged = None, fblocked = False \<rparr>"

datatype fast_result =
  FDelivered
  | FStagedBlocked
  | FWakeStaged
  | FRejected

text \<open>The CONTROL projection: everything the kernel's policy reads.
      The payload slot's CONTENT is deliberately not part of it.\<close>

definition f_ctrl :: "'p fast_ep \<Rightarrow> bool \<times> bool \<times> bool" where
  "f_ctrl s \<equiv> (fparked s, fstaged s \<noteq> None, fblocked s)"

subsection \<open>Fast-path commands\<close>

fun f_send :: "'p regs \<Rightarrow> 'p fast_ep \<Rightarrow> ('p fast_ep \<times> fast_result)" where
  "f_send p s =
     (if fparked s then (s\<lparr> fparked := False \<rparr>, FDelivered)
      else if fstaged s = None \<and> \<not> fblocked s
      then (s\<lparr> fstaged := Some p, fblocked := True \<rparr>, FStagedBlocked)
      else (s, FRejected))"

fun f_recv :: "'p fast_ep \<Rightarrow> ('p fast_ep \<times> fast_result \<times> ('p regs) option)" where
  "f_recv s =
     (case fstaged s of
        Some p \<Rightarrow> (s\<lparr> fstaged := None, fblocked := False \<rparr>, FWakeStaged, Some p)
      | None \<Rightarrow> (s\<lparr> fparked := True \<rparr>, FRejected, None))"

subsection \<open>Control-blindness\<close>

text \<open>THE blindness theorem: the control state and the result code after
      a send are independent of the payload. Two sends with different
      payloads are indistinguishable to every later control decision.\<close>

theorem f_send_ctrl_blind:
  "\<forall>p1 p2 s. f_ctrl (fst (f_send p1 s)) = f_ctrl (fst (f_send p2 s))
             \<and> snd (f_send p1 s) = snd (f_send p2 s)"
proof (intro allI, goal_cases)
  case (1 p1 p2 s)
  then show ?case by (cases s) (simp split: if_splits)+
qed

text \<open>Control-equal states evolve control-equal under sends with
      ARBITRARY (different) payloads -- the induction step for
      payload-independent traces.\<close>

theorem f_send_ctrl_congruent:
  assumes ceq: "f_ctrl s = f_ctrl s'"
  shows "f_ctrl (fst (f_send p s)) = f_ctrl (fst (f_send p' s'))
         \<and> snd (f_send p s) = snd (f_send p' s')"
  using ceq by (simp add: f_ctrl_def split: if_splits option.splits)

text \<open>Sequences: iterating sends with payload list P vs payload list P'
      from CONTROL-EQUAL states yields control-equal final states. The
      induction is on the (equal) length; the step is
      f_send_ctrl_congruent, and the payloads may differ arbitrarily
      between the two runs -- that is the whole point.\<close>

fun fsends :: "'p regs list \<Rightarrow> 'p fast_ep \<Rightarrow> 'p fast_ep" where
  "fsends [] s = s"
  | "fsends (p # ps) s = fsends ps (fst (f_send p s))"

theorem f_send_seq_ctrl_blind:
  "\<forall>ps ps' s s'. length ps = length ps' \<longrightarrow> f_ctrl s = f_ctrl s' \<longrightarrow>
     f_ctrl (fsends ps s) = f_ctrl (fsends ps' s')"
proof (induct ps arbitrary: ps' s s')
  case Nil
  then show ?case by (cases ps') auto
next
  case (Cons p ps)
  show ?case
  proof (cases ps')
    case Nil
    then show ?thesis using Cons.prems by auto
  next
    case (Cons q qs)
    from Cons.prems have len: "length ps = length qs" by simp
    from Cons.prems have ceq0: "f_ctrl s = f_ctrl s'" by simp
    have step: "f_ctrl (fst (f_send p s)) = f_ctrl (fst (f_send q s'))"
      using ceq0 f_send_ctrl_congruent by blast
    have rest: "f_ctrl (fsends ps (fst (f_send p s)))
              = f_ctrl (fsends qs (fst (f_send q s')))"
      by (rule Cons.hyps[of qs "fst (f_send p s)" "fst (f_send q s')"])
         (use len step in auto)
    then show ?thesis by simp
  qed
qed

subsection \<open>Exactly-once delivery\<close>

theorem f_deliver_consumes_park:
  "fparked s \<Longrightarrow> fparked (fst (f_send p s)) = False"
  by simp

theorem f_no_double_delivery:
  "fparked s \<Longrightarrow> snd (f_send p (fst (f_send p s))) \<noteq> FDelivered"
  by (simp add: f_deliver_consumes_park)

text \<open>Reachability invariant: a parked receiver and a staged sender
      never coexist. Park happens only on the no-stage branch; the
      stage path only fires when nobody is parked.\<close>

definition f_sane :: "'p fast_ep \<Rightarrow> bool" where
  "f_sane s \<equiv> \<not> (fparked s \<and> fstaged s \<noteq> None) \<and> (fblocked s \<longrightarrow> fstaged s \<noteq> None)"

theorem fep_empty_sane: "f_sane fep_empty"
  by (simp add: fep_empty_def f_sane_def)

theorem f_send_preserves_sane: "f_sane s \<Longrightarrow> f_sane (fst (f_send p s))"
  by (simp add: f_sane_def split: if_splits) fastforce

theorem f_recv_preserves_sane: "f_sane s \<Longrightarrow> f_sane (fst (f_recv s))"
  by (simp add: f_sane_def split: if_splits option.splits) fastforce

text \<open>The staged-sender exclusion: while a sender is blocked on the
      stage slot, a second send is the named rejection (SYS_ERR twin) --
      never a silent overwrite.\<close>

theorem f_second_sender_rejected:
  "fblocked s \<Longrightarrow> snd (f_send p s) = FRejected"
  by simp

theorem f_stage_exclusive:
  "fstaged s = None \<Longrightarrow> \<not> fblocked s \<Longrightarrow>
     fblocked (fst (f_send p s)) \<Longrightarrow> fstaged (fst (f_send p s)) = Some p"
  by simp

text \<open>The recv-side wake consumes the stage: the woken sender cannot be
      woken twice.\<close>

theorem f_wake_consumes_stage:
  "fstaged s = Some p \<Longrightarrow>
     fstaged (fst (f_recv s)) = None \<and> \<not> fblocked (fst (f_recv s))"
  by simp

theorem f_no_double_wake:
  "snd (f_recv (fst (f_recv s))) \<noteq> FWakeStaged"
  by (cases "fstaged s") simp_all

subsection \<open>TLB invalidation obligation (PCID model)\<close>

text \<open>With PCID, a noflush CR3 load retains translations. The safety
      obligation is per (root, page): an admitted access may not name a
      page whose unmap has not been invalidated. Root switches do NOT
      discharge the obligation -- that is precisely the PCID hazard.\<close>

datatype tcmd =
  TUnmap nat nat        \<comment> \<open>unmap (root, page)\<close>
  | TInvalidate nat nat \<comment> \<open>invpcid type-2 / invlpg (root, page)\<close>
  | TAccess nat nat     \<comment> \<open>an admitted access through (root, page)\<close>
  | TSwitch nat         \<comment> \<open>CR3 load (root); noflush keeps foreign entries\<close>

record tstate =
  cur :: nat
  dirty :: "(nat \<times> nat) set"

definition t0 :: tstate where
  "t0 \<equiv> \<lparr> cur = 0, dirty = {} \<rparr>"

fun tstep :: "tcmd \<Rightarrow> tstate \<Rightarrow> tstate" where
  "tstep (TUnmap r v) s = s\<lparr> dirty := dirty s \<union> {(r, v)} \<rparr>"
  | "tstep (TInvalidate r v) s = s\<lparr> dirty := dirty s - {(r, v)} \<rparr>"
  | "tstep (TAccess r v) s = s"
  | "tstep (TSwitch r) s = s\<lparr> cur := r \<rparr>"

text \<open>An access at trace position i is clean iff its (root, page) is
      not dirty in the state accumulated by the trace PREFIX.\<close>

definition access_clean :: "tcmd list \<Rightarrow> bool" where
  "access_clean cs \<equiv> \<forall>i < length cs. (case cs ! i of
      TAccess r v \<Rightarrow> (r, v) \<notin> dirty (fold tstep (take i cs) t0)
    | _ \<Rightarrow> True)"

text \<open>The dirty set is exactly the unmaps minus the invalidations --
      the trace-level characterization everything else follows from.\<close>

theorem dirty_characterization:
  "dirty (fold tstep cs t0) =
     {(r, v). TUnmap r v \<in> set cs} - {(r, v). TInvalidate r v \<in> set cs}"
  by (induct cs rule: rev_induct) (simp_all add: t0_def)

text \<open>THE PCID hazard: unmap, root switch, access -- WITHOUT the
      invalidation the access is NOT safe. The switch kept the stale
      translation alive (noflush); the model refuses the access.\<close>

theorem noflush_switch_does_not_clean:
  "\<not> access_clean [TUnmap r v, TSwitch r2, TAccess r v]"
proof -
  have "dirty (fold tstep [TUnmap r v, TSwitch r2] t0) = {(r, v)}"
    by (simp add: t0_def)
  then show ?thesis by (simp add: access_clean_def)
qed

text \<open>THE revocation theorem: with the invalidation in place, the same
      access IS safe. The invalidation is the ONLY command that
      discharges the obligation (switches do not -- see above).\<close>

theorem invalidated_access_is_safe:
  "access_clean [TUnmap r v, TInvalidate r v, TAccess r v]"
  by (simp add: access_clean_def t0_def)

text \<open>Generality: a clean trace IMPLIES every access in it was
      invalidated (or never unmapped) up to its position -- stated for
      a final access (the necessity direction; the converse holds for
      traces whose only access is the final one, see
      invalidated_access_is_safe).\<close>

theorem access_clean_implies_invalidated:
  "access_clean (cs @ [TAccess r v]) \<Longrightarrow>
     (r, v) \<notin> {(r, v). TUnmap r v \<in> set cs}
              - {(r, v). TInvalidate r v \<in> set cs}"
  by (simp add: access_clean_def dirty_characterization)

subsection \<open>Glass wall: the compositor's visibility set\<close>

text \<open>Pages are abstract. The viewer (compositor) reaches its own
      private pages plus granted read-only panes. The pane map grows
      ONLY through GGrant; the scenario's grants name the app's SURFACE
      block, never its private page.\<close>

record glass_state =
  g_own :: "nat set"                 \<comment> \<open>viewer's own private pages\<close>
  g_panes :: "nat \<rightharpoonup> bool"        \<comment> \<open>app page -> read-only pane\<close>

definition g0 :: "nat set \<Rightarrow> glass_state" where
  "g0 own \<equiv> \<lparr> g_own = own, g_panes = empty \<rparr>"

datatype gcmd =
  GGrant nat              \<comment> \<open>app grants a RO pane of page p (share_ro)\<close>
  | GRevokePane nat       \<comment> \<open>pane revoked (unmap from the viewer root)\<close>
  | GCompose nat          \<comment> \<open>viewer reads pane p (admission checked)\<close>
  | GOwnUse nat           \<comment> \<open>viewer touches its own private page\<close>

fun gstep :: "gcmd \<Rightarrow> glass_state \<Rightarrow> glass_state" where
  "gstep (GGrant p) s = s\<lparr> g_panes := (g_panes s)(p \<mapsto> True) \<rparr>"
  | "gstep (GRevokePane p) s = s\<lparr> g_panes := (g_panes s)(p := None) \<rparr>"
  | "gstep _ s = s"

definition g_admitted :: "glass_state \<Rightarrow> nat \<Rightarrow> bool" where
  "g_admitted s p \<equiv> p \<in> g_own s \<or> g_panes s p = Some True"

text \<open>Panes are born read-only: every pane value in the map is True --
      there is no command that stores a writable pane.\<close>

theorem panes_read_only:
  "g_panes (fold gstep cs s) p = Some w \<Longrightarrow> w = True"
proof (induct cs arbitrary: s)
  case Nil
  then show ?case by simp
next
  case (Cons c cs)
  then show ?case by (cases c) (auto split: option.splits)
qed

text \<open>Pane provenance: an admitted pane traces to an explicit grant in
      the trace. (Panes grow only via GGrant; GRevokePane shrinks.)\<close>

theorem pane_admitted_granted:
  "g_panes (fold gstep cs s) p = Some True \<Longrightarrow> GGrant p \<in> set cs"
proof (induct cs arbitrary: s)
  case Nil
  then show ?case by simp
next
  case (Cons c cs)
  then show ?case by (cases c) (auto split: option.splits)
qed

text \<open>THE glass theorem: if every grant in the trace names a page
      outside the app's private set, and the viewer's own set is
      disjoint from it, then no private page is ever admitted to the
      viewer. The MMU denial (glass.rs's probe) is the hardware face of
      this statement.\<close>

theorem glass_own_unchanged:
  "g_own (fold gstep cs s) = g_own s"
  by (induct cs rule: rev_induct) (case_tac c, auto)+

theorem glass_private_never_admitted:
  assumes grants_clean:
    "\<forall>c \<in> set cs. (case c of GGrant p \<Rightarrow> p \<notin> app_private | _ \<Rightarrow> True)"
    and own_disjoint: "g_own s \<inter> app_private = {}"
  shows "p \<in> app_private \<Longrightarrow> \<not> g_admitted (fold gstep cs s) p"
proof -
  assume priv: "p \<in> app_private"
  have notin: "GGrant p \<notin> set cs"
    using grants_clean priv by auto
  have not_pane: "g_panes (fold gstep cs s) p \<noteq> Some True"
  proof
    assume "g_panes (fold gstep cs s) p = Some True"
    then have "GGrant p \<in> set cs" by (rule pane_admitted_granted)
    with notin show False ..
  qed
  have not_own: "p \<notin> g_own (fold gstep cs s)"
    using glass_own_unchanged own_disjoint priv by auto
  then show "\<not> g_admitted (fold gstep cs s) p"
    using not_pane by (simp add: g_admitted_def)
qed

text \<open>Revocation denies: after GRevokePane the pane is gone; the page is
      admitted again only through its own-set membership or a fresh
      grant.\<close>

theorem pane_revoke_denies:
  "g_own s = {} \<Longrightarrow> \<not> g_admitted (gstep (GRevokePane p) s) p"
  by (simp add: g_admitted_def)

subsection \<open>Ring-3 containment scope\<close>

text \<open>A ring-3 fault kills exactly the faulting task: the victim dies
      with a marker exit code; every other task's state is untouched.\<close>

datatype tstate3 = TAlive | TDead

definition contain :: "nat \<Rightarrow> (nat \<Rightarrow> tstate3) \<Rightarrow> nat \<Rightarrow> tstate3" where
  "contain victim st cur = (if cur = victim then TDead else st cur)"

theorem containment_scoped:
  "victim \<noteq> other \<Longrightarrow>
     contain victim st victim = TDead \<and> contain victim st other = st other"
  by (simp add: contain_def)

theorem contained_is_dead:
  "contain victim st victim = TDead"
  by (simp add: contain_def)

end
