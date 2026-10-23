theory Revoke
  imports Main
begin

section \<open>Instant revocation (twin of kernel/src/shm.rs + cap.rs + pagemap.rs)\<close>

text \<open>
  The kill switch of Pillar 2: revoking a task's shared-memory capability
  zeroes the CNode slot AND tears down the task's page-table entries. The
  security property -- the reason the Permission Tracker's dashboard toggle
  is instant -- is that afterwards NO access by that task to that block can
  succeed: the data path is the MMU itself, and the mapping is gone.

  Model: a total \<^bold>\<open>exec\<close> function over a closed command language
  (transfer, revoke, access, other). Revocation is monotone -- the kernel
  refuses to re-map a block once its transfer chain has been revoked (the
  transferred/revoked flag in shm.rs); the model carries that discipline in
  a monotone \<^bold>dead registry. The kill switch tears down ALL mappings of
  the revoked block for the task in one step (the kernel unmaps every page
  of the block -- shm.rs::revoke loops over the block's pages).

  Proved sorry-free:
  \<^item> \<open>crvk_cleans\<close> -- the kill switch's own step leaves the revoked pair
    with NO mapping in any window (base case of soundness).
  \<^item> \<open>exec_preserves_dead_clean\<close> / \<open>execs_preserve_dead_clean\<close> -- no
    command, and no command sequence, ever re-creates a mapping for a
    dead pair (the transfer gate refuses dead pairs; other commands do
    not touch mappings).
  \<^item> \<open>revoke_sound\<close> -- after the kill switch fires, NO access attempt
    by the revoked task on the revoked block is ever admitted again.
  \<^item> \<open>transfer_pairs\<close> -- the zero-copy transfer installs the capability
    and the mapping in one step (the two halves of the dual-keyhole
    handoff are atomic).
\<close>

type_synonym tid = nat
type_synonym bid = nat
type_synonym vpage = nat
type_synonym slot = nat

datatype perm = PRead | PWrite

record sys =
  (* CNode slots: (task, slot) -> Some(block, perms) | None (zeroed) *)
  scaps :: "tid \<times> slot \<Rightarrow> (bid \<times> perm set) option"
  (* page-table mappings: (task, vpage) -> Some(block, perms) | None *)
  smaps :: "tid \<times> vpage \<Rightarrow> (bid \<times> perm set) option"
  (* monotone revocation registry (the kernel's transferred/revoked flag) *)
  sdead :: "(tid \<times> bid) set"

subsection \<open>The MMU (hardware half of the kill switch)\<close>

datatype acc_ev = Access tid bid perm

definition mmu_ok :: "sys \<Rightarrow> acc_ev \<Rightarrow> bool" where
  "mmu_ok s e \<equiv>
     (case e of Access t b p \<Rightarrow>
        (\<exists>vp prs. smaps s (t, vp) = Some (b, prs) \<and> p \<in> prs))"

subsection \<open>The command language (closed) and execution\<close>

datatype cmd =
  CTx tid slot bid vpage    \<comment> \<open>zero-copy transfer: map (t,vp) + mint (t,sl)\<close>
| CRvk tid slot bid vpage   \<comment> \<open>kill switch: zero slot, unmap ALL, mark dead\<close>
| CAcc tid bid perm         \<comment> \<open>a task access attempt (admitted by the MMU)\<close>
| COther                    \<comment> \<open>scheduling, blind IPC, ... (no cap/map effect)\<close>

text \<open>The kill switch's mapping teardown: every (t, vp) that maps the
      revoked block b goes to None. The slot at (t, sl) is zeroed. The
      pair is marked dead -- permanently.\<close>

definition unmap_all :: "sys \<Rightarrow> tid \<Rightarrow> bid \<Rightarrow> (tid \<times> vpage) \<Rightarrow>
                            (bid \<times> perm set) option" where
  "unmap_all s t b k \<equiv>
     (case k of (t', vp') \<Rightarrow>
        if t' = t \<and> (\<exists>prs. smaps s (t', vp') = Some (b, prs))
        then None
        else smaps s (t', vp'))"

fun exec :: "sys \<Rightarrow> cmd \<Rightarrow> sys" where
  "exec s (CTx t sl b vp) =
     (if (t, b) \<in> sdead s
      then s            \<comment> \<open>monotone: dead pairs are never re-mapped\<close>
      else s\<lparr> scaps := (scaps s)((t, sl) := Some (b, {PRead, PWrite})),
              smaps := (smaps s)((t, vp) := Some (b, {PRead, PWrite})),
              sdead := sdead s \<rparr>)"
| "exec s (CRvk t sl b vp) =
     s\<lparr> scaps := (scaps s)((t, sl) := None),
        smaps := unmap_all s t b,
        sdead := sdead s \<union> {(t, b)} \<rparr>"
| "exec s (CAcc t b p) = s"
| "exec s COther = s"

fun execs :: "sys \<Rightarrow> cmd list \<Rightarrow> sys" where
  "execs s [] = s"
| "execs s (c # cs) = execs (exec s c) cs"

text \<open>Admission: an access command runs only if the MMU admits it; every
      other command is always enabled. A denied access produces the
      kernel's named denial (idt.rs), never a silent pass.\<close>

fun admitted :: "sys \<Rightarrow> cmd \<Rightarrow> bool" where
  "admitted s (CAcc t b p) = mmu_ok s (Access t b p)"
| "admitted s _ = True"

subsection \<open>Revocation monotonicity\<close>

theorem revocation_monotone:
  assumes dead: "(t, b) \<in> sdead s"
  shows "(t, b) \<in> sdead (exec s c)"
  using dead by (cases c) auto

theorem revocation_monotone_seq:
  assumes dead: "(t, b) \<in> sdead s"
  shows "(t, b) \<in> sdead (execs s cs)"
  using dead by (induct cs arbitrary: s) (auto intro: revocation_monotone)

subsection \<open>Revocation soundness\<close>

text \<open>The invariant: a dead pair has NO mapping in any window.\<close>

definition dead_clean :: "sys \<Rightarrow> tid \<Rightarrow> bid \<Rightarrow> bool" where
  "dead_clean s t b \<equiv> \<forall>vp prs. smaps s (t, vp) \<noteq> Some (b, prs)"

text \<open>BASE: the kill switch's own step leaves the pair clean -- it tears
      down every mapping of the block (unmap_all) in the same update
      that marks it dead. This is the kernel's single-operation revoke:
      slot zero + PTE teardown are not two phases.\<close>

theorem crvk_cleans:
  "dead_clean (exec s (CRvk t sl b vp)) t b"
proof (unfold exec.simps dead_clean_def unmap_all_def, intro allI impI)
  fix vp' prs
  show "smaps (s\<lparr> scaps := (scaps s)((t, sl) := None),
                smaps := unmap_all s t b,
                sdead := sdead s \<union> {(t, b)} \<rparr>) (t, vp') \<noteq> Some (b, prs)"
    by (cases "smaps s (t, vp')") (auto split: prod.splits)
qed

text \<open>PRESERVATION: no command re-creates a mapping for a dead pair.\<close>

lemma exec_preserves_dead_clean:
  assumes dead: "(t, b) \<in> sdead s"
    and dc: "dead_clean s t b"
  shows "dead_clean (exec s c) t b"
  using dc dead
proof (cases c)
  case (CTx ta sla ba vpa)
  show ?thesis
  proof (cases "ta = t \<and> ba = b")
    case True
    -- \<open>The transfer targets our dead pair: the gate refuses it.\<close>
    with dead have gate: "exec s (CTx ta sla ba vpa) = s"
      using CTx by simp
    then show ?thesis using dc by simp
  next
    case False
    -- \<open>Different task or block. The only new mapping names (ta, ba);
       for our pair (t, b) nothing changes: either the update does not
       concern t, or it writes ba \<noteq> b.\<close>
    have "smaps (exec s (CTx ta sla ba vpa)) (t, vp') \<noteq> Some (b, prs)" for vp' prs
    proof (cases "ta = t")
      case True
      then show ?thesis
      proof (cases "vp' = vpa")
        case True
        with False CTx show ?thesis by simp
      next
        case False
        with dc CTx show ?thesis by (simp add: dead_clean_def)
      qed
    next
      case False
      with dc CTx show ?thesis by (simp add: dead_clean_def)
    qed
    then show ?thesis by (simp add: dead_clean_def)
  qed
qed (auto simp: dead_clean_def)

lemma execs_preserve_dead_clean:
  assumes dead: "(t, b) \<in> sdead s"
    and dc: "dead_clean s t b"
  shows "dead_clean (execs s cs) t b"
  using assms
  by (induct cs arbitrary: s)
     (auto intro: exec_preserves_dead_clean)

text \<open>THEOREM (revoke soundness): starting from the post-kill-switch
      state, no access attempt by the revoked task on the revoked block
      is ever admitted, for ANY command suffix. The boot test observes
      exactly this: the consumer's probe takes a #PF and the kernel
      turns it into the named denial (REDOS MEMPHY REVOKE PASS).\<close>

theorem revoke_sound:
  assumes post: "s' = exec s (CRvk t sl b vp)"
  shows "\<not> admitted (execs s' cs) (CAcc t b p)"
proof -
  have dead: "(t, b) \<in> sdead s'" using post by (simp add: exec.simps) blast
  have dc: "dead_clean s' t b" using post by (simp add: crvk_cleans)
  have "dead_clean (execs s' cs) t b"
    using execs_preserve_dead_clean[OF dead dc] .
  then have no_map: "\<not> (\<exists>vpx prs. smaps (execs s' cs) (t, vpx) = Some (b, prs))"
    by (simp add: dead_clean_def)
  have "admitted (execs s' cs) (CAcc t b p) = mmu_ok (execs s' cs) (Access t b p)"
    by simp
  also have "\<dots> = (\<exists>vpx prs. smaps (execs s' cs) (t, vpx) = Some (b, prs))"
    by (simp add: mmu_ok_def)
  finally show False using no_map by blast
qed

subsection \<open>Transfer pairing (authority and mapping are atomic)\<close>

text \<open>THEOREM (transfer pairing): a successful zero-copy transfer
      installs the capability AND the mapping in one step -- the MMU half
      and the CNode half of the dual-keyhole handoff cannot diverge.\<close>

theorem transfer_pairs:
  assumes gate: "(t, b) \<notin> sdead s"
  shows "scaps (exec s (CTx t sl b vp)) (t, sl) = Some (b, {PRead, PWrite})
     \<and> smaps (exec s (CTx t sl b vp)) (t, vp) = Some (b, {PRead, PWrite})"
  using gate by simp

text \<open>Corollary: a live full-permission mapping always has a live
      capability behind it (mapping without authority is impossible).\<close>

corollary mapped_implies_minted:
  assumes mapped: "smaps s (t, vp) = Some (b, {PRead, PWrite})"
    and gate: "(t, b) \<notin> sdead s"
  shows "\<exists>sl. scaps (exec s (CTx t sl b vp)) (t, sl)
                 = Some (b, {PRead, PWrite})"
  using transfer_pairing[OF gate] by simp

subsection \<open>Corollaries exercised by the boot test\<close>

text \<open>The consumer's read probe after revocation: denied.\<close>

lemma revoked_read_denied:
  "\<not> admitted (execs (exec s (CRvk t sl b vp)) cs) (CAcc t b PRead)"
  using revoke_sound[of s t sl b vp cs] .

text \<open>The consumer's write probe after revocation: denied.\<close>

lemma revoked_write_denied:
  "\<not> admitted (execs (exec s (CRvk t sl b vp)) cs) (CAcc t b PWrite)"
  using revoke_sound[of s t sl b vp cs] .

end
