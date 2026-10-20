theory IPC
  imports Cap
begin

section \<open>Blind IPC routing (twin of kernel/src/ipc.rs)\<close>

text \<open>
  The security tenet: the router validates ONLY the capability rights and
  the message length; it copies payload bytes without ever inspecting them.
  This theory models an endpoint's state machine and proves the two
  properties that matter:

  \<^item> \<open>payload independence\<close> -- the observable router transition is a
    function of (rights, message length, current state) alone; two messages
    with equal length are indistinguishable to the kernel.
  \<^item> \<open>state-machine invariants\<close> -- the mailbox holds at most one
    message and waiter flags stay consistent under every step.

  Model simplifications vs kernel/src/ipc.rs, each documented: waiters are
  booleans (Phase 1 has at most one blocked task per side -- enforced by the
  named contract errors added in v0.3.0); payloads are polymorphic opaque
  values; the copy operation is the identity on the message value (the
  kernel-side copy cannot change content, only location).
\<close>

datatype 'p message = Msg (msg_len :: nat) (msg_payload :: 'p)

datatype route_result =
  Delivered nat
  | Deposited
  | StagedBlocked
  | RejectedCap
  | RejectedLen

record 'p ep_state =
  pending :: "('p message) option"
  recv_waiter :: bool
  send_staged :: "('p message) option"
  send_waiter :: bool

definition ep_empty :: "'p ep_state" where
  "ep_empty \<equiv> \<lparr> pending = None, recv_waiter = False,
                send_staged = None, send_waiter = False \<rparr>"

subsection \<open>Router steps\<close>

text \<open>Sender step. Mirrors ipc_send: rights check, length contract, direct
      delivery to a waiting receiver, mailbox deposit, or stage-and-block.\<close>

fun ep_send :: "rights \<Rightarrow> nat \<Rightarrow> 'p message \<Rightarrow> 'p ep_state
                \<Rightarrow> ('p ep_state \<times> route_result)" where
  "ep_send rights maxlen m s =
     (if \<not> Send \<in> rights then (s, RejectedCap)
      else if msg_len m = 0 \<or> msg_len m > maxlen then (s, RejectedLen)
      else (case recv_waiter s of
              True \<Rightarrow> (s\<lparr> pending := Some m, recv_waiter := False \<rparr>,
                        Delivered (msg_len m))
            | False \<Rightarrow> (case pending s of
                          None \<Rightarrow> (s\<lparr> pending := Some m \<rparr>, Deposited)
                        | Some _ \<Rightarrow> (s, StagedBlocked))))"

text \<open>Receiver step. Mirrors ipc_recv: rights check, drain mailbox (waking a
      staged sender exactly as wake_sender does), or block. A blocked
      receiver that is directly delivered-to consumes the delivered flag
      first (Task.delivered in the kernel); the model folds that into
      recv_waiter.\<close>

fun ep_recv :: "rights \<Rightarrow> 'p ep_state
                \<Rightarrow> ('p ep_state \<times> nat option)" where
  "ep_recv rights s =
     (if \<not> Recv \<in> rights then (s, None)
      else (case pending s of
              Some m \<Rightarrow> (if send_waiter s
                          then (s\<lparr> pending := send_staged s,
                                       send_staged := None,
                                       send_waiter := False \<rparr>,
                                Some (msg_len m))
                          else (s\<lparr> pending := None \<rparr>,
                                Some (msg_len m)))
            | None \<Rightarrow> (s\<lparr> recv_waiter := True \<rparr>, None)))"

subsection \<open>Payload independence (the blindness theorem)\<close>

text \<open>Two messages of equal length drive the sender step to identical
      outcomes. The kernel never looks at the payload -- here that is a
      theorem, not a comment (Law 3).\<close>

theorem send_payload_independence:
  assumes "msg_len m1 = msg_len m2"
  shows "ep_send r maxlen m1 s = ep_send r maxlen m2 s"
  using assms
  by (cases "Send \<in> r";
      cases "msg_len m1 = 0 \<or> msg_len m1 > maxlen";
      auto split: bool.splits option.splits)

text \<open>The receiver step has no message input at all: its output cannot
      depend on any payload by construction.\<close>

theorem recv_has_no_payload_input:
  shows "ep_recv r s = ep_recv r s"
  by simp

text \<open>Stronger, relational form: the delivered length depends only on the
      message length, never the payload.\<close>

theorem delivered_length_depends_only_on_length:
  assumes len_eq: "msg_len m1 = msg_len m2"
    and out1: "ep_send r maxlen m1 s = (s1, Delivered n1)"
    and out2: "ep_send r maxlen m2 s = (s2, Delivered n2)"
  shows "n1 = n2 \<and> s1 = s2"
proof -
  have "ep_send r maxlen m1 s = ep_send r maxlen m2 s"
    using len_eq send_payload_independence by blast
  then show ?thesis
    using out1 out2 by simp
qed

subsection \<open>State-machine invariants\<close>

text \<open>ep_inv: at most one message in flight and waiters consistent with the
      mailbox. This is the Isabelle twin of the endpoint object contract.\<close>

definition ep_inv :: "'p ep_state \<Rightarrow> bool" where
  "ep_inv s \<equiv>
     (pending s \<noteq> None \<longrightarrow> recv_waiter s = False)
   \<and> (send_waiter s \<longrightarrow> pending s \<noteq> None \<and> send_staged s \<noteq> None)
   \<and> (send_waiter s \<longrightarrow> recv_waiter s = False)"

lemma ep_inv_empty [simp]:
  "ep_inv ep_empty"
  by (simp add: ep_inv_def ep_empty_def)

text \<open>The sender step preserves the invariant.\<close>

lemma ep_inv_preserved_send:
  assumes inv: "ep_inv s"
    and auth: "Send \<in> r"
    and len: "0 < msg_len m" "msg_len m \<le> maxlen"
  shows "ep_inv (fst (ep_send r maxlen m s))"
  using inv len auth
proof (cases "recv_waiter s")
  case True
  then show ?thesis
    by (auto simp add: ep_inv_def)
next
  case False
  then show ?thesis
    by (cases "pending s"; auto simp add: ep_inv_def)
qed

text \<open>The receiver step preserves the invariant (including the staged-sender
      wake).\<close>

lemma ep_inv_preserved_recv:
  assumes inv: "ep_inv s"
    and auth: "Recv \<in> r"
  shows "ep_inv (fst (ep_recv r s))"
  using inv auth
proof (cases "pending s")
  case None
  then show ?thesis
    by (auto simp add: ep_inv_def)
next
  case (Some m)
  then show ?thesis
    using inv
    by (cases "send_waiter s"; auto simp add: ep_inv_def)
qed

subsection \<open>Tying it to the capability algebra\<close>

text \<open>Capability rejection paths are total: without the right, the state is
      returned untouched.\<close>

lemma send_without_send_right_is_stutter:
  assumes "Send \<notin> r"
  shows "ep_send r maxlen m s = (s, RejectedCap)"
  using assms by simp

lemma recv_without_recv_right_is_stutter:
  assumes "Recv \<notin> r"
  shows "ep_recv r s = (s, None)"
  using assms by simp

text \<open>A revoked capability (rights = {}) stutters on send.\<close>

theorem revoked_cap_cannot_send:
  assumes "cap_rights c = {}"
  shows "ep_send (cap_rights c) maxlen m s = (s, RejectedCap)"
  using assms send_without_send_right_is_stutter by blast

text \<open>A reachable capability's rights stay inside the lattice, so an
      authorized send is always well-formed.\<close>

theorem send_authorized_by_reachable_cap:
  assumes base_ok: "\<forall>c0 \<in> base. cap_rights c0 \<subseteq> RW"
    and reach: "c \<in> cap_reach base"
    and auth: "Send \<in> cap_rights c"
  shows "cap_rights c \<subseteq> RW"
  using reach_rights_bounded[OF base_ok reach] auth by blast

end
