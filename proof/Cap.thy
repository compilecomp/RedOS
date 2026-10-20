theory Cap
  imports Main
begin

section \<open>Capability algebra (twin of kernel/src/cap.rs)\<close>

text \<open>
  The kernel's authority model in three sentences: authority is carried
  exclusively by capabilities; a capability names an endpoint plus a set of
  rights; the only way to create a capability is to mint it from an existing
  one with a subset of its rights. This theory formalizes the rights lattice,
  minting monotonicity, and the no-forgery property of the reachability
  relation. The Rust implementation uses a two-bit mask; here rights are a
  \<open>right set\<close> -- the map between the two representations is the
  identity on {Send, Recv}.
\<close>

datatype right = Send | Recv

type_synonym rights = "right set"

definition RW :: rights where
  "RW \<equiv> {Send, Recv}"

subsection \<open>Minting: only narrows\<close>

text \<open>Minting is legal iff the minted rights are a subset of the source
      rights (kernel/src/cap.rs @{text \<open>CTable::mint\<close>} rejects anything
      outside the lattice).\<close>

definition mint_ok :: "rights \<Rightarrow> rights \<Rightarrow> bool" where
  "mint_ok src new \<equiv> new \<subseteq> src"

lemma mint_reflexive [simp]:
  "mint_ok r r"
  by (simp add: mint_ok_def)

lemma mint_subset:
  "mint_ok src new \<Longrightarrow> new \<subseteq> src"
  by (simp add: mint_ok_def)

lemma mint_trans:
  "mint_ok a b \<Longrightarrow> mint_ok b c \<Longrightarrow> mint_ok a c"
  by (simp add: mint_ok_def)

lemma mint_narrow_rw:
  "mint_ok RW r"
  by (simp add: mint_ok_def RW_def)

subsection \<open>Capabilities and reachability (no forgery)\<close>

record cap =
  cap_ep :: nat
  cap_rights :: rights

text \<open>\<open>cap_reach\<close> is the set of capabilities derivable from a base set:
      nothing is in it unless it was given or minted from something in it.
      There is no other constructor -- that is the no-forgery statement.\<close>

inductive_set cap_reach :: "cap set \<Rightarrow> cap set" for base :: "cap set" where
  base: "c \<in> base \<Longrightarrow> c \<in> cap_reach base"
| mint_step: "\<lbrakk> c \<in> cap_reach base;
               cap_ep c' = cap_ep c;
               cap_rights c' \<subseteq> cap_rights c \<rbrakk> \<Longrightarrow> c' \<in> cap_reach base"

text \<open>No forgery, part 1: if the base set's rights are legal, every
      reachable capability's rights are legal (within the RW lattice).\<close>

lemma reach_rights_bounded:
  assumes base_ok: "\<forall>c0 \<in> base. cap_rights c0 \<subseteq> RW"
    and "c \<in> cap_reach base"
  shows "cap_rights c \<subseteq> RW"
  using assms(2)
proof (induct rule: cap_reach.induct)
  case base
  then show ?case
    using base_ok by blast
next
  case (mint_step c c')
  then show ?case
    using RW_def by blast
qed

text \<open>No forgery, part 2 (monotonicity): minting a reachable capability
      again only narrows rights on the same endpoint.\<close>

lemma mint_preserves_reach:
  assumes "c \<in> cap_reach base"
    and "cap_ep c' = cap_ep c"
    and "cap_rights c' \<subseteq> cap_rights c"
  shows "c' \<in> cap_reach base"
  using assms by (blast intro: cap_reach.mint_step)

text \<open>No forgery, part 3 (the endpoint anchor): rights can never move a
      capability to a different endpoint.\<close>

lemma reach_endpoint_stable:
  assumes "c \<in> cap_reach base"
    and "\<forall>c0 \<in> base. cap_ep c0 = \<E>"
  shows "cap_ep c = \<E>"
  using assms(2,1)
proof (induct rule: cap_reach.induct)
  case base
  then show ?case
    by blast
next
  case (mint_step c c')
  then show ?case
    by simp
qed

subsection \<open>Revocation is monotone (rights only shrink)\<close>

definition revoked :: "cap \<Rightarrow> cap" where
  "revoked c \<equiv> c\<lparr> cap_rights := {} \<rparr>"

lemma revoked_narrows:
  "cap_rights (revoked c) \<subseteq> cap_rights c"
  by (simp add: revoked_def)

lemma revoked_in_reach:
  assumes "c \<in> cap_reach base"
  shows "revoked c \<in> cap_reach base"
proof (rule mint_preserves_reach[OF assms])
  show "cap_ep (revoked c) = cap_ep c"
    by (simp add: revoked_def)
next
  show "cap_rights (revoked c) \<subseteq> cap_rights c"
    by (simp add: revoked_def)
qed

text \<open>A revoked (rights = {}) capability authorizes nothing: both IPC
      operations require nonempty rights.\<close>

lemma empty_rights_authorize_nothing:
  assumes "cap_rights c = {}"
  shows "\<not> Send \<in> cap_rights c" and "\<not> Recv \<in> cap_rights c"
  using assms by blast+

end
