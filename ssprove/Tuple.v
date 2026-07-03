
From SSProve.Relational Require Import OrderEnrichedCategory GenericRulesSimple.

Set Warnings "-notation-overridden,-ambiguous-paths".
From mathcomp Require Import all_ssreflect all_algebra reals distr realsum
  ssrnat ssreflect ssrfun ssrbool ssrnum eqtype choice seq.
Set Warnings "notation-overridden,ambiguous-paths".
Unset SsrOldRewriteGoalsOrder. (* remove the line when requiring MathComp >= 2.6 *)

From SSProve.Crypt Require Import Axioms ChoiceAsOrd SubDistr Couplings
  UniformDistrLemmas FreeProbProg Theta_dens RulesStateProb UniformStateProb
  pkg_core_definition choice_type pkg_composition pkg_rhl
  Package Prelude.

From Stdlib Require Import Utf8.
From extructures Require Import ord fset fmap.
From Hammer Require Import Tactics.

Set Bullet Behavior "Strict Subproofs".
Set Default Goal Selector "!".
Set Primitive Projections.

Import Num.Def.
Import Num.Theory.

Import PackageNotation.

(* Bijection between an m-tuple of ['fin n] and ['fin(n ^ m)]. *)
Section VecFinBij.
  Variables (n_vec m_vec : nat).

  Lemma card_tuple_fin : #|{:m_vec.-tuple 'I_n_vec}| = (n_vec ^ m_vec)%N.
  Proof. by rewrite card_tuple card_ord. Qed.

  Definition tuple_fin_to_fin (t : m_vec.-tuple 'I_n_vec) : 'I_(n_vec ^ m_vec)%N :=
    cast_ord card_tuple_fin (enum_rank t).

  Definition fin_to_tuple_fin (i : 'I_(n_vec ^ m_vec)%N) : m_vec.-tuple 'I_n_vec :=
    enum_val (cast_ord (esym card_tuple_fin) i).

  Lemma tuple_fin_to_finK : cancel tuple_fin_to_fin fin_to_tuple_fin.
  Proof.
    move=> t.
    rewrite /tuple_fin_to_fin /fin_to_tuple_fin.
    rewrite [in LHS](cast_ord_comp card_tuple_fin (esym card_tuple_fin)).
    have H : etrans card_tuple_fin (esym card_tuple_fin) = erefl by apply: eq_irrelevance.
    rewrite H cast_ord_id.
    by rewrite enum_rankK.
  Qed.

  Lemma fin_to_tuple_finK : cancel fin_to_tuple_fin tuple_fin_to_fin.
  Proof.
    move=> i.
    rewrite /tuple_fin_to_fin /fin_to_tuple_fin.
    set j := cast_ord (esym card_tuple_fin) i.
    have H : enum_rank (enum_val j) = j by apply: enum_valK.
    by rewrite H cast_ordKV.
  Qed.

  Lemma tuple_fin_bij : bijective tuple_fin_to_fin.
  Proof. exact: (Bijective tuple_fin_to_finK fin_to_tuple_finK). Qed.
End VecFinBij.

(* ------------------------------------------------------------------------ *)
(*  Heterogeneous product splitting for finite types                        *)
(*  'I_(p * q)  <->  'I_p * 'I_q, and 3-way variant                          *)
(* ------------------------------------------------------------------------ *)

Section FinPairSplit.
  Variables (p q : nat).

  Lemma ltn_div_mul (i : 'I_(p * q)) : i %/ q < p.
  Proof.
    case: p i => [|p'] i; first by case: i.
    case: q i => [|q'] i; first by case: i.
    rewrite (ltn_divLR _ _ (ltn0Sn q')).
    exact: (ltn_ord i).
  Qed.


  Lemma ltn_mod_mul (i : 'I_(p * q)) : i %% q < q.
  Proof.
    have Hpos : 0 < p * q by apply: (leq_ltn_trans (leq0n (i : nat)) (ltn_ord i)).
    rewrite muln_gt0 in Hpos.
    case/andP: Hpos => _ Hq.
    apply: ltn_pmod.
    exact: Hq.
  Qed.

  Definition fin_split2 (i : 'I_(p * q)) : 'I_p * 'I_q :=
    (Ordinal (ltn_div_mul i), Ordinal (ltn_mod_mul i)).

  Lemma ltn_combine2 (i : 'I_p) (j : 'I_q) : i * q + j < p * q.
  Proof.
    case: p i => [|p'] i; first by case: i.
    case: q j => [|q'] j; first by case: j.
    rewrite -[(i * _ + j).+1]addnS.
    apply: (leq_trans (n := (i : nat) * q'.+1 + q'.+1)).
    - rewrite leq_add2l. exact: ltn_ord j.
    - rewrite addnC -mulSn. apply: leq_mul; [exact: ltn_ord i | exact: leqnn].
  Qed.

  Definition fin_combine2 (ij : 'I_p * 'I_q) : 'I_(p * q) :=
    let '(i, j) := ij in Ordinal (ltn_combine2 i j).

  Lemma fin_split2K : cancel fin_split2 fin_combine2.
  Proof.
    have H0 : 'I_0 -> False
      by move=> i0; case: i0; move=> m Hm; by move: Hm; rewrite ltn0; discriminate.
    move=> i; apply: val_inj => /=.
    case: p i => [|p'] i; first by exfalso; apply: H0; exact: i.
    case: q i => [|q'] i; first by exfalso; apply: H0; exact: (cast_ord (muln0 _) i).
    rewrite /fin_combine2 /=.
    by rewrite -(divn_eq (i : nat) q'.+1).
  Qed.

  Lemma fin_combine2K : cancel fin_combine2 fin_split2.
  Proof.
    move=> [i j]; rewrite /fin_split2 /=.
    congr (_, _).
    - apply/val_eqP; rewrite /=.
      case: p i => [|p'] i; first by case: i.
      case: q j => [|q'] j; first by case: j.
      rewrite (divnMDl _ _ (ltn0Sn q')).
      by rewrite (divn_small (ltn_ord j)) addn0.
    - apply/val_eqP; rewrite /=.
      case: p i => [|p'] i; first by case: i.
      case: q j => [|q'] j; first by case: j.
      rewrite (modnMDl i j q'.+1).
      by rewrite (modn_small (ltn_ord j)).
  Qed.

  Lemma fin_split2_bij : bijective fin_split2.
  Proof. exact: (Bijective fin_split2K fin_combine2K). Qed.
End FinPairSplit.

Section FinTripleSplit.
  Variables (p q r : nat).

  Definition fin_split3 (i : 'I_(p * q * r)) : 'I_p * 'I_q * 'I_r :=
    let '(ij, k) := @fin_split2 (p * q) r i in
    let '(i', j)  := @fin_split2 p q ij in
    (i', j, k).

  Definition fin_combine3 (ijk : 'I_p * 'I_q * 'I_r) : 'I_(p * q * r) :=
    let ij : 'I_p * 'I_q := ijk.1 in
    let k  : 'I_r := ijk.2 in
    let i_j : 'I_(p * q) := fin_combine2 p q ij in
    let ik : 'I_(p * q) * 'I_r := (i_j, k) in
    fin_combine2 (p * q) r ik.

  Lemma fin_split3K : cancel fin_split3 fin_combine3.
  Proof.
    move=> i; rewrite /fin_split3 /fin_combine3.
    apply: val_inj; rewrite /=.
    by rewrite -divn_eq -divn_eq.
  Qed.

  Lemma fin_combine3K : cancel fin_combine3 fin_split3.
  Proof.
    move=> [[i j] k]; rewrite /fin_split3 /fin_combine3 /=.
    have Hq : 0 < q by apply: (leq_ltn_trans (leq0n (j : nat)) (ltn_ord j)).
    have Hr : 0 < r by apply: (leq_ltn_trans (leq0n (k : nat)) (ltn_ord k)).
    congr (_,_); last first.
    - apply/val_eqP; rewrite /=.
      by rewrite (modnMDl (i * q + j) k r) modn_small.
    - congr (_,_).
      + apply/val_eqP; rewrite /=.
        by rewrite (divnMDl _ _ Hr) (divn_small (ltn_ord k)) addn0
                   (divnMDl _ _ Hq) (divn_small (ltn_ord j)) addn0.
      + apply/val_eqP; rewrite /=.
        by rewrite (divnMDl _ _ Hr) (divn_small (ltn_ord k)) addn0
                   (modnMDl i j q) modn_small.
  Qed.

  Lemma fin_split3_bij : bijective fin_split3.
  Proof. exact: (Bijective fin_split3K fin_combine3K). Qed.
End FinTripleSplit.
