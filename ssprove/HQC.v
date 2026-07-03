(******************************************************************************)
(*  HQC IND-CPA Advantage                                                     *)
(*                                                                            *)
(*  The quotient ring R = F₂[X]/(Xⁿ-1) via mathcomp's qpoly.v.       *)
(*  Bijection with ['fin (2 ^ n)] via to_int/of_int.                        *)
(******************************************************************************)

Set Warnings "-notation-overridden,-ambiguous-paths".
From mathcomp Require Import all_ssreflect all_algebra reals distr realsum ssralg.
From mathcomp Require Import poly polydiv qpoly.
Set Warnings "notation-overridden,ambiguous-paths".
Unset SsrOldRewriteGoalsOrder.
Open Scope ring_scope.
Import GRing.Theory.

From Stdlib Require Import Utf8.
From extructures Require Import ord fset fmap.
From Equations Require Import Equations.
Require Equations.Prop.DepElim.
Set Equations With UIP.
Set Bullet Behavior "Strict Subproofs".
Set Default Goal Selector "!".
Set Primitive Projections.

From HB Require Import structures.

From SSProve.Crypt Require Import NominalPrelude Package Prelude pkg_advantage.
Import PackageNotation.
From SSProveHQC Require Import Tuple.
#[local] Open Scope package_scope.
#[local] Open Scope ring_scope.

Module Type RqParams.
  Parameter n : nat.
  Parameter n_gt1 : (1 < n)%N.
End RqParams.

Module RqRing (P : RqParams).
  Import P.
  Definition F2 := 'F_2.
  Notation polyF2 := {poly F2}.
  Definition gen : polyF2 := 'X ^+ n - 1%:P.

  Lemma gen_monic : gen \is monic.
  Proof.
    rewrite /gen monicE lead_coefXnsubC //.
    exact: ltnW n_gt1.
  Qed.

  Lemma size_gen : (size gen = n.+1)%N.
  Proof.
    rewrite /gen size_XnsubC //.
    exact: ltnW n_gt1.
  Qed.

  Lemma size_mk_monic_gen : size (mk_monic gen) = n.+1.
  Proof.
    rewrite /mk_monic.
    move: (ltn_trans n_gt1 (ltnSn n)).
    rewrite size_gen => H_gt1.
    rewrite H_gt1 gen_monic /=.
    apply: size_gen.
  Qed.

  Definition Rq := {poly %/ gen}.
End RqRing.

(* ==================================================================== *)
Module Type HQCParams.
  Parameter n     : nat.
  Parameter n1n2  : nat.
  Parameter k     : nat.
  Parameter seed_size : nat.
  Parameter w     : nat.
  Parameter wr    : nat.
  Parameter we    : nat.
  Parameter n_gt1      : (1 < n)%N.
  Parameter n1n2_gt0   : (0 < n1n2)%N.
  Parameter n1n2_le_n  : (n1n2 <= n)%N.
  Parameter k_gt0      : (0 < k)%N.
  Parameter seed_size_gt0 : (0 < seed_size)%N.
  Parameter w_gt0      : (0 < w)%N.
  Parameter wr_gt0     : (0 < wr)%N.
  Parameter we_gt0     : (0 < we)%N.

  Module RingP.
    Definition n := n.
    Definition n_gt1 := n_gt1.
  End RingP.
  Module Ring := RqRing RingP.

  Parameter encode     : 'fin (2^k)%N -> Ring.Rq.
  Parameter decode     : Ring.Rq -> 'fin (2^k)%N.
End HQCParams.

Module HQC1 <: HQCParams.
  Definition n := 17669%N. Definition n1n2 := 17664%N. Definition k := 128%N.
  Definition seed_size := (2 ^ k)%N.
  Definition w := 66%N.    Definition wr := 75%N.     Definition we := 75%N.
  Lemma n_gt1     : (1 < n)%N.     Proof. done. Qed.
  Lemma n1n2_gt0  : (0 < n1n2)%N.  Proof. done. Qed.
  Lemma n1n2_le_n : (n1n2 <= n)%N. Proof. done. Qed.
  Lemma k_gt0     : (0 < k)%N.     Proof. done. Qed.
  Lemma seed_size_gt0 : (0 < seed_size)%N. Proof. done. Qed.
  Lemma w_gt0     : (0 < w)%N.     Proof. done. Qed.
  Lemma wr_gt0    : (0 < wr)%N.    Proof. done. Qed.
  Lemma we_gt0    : (0 < we)%N.    Proof. done. Qed.

  Module RingP.
    Definition n := n.
    Definition n_gt1 := n_gt1.
  End RingP.
  Module Ring := RqRing RingP.

  Parameter encode     : 'fin (2^k)%N -> Ring.Rq.
  Parameter decode     : Ring.Rq -> 'fin (2^k)%N.
End HQC1.

Module HQC3 <: HQCParams.
  Definition n := 35851%N. Definition n1n2 := 35840%N. Definition k := 192%N.
  Definition seed_size := (2 ^ k)%N.
  Definition w := 100%N.   Definition wr := 114%N.     Definition we := 114%N.
  Lemma n_gt1     : (1 < n)%N.     Proof. done. Qed.
  Lemma n1n2_gt0  : (0 < n1n2)%N.  Proof. done. Qed.
  Lemma n1n2_le_n : (n1n2 <= n)%N. Proof. done. Qed.
  Lemma k_gt0     : (0 < k)%N.     Proof. done. Qed.
  Lemma seed_size_gt0 : (0 < seed_size)%N. Proof. done. Qed.
  Lemma w_gt0     : (0 < w)%N.     Proof. done. Qed.
  Lemma wr_gt0    : (0 < wr)%N.    Proof. done. Qed.
  Lemma we_gt0    : (0 < we)%N.    Proof. done. Qed.

  Module RingP.
    Definition n := n.
    Definition n_gt1 := n_gt1.
  End RingP.
  Module Ring := RqRing RingP.

  Parameter encode     : 'fin (2^k)%N -> Ring.Rq.
  Parameter decode     : Ring.Rq -> 'fin (2^k)%N.
End HQC3.

Module HQC5 <: HQCParams.
  Definition n := 57637%N. Definition n1n2 := 57600%N. Definition k := 256%N.
  Definition seed_size := (2 ^ k)%N.
  Definition w := 131%N.   Definition wr := 149%N.     Definition we := 149%N.
  Lemma n_gt1     : (1 < n)%N.     Proof. done. Qed.
  Lemma n1n2_gt0  : (0 < n1n2)%N.  Proof. done. Qed.
  Lemma n1n2_le_n : (n1n2 <= n)%N. Proof. done. Qed.
  Lemma k_gt0     : (0 < k)%N.     Proof. done. Qed.
  Lemma seed_size_gt0 : (0 < seed_size)%N. Proof. done. Qed.
  Lemma w_gt0     : (0 < w)%N.     Proof. done. Qed.
  Lemma wr_gt0    : (0 < wr)%N.    Proof. done. Qed.
  Lemma we_gt0    : (0 < we)%N.    Proof. done. Qed.

  Module RingP.
    Definition n := n.
    Definition n_gt1 := n_gt1.
  End RingP.
  Module Ring := RqRing RingP.

  Parameter encode     : 'fin (2^k)%N -> Ring.Rq.
  Parameter decode     : Ring.Rq -> 'fin (2^k)%N.
End HQC5.

(* ==================================================================== *)
Module HQC (P : HQCParams).
  Import P.

  Module Ring := P.Ring.
  Import Ring.

  (** ------------------------------------------------------------------ *)
  (**  Bijection Rq ≅ ['fin (2^n)]                                        *)
  (**                                                                     *)
  (**  Since Rq = F₂[X]/(Xⁿ-1), every element is uniquely determined      *)
  (**  by its n-bit coefficient vector.  This bijection lets us sample     *)
  (**  from Rq via [sample uniform (2^n)] and use [r_uniform_bij]          *)
  (**  in relational proofs (see OTP.v for the pattern).                   *)
  (** ------------------------------------------------------------------ *)

  (** Extract the first [n] coefficients of a polynomial as a nat < 2ⁿ. *)
  Fixpoint nat_of_polyF2 (p : {poly F2}) (pos n : nat) : nat :=
    match n with
    | 0    => 0%N
    | n'.+1 =>
      ((if coefp pos p == 1%R then (2^pos)%N else 0%N)
       + nat_of_polyF2 p (pos.+1) n')%N
    end.

  Lemma nat_of_polyF2_bound_general (p : {poly F2}) (pos n : nat) :
     (nat_of_polyF2 p pos n + 2^pos ≤ 2^(pos + n))%N.
  Proof.
    apply/leP.
    elim: n => [|n IHn] in pos *.
    - rewrite /= add0n addn0. done.
    - rewrite /=. case_eq (p`_pos == 1)%B.
      + move => Ppos. rewrite Ppos -addnA addnC -addnA addnn -(mul2n (2 ^ pos)) -expnS.
        rewrite addnS -addSn. apply: (IHn pos.+1).
      + move => Ppos. rewrite Ppos add0n. rewrite addnS -addSn.
        pose A := nat_of_polyF2 p pos.+1 n.
        pose B := expn 2 pos.
        pose C := expn 2 pos.+1.
        pose D := expn 2 (addn pos.+1 n).
        move: (IHn pos.+1); rewrite /A /C /D => IH.
        apply: (leq_trans (n := addn A C) _ IH).
        rewrite leq_add2l.
        exact: (leq_pexp2l _ _).
  Qed.

  Lemma nat_of_polyF2_bound (p : {poly F2}) (n : nat) :
    (nat_of_polyF2 p 0 n < 2^n)%N.
  Proof.
    apply/ltP; unfold lt.
    move: (nat_of_polyF2_bound_general p 0 n).
    rewrite expn0 add0n addn1. exact.
  Qed.

  Definition rq_to_fin (x : Rq) : 'fin (2^n) :=
    let val := nat_of_polyF2 (x : {poly F2}) 0 n in
    Ordinal (nat_of_polyF2_bound (x : {poly F2}) n).

  (** Build a polynomial from the binary representation of a nat. *)
  Fixpoint polyF2_of_nat (m : nat) (pos : nat) (n : nat) : {poly F2} :=
    match n with
    | 0    => 0
    | n'.+1 =>
      ((m %% 2)%:R : F2) *: 'X^pos + polyF2_of_nat (m %/ 2) (pos.+1) n'
    end.

  Lemma nat_of_polyF2_add_poly (p q : {poly F2}) pos len :
    (forall i, (i < len)%N -> p`_(pos + i)%N = 0) ->
    nat_of_polyF2 (p + q) pos len = nat_of_polyF2 q pos len.
  Proof.
    elim: len => [|len IH] in pos *.
    - done.
    - move=> Hp.
      rewrite /=.
      have Hcoef : (p + q)`_pos = q`_pos.
      { rewrite coefD.
        have -> : p`_pos = 0.
        { have := Hp 0%N. rewrite addn0. apply. done. }
        by rewrite add0r. }
      rewrite Hcoef.
      congr (_ + _)%N.
      apply: IH => i Hi.
      have -> : (pos.+1+i = pos + i.+1)%N by rewrite addnS.
      apply: Hp.
      by rewrite ltnS.
  Qed.

  Lemma coef_scale_Xn (c : F2) (pos : nat) (i : nat) :
    (pos < i)%N ->
    (c *: 'X ^+ pos)`_i = 0.
  Proof.
    move=> Hi.
    rewrite coefZ coefXn.
    case: eqP => [Heq | _].
    - subst. by rewrite ltnn in Hi.
    - by rewrite mulr0.
  Qed.

  Lemma coef_polyF2_of_nat (m : nat) (pos : nat) (len : nat) (i : nat) :
    (i < pos)%N ->
    (polyF2_of_nat m pos len)`_i = 0.
  Proof.
    elim: len => [|len IH] in m pos i *.
    - rewrite /= coef0. done.
    - rewrite /= coefD coefZ coefXn.
      move=> Hi.
      case: eqP => [Heq | _].
      + subst. by rewrite ltnn in Hi.
      + rewrite mulr0 add0r.
        apply: IH.
        exact: ltnW.
  Qed.

  Lemma nat_of_polyF2_of_nat (m : nat) (pos : nat) (len : nat) :
    (m < 2^len)%N ->
    nat_of_polyF2 (polyF2_of_nat m pos len) pos len = (m * 2^pos)%N.
  Proof.
    elim: len => [|len IH] in m pos *.
    - rewrite /=. move=> H.
      have -> : m = 0%N.
      { move: H. by case: m. }
      done.
    - move=> H.
      have Hdiv : (m %/ 2 < 2^len)%N.
      { rewrite -ltn_double.
        have H_le : ((m %/ 2).*2 <= m)%N.
        { rewrite {2}(divn_eq m 2). rewrite -muln2. exact: leq_addr. }
        have H_lt : (m < (2^len).*2)%N.
        { move: H. by rewrite expnS mul2n. }
        exact: leq_ltn_trans H_le H_lt. }
      (* Prove the coef at pos *)
      have Hcoef : (polyF2_of_nat m pos len.+1)`_pos = ((m %% 2)%:R : F2).
      { rewrite /= coefD coefZ coefXn eq_refl mulr1.
        have -> : (polyF2_of_nat (m %/ 2) pos.+1 len)`_pos = 0.
        { apply: coef_polyF2_of_nat. exact: ltnSn. }
        by rewrite addr0. }
      (* Prove the tail equality using add_poly *)
      have Hrest : nat_of_polyF2 (polyF2_of_nat m pos len.+1) pos.+1 len =
                   nat_of_polyF2 (polyF2_of_nat (m %/ 2) pos.+1 len) pos.+1 len.
      { apply: (nat_of_polyF2_add_poly ((m %% 2)%:R *: 'X ^+ pos)).
        move=> i Hi.
        apply: coef_scale_Xn.
        by rewrite ltnS leq_addr. }
      (* Now unfold nat_of_polyF2 one step, keeping polyF2_of_nat locked *)
      set P := polyF2_of_nat m pos len.+1.
      rewrite /= Hcoef Hrest (IH (m %/ 2)%N pos.+1 Hdiv).
      (* Case split on m %% 2 being 0 or 1 *)
      have Hodd : (m %% 2)%N = 0%N \/ (m %% 2)%N = 1%N.
      { have Hlt := ltn_mod m 2.
        case: (m %% 2)%N Hlt => [|[|k]] Hk.
        - by left.
        - by right.
        - by rewrite !ltnS ltn0 in Hk. }
      case: Hodd => Hmod.
      + (* Even: m %% 2 = 0, so (m%%2)%:R = 0 in F2 *)
        have HF2 : ((m %% 2)%:R : F2) = 0 by rewrite Hmod.
        rewrite HF2 /=.
        have Hm : m = (m %/ 2 * 2)%N.
        { rewrite {1}(divn_eq m 2) Hmod addn0. done. }
        rewrite add0n.
        rewrite {2}Hm ssrnat.expnS.
        by rewrite ssrnat.mulnA.
      + (* Odd: m %% 2 = 1, so (m%%2)%:R = 1 in F2 *)
        have HF2 : ((m %% 2)%:R : F2) = 1 by rewrite Hmod.
        rewrite HF2 eq_refl /=.
        have Hm : m = (m %/ 2 * 2 + 1)%N.
        { rewrite {1}(divn_eq m 2) Hmod. done. }
        rewrite {2}Hm mulnDl ssrnat.mul1n addnC.
        by rewrite ssrnat.expnS -ssrnat.mulnA.
  Qed.

  Lemma size_polyF2_of_nat m pos len :
    (size (polyF2_of_nat m pos len) <= pos + len)%N.
  Proof.
    elim: len => [|len IH] in m pos *.
    - rewrite /= size_poly0. exact: leq0n.
    - rewrite /=.
      apply: leq_trans (size_polyD _ _) _.
      rewrite geq_max.
      apply/andP; split.
      + set c := ((m %% 2)%:R : F2).
        have size_c_X : (size (c *: 'X^pos) <= pos.+1)%N.
        * apply: leq_trans (size_scale_leq _ _) _. rewrite size_polyXn. by [].
        * apply: leq_trans size_c_X _. by rewrite addnS leq_addr.
      + have H := IH (m %/ 2)%N pos.+1.
        rewrite addSnnS in H.
        exact: H.
  Qed.

  Definition fin_to_rq (i : 'fin (2^n)) : Rq :=
    in_qpoly gen (polyF2_of_nat (nat_of_ord i) 0 n).

  (** Helper: CodeSeq.code is strictly increasing with sequence length.    *)
  Lemma code_cons_gt (n : nat) (s : seq nat) :
    (CodeSeq.code s < CodeSeq.code (n :: s))%N.
  Proof.
    rewrite /CodeSeq.code /=.
    set c := foldr _ 0 s.
    have Hc : (c < c.*2.+1)%N by elim: c => [|c' IH] //=; rewrite doubleS; exact: ltnW.
    exact: leq_trans Hc (leq_pmull (c.*2.+1) (expn_gt0 2 n)).
  Qed.

  Lemma polyF2_of_nat_shift m pos len :
    polyF2_of_nat m pos len = 'X ^+ pos * polyF2_of_nat m 0 len.
  Proof.
    elim: len => [|len IH] in m pos *.
    - rewrite /= mulr0. done.
    - rewrite /= IH [in RHS]IH.
      rewrite expr1.
      rewrite mulrDr.
      rewrite mulrA.
      rewrite -exprSr.
      (* Now we need to prove:
         (m %% 2)%:R *: 'X ^+ pos = 'X ^+ pos * ((m %% 2)%:R *: 'X ^+ 0) *)
      rewrite expr0.
      congr (_ + _).
      rewrite mulr_algr.
      done.
  Qed.

  Lemma nat_of_polyF2_shift p pos len :
    nat_of_polyF2 p pos len = (2^pos * nat_of_polyF2 (drop_poly pos p) 0 len)%N.
  Proof.
    elim: len => [|len IH] in p pos *.
    - rewrite /= muln0. done.
    - rewrite /=.
      have Hcoef : (drop_poly pos p)`_0 = p`_pos.
      { by rewrite coef_drop_poly add0n. }
      rewrite Hcoef.
      have Hdrop : drop_poly 1 (drop_poly pos p) = drop_poly pos.+1 p.
      { apply/polyP => i. by rewrite !coef_drop_poly addn1 addnS. }
      rewrite (IH (drop_poly pos p) 1) Hdrop.
      rewrite mulnDr.
      congr (_ + _)%N.
      + case: (p`_pos == 1)%B => /=.
        * by rewrite muln1.
        * by rewrite muln0.
      + rewrite mulnA.
        have H_eq : (2^pos * 2)%N = (2^pos.+1)%N by rewrite mulnC -expnS.
        by rewrite H_eq.
  Qed.

  Lemma polyF2_takeK p len :
    polyF2_of_nat (nat_of_polyF2 p 0 len) 0 len = take_poly len p.
  Proof.
    have H_F2 (x : F2) : x = (if x == 1 then 1 else 0)%R.
    { case: x => [[|[|j]] c] //=; apply/eqP; done. }
    elim: len => [|len IH] in p *.
    - rewrite /= take_poly0l. done.
    - rewrite /= nat_of_polyF2_shift.
      set b := if p`_0 == 1 then 1%N else 0%N.
      set K := nat_of_polyF2 (drop_poly 1 p) 0 len.
      have Hb : (b < 2)%N.
      { rewrite /b. case: (p`_0 == 1)%B => /=; done. }
      have Hdiv : ((b + 2 * K) %/ 2 = K)%N.
      { by rewrite mulnC divnDMl // divn_small. }
      have Hmod : ((b + 2 * K) %% 2 = b)%N.
      { by rewrite mulnC addnC modnMDl modn_small. }
      rewrite /=.
      rewrite Hmod Hdiv.
      rewrite expr0 polyF2_of_nat_shift.
      rewrite IH.
      apply/polyP => i.
      rewrite alg_polyC !coefE.
      case: i => [|i].
      + rewrite /= addr0 /b.
        have -> : p`_0 = (if p`_0 == 1 then 1 else 0) by exact: H_F2.
        case: (p`_0 == 1)%B => /=; done.
      + rewrite /= add0r.
        rewrite subn1 addn1.
        done.
  Qed.

  Lemma polyF2_natK (p : {poly F2}) : (size p <= n)%N ->
    polyF2_of_nat (nat_of_polyF2 p 0 n) 0 n = p.
  Proof.
    move=> Hsize.
    rewrite polyF2_takeK.
    exact: take_poly_id.
  Qed.

  Lemma rq_to_finK : cancel rq_to_fin fin_to_rq.
  Proof.
    move=> x.
    rewrite /rq_to_fin /fin_to_rq /=.
    apply: val_inj.
    change ((in_qpoly gen (polyF2_of_nat (nat_of_polyF2 (x : {poly F2}) 0 n) 0 n) : {poly F2}) = (x : {poly F2})).
    rewrite in_qpoly_small.
    { apply: leq_ltn_trans (size_polyF2_of_nat (nat_of_polyF2 (x : {poly F2}) 0 n) 0 n) _.
      rewrite size_mk_monic_gen.
      exact: ltnSn. }
    apply: polyF2_natK.
    move: (size_npoly x) => Hsize.
    apply: leq_trans Hsize _.
    rewrite size_mk_monic_gen.
    exact: leqnn.
  Qed.

  Lemma fin_to_rqK : cancel fin_to_rq rq_to_fin.
  Proof.
    move=> i.
    rewrite /fin_to_rq /rq_to_fin /=.
    apply: val_inj => /=.
    change (Pdiv.CommonRing.rmodp (polyF2_of_nat i 0 n) (mk_monic gen)) with ((in_qpoly gen (polyF2_of_nat i 0 n) : {poly F2})).
    rewrite in_qpoly_small.
    { apply: leq_ltn_trans (size_polyF2_of_nat i 0 n) _.
      rewrite size_mk_monic_gen.
      exact: ltnSn. }
    rewrite /=.
    rewrite nat_of_polyF2_of_nat.
    { exact: ltn_ord. }
    by rewrite muln1.
  Qed.
 
  Lemma rq_fin_bij : bijective rq_to_fin.
  Proof.
    exact: (Bijective rq_to_finK fin_to_rqK).
  Qed.

  Definition wt (x : Rq) : nat :=
    \sum_(i < n) (if @nth F2 0%R (x : polyF2) i == 1%R then 1 else 0).

  Definition rq_to_set (x : Rq) : {set 'fin n} :=
    [set i : 'fin n | @nth F2 0%R (x : polyF2) i == 1%R].

  Definition set_to_rq (s : {set 'fin n}) : Rq :=
    in_qpoly gen (\poly_(i < n) (if (insub i : option ('fin n)) is Some ord_i then (if ord_i \in s then 1%R : F2 else 0%R : F2) else 0%R : F2)).

  Lemma wt_eq_card (x : Rq) : wt x = #|rq_to_set x|.
  Proof.
    rewrite /wt /rq_to_set.
    rewrite cardE size_filter -big_mkcond -sum1_count /=.
    apply: eq_bigl => j; rewrite in_set.
    done.
  Qed.

  Lemma rq_to_setK : cancel rq_to_set set_to_rq.
  Proof.
    move=> x.
    rewrite /rq_to_set /set_to_rq /=.
    apply: val_inj => /=.
    have Hpoly : \poly_(i < n) (if (insub i : option ('fin n)) is Some ord_i then (if ord_i \in rq_to_set x then 1%R : F2 else 0%R : F2) else 0%R : F2) = (x : polyF2).
    { apply/polyP => i.
      rewrite coef_poly.
      case: ifP => Hi.
      - have Hinsub : (insub i : option ('fin n)) = Some (Ordinal Hi) by apply: insubT.
        rewrite Hinsub /=.
        rewrite in_set /=.
        case: ifP => [/eqP -> // | /eqP Hnot].
        have -> : @nth F2 0%R (x : polyF2) i = 0.
        { case: (x`_i) => [[|[|c]] Hc] /= in Hnot *.
          - apply: val_inj => /=. done.
          - exfalso. apply: Hnot. apply: val_inj => /=. done.
          - by []. }
        done.
      - move: (size_npoly x) => Hsize.
        rewrite nth_default; last by [].
        apply: leq_trans Hsize _.
        by rewrite size_mk_monic_gen /= leqNgt Hi. }
    rewrite Hpoly.
    rewrite Pdiv.CommonRing.rmodp_small.
    { apply: leq_ltn_trans (size_npoly x) _.
      rewrite size_mk_monic_gen.
      exact: ltnSn. }
    done.
  Qed.

  Lemma set_to_rqK : cancel set_to_rq rq_to_set.
  Proof.
    move=> s.
    rewrite /rq_to_set /set_to_rq /=.
    apply/setP => i.
    rewrite in_set.
    have Hsz : (size (\poly_(i0 < n) (if (insub i0 : option ('fin n)) is Some ord_i0 then (if ord_i0 \in s then 1%R : F2 else 0%R : F2) else 0%R : F2)) <= n)%N.
    { exact: size_poly. }
    rewrite Pdiv.CommonRing.rmodp_small.
    { apply: leq_ltn_trans Hsz _.
      rewrite size_mk_monic_gen.
      exact: ltnSn. }
    rewrite coef_poly ltn_ord.
    have Hinsub : (insub (\val i) : option ('fin n)) = Some i by rewrite valK.
    rewrite Hinsub.
    case: ifP => Hin.
    - by rewrite eq_refl.
    - by [].
  Qed.

  Definition Rq_w : finType := {x : Rq | (wt x == w)%B}.

  Definition rq_w_to_set_w (x : Rq_w) : {s : {set 'fin n} | (#|s| == w)%B}.
  Proof.
    exists (rq_to_set (\val x)).
    have Hwt := (valP x).
    by rewrite -wt_eq_card (eqP Hwt).
  Defined.

  Definition set_w_to_rq_w (s : {s : {set 'fin n} | (#|s| == w)%B}) : Rq_w.
  Proof.
    exists (set_to_rq (\val s)).
    apply/eqP.
    by rewrite wt_eq_card set_to_rqK (eqP (valP s)).
  Defined.

  Lemma rq_w_to_set_wK : cancel rq_w_to_set_w set_w_to_rq_w.
  Proof.
    move=> x.
    apply: val_inj => /=.
    exact: rq_to_setK.
  Qed.

  Lemma set_w_to_rq_wK : cancel set_w_to_rq_w rq_w_to_set_w.
  Proof.
    move=> s.
    apply: val_inj => /=.
    exact: set_to_rqK.
  Qed.

  Lemma rq_w_set_w_bij : bijective rq_w_to_set_w.
  Proof.
    exact: (Bijective rq_w_to_set_wK set_w_to_rq_wK).
  Qed.

  Lemma card_Rq_w : #|Rq_w| = 'C(n, w).
  Proof.
    rewrite (bij_eq_card rq_w_set_w_bij).
    rewrite card_sub.
    have -> : [pred x : {set 'fin n} | #|x| == w] = [pred x in [set A : {set 'fin n} | #|A| == w]]; [ | rewrite card_draws card_ord; done ].
    congr SimplPred.
    apply: boolp.funext => x.
    by rewrite in_set.
  Qed.

  Definition rq_w_to_fin (x : Rq_w) : 'fin ('C(n, w)).
  Proof.
    apply: (@Ordinal ('C(n, w)) (index x (enum Rq_w))).
    rewrite -card_Rq_w cardE index_mem.
    exact: mem_enum.
  Defined.

  Definition fin_to_rq_w (i : 'fin ('C(n, w))) : Rq_w.
  Proof.
    case: (posnP #|Rq_w|) => [Hempty | Hnonempty].
    - exfalso.
      have Hlt0 := ltn_ord i.
      move: (\val i) Hlt0 => m Hlt0.
      rewrite -card_Rq_w in Hlt0.
      rewrite Hempty in Hlt0.
      by [].
    - case: (pickP (xpredT : pred Rq_w)) => [x0 _ | Hempty].
      + exact: (nth x0 (enum Rq_w) i).
      + move: Hnonempty.
        rewrite (eq_card Hempty) card0.
        by [].
  Defined.

  Lemma rq_w_to_finK : cancel rq_w_to_fin fin_to_rq_w.
  Proof.
    move=> x.
    apply: val_inj.
    rewrite /fin_to_rq_w.
    case: (posnP #|Rq_w|) => [Hempty | Hnonempty].
    - exfalso.
      have Hlt: (0 < #|Rq_w|)%N.
      { rewrite cardE.
        have: x \in enum Rq_w by exact: mem_enum.
        by case: (enum Rq_w). }
      rewrite Hempty in Hlt.
      by [].
    - case: (pickP (xpredT : pred Rq_w)) => [x0 _ | Hempty].
      + rewrite /=.
        congr sval.
        rewrite nth_index //=.
        exact: mem_enum.
      + exfalso.
        move: Hnonempty.
        rewrite (eq_card Hempty) card0.
        by [].
  Qed.

  Lemma fin_to_rq_wK : cancel fin_to_rq_w rq_w_to_fin.
  Proof.
    move=> i.
    apply: val_inj.
    rewrite /fin_to_rq_w.
    case: (posnP #|Rq_w|) => [Hempty | Hnonempty].
    - exfalso.
      have Hlt: (i < 0)%N.
      { have Hlt0 := ltn_ord i.
        move: (\val i) Hlt0 => m Hlt0.
        rewrite -card_Rq_w in Hlt0.
        rewrite Hempty in Hlt0.
        exact: Hlt0. }
      by [].
    - case: (pickP (xpredT : pred Rq_w)) => [x0 _ | Hempty].
      + rewrite /=.
        move: (\val i) (ltn_ord i) => m Hlt0.
        rewrite index_uniq //; last exact: enum_uniq.
        by rewrite -card_Rq_w cardE in Hlt0.
      + exfalso.
        move: Hnonempty.
        rewrite (eq_card Hempty) card0.
        by [].
  Qed.

  Lemma rq_w_fin_bij : bijective rq_w_to_fin.
  Proof.
    exact: (Bijective rq_w_to_finK fin_to_rq_wK).
  Qed.

  Definition Rq_we : finType := {x : Rq | (wt x == we)%B}.

  Definition rq_we_to_set_we (x : Rq_we) : {s : {set 'fin n} | (#|s| == we)%B}.
  Proof.
    exists (rq_to_set (\val x)).
    have Hwt := (valP x).
    by rewrite -wt_eq_card (eqP Hwt).
  Defined.

  Definition set_we_to_rq_we (s : {s : {set 'fin n} | (#|s| == we)%B}) : Rq_we.
  Proof.
    exists (set_to_rq (\val s)).
    apply/eqP.
    by rewrite wt_eq_card set_to_rqK (eqP (valP s)).
  Defined.

  Lemma rq_we_to_set_weK : cancel rq_we_to_set_we set_we_to_rq_we.
  Proof.
    move=> x.
    apply: val_inj => /=.
    exact: rq_to_setK.
  Qed.

  Lemma set_we_to_rq_weK : cancel set_we_to_rq_we rq_we_to_set_we.
  Proof.
    move=> s.
    apply: val_inj => /=.
    exact: set_to_rqK.
  Qed.

  Lemma rq_we_set_we_bij : bijective rq_we_to_set_we.
  Proof.
    exact: (Bijective rq_we_to_set_weK set_we_to_rq_weK).
  Qed.

  Lemma card_Rq_we : #|Rq_we| = 'C(n, we).
  Proof.
    rewrite (bij_eq_card rq_we_set_we_bij).
    rewrite card_sub.
    have -> : [pred x : {set 'fin n} | #|x| == we] = [pred x in [set A : {set 'fin n} | #|A| == we]]; [ | rewrite card_draws card_ord; done ].
    congr SimplPred.
    apply: boolp.funext => x.
    by rewrite in_set.
  Qed.

  Definition rq_we_to_fin (x : Rq_we) : 'fin ('C(n, we)).
  Proof.
    apply: (@Ordinal ('C(n, we)) (index x (enum Rq_we))).
    rewrite -card_Rq_we cardE index_mem.
    exact: mem_enum.
  Defined.

  Definition fin_to_rq_we (i : 'fin ('C(n, we))) : Rq_we.
  Proof.
    case: (posnP #|Rq_we|) => [Hempty | Hnonempty].
    - exfalso.
      have Hlt0 := ltn_ord i.
      move: (\val i) Hlt0 => m Hlt0.
      rewrite -card_Rq_we in Hlt0.
      rewrite Hempty in Hlt0.
      by [].
    - case: (pickP (xpredT : pred Rq_we)) => [x0 _ | Hempty].
      + exact: (nth x0 (enum Rq_we) i).
      + move: Hnonempty.
        rewrite (eq_card Hempty) card0.
        by [].
  Defined.

  Lemma rq_we_to_finK : cancel rq_we_to_fin fin_to_rq_we.
  Proof.
    move=> x.
    apply: val_inj.
    rewrite /fin_to_rq_we.
    case: (posnP #|Rq_we|) => [Hempty | Hnonempty].
    - exfalso.
      have Hlt: (0 < #|Rq_we|)%N.
      { rewrite cardE.
        have: x \in enum Rq_we by exact: mem_enum.
        by case: (enum Rq_we). }
      rewrite Hempty in Hlt.
      by [].
    - case: (pickP (xpredT : pred Rq_we)) => [x0 _ | Hempty].
      + rewrite /=.
        congr sval.
        rewrite nth_index //=.
        exact: mem_enum.
      + exfalso.
        move: Hnonempty.
        rewrite (eq_card Hempty) card0.
        by [].
  Defined.

  Lemma fin_to_rq_weK : cancel fin_to_rq_we rq_we_to_fin.
  Proof.
    move=> i.
    apply: val_inj.
    rewrite /fin_to_rq_we.
    case: (posnP #|Rq_we|) => [Hempty | Hnonempty].
    - exfalso.
      have Hlt: (i < 0)%N.
      { have Hlt0 := ltn_ord i.
        move: (\val i) Hlt0 => m Hlt0.
        rewrite -card_Rq_we in Hlt0.
        rewrite Hempty in Hlt0.
        exact: Hlt0. }
      by [].
    - case: (pickP (xpredT : pred Rq_we)) => [x0 _ | Hempty].
      + rewrite /=.
        move: (\val i) (ltn_ord i) => m Hlt0.
        rewrite index_uniq //; last exact: enum_uniq.
        by rewrite -card_Rq_we cardE in Hlt0.
      + exfalso.
        move: Hnonempty.
        rewrite (eq_card Hempty) card0.
        by [].
  Defined.

  Lemma rq_we_fin_bij : bijective rq_we_to_fin.
  Proof.
    exact: (Bijective rq_we_to_finK fin_to_rq_weK).
  Qed.

End HQC.

Module HQC_Security (P : HQCParams).
  Include HQC P.
  Import P.
  Import Ring.

  Notation " 'ch ( x ) " := x (in custom pack_type at level 2, x constr).
  Notation " 'ch ( x ) " := x (at level 2) : package_scope.

  Definition Rq_ct := chFin (2^n).
  Definition Message_t := chFin (2^k).
  Definition PublicKey_t := chProd Rq_ct Rq_ct.
  Definition Ciphertext_t := chProd Rq_ct Rq_ct.

  Definition split_fin3 (i : 'fin ('C(n, we) ^ 3)) :
    'fin ('C(n, we)) * 'fin ('C(n, we)) * 'fin ('C(n, we)) :=
    let t := @fin_to_tuple_fin 'C(n, we) 3 i in
    (tnth t (inord 0), tnth t (inord 1), tnth t (inord 2)).

  Definition truncate (p : Rq) : Rq :=
    in_qpoly gen (\poly_(i < n1n2) (@nth F2 0%R (p : polyF2) i)).

  Definition HQC_ENC : ident := 0%N.

  Definition I_hqc_encrypt : Interface :=
    [interface
      #val #[ HQC_ENC ] : 'ch(chProd PublicKey_t Message_t) → 'ch(Ciphertext_t)
    ].

  Definition hqc_encrypt : package emptym I_hqc_encrypt :=
    [package emptym ;
      #def #[ HQC_ENC ] (args : 'ch(chProd PublicKey_t Message_t)) : 'ch(Ciphertext_t) {
        let '(pk, msg) := args in
        let h := fin_to_rq pk.1 in
        let s := fin_to_rq pk.2 in
        let m := P.encode msg in
        t_fin ← sample uniform ('C(n, we) ^ 3)  ;;
        let '(r1_fin, r2_fin, e_fin) := split_fin3 t_fin in
        let r1 := \val (fin_to_rq_we r1_fin) in
        let r2 := \val (fin_to_rq_we r2_fin) in
        let e  := \val (fin_to_rq_we e_fin) in
        let u := r1 + h * r2 in
        let v := m + s * r2 + e in
        ret (rq_to_fin u, rq_to_fin (truncate v))
      }
    ].

End HQC_Security.
