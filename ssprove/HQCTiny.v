(******************************************************************************)
(*  HQCTiny                                                                   *)
(*                                                                            *)
(*  Point-value form of HQC encryption with quotient blinding and             *)
(*  truncate blinding.                                                        *)
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
#[local] Open Scope package_scope.
#[local] Open Scope ring_scope.

From SSProveHQC Require Import Tuple Interpolate HQC.

Module Type HQCTinyParams.
  Include HQCParams.

  (** Point-field parameters *)
  Parameter d        : nat.
  Parameter gen_K    : {poly 'F_2}.
  Parameter gen_K_monic       : gen_K \is monic.
  Parameter size_gen_K        : size gen_K = d.+1.
  Parameter gen_K_irreducible : irreducible_poly gen_K.

  (** Split/Combine window *)
  Parameter W       : nat.
  Parameter W_gt0   : (0 < W)%N.
  Parameter W_le_d  : (W <= d)%N.
  Parameter W2_lt_d : ((2 * W).-1 <= d)%N.

  (** Number of K[z] blocks — must fit the ciphertext polynomials *)
  Parameter nblocks : nat.
  Parameter nblocks_bound : (2 * n <= nblocks * W)%N.

  (** Number of evaluation points *)
  Parameter npoints : nat.
  Parameter npoints_gt0 : (0 < npoints)%N.
  Parameter npoints_le_card : (npoints <= (2 ^ d))%N.
End HQCTinyParams.

Module HQCTiny (P : HQCTinyParams).
  Include P.

  Module HQC_Sec := HQC_Security P.
  Import HQC_Sec.

  Module PointSplitParams.
    Definition d := P.d.
    Definition gen := P.gen_K.
    Definition gen_monic := P.gen_K_monic.
    Definition size_gen := P.size_gen_K.
    Definition gen_irreducible := P.gen_K_irreducible.
    Definition W := P.W.
    Definition W_gt0 := P.W_gt0.
    Definition W_le_d := P.W_le_d.
    Definition W2_lt_d := P.W2_lt_d.
  End PointSplitParams.

  Module SC := SplitCombine PointSplitParams.
  Import SC.
  Import SC.PF.

  Lemma npoints_le_card_K : (npoints <= #|K|)%N.
  Proof. rewrite card_K. exact: npoints_le_card. Qed.

  Definition eval_pts_n := eval_points npoints.
  Definition interpolate_n := interpolate npoints.

  Lemma size_eval_pts_n (q : {poly K}) : size (eval_pts_n q) = npoints.
  Proof. apply: size_eval_points; exact: npoints_le_card_K. Qed.

  Definition K_to_fin (x : K) : 'I_(2 ^ d) :=
    cast_ord card_K (enum_rank x).

  Definition fin_to_K (i : 'I_(2 ^ d)) : K :=
    enum_val (cast_ord (esym card_K) i).

  Lemma K_to_finK : cancel K_to_fin fin_to_K.
  Proof.
    rewrite /K_to_fin /fin_to_K.
    move=> x.
    by rewrite cast_ordK enum_rankK.
  Qed.

  Lemma fin_to_KK : cancel fin_to_K K_to_fin.
  Proof.
    rewrite /K_to_fin /fin_to_K.
    move=> i.
    by rewrite enum_valK cast_ordKV.
  Qed.

  Lemma K_fin_bij : bijective K_to_fin.
  Proof.
    exact: (Bijective K_to_finK fin_to_KK).
  Qed.

  Definition K_tuple_to_fin (tup : npoints.-tuple K) : 'I_((2 ^ d) ^ npoints) :=
    let tup' : npoints.-tuple 'I_(2 ^ d) :=
      [tuple K_to_fin (tnth tup i) | i < npoints] in
    tuple_fin_to_fin (2 ^ d) npoints tup'.

  Definition fin_to_K_tuple (i : 'I_((2 ^ d) ^ npoints)) : npoints.-tuple K :=
    let tup' : npoints.-tuple 'I_(2 ^ d) := fin_to_tuple_fin (2 ^ d) npoints i in
    [tuple fin_to_K (tnth tup' j) | j < npoints].

  Lemma K_tuple_to_finK : cancel K_tuple_to_fin fin_to_K_tuple.
  Proof.
    rewrite /K_tuple_to_fin /fin_to_K_tuple => tup.
    apply/eq_from_tnth => j.
    rewrite !tnth_mktuple.
    rewrite tuple_fin_to_finK.
    rewrite tnth_mktuple.
    by rewrite K_to_finK.
  Qed.

  Lemma fin_to_K_tupleK : cancel fin_to_K_tuple K_tuple_to_fin.
  Proof.
    rewrite /K_tuple_to_fin /fin_to_K_tuple => i.
    have H_eq : [tuple K_to_fin (tnth [tuple fin_to_K (tnth (fin_to_tuple_fin (2 ^ d) npoints i) j) | j < npoints] k) | k < npoints] = fin_to_tuple_fin (2 ^ d) npoints i.
    { apply/eq_from_tnth => j.
      rewrite !tnth_mktuple.
      by rewrite fin_to_KK. }
    rewrite H_eq.
    by rewrite fin_to_tuple_finK.
  Qed.

  Lemma K_tuple_fin_bij : bijective K_tuple_to_fin.
  Proof.
    exact: (Bijective K_tuple_to_finK fin_to_K_tupleK).
  Qed.

  Definition seq_to_points_tuple (s : seq K) : npoints.-tuple K :=
    [tuple nth 0%R s i | i < npoints].

  Definition points_tuple_to_seq (tup : npoints.-tuple K) : seq K :=
    tval tup.

  Definition pack_points (pts : seq K) : 'I_((2 ^ d) ^ npoints) :=
    K_tuple_to_fin (seq_to_points_tuple pts).

  Definition unpack_points (i : 'I_((2 ^ d) ^ npoints)) : seq K :=
    points_tuple_to_seq (fin_to_K_tuple i).

  Lemma size_eval_points_q (q : {poly K}) : size (eval_pts_n q) = npoints.
  Proof. exact: size_eval_pts_n. Qed.

  Definition fin_to_poly (d : nat) (i : 'fin (expn 2 d)) : {poly F2} :=
    polyF2_of_nat (nat_of_ord i) 0 d.

  Definition poly_to_fin (d : nat) (p : {poly F2}) : 'fin (expn 2 d) :=
    let val := nat_of_polyF2 p 0 d in
    Ordinal (nat_of_polyF2_bound p d).

  Definition poly_to_points (p : {poly F2}) : seq K :=
    eval_pts_n (split_poly p nblocks).

  Definition PointSeqCt := chFin ((2 ^ d) ^ npoints).
  Definition PublicKey_t := chProd PointSeqCt PointSeqCt.
  Definition Ciphertext_t := chProd PointSeqCt PointSeqCt.
  Definition Message_t := chFin (2^k).

  Notation " 'ch ( x ) " := x (in custom pack_type at level 2, x constr).
  Notation " 'ch ( x ) " := x (at level 2) : package_scope.

  Definition HQCTINY_ENC : ident := 0%N.

  Definition I_hqctiny_encrypt : Interface :=
    [interface
      #val #[ HQCTINY_ENC ] : 'ch(chProd PublicKey_t Message_t) → 'ch(Ciphertext_t)
    ].

  Definition hqctiny_encrypt : package emptym I_hqctiny_encrypt :=
    [package emptym ;
      #def #[ HQCTINY_ENC ] (args : 'ch(chProd PublicKey_t Message_t)) : 'ch(Ciphertext_t) {
        let '(pk, msg) := args in
        let h_pts := unpack_points pk.1 in
        let s_pts := unpack_points pk.2 in
        let m := P.encode msg in
        t_fin ← sample (uniform ('C(n, we) ^ 3)) ;;
        let '(r1_fin, r2_fin, e_fin) := split_fin3 t_fin in
        k_u_fin ← sample (uniform (2^n)) ;;
        k_v_fin ← sample (uniform (2^n)) ;;
        t_fin' ← sample (uniform (2^(n - n1n2))) ;;
        let r1 := \val (fin_to_rq_we r1_fin) in
        let r2 := \val (fin_to_rq_we r2_fin) in
        let e  := \val (fin_to_rq_we e_fin) in
        let k_u := fin_to_poly n k_u_fin in
        let k_v := fin_to_poly n k_v_fin in
        let t   := fin_to_poly (n - n1n2) t_fin' in
        let r1_pts := poly_to_points r1 in
        let r2_pts := poly_to_points r2 in
        let e_pts  := poly_to_points e in
        let m_pts  := poly_to_points (m : {poly F2}) in
        let ku_pts := poly_to_points (k_u * Ring.gen) in
        let kv_pts := poly_to_points (k_v * Ring.gen) in
        let t_pts  := poly_to_points ('X ^+ n1n2 * t) in
        let u_pts := point_seq_add r1_pts
                       (point_seq_add (point_seq_mul h_pts r2_pts) ku_pts) in
        let v_pts := point_seq_add m_pts
                       (point_seq_add (point_seq_mul s_pts r2_pts)
                         (point_seq_add e_pts (point_seq_add kv_pts t_pts))) in
        ret (pack_points u_pts, pack_points v_pts)
      }
    ].

End HQCTiny.
