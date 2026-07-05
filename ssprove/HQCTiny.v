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
  Parameter W_lt_n  : (W < n)%N.

  (** Number of K[z] blocks — must fit the ciphertext polynomials *)
  Parameter nblocks : nat.
  Parameter nblocks_bound : (2 * n <= nblocks * W)%N.

  (** Number of evaluation points *)
  Parameter npoints : nat.
  Parameter npoints_gt0 : (0 < npoints)%N.
  Parameter npoints_le_card : (npoints <= (2 ^ d))%N.
  Parameter nblocks2_le_npoints : (2 * nblocks <= npoints)%N.
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

  (** Boolean version of all_coeffs_small for use in guards *)
  Definition all_coeffs_smallb (q : {poly K}) : bool :=
    all (fun k : nat => (size ((q`_k)%R : {poly 'F_2}) <= W)%N) (iota 0 (size q)).

  Lemma all_coeffs_smallbP (q : {poly K}) :
    reflect (all_coeffs_small q) (all_coeffs_smallb q).
  Proof.
    rewrite /all_coeffs_smallb /all_coeffs_small.
    apply: (iffP allP) => H k Hk.
    - by apply: H; rewrite mem_iota.
    - by apply: H; rewrite mem_iota in Hk.
  Qed.

  Lemma all_coeffs_small_split_poly (p : {poly 'F_2}) nblks :
    all_coeffs_small (split_poly p nblks).
  Proof.
    rewrite /all_coeffs_small => k Hk.
    have Hk_lt : (k < nblks)%N.
    { have Hsz := size_split_poly p nblks.
      exact: (leq_trans Hk Hsz). }
    rewrite coef_split_poly Hk_lt /split_block.
    have -> : (in_qpoly gen (take_poly W (drop_poly (k * W) p)) : {poly 'F_2}) =
              take_poly W (drop_poly (k * W) p).
    { apply: in_qpoly_small.
      apply: (leq_ltn_trans (size_take_poly W _)).
      rewrite size_mk_monic_gen.
      exact: W_le_d. }
    exact: size_take_poly.
  Qed.

  (** Guard predicate for valid point sequences *)
  Definition valid_pk_b (pts : seq K) : bool :=
    let iph := interpolate_n pts in
    (size iph <= nblocks)%N && all_coeffs_smallb iph && (size (combine_poly iph) <= n)%N.

  Definition valid_pk (pts : seq K) : Prop :=
    exists h : Ring.Rq, eval_pts_n (split_poly (h : {poly F2}) nblocks) = pts.

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

  Lemma eval_interpolate_id (pts : seq K) :
    size pts = npoints ->
    eval_pts_n (interpolate_n pts) = pts.
  Proof.
    move=> Hsz.
    rewrite /eval_pts_n /interpolate_n.
    apply: (@eq_from_nth _ 0).
    - by rewrite size_eval_pts_n Hsz.
    - move=> i. rewrite size_eval_pts_n => Hi.
      exact: (eval_interpolate npoints npoints_le_card_K pts (Ordinal Hi)).
  Qed.

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
        if valid_pk_b h_pts && valid_pk_b s_pts then
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
          let r1_pts := eval_pts_n (split_poly r1 nblocks) in
          let r2_pts := eval_pts_n (split_poly r2 nblocks) in
          let e_pts  := eval_pts_n (split_poly e nblocks) in
          let m_pts  := eval_pts_n (split_poly m nblocks) in
          let gen_pts := eval_pts_n (split_poly Ring.gen nblocks) in
          let ku_pts := point_seq_mul (eval_pts_n (split_poly k_u nblocks)) gen_pts in
          let kv_pts := point_seq_mul (eval_pts_n (split_poly k_v nblocks)) gen_pts in
          let t_pts  := eval_pts_n (split_poly ('X ^+ n1n2 * t) nblocks) in
          let u_pts := point_seq_add r1_pts
                         (point_seq_add (point_seq_mul h_pts r2_pts) ku_pts) in
          let v_pts := point_seq_add m_pts
                         (point_seq_add (point_seq_mul s_pts r2_pts)
                           (point_seq_add e_pts (point_seq_add kv_pts t_pts))) in
          ret (pack_points u_pts, pack_points v_pts)
        else
          fail
      }
    ].

  Definition Sim : package HQC_Sec.I_hqc_encrypt I_hqctiny_encrypt :=
    [package emptym ;
      #def #[ HQCTINY_ENC ] (args : 'ch(chProd PublicKey_t Message_t)) : 'ch(Ciphertext_t) {
        #import {sig #[ HQC_Sec.HQC_ENC ] : 'ch(chProd HQC_Sec.PublicKey_t HQC_Sec.Message_t) → 'ch(HQC_Sec.Ciphertext_t)} as HQC_enc_oracle ;;
        let '(pk, msg) := args in
        let h_pts := unpack_points pk.1 in
        let s_pts := unpack_points pk.2 in
        if valid_pk_b h_pts && valid_pk_b s_pts then
          let h_poly := combine_poly (interpolate_n h_pts) in
          let s_poly := combine_poly (interpolate_n s_pts) in
          let h_fin := poly_to_fin n h_poly in
          let s_fin := poly_to_fin n s_poly in
          c_poly ← HQC_enc_oracle ((h_fin, s_fin), msg) ;;
          k_u_fin ← sample (uniform (2^n)) ;;
          k_v_fin ← sample (uniform (2^n)) ;;
          t_fin' ← sample (uniform (2^(n - n1n2))) ;;
          let u := fin_to_poly n c_poly.1 in
          let v := fin_to_poly n c_poly.2 in
          let k_u := fin_to_poly n k_u_fin in
          let k_v := fin_to_poly n k_v_fin in
          let t   := fin_to_poly (n - n1n2) t_fin' in
          let u_pts := eval_pts_n (split_poly u nblocks) in
          let v_pts := eval_pts_n (split_poly v nblocks) in
          let ku_pts := point_seq_mul (eval_pts_n (split_poly k_u nblocks)) (eval_pts_n (split_poly Ring.gen nblocks)) in
          let kv_pts := point_seq_mul (eval_pts_n (split_poly k_v nblocks)) (eval_pts_n (split_poly Ring.gen nblocks)) in
          let t_pts  := eval_pts_n (split_poly ('X ^+ n1n2 * t) nblocks) in
          let u_pts_blinded := point_seq_add u_pts ku_pts in
          let v_pts_blinded := point_seq_add v_pts (point_seq_add kv_pts t_pts) in
          ret (pack_points u_pts_blinded, pack_points v_pts_blinded)
        else
          fail
      }
    ].

  (** * Proof of perfect indistinguishability
      Follows the HQCBig.v proof structure from the main branch. *)

  (** Size bound for Rq elements *)
  Lemma size_Rq_val (x : Ring.Rq) : (size (x : {poly F2}) <= n)%N.
  Proof.
    have := size_npoly x.
    have Hsz : (size (mk_monic Ring.gen) = n.+1)%N by exact: Ring.size_mk_monic_gen.
    move=> H. apply: leq_trans H _. by rewrite Hsz.
  Qed.

  (** Bijection functions: add the quotient of division by gen to the
      blinding randomness. This is the HQCBig.v construction. *)
  Definition f_u (p_u : {poly F2}) (k : 'I_(2^n)) : 'I_(2^n) :=
    let q_u := p_u %/ Ring.gen in
    poly_to_fin n (fin_to_poly n k + q_u).

  Definition f_v (p_v : {poly F2}) (k : 'I_(2^n)) : 'I_(2^n) :=
    let q_v := p_v %/ Ring.gen in
    poly_to_fin n (fin_to_poly n k + q_v).

  Definition f_t (p_v : {poly F2}) (t : 'I_(2^(n-n1n2))) : 'I_(2^(n-n1n2)) :=
    let v_poly := p_v %% Ring.gen in
    let q_trunc := drop_poly n1n2 v_poly in
    poly_to_fin (n - n1n2) (fin_to_poly (n - n1n2) t + q_trunc).

  (** Helper lemma *)
  Lemma prime2_proof : prime 2.
  Proof. apply/primeP; split; first done. move=> d0 Hd0. case: d0 Hd0 => [|[|[|d0]]] //=. Qed.

  Lemma fin_to_poly_rq_to_fin : forall (X : Ring.Rq),
    fin_to_poly n (rq_to_fin X) = (X : {poly F2}).
  Proof.
    intros. rewrite /fin_to_poly /rq_to_fin /= polyF2_takeK. apply: take_poly_id.
    move: (size_npoly X) => Hsize. apply: (leq_trans Hsize).
    rewrite Ring.size_mk_monic_gen. exact: leqnn.
  Qed.

  Lemma f_general_inv : forall (d : nat) (q : {poly F2}) (x : 'fin (expn 2 d)),
    poly_to_fin d (fin_to_poly d (poly_to_fin d (fin_to_poly d x + q)) + q) = x.
  Proof.
    intros d q x. apply: val_inj => /=.
    rewrite /fin_to_poly /poly_to_fin /= polyF2_takeK take_polyD.
    rewrite take_poly_id.
    - move: (size_polyF2_of_nat x 0 d). by rewrite add0n.
    - have H_take_drop: take_poly d q + q = drop_poly d q * 'X^d.
      { apply/polyP => i. rewrite !coefE. case: ltnP => Hi.
        - rewrite GRing.addrC. by apply: addrr_pchar2; exact: (pchar_Fp prime2_proof).
        - by rewrite GRing.add0r (ssrnat.subnK Hi). }
      rewrite -addrA H_take_drop GRing.addrC.
      have H_add_scale: forall p r, nat_of_polyF2 (p * 'X^d + r) 0 d = nat_of_polyF2 r 0 d.
      { intros. apply: nat_of_polyF2_add_poly. move=> i Hi. by rewrite coefE Hi. }
      rewrite H_add_scale (nat_of_polyF2_of_nat x 0 d).
      + exact: ltn_ord.
      + by rewrite expn0 muln1.
  Qed.

  Lemma f_u_bij : forall (p_u : {poly F2}), bijective (f_u p_u).
  Proof.
    intro p_u. apply: (Bijective (g := f_u p_u)); intro x;
      exact: (f_general_inv n (p_u %/ Ring.gen) x).
  Qed.

  Lemma f_v_bij : forall (p_v : {poly F2}), bijective (f_v p_v).
  Proof.
    intro p_v. apply: (Bijective (g := f_v p_v)); intro x;
      exact: (f_general_inv n (p_v %/ Ring.gen) x).
  Qed.

  Lemma f_t_bij : forall (p_v : {poly F2}), bijective (f_t p_v).
  Proof.
    intro p_v. apply: (Bijective (g := f_t p_v)); intro x;
      exact: (f_general_inv (n - n1n2) (drop_poly n1n2 (p_v %% Ring.gen)) x).
  Qed.

  (** Product bijection for the three blinding terms *)
  Definition F_prod (p_u p_v : {poly F2})
    (x : 'fin ((2 ^ n) * (2 ^ n) * (2 ^ (n - n1n2))%N))
    : 'fin ((2 ^ n) * (2 ^ n) * (2 ^ (n - n1n2))%N) :=
    let '(k_u, k_v, t) := fin_split3 (2 ^ n) (2 ^ n) (2 ^ (n - n1n2)) x in
    fin_combine3 (2 ^ n) (2 ^ n) (2 ^ (n - n1n2))
      (f_u p_u k_u, f_v p_v k_v, f_t p_v t).

  Lemma F_prod_inv (p_u p_v : {poly F2})
    (x : 'fin ((2 ^ n) * (2 ^ n) * (2 ^ (n - n1n2))%N)) :
    F_prod p_u p_v (F_prod p_u p_v x) = x.
  Proof.
    rewrite /F_prod.
    case E: (fin_split3 (2 ^ n) (2 ^ n) (2 ^ (n - n1n2)) x) => [[k_u k_v] t].
    set combined := fin_combine3 (2 ^ n) (2 ^ n) (2 ^ (n - n1n2))
      (f_u p_u k_u, f_v p_v k_v, f_t p_v t).
    rewrite [fin_split3 (2 ^ n) (2 ^ n) (2 ^ (n - n1n2))
      combined](fin_combine3K (2 ^ n) (2 ^ n) (2 ^ (n - n1n2))
        (f_u p_u k_u, f_v p_v k_v, f_t p_v t)).
    rewrite /f_u /f_v /f_t.
    rewrite (f_general_inv n (p_u %/ Ring.gen) k_u).
    rewrite (f_general_inv n (p_v %/ Ring.gen) k_v).
    rewrite (f_general_inv (n - n1n2) (drop_poly n1n2 (p_v %% Ring.gen)) t).
    rewrite -E.
    exact: fin_split3K.
  Qed.

  Lemma F_prod_bij (p_u p_v : {poly F2}) : bijective (F_prod p_u p_v).
  Proof.
    apply: (Bijective (g := F_prod p_u p_v)). all: intro x; exact: F_prod_inv.
  Qed.

  Local Notation " 'errpt " := (chFin ('C(n, we) ^ 3)) (in custom pack_type at level 2).
  Local Notation " 'ktpt " := (chFin ((2 ^ n) * (2 ^ n) * (2 ^ (n - n1n2))%N))
    (in custom pack_type at level 2).

  (** The main algebraic lemmas from HQCBig.v, adapted to the HQCTiny context.
      u_eq: the LHS (direct poly computation) equals the RHS (via Rq) after
      applying the bijection f_u to the blinding term k. *)
  Lemma u_eq : forall (r1 r2 h : {poly F2}) (k : 'I_(2^n)),
    (size r1 <= n)%N -> (size r2 <= n)%N -> (size h <= n)%N ->
    let p := r1 + h * r2 in
    let X := in_qpoly Ring.gen p in
    r1 + h * r2 + (fin_to_poly n k) * Ring.gen =
    (fin_to_poly n (rq_to_fin X)) + (fin_to_poly n (f_u p k)) * Ring.gen.
  Proof.
    intros r1 r2 h k Hr1 Hr2 Hh p X.
    rewrite /f_u.
    rewrite fin_to_poly_rq_to_fin /fin_to_poly /poly_to_fin /= !polyF2_takeK.
    have H_monic_gen: Ring.gen \is monic by exact: Ring.gen_monic.
    have H_neq0: Ring.gen != 0 by apply: monic_neq0; exact: H_monic_gen.
    have Hltn : (0 < n)%N by apply: (ltn_trans (n := 1)); [done | exact: n_gt1].
    have H_monic: mk_monic Ring.gen = Ring.gen.
    { rewrite /mk_monic Ring.size_gen H_monic_gen ltnS Hltn /=.
      by case: (lead_coef Ring.gen). }
    rewrite H_monic.
    set P_goal := (polyF2_of_nat k 0 n + p %/ Ring.gen)%R.
    have Hsz_P: (size P_goal <= n)%N.
    { apply: (leq_trans (size_polyD _ _)). rewrite geq_max. apply/andP; split.
      - move: (size_polyF2_of_nat k 0 n); by rewrite add0n.
      - rewrite size_divp // Ring.size_gen leq_subLR.
        apply: (leq_trans (size_polyD r1 (h * r2)%R)). rewrite geq_max. apply/andP; split.
        + apply: (leq_trans Hr1). exact: leq_addr.
        + apply: (leq_trans (size_polyMleq h r2)).
          apply: (leq_trans (leq_pred _)).
          apply: leq_add; exact. }
    have Hsz_mod: (size (p %% Ring.gen)%R <= n)%N.
    { have Hltmod: (size (p %% Ring.gen)%R < size Ring.gen)%N.
      { rewrite ltn_modp. exact: H_neq0. }
      rewrite Ring.size_gen in Hltmod. exact: Hltmod. }
    apply/polyP => j. rewrite !coefE.
    case: (ltnP j n) => [Hj_lt | Hj_ge].
    - have -> : Pdiv.CommonRing.rmodp p Ring.gen = p %% Ring.gen
        by rewrite -Pdiv.IdomainMonic.modpE //; exact: H_monic_gen.
      rewrite take_poly_id //.
      have -> : P_goal * Ring.gen = P_goal * 'X^n - P_goal by rewrite /Ring.gen mulrBr mulr1.
      have -> : polyF2_of_nat k 0 n * Ring.gen = polyF2_of_nat k 0 n * 'X^n - polyF2_of_nat k 0 n
        by rewrite /Ring.gen mulrBr mulr1.
      rewrite !coefE Hj_lt.
      rewrite !sub0r !(oppr_pchar2 (pchar_Fp prime2_proof)).
      have -> : r1`_j + (h * r2)`_j = p`_j by rewrite /p coefD.
      rewrite {1}(divp_eq p Ring.gen).
      rewrite !coefE.
      have -> : p %/ Ring.gen * Ring.gen = p %/ Ring.gen * 'X^n - p %/ Ring.gen
        by rewrite /Ring.gen mulrBr mulr1.
      rewrite !coefE Hj_lt.
      by rewrite !sub0r !(oppr_pchar2 (pchar_Fp prime2_proof)) addrA addrC addrA.
    - rewrite take_poly_id //.
      have -> : P_goal * Ring.gen = P_goal * 'X^n - P_goal by rewrite /Ring.gen mulrBr mulr1.
      have -> : polyF2_of_nat k 0 n * Ring.gen = polyF2_of_nat k 0 n * 'X^n - polyF2_of_nat k 0 n
        by rewrite /Ring.gen mulrBr mulr1.
      rewrite !coefE ltnNge Hj_ge /=.
      have -> : r1`_j = 0 by apply: nth_default; exact: (leq_trans Hr1 Hj_ge).
      have Hsz_k : (size (polyF2_of_nat k 0 n) <= n)%N
        by move: (size_polyF2_of_nat k 0 n); rewrite add0n.
      have -> : (polyF2_of_nat k 0 n)`_j = 0 by apply: nth_default; exact: (leq_trans Hsz_k Hj_ge).
      rewrite !add0r !subr0.
      have -> : (h * r2)`_j = p`_j by rewrite /p coefD (nth_default 0 (leq_trans Hr1 Hj_ge)) add0r.
      have -> : Pdiv.CommonRing.rmodp p Ring.gen = p %% Ring.gen
        by rewrite -Pdiv.IdomainMonic.modpE //; exact: H_monic_gen.
      have -> : (p %% Ring.gen)`_j = 0 by apply: nth_default; exact: (leq_trans Hsz_mod Hj_ge).
      rewrite add0r.
      rewrite {1}(divp_eq p Ring.gen).
      rewrite !coefE.
      have -> : (p %% Ring.gen)`_j = 0 by apply: nth_default; exact: (leq_trans Hsz_mod Hj_ge).
      rewrite addr0.
      have -> : p %/ Ring.gen * Ring.gen = p %/ Ring.gen * 'X^n - p %/ Ring.gen
        by rewrite /Ring.gen mulrBr mulr1.
      rewrite !coefE ltnNge Hj_ge /=.
      by rewrite !(oppr_pchar2 (pchar_Fp prime2_proof)) addrAC [X in X + _]addrC.
  Qed.

  Lemma v_eq : forall (r2 e s m : {poly F2}) (k : 'I_(2^n)) (t : 'I_(2^(n-n1n2))),
    (size r2 <= n)%N -> (size e <= n)%N -> (size s <= n)%N -> (size m <= n)%N ->
    let p := m + s * r2 + e in
    let X := in_qpoly Ring.gen p in
    m + s * r2 + e + (fin_to_poly n k) * Ring.gen + 'X^n1n2 * (fin_to_poly (n-n1n2) t) =
    (fin_to_poly n (rq_to_fin (HQC_Sec.truncate X))) + (fin_to_poly n (f_v p k)) * Ring.gen
    + 'X^n1n2 * (fin_to_poly (n-n1n2) (f_t p t)).
  Proof.
    intros r2 e s m k t Hr2 He Hs Hm p X.
    rewrite /f_v /f_t /HQC_Sec.truncate.
    rewrite fin_to_poly_rq_to_fin /fin_to_poly /poly_to_fin /= !polyF2_takeK.
    have H_monic_gen: Ring.gen \is monic by exact: Ring.gen_monic.
    have Hltn : (0 < n)%N by apply: (ltn_trans (n := 1)); [done | exact: n_gt1].
    have H_monic: mk_monic Ring.gen = Ring.gen.
    { rewrite /mk_monic Ring.size_gen H_monic_gen ltnS Hltn /=.
      by case: (lead_coef Ring.gen). }
    rewrite H_monic.
    rewrite -!Pdiv.IdomainMonic.modpE //.
    have H_sz_trunc: (size (\poly_(j0 < n1n2) ((p %% Ring.gen)`_j0)%R) < size Ring.gen)%N
      by have H_poly := size_poly n1n2 (fun j0 => ((p %% Ring.gen)`_j0)%R);
         apply: (leq_ltn_trans H_poly); rewrite Ring.size_gen; exact: n1n2_le_n.
    rewrite (modp_small H_sz_trunc).
    have -> : \poly_(j0 < n1n2) (p %% Ring.gen)`_j0 = take_poly n1n2 (p %% Ring.gen)
      by apply/polyP => j0; rewrite !coefE.
    have H_neq0: Ring.gen != 0 by apply: monic_neq0; exact: H_monic_gen.
    have Hsz_P: (size (polyF2_of_nat k 0 n + p %/ Ring.gen)%R <= n)%N
      by apply: (leq_trans (size_polyD _ _)); rewrite geq_max; apply/andP; split;
         [move: (size_polyF2_of_nat k 0 n); rewrite add0n |
          rewrite size_divp // Ring.size_gen leq_subLR;
          apply: (leq_trans (size_polyD (m + s * r2)%R e)); rewrite geq_max; apply/andP; split;
          [apply: (leq_trans (size_polyD m (s * r2)%R)); rewrite geq_max; apply/andP; split;
           [apply: (leq_trans Hm); exact: leq_addr |
            apply: (leq_trans (size_polyMleq s r2)); apply: (leq_trans (leq_pred _));
            apply: leq_add; exact] |
           apply: (leq_trans He); exact: leq_addr]].
    rewrite (take_poly_id Hsz_P).
    have Hsz_mod: (size (p %% Ring.gen)%R <= n)%N.
    - have Hltmod: (size (p %% Ring.gen)%R < size Ring.gen)%N by rewrite ltn_modp; exact: H_neq0.
      rewrite Ring.size_gen in Hltmod. exact: Hltmod.
    - have Hsz_t: (size (polyF2_of_nat t 0 (n - n1n2) + drop_poly n1n2 (p %% Ring.gen)%R)%R <= n - n1n2)%N
        by apply: (leq_trans (size_polyD _ _)); rewrite geq_max; apply/andP; split;
           [move: (size_polyF2_of_nat t 0 (n - n1n2)); rewrite add0n |
            rewrite size_drop_poly; apply: leq_sub2r; exact: Hsz_mod].
      rewrite (take_poly_id Hsz_t).
      rewrite mulrDl (mulrDr 'X^n1n2).
      rewrite (mulrC 'X^n1n2 (drop_poly n1n2 (p %% Ring.gen)%R)).
      have -> : take_poly n1n2 (p %% Ring.gen) + (polyF2_of_nat k 0 n * Ring.gen + p %/ Ring.gen * Ring.gen)
               + ('X^n1n2 * polyF2_of_nat t 0 (n - n1n2) + drop_poly n1n2 (p %% Ring.gen)%R * 'X^n1n2)
             = take_poly n1n2 (p %% Ring.gen) + polyF2_of_nat k 0 n * Ring.gen
               + p %/ Ring.gen * Ring.gen + drop_poly n1n2 (p %% Ring.gen)%R * 'X^n1n2
               + 'X^n1n2 * polyF2_of_nat t 0 (n - n1n2)
        by rewrite !addrA addrAC.
      have -> : take_poly n1n2 (p %% Ring.gen) + polyF2_of_nat k 0 n * Ring.gen
               + p %/ Ring.gen * Ring.gen + drop_poly n1n2 (p %% Ring.gen)%R * 'X^n1n2
             = take_poly n1n2 (p %% Ring.gen) + polyF2_of_nat k 0 n * Ring.gen
               + drop_poly n1n2 (p %% Ring.gen)%R * 'X^n1n2 + p %/ Ring.gen * Ring.gen
        by rewrite addrAC.
      have -> : take_poly n1n2 (p %% Ring.gen) + polyF2_of_nat k 0 n * Ring.gen
               + drop_poly n1n2 (p %% Ring.gen)%R * 'X^n1n2
             = take_poly n1n2 (p %% Ring.gen) + drop_poly n1n2 (p %% Ring.gen)%R * 'X^n1n2
               + polyF2_of_nat k 0 n * Ring.gen
        by rewrite addrAC.
      rewrite poly_take_drop.
      have -> : p %% Ring.gen + polyF2_of_nat k 0 n * Ring.gen + p %/ Ring.gen * Ring.gen
             = p + polyF2_of_nat k 0 n * Ring.gen
        by rewrite addrAC (addrC (p %% Ring.gen)) -divp_eq.
      by rewrite /p.
  Qed.

  (** Equality between the in_qpoly representation and the Rq coercion.
      For any Rq elements a, b, h, their Rq sum+product coerced to polyF2
      equals in_qpoly gen applied to the polyF2 sum+product. *)
  Lemma in_qpoly_rq_eq (a b : Ring.Rq) (h : Ring.Rq) :
    ((a + h * b) : {poly 'F_2})
    = (in_qpoly Ring.gen ((a : {poly 'F_2}) + (h : {poly 'F_2}) * (b : {poly 'F_2})) : {poly 'F_2}).
  Proof.
    apply/val_inj => /=.
    set d := mk_monic Ring.gen.
    have Hd_monic : d \is monic by rewrite /d; apply: monic_mk_monic.
    have sz_lt_d : forall (x : Ring.Rq), (size (x : {poly 'F_2}) < size d)%N.
    { move=> x. apply: (leq_ltn_trans (size_Rq_val x)).
      rewrite /d Ring.size_mk_monic_gen. exact: ltnSn. }
    rewrite -!(Pdiv.IdomainMonic.modpE (q := d) Hd_monic) //.
    rewrite modpD.
    rewrite (modp_small (sz_lt_d a)).
    reflexivity.
  Qed.

  (** Main theorem *)
  Theorem hqctiny_indistinguishable :
    hqctiny_encrypt ≈₀ (Sim ∘ HQC_Sec.hqc_encrypt)%pack.
  Proof.
    eapply eq_rel_perf_ind_eq.
    simplify_eq_rel m.
    destruct m as [[pk1 pk2] msg].
    simplify_linking.
    rewrite code_link_if.
    case E: (valid_pk_b (unpack_points pk1) && valid_pk_b (unpack_points pk2)).
    { (* true branch *)
      move/andP: E => [Hpk1 Hpk2].
      simplify_linking.
      eapply r_uniform_bij.
      Unshelve. 3: exact (fun x => x).
      { exact: (@Bijective _ _ id id (fun x => erefl) (fun x => erefl)). }
      intro t_fin. simpl.
      pose r1 := sval (fin_to_rq_we (tnth (fin_to_tuple_fin 'C(n,we) 3 t_fin) (inord 0))).
      pose r2 := sval (fin_to_rq_we (tnth (fin_to_tuple_fin 'C(n,we) 3 t_fin) (inord 1))).
      pose e  := sval (fin_to_rq_we (tnth (fin_to_tuple_fin 'C(n,we) 3 t_fin) (inord 2))).
      pose h_poly := combine_poly (interpolate_n (unpack_points pk1)).
      pose h_rq := fin_to_rq (poly_to_fin n h_poly).
      pose p_u : {poly F2} := ((r1 : {poly F2}) + (h_rq : {poly F2}) * (r2 : {poly F2})).
      eapply r_uniform_bij.
      Unshelve. 3: exact (f_u p_u).
      { apply: f_u_bij. }
      intro k_u_val. simpl.
      pose s_poly := combine_poly (interpolate_n (unpack_points pk2)).
      pose s_rq := fin_to_rq (poly_to_fin n s_poly).
      pose m_poly := P.encode msg.
      pose p_v : {poly F2} := ((m_poly : {poly F2}) + (s_rq : {poly F2}) * (r2 : {poly F2}) + (e : {poly F2})).
      eapply r_uniform_bij.
      Unshelve. 3: exact (f_v p_v).
      { apply: f_v_bij. }
      intro k_v_val. simpl.
      eapply r_uniform_bij.
      Unshelve. 3: exact (f_t p_v).
      { apply: f_t_bij. }
      intro t_val. simpl.
      eapply r_ret.
      move=> s0 s1 ->. split; [ | done ].
      f_equal.
      (* --- u component --- *)
      { f_equal.
        have Hsz_pts1 : size (unpack_points pk1) = npoints.
        { rewrite /unpack_points /points_tuple_to_seq. exact: size_tuple. }
        rewrite -{1}(eval_interpolate_id (unpack_points pk1) Hsz_pts1).
        rewrite -!eval_points_mul -!eval_points_add.
        f_equal.
        move: Hpk1; rewrite /valid_pk_b => /andP [/andP [Hsz_ip Hacsb] Hsz_cp].
        have Hacs_ip : all_coeffs_small (interpolate_n (unpack_points pk1))
          by apply/all_coeffs_smallbP.
        have Hsplit_eq : split_poly h_poly nblocks =
                         interpolate_n (unpack_points pk1)
          by apply: split_poly_combine_poly.
        rewrite -Hsplit_eq.
        have Hsz_h_poly : (size h_poly <= nblocks * W)%N.
        { rewrite /h_poly.
          have H_n_bound : (n <= nblocks * W)%N.
          { move: nblocks_bound => Hnb.
            apply: (leq_trans _ Hnb).
            exact: leq_addr. }
          exact: (leq_trans Hsz_cp H_n_bound). }
        rewrite (combine_poly_split h_poly nblocks Hsz_h_poly).
        rewrite fin_to_poly_rq_to_fin.
        admit. }
      (* --- v component --- *)
      { f_equal.
        have Hsz_pts2 : size (unpack_points pk2) = npoints.
        { rewrite /unpack_points /points_tuple_to_seq. exact: size_tuple. }
        rewrite -{1}(eval_interpolate_id (unpack_points pk2) Hsz_pts2).
        admit. } }
    { (* false branch *)
      simplify_linking.
      apply: r_fail. }
  Admitted.

End HQCTiny.