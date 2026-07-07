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
  Parameter d_le_W2 : (d <= 2 * W)%N.
  Parameter W_lt_n  : (W < n)%N.

  (** Number of K[z] blocks — must fit the ciphertext polynomials *)
  Parameter nblocks : nat.
  Parameter nblocks_bound : (n < nblocks * W)%N.

  (** Number of evaluation points *)
  Parameter npoints : nat.
  Parameter npoints_gt0 : (0 < npoints)%N.
  Parameter npoints_le_card : (npoints <= (2 ^ d))%N.
  Parameter nblocks2_le_npoints : ((2 * nblocks).-1 <= npoints)%N.
End HQCTinyParams.

Module HQCTiny (P : HQCTinyParams).
  Include P.

  Module HQC_Sec := HQC_Security P.
  Import HQC_Sec.

  Module PointSegmentParams.
    Definition d := P.d.
    Definition gen := P.gen_K.
    Definition gen_monic := P.gen_K_monic.
    Definition size_gen := P.size_gen_K.
    Definition gen_irreducible := P.gen_K_irreducible.
    Definition W := P.W.
    Definition W_gt0 := P.W_gt0.
    Definition W_le_d := P.W_le_d.
    Definition W2_lt_d := P.W2_lt_d.
  End PointSegmentParams.

  Module SC := SegmentCombine PointSegmentParams.
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

  Lemma all_coeffs_small_segment_poly (p : {poly 'F_2}) nblks :
    all_coeffs_small (segment_poly p nblks).
  Proof.
    rewrite /all_coeffs_small => k Hk.
    have Hk_lt : (k < nblks)%N.
    { have Hsz := size_segment_poly p nblks.
      exact: (leq_trans Hk Hsz). }
    rewrite coef_segment_poly Hk_lt /segment_block.
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
    exists h : Ring.Rq, eval_pts_n (segment_poly (h : {poly F2}) nblocks) = pts.

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

  Definition deltas_size : nat := ((2 ^ W) ^ (2 * nblocks))%N.

  Definition fin_to_deltas (i : 'I_deltas_size) : seq {poly 'F_2} :=
    let tup := fin_to_tuple_fin (2 ^ W) (2 * nblocks) i in
    [seq fin_to_poly W (tnth tup j) | j <- enum 'I_(2 * nblocks)].

  Definition deltas_to_fin (deltas : seq {poly 'F_2}) : 'I_deltas_size :=
    let tup := [tuple poly_to_fin W (nth 0%R deltas i) | i < 2 * nblocks] in
    tuple_fin_to_fin (2 ^ W) (2 * nblocks) tup.

  Lemma fin_to_poly_to_fin : forall (p : {poly F2}),
    (size p <= W)%N ->
    fin_to_poly W (poly_to_fin W p) = p.
  Proof.
    move=> p Hsz.
    rewrite /fin_to_poly /poly_to_fin /= polyF2_takeK.
    exact: take_poly_id.
  Qed.

  Lemma deltas_to_finK : forall (deltas : seq {poly F2}),
    size deltas = (2 * nblocks)%N ->
    (forall idx, (idx < 2 * nblocks)%N -> size (nth 0%R deltas idx) <= W)%N ->
    fin_to_deltas (deltas_to_fin deltas) = deltas.
  Proof.
    move=> deltas Hsz Hsz_el.
    rewrite /fin_to_deltas /deltas_to_fin tuple_fin_to_finK.
    apply: (@eq_from_nth _ 0%R).
    - by rewrite size_map size_enum_ord Hsz.
    - move=> idx. rewrite size_map size_enum_ord => Hidx.
      have Hidx_ord : (idx < 2 * nblocks)%N by exact: Hidx.
      rewrite (nth_map (Ordinal Hidx_ord)) ?size_enum_ord //=.
      rewrite tnth_mktuple /=.
      rewrite nth_enum_ord //=.
      have H_sz_p : (size (nth 0%R deltas idx) <= W)%N by exact: (Hsz_el idx Hidx).
      apply: fin_to_poly_to_fin.
      exact: H_sz_p.
  Qed.

  Lemma size_fin_to_deltas : forall i idx, (size (nth 0%R (fin_to_deltas i) idx) <= W)%N.
  Proof.
    move=> i idx.
    rewrite /fin_to_deltas.
    case: (ltnP idx (2 * nblocks)) => Hidx.
    - have Hidx_ord : (idx < 2 * nblocks)%N by exact: Hidx.
      rewrite (nth_map (Ordinal Hidx_ord)) ?size_enum_ord //=.
      rewrite /fin_to_poly.
      apply: (leq_trans (size_polyF2_of_nat _ 0 W)).
      by rewrite add0n.
    - rewrite nth_default.
      + rewrite size_map size_enum_ord. exact: Hidx.
      + simpl. rewrite size_poly0. exact: leq0n.
  Qed.

  Lemma poly_to_fin_fin_to_poly : forall (i : 'I_(2^W)), poly_to_fin W (fin_to_poly W i) = i.
  Proof.
    move=> i.
    rewrite /poly_to_fin /fin_to_poly /=.
    apply/val_inj => /=.
    by rewrite nat_of_polyF2_of_nat // muln1.
  Qed.

  Lemma ker_elem_add : forall d1 d2, ker_elem (d1 + d2)%R = (ker_elem d1 + ker_elem d2)%R.
  Proof.
    move=> d1 d2.
    rewrite /ker_elem.
    rewrite mulrDl.
    rewrite !rmorphD /=.
    rewrite mulrDl !addrA.
    congr (_ + _).
    rewrite -!addrA.
    congr (_ + _).
    exact: addrC.
  Qed.

  Lemma ker_chain_add : forall (ds1 ds2 : seq {poly F2}),
    size ds1 = size ds2 ->
    ker_chain [seq (nth 0%R ds1 idx + nth 0%R ds2 idx)%R | idx <- iota 0 (size ds1)] =
    (ker_chain ds1 + ker_chain ds2)%R.
  Proof.
    elim=> [|d1 ds1 IH] ds2 Hsz.
    - have -> : ds2 = [::] by move: Hsz; case: ds2.
      by simpl; rewrite addr0.
    - case: ds2 Hsz => [|d2 ds2] Hsz //=.
      move: Hsz => [Hsz].
      have -> : [seq (nth 0%R (d1 :: ds1) idx + nth 0%R (d2 :: ds2) idx)%R | idx <- iota 1 (size ds1)]
              = [seq (nth 0%R ds1 idx + nth 0%R ds2 idx)%R | idx <- iota 0 (size ds1)]
        by apply: (@eq_from_nth _ 0%R); [rewrite !size_map !size_iota | move=> idx Hidx; rewrite size_map size_iota in Hidx; rewrite !(nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n nth_iota //=].
      rewrite (IH ds2) //.
      rewrite ker_elem_add.
      rewrite mulrDl.
      rewrite !addrA.
      congr (_ + _).
      rewrite -!addrA.
      congr (_ + _).
      congr (_ + _).
      rewrite addrA.
      exact: addrC.
  Qed.

  Definition poly_to_points (p : {poly F2}) : seq K :=
    eval_pts_n (segment_poly p nblocks).

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
          k_u_ker ← sample (uniform deltas_size) ;;
          k_v_ker ← sample (uniform deltas_size) ;;
          t_fin' ← sample (uniform (2^(n - n1n2))) ;;
          let r1 := \val (fin_to_rq_we r1_fin) in
          let r2 := \val (fin_to_rq_we r2_fin) in
          let e  := \val (fin_to_rq_we e_fin) in
          let k_u := fin_to_poly n k_u_fin in
          let k_v := fin_to_poly n k_v_fin in
          let ku_deltas := fin_to_deltas k_u_ker in
          let kv_deltas := fin_to_deltas k_v_ker in
          let t   := fin_to_poly (n - n1n2) t_fin' in
          let r1_pts := eval_pts_n (segment_poly r1 nblocks) in
          let r2_pts := eval_pts_n (segment_poly r2 nblocks) in
          let e_pts  := eval_pts_n (segment_poly e nblocks) in
          let m_pts  := eval_pts_n (segment_poly m nblocks) in
          let gen_pts := eval_pts_n (segment_poly Ring.gen nblocks) in
          let ku_pts := point_seq_add
                          (point_seq_mul (eval_pts_n (segment_poly k_u nblocks)) gen_pts)
                          (eval_pts_n (ker_chain ku_deltas)) in
          let kv_pts := point_seq_add
                          (point_seq_mul (eval_pts_n (segment_poly k_v nblocks)) gen_pts)
                          (eval_pts_n (ker_chain kv_deltas)) in
          let t_pts  := eval_pts_n (segment_poly ('X ^+ n1n2 * t) nblocks) in
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
          k_u_ker ← sample (uniform deltas_size) ;;
          k_v_ker ← sample (uniform deltas_size) ;;
          t_fin' ← sample (uniform (2^(n - n1n2))) ;;
          let u := fin_to_poly n c_poly.1 in
          let v := fin_to_poly n c_poly.2 in
          let k_u := fin_to_poly n k_u_fin in
          let k_v := fin_to_poly n k_v_fin in
          let ku_deltas := fin_to_deltas k_u_ker in
          let kv_deltas := fin_to_deltas k_v_ker in
          let t   := fin_to_poly (n - n1n2) t_fin' in
          let u_pts := eval_pts_n (segment_poly u nblocks) in
          let v_pts := eval_pts_n (segment_poly v nblocks) in
          let ku_pts := point_seq_add
                          (point_seq_mul (eval_pts_n (segment_poly k_u nblocks)) (eval_pts_n (segment_poly Ring.gen nblocks)))
                          (eval_pts_n (ker_chain ku_deltas)) in
          let kv_pts := point_seq_add
                          (point_seq_mul (eval_pts_n (segment_poly k_v nblocks)) (eval_pts_n (segment_poly Ring.gen nblocks)))
                          (eval_pts_n (ker_chain kv_deltas)) in
          let t_pts  := eval_pts_n (segment_poly ('X ^+ n1n2 * t) nblocks) in
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

  Lemma in_qpoly_rq_eq3 (a b c d' : Ring.Rq) :
    ((a + b * c + d') : {poly 'F_2})
    = (in_qpoly Ring.gen ((a : {poly 'F_2}) + (b : {poly 'F_2})
        * (c : {poly 'F_2}) + (d' : {poly 'F_2})) : {poly 'F_2}).
  Proof.
    apply/val_inj => /=.
    set m := mk_monic Ring.gen.
    have Hm_monic : m \is monic by rewrite /m; apply: monic_mk_monic.
    have sz_lt_m : forall (x : Ring.Rq), (size (x : {poly 'F_2}) < size m)%N.
    { move=> x. apply: (leq_ltn_trans (size_Rq_val x)).
      rewrite /m Ring.size_mk_monic_gen. exact: ltnSn. }
    rewrite -!(Pdiv.IdomainMonic.modpE (q := m) Hm_monic) //.
    rewrite !modpD.
    rewrite (modp_small (sz_lt_m a)).
    rewrite (modp_small (sz_lt_m d')).
    reflexivity.
  Qed.

  Definition f_u_ker (diff : 'I_deltas_size) (k : 'I_deltas_size) : 'I_deltas_size :=
    let deltas_k := fin_to_deltas k in
    let deltas_diff := fin_to_deltas diff in
    let deltas_sum := [seq (nth 0%R deltas_k idx + nth 0%R deltas_diff idx)%R | idx <- iota 0 (2 * nblocks)] in
    deltas_to_fin deltas_sum.

  Lemma f_u_ker_bij : forall diff, bijective (f_u_ker diff).
  Proof.
    move=> diff.
    have H_inj : injective (tuple_fin_to_fin (2^W) (2 * nblocks)) := can_inj (tuple_fin_to_finK (2^W) (2 * nblocks)).
    apply: (Bijective (g := f_u_ker diff)) => x.
    - rewrite /f_u_ker.
      have H_sz_sum : forall k_val idx, (idx < 2 * nblocks)%N ->
        (size (nth 0%R [seq (nth 0%R (fin_to_deltas k_val) idx0 + nth 0%R (fin_to_deltas diff) idx0)%R | idx0 <- iota 0 (2 * nblocks)] idx) <= W)%N.
      { move=> k_val idx Hidx.
        rewrite (nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n.
        apply: (leq_trans (size_polyD _ _)).
        rewrite geq_max.
        apply/andP; split; exact: size_fin_to_deltas. }
      rewrite -{2}(fin_to_tuple_finK (2^W) (2 * nblocks) x).
      rewrite /deltas_to_fin.
      congr tuple_fin_to_fin.
      apply/val_inj => /=.
      apply: (@eq_from_nth _ (Ordinal (expn_gt0 2 W))); first by rewrite size_map size_enum_ord size_tuple.
      move=> idx Hidx.
      rewrite size_map size_enum_ord in Hidx.
      rewrite (nth_map (Ordinal Hidx)) ?size_enum_ord //=.
      rewrite nth_enum_ord //=.
      rewrite (nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n.
      rewrite deltas_to_finK.
      + by rewrite size_map size_iota.
      + move=> idx' Hidx'. exact: H_sz_sum.
      + rewrite (nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n.
        rewrite -addrA.
        have -> : (fin_to_deltas diff)`_idx + (fin_to_deltas diff)`_idx = 0.
        { apply/polyP => i0.
          rewrite coefD coef0.
          rewrite -[((fin_to_deltas diff)`_idx)`_i0 + _]/( _ *+ 2).
          rewrite -mulr_natr.
          have Hchar : 2 \in [char 'F_2] by exact: pchar_Fp 2 PointFieldHelpers.prime2.
          by rewrite (pcharf0 Hchar) mulr0. }
        rewrite addr0.
        rewrite /fin_to_deltas.
        have H_idx_ord : (idx < 2 * nblocks)%N by exact: Hidx.
        rewrite (nth_map (Ordinal H_idx_ord)) ?size_enum_ord //=.
        rewrite /tnth /= nth_enum_ord //=.
        rewrite poly_to_fin_fin_to_poly.
        by rewrite (set_nth_default (Ordinal (expn_gt0 2 W))) ?size_tuple.
    - rewrite /f_u_ker.
      have H_sz_sum : forall k_val idx, (idx < 2 * nblocks)%N ->
        (size (nth 0%R [seq (nth 0%R (fin_to_deltas k_val) idx0 + nth 0%R (fin_to_deltas diff) idx0)%R | idx0 <- iota 0 (2 * nblocks)] idx) <= W)%N.
      { move=> k_val idx Hidx.
        rewrite (nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n.
        apply: (leq_trans (size_polyD _ _)).
        rewrite geq_max.
        apply/andP; split; exact: size_fin_to_deltas. }
      rewrite -{2}(fin_to_tuple_finK (2^W) (2 * nblocks) x).
      rewrite /deltas_to_fin.
      congr tuple_fin_to_fin.
      apply/val_inj => /=.
      apply: (@eq_from_nth _ (Ordinal (expn_gt0 2 W))); first by rewrite size_map size_enum_ord size_tuple.
      move=> idx Hidx.
      rewrite size_map size_enum_ord in Hidx.
      rewrite (nth_map (Ordinal Hidx)) ?size_enum_ord //=.
      rewrite nth_enum_ord //=.
      rewrite (nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n.
      rewrite deltas_to_finK.
      + by rewrite size_map size_iota.
      + move=> idx' Hidx'. exact: H_sz_sum.
      + rewrite (nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n.
        rewrite -addrA.
        have -> : (fin_to_deltas diff)`_idx + (fin_to_deltas diff)`_idx = 0.
        { apply/polyP => i0.
          rewrite coefD coef0.
          rewrite -[((fin_to_deltas diff)`_idx)`_i0 + _]/( _ *+ 2).
          rewrite -mulr_natr.
          have Hchar : 2 \in [char 'F_2] by exact: pchar_Fp 2 PointFieldHelpers.prime2.
          by rewrite (pcharf0 Hchar) mulr0. }
        rewrite addr0.
        rewrite /fin_to_deltas.
        have H_idx_ord : (idx < 2 * nblocks)%N by exact: Hidx.
        rewrite (nth_map (Ordinal H_idx_ord)) ?size_enum_ord //=.
        rewrite /tnth /= nth_enum_ord //=.
        rewrite poly_to_fin_fin_to_poly.
        by rewrite (set_nth_default (Ordinal (expn_gt0 2 W))) ?size_tuple.
  Qed.

  Definition f_v_ker (diff : 'I_deltas_size) (k : 'I_deltas_size) : 'I_deltas_size :=
    let deltas_k := fin_to_deltas k in
    let deltas_diff := fin_to_deltas diff in
    let deltas_sum := [seq (nth 0%R deltas_k idx + nth 0%R deltas_diff idx)%R | idx <- iota 0 (2 * nblocks)] in
    deltas_to_fin deltas_sum.

  Lemma f_v_ker_bij : forall diff, bijective (f_v_ker diff).
  Proof.
    move=> diff.
    have H_inj : injective (tuple_fin_to_fin (2^W) (2 * nblocks)) := can_inj (tuple_fin_to_finK (2^W) (2 * nblocks)).
    apply: (Bijective (g := f_v_ker diff)) => x.
    - rewrite /f_v_ker.
      have H_sz_sum : forall k_val idx, (idx < 2 * nblocks)%N ->
        (size (nth 0%R [seq (nth 0%R (fin_to_deltas k_val) idx0 + nth 0%R (fin_to_deltas diff) idx0)%R | idx0 <- iota 0 (2 * nblocks)] idx) <= W)%N.
      { move=> k_val idx Hidx.
        rewrite (nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n.
        apply: (leq_trans (size_polyD _ _)).
        rewrite geq_max.
        apply/andP; split; exact: size_fin_to_deltas. }
      rewrite -{2}(fin_to_tuple_finK (2^W) (2 * nblocks) x).
      rewrite /deltas_to_fin.
      congr tuple_fin_to_fin.
      apply/val_inj => /=.
      apply: (@eq_from_nth _ (Ordinal (expn_gt0 2 W))); first by rewrite size_map size_enum_ord size_tuple.
      move=> idx Hidx.
      rewrite size_map size_enum_ord in Hidx.
      rewrite (nth_map (Ordinal Hidx)) ?size_enum_ord //=.
      rewrite nth_enum_ord //=.
      rewrite (nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n.
      rewrite deltas_to_finK.
      + by rewrite size_map size_iota.
      + move=> idx' Hidx'. exact: H_sz_sum.
      + rewrite (nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n.
        rewrite -addrA.
        have -> : (fin_to_deltas diff)`_idx + (fin_to_deltas diff)`_idx = 0.
        { apply/polyP => i0.
          rewrite coefD coef0.
          rewrite -[((fin_to_deltas diff)`_idx)`_i0 + _]/( _ *+ 2).
          rewrite -mulr_natr.
          have Hchar : 2 \in [char 'F_2] by exact: pchar_Fp 2 PointFieldHelpers.prime2.
          by rewrite (pcharf0 Hchar) mulr0. }
        rewrite addr0.
        rewrite /fin_to_deltas.
        have H_idx_ord : (idx < 2 * nblocks)%N by exact: Hidx.
        rewrite (nth_map (Ordinal H_idx_ord)) ?size_enum_ord //=.
        rewrite /tnth /= nth_enum_ord //=.
        rewrite poly_to_fin_fin_to_poly.
        by rewrite (set_nth_default (Ordinal (expn_gt0 2 W))) ?size_tuple.
    - rewrite /f_v_ker.
      have H_sz_sum : forall k_val idx, (idx < 2 * nblocks)%N ->
        (size (nth 0%R [seq (nth 0%R (fin_to_deltas k_val) idx0 + nth 0%R (fin_to_deltas diff) idx0)%R | idx0 <- iota 0 (2 * nblocks)] idx) <= W)%N.
      { move=> k_val idx Hidx.
        rewrite (nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n.
        apply: (leq_trans (size_polyD _ _)).
        rewrite geq_max.
        apply/andP; split; exact: size_fin_to_deltas. }
      rewrite -{2}(fin_to_tuple_finK (2^W) (2 * nblocks) x).
      rewrite /deltas_to_fin.
      congr tuple_fin_to_fin.
      apply/val_inj => /=.
      apply: (@eq_from_nth _ (Ordinal (expn_gt0 2 W))); first by rewrite size_map size_enum_ord size_tuple.
      move=> idx Hidx.
      rewrite size_map size_enum_ord in Hidx.
      rewrite (nth_map (Ordinal Hidx)) ?size_enum_ord //=.
      rewrite nth_enum_ord //=.
      rewrite (nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n.
      rewrite deltas_to_finK.
      + by rewrite size_map size_iota.
      + move=> idx' Hidx'. exact: H_sz_sum.
      + rewrite (nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n.
        rewrite -addrA.
        have -> : (fin_to_deltas diff)`_idx + (fin_to_deltas diff)`_idx = 0.
        { apply/polyP => i0.
          rewrite coefD coef0.
          rewrite -[((fin_to_deltas diff)`_idx)`_i0 + _]/( _ *+ 2).
          rewrite -mulr_natr.
          have Hchar : 2 \in [char 'F_2] by exact: pchar_Fp 2 PointFieldHelpers.prime2.
          by rewrite (pcharf0 Hchar) mulr0. }
        rewrite addr0.
        rewrite /fin_to_deltas.
        have H_idx_ord : (idx < 2 * nblocks)%N by exact: Hidx.
        rewrite (nth_map (Ordinal H_idx_ord)) ?size_enum_ord //=.
        rewrite /tnth /= nth_enum_ord //=.
        rewrite poly_to_fin_fin_to_poly.
        by rewrite (set_nth_default (Ordinal (expn_gt0 2 W))) ?size_tuple.
  Qed.

  Lemma hqctiny_u_eq : forall (pk1 : PointSeqCt) (t_fin : 'I_('C(n, we) ^ 3)) (k_u_val : 'I_(2^n)),
    let r1 := sval (fin_to_rq_we (tnth (fin_to_tuple_fin 'C(n, we) 3 t_fin) (inord 0))) in
    let r2 := sval (fin_to_rq_we (tnth (fin_to_tuple_fin 'C(n, we) 3 t_fin) (inord 1))) in
    let h_poly := combine_poly (interpolate_n (unpack_points pk1)) in
    let h_rq := fin_to_rq (poly_to_fin n h_poly) in
    let p_u := ((r1 : {poly F2}) + (h_rq : {poly F2}) * (r2 : {poly F2})) in
    valid_pk_b (unpack_points pk1) ->
    exists (diff : 'I_deltas_size),
      forall (k_u_ker_val : 'I_deltas_size),
        point_seq_add
          (eval_pts_n (segment_poly r1 nblocks))
          (point_seq_add
             (point_seq_mul (unpack_points pk1) (eval_pts_n (segment_poly r2 nblocks)))
             (point_seq_add
                (point_seq_mul (eval_pts_n (segment_poly (fin_to_poly n k_u_val) nblocks)) (eval_pts_n (segment_poly Ring.gen nblocks)))
                (eval_pts_n (ker_chain (fin_to_deltas k_u_ker_val))))) =
        point_seq_add
          (eval_pts_n (segment_poly (fin_to_poly n (rq_to_fin (r1 + h_rq * r2))) nblocks))
          (point_seq_add
             (point_seq_mul (eval_pts_n (segment_poly (fin_to_poly n (f_u p_u k_u_val)) nblocks)) (eval_pts_n (segment_poly Ring.gen nblocks)))
             (eval_pts_n (ker_chain (fin_to_deltas (f_u_ker diff k_u_ker_val))))).
  Proof.
    intros pk1 t_fin k_u_val r1 r2 h_poly h_rq p_u Hpk1.
    move/andP: Hpk1 => [/andP [H1 H2] H3].
    have H2_small : all_coeffs_small (interpolate_n (unpack_points pk1)) by move/all_coeffs_smallbP: H2.
    have Hsz_pk1 : size (unpack_points pk1) = npoints by rewrite /unpack_points /points_tuple_to_seq size_tuple.
    have H_pk1_eq : eval_pts_n (interpolate_n (unpack_points pk1)) = unpack_points pk1 by apply: eval_interpolate_id.
    have H_h_eq : fin_to_poly n (poly_to_fin n h_poly) = h_poly.
    { rewrite /fin_to_poly /poly_to_fin /= polyF2_takeK.
      exact: take_poly_id. }
    have H_h_rq_eq : (h_rq : {poly F2}) = h_poly.
    { rewrite /h_rq.
      rewrite -fin_to_poly_rq_to_fin.
      rewrite fin_to_rqK.
      exact: H_h_eq. }
    have H_split_h : segment_poly h_poly nblocks = interpolate_n (unpack_points pk1).
    { rewrite /h_poly.
      by rewrite segment_poly_combine_poly. }
    have H_test : forall (p q : {poly K}), eval_points npoints (p + q) = point_seq_add (eval_points npoints p) (eval_points npoints q) by move=> p q; exact: eval_points_add.
    have Hn_le : (n <= nblocks * W)%N by exact: (ltnW nblocks_bound).
    pose P_diff :=
      segment_poly (fin_to_poly n (rq_to_fin (r1 + h_rq * r2))) nblocks +
      segment_poly (fin_to_poly n (f_u p_u k_u_val)) nblocks * segment_poly Ring.gen nblocks +
      segment_poly r1 nblocks +
      segment_poly h_poly nblocks * segment_poly r2 nblocks +
      segment_poly (fin_to_poly n k_u_val) nblocks * segment_poly Ring.gen nblocks.
    have H_comb : combine_poly P_diff = 0.
    { rewrite /P_diff !combine_poly_add.
      have H_sz_f1 : (size (fin_to_poly n (rq_to_fin (r1 + h_rq * r2)%R)) <= nblocks * W)%N.
      { apply: leq_trans Hn_le. rewrite /fin_to_poly. exact: size_polyF2_of_nat. }
      have H_sz_f2 : (size (fin_to_poly n (f_u p_u k_u_val)) <= nblocks * W)%N.
      { apply: leq_trans Hn_le. rewrite /fin_to_poly. exact: size_polyF2_of_nat. }
      have H_sz_f3 : (size (fin_to_poly n k_u_val) <= nblocks * W)%N.
      { apply: leq_trans Hn_le. rewrite /fin_to_poly. exact: size_polyF2_of_nat. }
      have H_sz_gen : (size Ring.gen <= nblocks * W)%N.
      { rewrite Ring.size_gen. change P.RingP.n with n. exact: nblocks_bound. }
      have H_sz_r1 : (size r1 <= nblocks * W)%N.
      { apply: (leq_trans _ Hn_le). exact: size_Rq_val. }
      have H_sz_r2 : (size r2 <= nblocks * W)%N.
      { apply: (leq_trans _ Hn_le). exact: size_Rq_val. }
      have H_sz_h : (size h_poly <= nblocks * W)%N.
      { apply: (leq_trans _ Hn_le). exact: H3. }
      rewrite (combine_poly_split _ _ H_sz_f1) (combine_poly_split _ _ H_sz_r1)
              (combine_poly_mul_segment_poly _ _ _ H_sz_f2 H_sz_gen)
              (combine_poly_mul_segment_poly _ _ _ H_sz_h H_sz_r2)
              (combine_poly_mul_segment_poly _ _ _ H_sz_f3 H_sz_gen).
      rewrite /rq_to_fin.
      rewrite (in_qpoly_rq_eq r1 r2 h_rq).
      fold rq_to_fin.
      rewrite -H_h_rq_eq.
      have H_sz_hrq : (size (h_rq : {poly F2}) <= n)%N by rewrite H_h_rq_eq.
      have H_ueq := u_eq (r1 : {poly F2}) (r2 : {poly F2}) (h_rq : {poly F2}) k_u_val (size_Rq_val r1) (size_Rq_val r2) H_sz_hrq.
      have H_char2 : forall p : {poly F2}, (p + p = 0)%R.
      { move=> p. apply/polyP => i. rewrite coefD coef0.
        rewrite -[p`_i + _]/(p`_i *+ 2).
        rewrite -mulr_natr.
        have Hchar : 2 \in [char 'F_2] by exact: pchar_Fp 2 PointFieldHelpers.prime2.
        by rewrite (pcharf0 Hchar) mulr0. }
      rewrite -H_ueq.
      apply/polyP => i.
      rewrite !coefD !coef0.
      have char2_F2 : forall x : F2, x + x = 0.
      { move=> x. rewrite -[x + _]/(x *+ 2) -mulr_natr.
        have Hchar : 2 \in [pchar 'F_2] by exact: pchar_Fp 2 PointFieldHelpers.prime2.
        by rewrite (pcharf0 Hchar) mulr0. }
      rewrite -!addrA.
      rewrite [in X in X = 0]addrA.
      rewrite [in X in X = 0]addrA.
      rewrite [in X in _ + X = 0]addrA.
      apply: char2_F2. }
    have Hsz_Pdiff : (size P_diff <= 2 * nblocks)%N.
    { rewrite /P_diff.
      apply: (leq_trans (size_polyD _ _)). rewrite geq_max. apply/andP; split.
      - apply: (leq_trans (size_polyD _ _)). rewrite geq_max. apply/andP; split.
        + apply: (leq_trans (size_polyD _ _)). rewrite geq_max. apply/andP; split.
          * apply: (leq_trans (size_polyD _ _)). rewrite geq_max. apply/andP; split.
            -- apply: (leq_trans (size_segment_poly _ _)).
               by rewrite mulnC; exact: leq_pmulr.
            -- apply: (leq_trans (size_polyMleq _ _)).
               apply: (leq_trans (leq_pred _)).
               by rewrite mulnC muln2 -addnn; apply: leq_add; exact: size_segment_poly.
          * apply: (leq_trans (size_segment_poly _ _)).
            by rewrite mulnC; exact: leq_pmulr.
        + apply: (leq_trans (size_polyMleq _ _)).
          apply: (leq_trans (leq_pred _)).
          by rewrite mulnC muln2 -addnn; apply: leq_add; exact: size_segment_poly.
      - apply: (leq_trans (size_polyMleq _ _)).
        apply: (leq_trans (leq_pred _)).
        by rewrite mulnC muln2 -addnn; apply: leq_add; exact: size_segment_poly. }
    have [deltas [H_deltas [H_sz H_all]]] := combine_poly_ker_decompose P_diff H_comb.
    pose deltas_pad := deltas ++ nseq (2 * nblocks - size deltas) 0%R.
    have H_deltas_sz : (size deltas <= 2 * nblocks)%N.
    { rewrite H_sz. case: (size P_diff <= 1)%N.
      - exact: Hsz_Pdiff.
      - apply: leq_trans (leq_pred _) Hsz_Pdiff. }
    have H_pad_sz : size deltas_pad = (2 * nblocks)%N by rewrite /deltas_pad size_cat size_nseq addnC subnK.
    have H_nseq_zero : forall k0, ker_chain (nseq k0 0) = 0.
    { elim=> [|k0 IH] /=; first done.
      rewrite IH mul0r addr0 /ker_elem.
      have Hz : in_qpoly gen 0 = 0 by rewrite in_qpoly0.
      by rewrite Hz mul0r Hz !polyC0 mul0r add0r. }
    have H_pad_eq_gen : forall ds k0, ker_chain (ds ++ nseq k0 0) = ker_chain ds.
    { elim=> [|d ds IH] k0 /=.
      - exact: H_nseq_zero.
      - by rewrite IH. }
    have H_pad_eq : ker_chain deltas_pad = ker_chain deltas by exact: H_pad_eq_gen.
    have H_deltas_el : forall idx, (idx < size deltas)%N -> (size (nth 0%R deltas idx) <= W)%N.
    { move=> idx Hidx.
      have /allP H_all' := H_all.
      have H_in : nth 0%R deltas idx \in deltas by exact: mem_nth.
      have H_sz_el' := H_all' (nth 0%R deltas idx) H_in.
      have H_tmp : (size (nth 0%R deltas idx) + W <= 2 * W)%N by exact: leq_trans H_sz_el' d_le_W2.
      rewrite mul2n in H_tmp.
      rewrite -addnn in H_tmp.
      by rewrite leq_add2r in H_tmp. }
    have H_pad_el : forall idx, (idx < 2 * nblocks)%N -> (size (nth 0%R deltas_pad idx) <= W)%N.
    { move=> idx Hidx.
      rewrite /deltas_pad nth_cat.
      case: ifPn => Hcond.
      - exact: H_deltas_el.
      - rewrite nth_nseq.
        case: ifPn => [_|//]; by rewrite size_poly0. }
    exists (deltas_to_fin deltas_pad).
    move=> k_u_ker_val.
    have H_f_u_eq : fin_to_deltas (f_u_ker (deltas_to_fin deltas_pad) k_u_ker_val) =
      [seq ((fin_to_deltas k_u_ker_val)`_idx + deltas_pad`_idx)%R | idx <- iota 0 (2 * nblocks)].
    { rewrite /f_u_ker.
      have H_deltas_padK : fin_to_deltas (deltas_to_fin deltas_pad) = deltas_pad.
      { by rewrite deltas_to_finK. }
      rewrite H_deltas_padK.
      rewrite deltas_to_finK.
      - by rewrite size_map size_iota.
      - move=> idx Hidx.
        rewrite (nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n.
        apply: (leq_trans (size_polyD _ _)).
        rewrite geq_max.
        apply/andP; split; [exact: size_fin_to_deltas | exact: H_pad_el].
      - by []. }
    rewrite -H_pk1_eq -H_split_h.
    rewrite /eval_pts_n.
    rewrite -!eval_points_mul.
    rewrite -!H_test.
    rewrite H_f_u_eq.
    have H_char_F2 : 2%N \in [pchar F2] by apply: pchar_Fp; exact: PointFieldHelpers.prime2.
    have H_charK : 2%N \in [pchar K] by rewrite /K pchar_qpoly.
    have H_char_polyK_pred : 2%N \in [pchar {poly K}] by rewrite pchar_poly.
    have H_char_polyK : forall x : {poly K}, x + x = 0 by move=> x; apply: (addrr_pchar2 H_char_polyK_pred).
    have H_sz_eq : size (fin_to_deltas k_u_ker_val) = size deltas_pad.
    { by rewrite H_pad_sz /fin_to_deltas size_map size_enum_ord. }
    have -> : (2 * nblocks)%nat = size (fin_to_deltas k_u_ker_val) by rewrite /fin_to_deltas size_map size_enum_ord.
    rewrite (ker_chain_add (fin_to_deltas k_u_ker_val) deltas_pad H_sz_eq).
    rewrite H_pad_eq -H_deltas /P_diff.
    f_equal.
    rewrite -!addrA.
    rewrite [ker_chain _ + (segment_poly _ _ + _)]addrCA.
    rewrite [segment_poly (fin_to_poly _ (f_u _ _)) _ * _ + (segment_poly (fin_to_poly _ (rq_to_fin _)) _ + _)]addrCA.
    rewrite [segment_poly (fin_to_poly _ (rq_to_fin _)) _ + (segment_poly (fin_to_poly _ (rq_to_fin _)) _ + _)]addrA.
    rewrite H_char_polyK add0r.
    rewrite [ker_chain _ + (segment_poly _ _ * _ + _)]addrCA.
    rewrite [segment_poly (fin_to_poly _ (f_u _ _)) _ * _ + (segment_poly (fin_to_poly _ (f_u _ _)) _ * _ + _)]addrA.
    rewrite H_char_polyK add0r.
    rewrite addrC.
    by rewrite -!addrA.
  Qed.

  Lemma hqctiny_v_eq : forall (pk2 : PointSeqCt) (msg : Message_t) (t_fin : 'I_('C(n, we) ^ 3)) (k_v_val : 'I_(2^n)),
    let r2 := sval (fin_to_rq_we (tnth (fin_to_tuple_fin 'C(n, we) 3 t_fin) (inord 1))) in
    let e := sval (fin_to_rq_we (tnth (fin_to_tuple_fin 'C(n, we) 3 t_fin) (inord 2))) in
    let s_poly := combine_poly (interpolate_n (unpack_points pk2)) in
    let s_rq := fin_to_rq (poly_to_fin n s_poly) in
    let m_poly := P.encode msg in
    let p_v := ((m_poly : {poly F2}) + (s_rq : {poly F2}) * (r2 : {poly F2}) + (e : {poly F2})) in
    valid_pk_b (unpack_points pk2) ->
    exists (diff : 'I_deltas_size),
      forall (k_v_ker_val : 'I_deltas_size) (t_val : 'I_(2^(n-n1n2))),
        point_seq_add (eval_pts_n (segment_poly (P.encode msg) nblocks))
          (point_seq_add
             (point_seq_mul (unpack_points pk2) (eval_pts_n (segment_poly r2 nblocks)))
             (point_seq_add
                (eval_pts_n (segment_poly e nblocks))
                (point_seq_add
                   (point_seq_add
                      (point_seq_mul (eval_pts_n (segment_poly (fin_to_poly n k_v_val) nblocks)) (eval_pts_n (segment_poly Ring.gen nblocks)))
                      (eval_pts_n (ker_chain (fin_to_deltas k_v_ker_val))))
                   (eval_pts_n (segment_poly ('X^n1n2 * fin_to_poly (n - n1n2) t_val) nblocks))))) =
        point_seq_add
          (eval_pts_n (segment_poly (fin_to_poly n (rq_to_fin (HQC_Sec.truncate (m_poly + s_rq * r2 + e)))) nblocks))
          (point_seq_add
             (point_seq_add
                (point_seq_mul (eval_pts_n (segment_poly (fin_to_poly n (f_v p_v k_v_val)) nblocks)) (eval_pts_n (segment_poly Ring.gen nblocks)))
                (eval_pts_n (ker_chain (fin_to_deltas (f_v_ker diff k_v_ker_val)))))
             (eval_pts_n (segment_poly ('X^n1n2 * fin_to_poly (n - n1n2) (f_t p_v t_val)) nblocks))).
  Proof.
    intros pk2 msg t_fin k_v_val r2 e s_poly s_rq m_poly p_v Hpk2.
    move/andP: Hpk2 => [/andP [H1 H2] H3].
    have H2_small : all_coeffs_small (interpolate_n (unpack_points pk2))
      by move/all_coeffs_smallbP: H2.
    have Hsz_pk2 : size (unpack_points pk2) = npoints
      by rewrite /unpack_points /points_tuple_to_seq size_tuple.
    have H_pk2_eq : eval_pts_n (interpolate_n (unpack_points pk2)) = unpack_points pk2
      by apply: eval_interpolate_id.
    have H_s_eq : fin_to_poly n (poly_to_fin n s_poly) = s_poly
      by rewrite /fin_to_poly /poly_to_fin /= polyF2_takeK; apply: take_poly_id.
    have H_s_rq_eq : (s_rq : {poly F2}) = s_poly
      by rewrite /s_rq -fin_to_poly_rq_to_fin fin_to_rqK H_s_eq.
    have H_split_s : segment_poly s_poly nblocks = interpolate_n (unpack_points pk2)
      by rewrite /s_poly segment_poly_combine_poly.
    have H_test : forall (p q : {poly K}),
        eval_points npoints (p + q) =
        point_seq_add (eval_points npoints p) (eval_points npoints q)
      by move=> p q; exact: eval_points_add.
    have Hn_le : (n <= nblocks * W)%N
      by exact: (ltnW nblocks_bound).
    pose q_trunc := (drop_poly n1n2 (p_v %% Ring.gen) : {poly F2}).
    have Hsz_q_trunc : (size q_trunc <= n - n1n2)%N.
    { rewrite /q_trunc size_drop_poly. apply: leq_sub2r.
      have H := ltn_modpN0 p_v (monic_neq0 Ring.gen_monic).
      rewrite Ring.size_gen in H. exact: H. }
    pose P_diff :=
      segment_poly (fin_to_poly n (rq_to_fin (HQC_Sec.truncate (m_poly + s_rq * r2 + e)))) nblocks +
      segment_poly (fin_to_poly n (f_v p_v k_v_val)) nblocks * segment_poly Ring.gen nblocks +
      segment_poly ('X^n1n2 * q_trunc) nblocks +
      segment_poly (m_poly : {poly F2}) nblocks +
      segment_poly s_poly nblocks * segment_poly (r2 : {poly F2}) nblocks +
      segment_poly (e : {poly F2}) nblocks +
      segment_poly (fin_to_poly n k_v_val) nblocks * segment_poly Ring.gen nblocks.
    have H_comb : combine_poly P_diff = 0.
    { rewrite /P_diff !combine_poly_add.
      have H_sz_f1 : (size (fin_to_poly n (rq_to_fin (HQC_Sec.truncate (m_poly + s_rq * r2 + e)%R))) <= nblocks * W)%N
        by (apply: leq_trans Hn_le; rewrite /fin_to_poly; exact: size_polyF2_of_nat).
      have H_sz_f2 : (size (fin_to_poly n (f_v p_v k_v_val)) <= nblocks * W)%N
        by (apply: leq_trans Hn_le; rewrite /fin_to_poly; exact: size_polyF2_of_nat).
      have H_sz_f3 : (size (fin_to_poly n k_v_val) <= nblocks * W)%N
        by (apply: leq_trans Hn_le; rewrite /fin_to_poly; exact: size_polyF2_of_nat).
      have H_sz_gen : (size Ring.gen <= nblocks * W)%N
        by (rewrite Ring.size_gen; change P.RingP.n with n; exact: nblocks_bound).
      have H_sz_m_poly : (size (m_poly : {poly F2}) <= nblocks * W)%N
        by (apply: (leq_trans _ Hn_le); exact: size_Rq_val).
      have H_sz_r2 : (size (r2 : {poly F2}) <= nblocks * W)%N
        by (apply: (leq_trans _ Hn_le); exact: size_Rq_val).
      have H_sz_e : (size (e : {poly F2}) <= nblocks * W)%N
        by (apply: (leq_trans _ Hn_le); exact: size_Rq_val).
      have H_sz_s : (size s_poly <= nblocks * W)%N
        by (apply: (leq_trans _ Hn_le); exact: H3).
      pose X_q : {poly F2} := ('X^n1n2 * q_trunc)%R.
      have H_sz_X_q : (size X_q <= nblocks * W)%N.
      { rewrite /X_q.
        have [-> | H_neq0] := eqVneq q_trunc 0.
        - by rewrite mulr0 size_poly0.
        - have Hpos : (0 < size q_trunc)%N by rewrite size_poly_gt0.
          have H_n1n2_le_n : (n1n2 <= n)%N.
          { have H_gt0 : (0 < n - n1n2)%N.
            { case: (n - n1n2)%N Hsz_q_trunc => [| m] Hsz.
              - exfalso. move: Hpos. apply/negP.
                rewrite -ltnNge. exact: Hsz.
              - by []. }
            have H_lt : (n1n2 < n)%N by rewrite -subn_gt0.
            exact: ltnW H_lt. }
          have := size_polyMleq 'X^n1n2 q_trunc.
          rewrite size_polyXn.
          move=> H_bound.
          apply: (leq_trans H_bound).
          rewrite addSn /=.
          have Htmp: (n1n2 + size q_trunc <= n1n2 + (n - n1n2))%N
            by rewrite leq_add2l.
          have Hfinal: (n1n2 + (n - n1n2) <= nblocks * W)%N
            by rewrite subnKC.
          exact: (leq_trans Htmp Hfinal). }
      rewrite (combine_poly_split _ _ H_sz_f1)
              (combine_poly_split _ _ H_sz_m_poly)
              (combine_poly_mul_segment_poly _ _ _ H_sz_f2 H_sz_gen)
              (combine_poly_mul_segment_poly _ _ _ H_sz_s H_sz_r2)
              (combine_poly_split _ _ H_sz_e)
              (combine_poly_mul_segment_poly _ _ _ H_sz_f3 H_sz_gen)
              (combine_poly_split X_q nblocks H_sz_X_q)
              /X_q.
      rewrite /p_v.
      have H_char2 : forall p : {poly F2}, (p + p = 0)%R.
      { move=> p. apply/polyP => i. rewrite coefD coef0.
        rewrite -[p`_i + _]/(p`_i *+ 2).
        rewrite -mulr_natr.
        have Hchar : 2 \in [char 'F_2] by exact: pchar_Fp 2 PointFieldHelpers.prime2.
        by rewrite (pcharf0 Hchar) mulr0. }
      set t_val := poly_to_fin (n - n1n2) q_trunc.
      have H_t_val_eq : fin_to_poly (n - n1n2) t_val = q_trunc.
      { rewrite /t_val /fin_to_poly /poly_to_fin /= polyF2_takeK.
        apply: take_poly_id. exact: Hsz_q_trunc. }
      have H_f_t_zero : fin_to_poly (n - n1n2) (f_t
        ((m_poly : {poly F2}) + s_poly * (r2 : {poly F2}) + (e : {poly F2}))
        t_val) = 0.
      { rewrite /f_t H_t_val_eq /q_trunc.
        have Hft0 : fin_to_poly (n - n1n2) (poly_to_fin (n - n1n2) 0) = 0.
        { rewrite /fin_to_poly /poly_to_fin /=.
          rewrite polyF2_takeK. apply: take_poly_id.
          rewrite size_poly0. exact: leq0n. }
        rewrite -H_s_rq_eq -/p_v -/q_trunc.
        rewrite H_char2.
        exact: Hft0. }
      have H_sz_pv_s : (size s_poly <= n)%N by exact: H3.
      have H_veq := v_eq (r2 : {poly F2}) (e : {poly F2}) s_poly
        (m_poly : {poly F2}) k_v_val t_val
        (size_Rq_val r2) (size_Rq_val e) H_sz_pv_s (size_Rq_val m_poly).
      move: H_veq; rewrite /= => H_veq'.
      rewrite H_t_val_eq in H_veq'.
      rewrite H_f_t_zero in H_veq'.
      rewrite mulr0 addr0 in H_veq'.
      set p_s := ((m_poly : {poly F2}) + s_poly * (r2 : {poly F2})
                 + (e : {poly F2}))%R.
      have H_rq_eq : m_poly + s_rq * r2 + e
        = in_qpoly Ring.gen p_s.
      { apply/val_inj; rewrite /p_s.
        rewrite -H_s_rq_eq; exact: in_qpoly_rq_eq3 m_poly s_rq r2 e. }
      rewrite H_rq_eq.
      rewrite -[Pdiv.CommonRing.rmodp (R:=fintype_ordinal__canonical__GRing_NzRing
        (Zp_trunc (pdiv 2))) (polyF2_of_nat (nat_of_polyF2 s_poly 0 n)
        0 P.n) (mk_monic Ring.gen)]/(s_rq : {poly F2}).
      rewrite H_s_rq_eq.
      rewrite -/p_s.
      have H_veq_ps : p_s + fin_to_poly n k_v_val * Ring.gen +
          'X^n1n2 * q_trunc =
        fin_to_poly n (rq_to_fin (truncate (in_qpoly Ring.gen p_s))) +
        fin_to_poly n (f_v p_s k_v_val) * Ring.gen
        by rewrite /p_s H_veq'.
      rewrite -H_veq_ps.
      apply/polyP => j; rewrite !coefD !coef0.
      have char2_F2 : forall (x : F2), x + x = 0.
      { move=> x. rewrite -[x + _]/(x *+ 2) -mulr_natr.
        have Hpchar : 2 \in [pchar 'F_2]
          by exact: pchar_Fp 2 PointFieldHelpers.prime2.
        by rewrite (pcharf0 Hpchar) mulr0. }
      rewrite -!addrA.
      rewrite [('X^n1n2 * q_trunc)`_j +
          (('X^n1n2 * q_trunc)`_j + _)]addrA char2_F2 add0r.
      rewrite [(fin_to_poly n k_v_val * Ring.gen)`_j +
          (m_poly`_j + _)]addrCA.
      rewrite [e`_j + (m_poly`_j + _)]addrCA.
      rewrite [(s_poly * r2)`_j + (m_poly`_j + _)]addrCA.
      rewrite [m_poly`_j + (m_poly`_j + _)]addrA char2_F2 add0r.
      rewrite [(fin_to_poly n k_v_val * Ring.gen)`_j +
          ((s_poly * r2)`_j + _)]addrCA.
      rewrite [e`_j + ((s_poly * r2)`_j + _)]addrCA.
      rewrite [(s_poly * r2)`_j +
          ((s_poly * r2)`_j + _)]addrA char2_F2 add0r.
      rewrite [(fin_to_poly n k_v_val * Ring.gen)`_j +
          (e`_j + _)]addrCA.
      rewrite [e`_j + (e`_j + _)]addrA char2_F2 add0r.
      exact: char2_F2. }
    have Hsz_Pdiff : (size P_diff <= 2 * nblocks)%N.
    { rewrite /P_diff.
      apply: (leq_trans (size_polyD _ _)). rewrite geq_max. apply/andP; split.
      - apply: (leq_trans (size_polyD _ _)). rewrite geq_max. apply/andP; split.
        + apply: (leq_trans (size_polyD _ _)). rewrite geq_max. apply/andP; split.
          * apply: (leq_trans (size_polyD _ _)). rewrite geq_max. apply/andP; split.
            -- apply: (leq_trans (size_polyD _ _)). rewrite geq_max. apply/andP; split.
               ++ { apply: (leq_trans (size_polyD _ _)).
                    rewrite geq_max. apply/andP; split.
                    - apply: (leq_trans (size_segment_poly _ _)).
                      by rewrite mulnC; exact: leq_pmulr.
                    - apply: (leq_trans (size_polyMleq _ _)).
                      apply: (leq_trans (leq_pred _)).
                      by rewrite mulnC muln2 -addnn;
                         apply: leq_add; exact: size_segment_poly. }
               ++ apply: (leq_trans (size_segment_poly _ _)).
                  by rewrite mulnC; exact: leq_pmulr.
            -- apply: (leq_trans (size_segment_poly _ _)).
               by rewrite mulnC; exact: leq_pmulr.
          * apply: (leq_trans (size_polyMleq _ _)).
            apply: (leq_trans (leq_pred _)).
            by rewrite mulnC muln2 -addnn; apply: leq_add; exact: size_segment_poly.
        + apply: (leq_trans (size_segment_poly _ _)).
          by rewrite mulnC; exact: leq_pmulr.
      - apply: (leq_trans (size_polyMleq _ _)).
        apply: (leq_trans (leq_pred _)).
        by rewrite mulnC muln2 -addnn; apply: leq_add; exact: size_segment_poly. }
    have [deltas [H_deltas [H_sz H_all]]] := combine_poly_ker_decompose P_diff H_comb.
    pose deltas_pad := deltas ++ nseq (2 * nblocks - size deltas) 0%R.
    have H_deltas_sz : (size deltas <= 2 * nblocks)%N.
    { rewrite H_sz. case: (size P_diff <= 1)%N.
      - exact: Hsz_Pdiff.
      - apply: leq_trans (leq_pred _) Hsz_Pdiff. }
    have H_pad_sz : size deltas_pad = (2 * nblocks)%N
      by rewrite /deltas_pad size_cat size_nseq addnC subnK.
    have H_nseq_zero : forall k0, ker_chain (nseq k0 0) = 0.
    { elim=> [|k0 IH] /=; first done.
      rewrite IH mul0r addr0 /ker_elem.
      have Hz : in_qpoly gen 0 = 0 by rewrite in_qpoly0.
      by rewrite Hz mul0r Hz !polyC0 mul0r add0r. }
    have H_pad_eq_gen : forall ds k0, ker_chain (ds ++ nseq k0 0) = ker_chain ds.
    { elim=> [|d ds IH] k0 /=.
      - exact: H_nseq_zero.
      - by rewrite IH. }
    have H_pad_eq : ker_chain deltas_pad = ker_chain deltas
      by exact: H_pad_eq_gen.
    have H_deltas_el : forall idx, (idx < size deltas)%N ->
        (size (nth 0%R deltas idx) <= W)%N.
    { move=> idx Hidx.
      have /allP H_all' := H_all.
      have H_in : nth 0%R deltas idx \in deltas by exact: mem_nth.
      have H_sz_el' := H_all' (nth 0%R deltas idx) H_in.
      have H_tmp : (size (nth 0%R deltas idx) + W <= 2 * W)%N
        by exact: leq_trans H_sz_el' d_le_W2.
      rewrite mul2n in H_tmp. rewrite -addnn in H_tmp.
      by rewrite leq_add2r in H_tmp. }
    have H_pad_el : forall idx, (idx < 2 * nblocks)%N ->
        (size (nth 0%R deltas_pad idx) <= W)%N.
    { move=> idx Hidx.
      rewrite /deltas_pad nth_cat.
      case: ifPn => Hcond.
      - exact: H_deltas_el.
      - rewrite nth_nseq.
        case: ifPn => [_|//]; by rewrite size_poly0. }
    exists (deltas_to_fin deltas_pad).
    move=> k_v_ker_val t_val.
    have H_f_v_eq : fin_to_deltas (f_v_ker (deltas_to_fin deltas_pad) k_v_ker_val) =
      [seq ((fin_to_deltas k_v_ker_val)`_idx + deltas_pad`_idx)%R
       | idx <- iota 0 (2 * nblocks)].
    { rewrite /f_v_ker.
      have H_deltas_padK : fin_to_deltas (deltas_to_fin deltas_pad) = deltas_pad
        by rewrite deltas_to_finK.
      rewrite H_deltas_padK.
      rewrite deltas_to_finK.
      - by rewrite size_map size_iota.
      - move=> idx Hidx.
        rewrite (nth_map 0%N 0%R) ?size_iota // nth_iota //= add0n.
        apply: (leq_trans (size_polyD _ _)).
        rewrite geq_max.
        apply/andP; split; [exact: size_fin_to_deltas | exact: H_pad_el].
      - by []. }
    have H_char_F2 : 2%N \in [pchar F2] by apply: pchar_Fp; exact: PointFieldHelpers.prime2.
    have H_charK : 2%N \in [pchar K] by rewrite /K pchar_qpoly.
    have H_char_polyK_pred : 2%N \in [pchar {poly K}] by rewrite pchar_poly.
    have H_char_polyK : forall x : {poly K}, x + x = 0
      by move=> x; apply: (addrr_pchar2 H_char_polyK_pred).
    have H_sz_eq : size (fin_to_deltas k_v_ker_val) = size deltas_pad
      by rewrite H_pad_sz /fin_to_deltas size_map size_enum_ord.
    rewrite -H_pk2_eq -H_split_s /eval_pts_n.
    rewrite -!eval_points_mul -!H_test.
    rewrite H_f_v_eq.
    have -> : (2 * nblocks)%nat = size (fin_to_deltas k_v_ker_val)
      by rewrite /fin_to_deltas size_map size_enum_ord.
    rewrite (ker_chain_add (fin_to_deltas k_v_ker_val) deltas_pad H_sz_eq).
    rewrite H_pad_eq -H_deltas /P_diff.
    f_equal.
    rewrite /f_t.
    change (drop_poly n1n2 (p_v %% Ring.gen)) with q_trunc.
    rewrite /fin_to_poly /poly_to_fin /= polyF2_takeK.
    rewrite polyF2_takeK.
    rewrite (polyF2_takeK (polyF2_of_nat t_val 0 (n - n1n2) + q_trunc) (n - n1n2)).
    have Hsz : (size (Pdiv.CommonRing.rmodp _ (mk_monic Ring.gen)) <= P.n)%N.
    { have H_monic : mk_monic Ring.gen \is monic by apply: monic_mk_monic.
      have H_lt := ltn_modpN0 _ (monic_neq0 H_monic).
      rewrite Ring.size_mk_monic_gen in H_lt.
      move=> p.
      rewrite -Pdiv.IdomainMonic.modpE //.
      exact: H_lt. }
    rewrite (take_poly_id (Hsz _)).
    have Hsz_sum : (size (polyF2_of_nat t_val 0 (n - n1n2) + q_trunc)%R <= n - n1n2)%N.
    { apply: (leq_trans (size_polyD _ _)).
      rewrite geq_max.
      apply/andP; split; [exact: size_polyF2_of_nat | exact: Hsz_q_trunc]. }
    rewrite (take_poly_id Hsz_sum).
    rewrite mulrDr segment_poly_add.
    rewrite segment_poly_add.
    rewrite -!addrA.
    rewrite [segment_poly ('X^n1n2 * q_trunc) nblocks + (segment_poly m_poly nblocks + _)]addrCA.
    rewrite [segment_poly ('X^n1n2 * q_trunc) nblocks + (segment_poly s_poly nblocks * _ + _)]addrCA.
    rewrite [segment_poly ('X^n1n2 * q_trunc) nblocks + (segment_poly e nblocks + _)]addrCA.
    rewrite [segment_poly ('X^n1n2 * q_trunc) nblocks + (segment_poly (polyF2_of_nat k_v_val 0 n) nblocks * _ + _)]addrCA.
    rewrite [segment_poly ('X^n1n2 * polyF2_of_nat t_val 0 (n - n1n2)) nblocks + segment_poly ('X^n1n2 * q_trunc) nblocks]addrC.
    rewrite [segment_poly ('X^n1n2 * q_trunc) nblocks + (segment_poly ('X^n1n2 * q_trunc) nblocks + _)]addrA.
    rewrite H_char_polyK add0r.
    rewrite [ker_chain (fin_to_deltas k_v_ker_val) + (segment_poly (Pdiv.CommonRing.rmodp _ (mk_monic Ring.gen)) nblocks + _)]addrCA.
    rewrite [segment_poly (polyF2_of_nat _ 0 n) nblocks * _ + (segment_poly (Pdiv.CommonRing.rmodp _ (mk_monic Ring.gen)) nblocks + _)]addrCA.
    rewrite [segment_poly (Pdiv.CommonRing.rmodp _ (mk_monic Ring.gen)) nblocks + (segment_poly (Pdiv.CommonRing.rmodp _ (mk_monic Ring.gen)) nblocks + _)]addrA.
    rewrite H_char_polyK add0r.
    rewrite [ker_chain (fin_to_deltas k_v_ker_val) + (_ + _)]addrCA.
    rewrite [segment_poly (polyF2_of_nat _ 0 n) nblocks * _ + (segment_poly (polyF2_of_nat _ 0 n) nblocks * _ + _)]addrA.
    rewrite H_char_polyK add0r.
    change (P.encode msg) with m_poly.
    rewrite [segment_poly (polyF2_of_nat k_v_val 0 n) nblocks * _ + (ker_chain _ + _)]addrCA.
    rewrite [segment_poly e nblocks + (ker_chain _ + _)]addrCA.
    rewrite [segment_poly s_poly nblocks * _ + (ker_chain _ + _)]addrCA.
    rewrite [segment_poly m_poly nblocks + (ker_chain _ + _)]addrCA.
    done.
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
      have [diff_u Hdiff_u] := hqctiny_u_eq pk1 t_fin k_u_val Hpk1.
      eapply r_uniform_bij.
      Unshelve. 3: exact (f_u_ker diff_u).
      { apply: f_u_ker_bij. }
      intro k_u_ker_val. simpl.
      have [diff_v Hdiff_v] := hqctiny_v_eq pk2 msg t_fin k_v_val Hpk2.
      eapply r_uniform_bij.
      Unshelve. 3: exact (f_v_ker diff_v).
      { apply: f_v_ker_bij. }
      intro k_v_ker_val. simpl.
      eapply r_uniform_bij.
      Unshelve. 3: exact (f_t p_v).
      { apply: f_t_bij. }
      intro t_val. simpl.
      eapply r_ret.
      move=> s0 s1 ->. split; [ | done ].
      f_equal.
      (* --- u component --- *)
      { f_equal.
        exact: Hdiff_u. }
      (* --- v component --- *)
      { f_equal.
        exact: Hdiff_v. } }
    { (* false branch *)
      simplify_linking.
      apply: r_fail. }
  Qed.

End HQCTiny.

Open Scope ring_scope.

Definition d_val : nat := 9009%N.
Definition gen_K_val : {poly 'F_2} := 'X^9009 + 'X^29 + 1.

Lemma gen_K_monic_aux : gen_K_val \is monic.
Proof.
  rewrite monicE.
  have H1 : (size (1%:P : {poly 'F_2}) <
             size (GRing.add 'X^9009 'X^29 : {poly 'F_2}))%N.
  - rewrite size_polyDl.
    + rewrite !size_polyXn. by [].
    + rewrite size_polyC size_polyXn. by [].
  - rewrite (lead_coefDl H1).
    have H2 : (size ('X^29 : {poly 'F_2}) < size ('X^9009 : {poly 'F_2}))%N.
    + rewrite !size_polyXn. by [].
    + rewrite (lead_coefDl H2).
      rewrite lead_coefXn. by [].
Qed.

Lemma size_gen_K_aux : size gen_K_val = d_val.+1.
Proof.
  rewrite /gen_K_val /d_val.
  have H1 : (size (1%:P : {poly 'F_2}) <
             size (GRing.add 'X^9009 'X^29 : {poly 'F_2}))%N.
  - rewrite size_polyDl.
    + rewrite !size_polyXn. by [].
    + rewrite size_polyC size_polyXn. by [].
  - rewrite (size_polyDl H1).
    have H2 : (size ('X^29 : {poly 'F_2}) < size ('X^9009 : {poly 'F_2}))%N.
    + rewrite !size_polyXn. by [].
    + rewrite (size_polyDl H2).
      rewrite size_polyXn. by [].
Qed.

Module HQCTiny1Params <: HQCTinyParams.
  Include HQC1.

  Definition d : nat := d_val.
  Definition gen_K : {poly 'F_2} := gen_K_val.

  Lemma gen_K_monic : gen_K \is monic.
  Proof. exact: gen_K_monic_aux. Qed.

  Lemma size_gen_K : size gen_K = d.+1.
  Proof. exact: size_gen_K_aux. Qed.

  (* Axiom: x^9009 + x^29 + 1 is irreducible over GF(2), a standard fact used
     to define GF(2^9009). Proving this in Rocq requires formalizing Rabin's
     irreducibility test: check gcd(p, X^(2^(9009/l)) - X) = 1 for each prime
     factor l of 9009 (l ∈ {3,7,11,13}) and p | X^(2^9009) - X. MathComp has
     no built-in Rabin test, and irreducibleb is infeasible here (it enumerates
     all 2^9009 polynomials of degree < 9009). *)
  Axiom gen_K_irreducible : irreducible_poly gen_K.

  Definition W : nat := 4505%N.
  Lemma W_gt0 : (0 < W)%N. Proof. done. Qed.
  Lemma W_le_d : (W <= d)%N. Proof. done. Qed.
  Lemma W2_lt_d : ((2 * W).-1 <= d)%N. Proof. done. Qed.
  Lemma d_le_W2 : (d <= 2 * W)%N. Proof. done. Qed.
  Lemma W_lt_n : (W < n)%N. Proof. done. Qed.

  Definition nblocks : nat := 4%N.
  Lemma nblocks_bound : (n < nblocks * W)%N. Proof. done. Qed.

  Definition npoints : nat := 7%N.
  Lemma npoints_gt0 : (0 < npoints)%N. Proof. done. Qed.
  Lemma npoints_le_card : (npoints <= (2 ^ d))%N.
  Proof.
    have H1 : (7 <= 2 ^ 3)%N by [].
    have H2 : (2 ^ 3 <= 2 ^ 9009)%N.
    { rewrite leq_exp2l //. }
    exact: (leq_trans H1 H2).
  Qed.
  Lemma nblocks2_le_npoints : ((2 * nblocks).-1 <= npoints)%N. Proof. done. Qed.
End HQCTiny1Params.

Module HQCTiny3Params <: HQCTinyParams.
  Include HQC3.

  Definition d : nat := d_val.
  Definition gen_K : {poly 'F_2} := gen_K_val.

  Lemma gen_K_monic : gen_K \is monic.
  Proof. exact: gen_K_monic_aux. Qed.

  Lemma size_gen_K : size gen_K = d.+1.
  Proof. exact: size_gen_K_aux. Qed.

  (* See HQCTiny1Params for explanation. *)
  Axiom gen_K_irreducible : irreducible_poly gen_K.

  Definition W : nat := 4505%N.
  Lemma W_gt0 : (0 < W)%N. Proof. done. Qed.
  Lemma W_le_d : (W <= d)%N. Proof. done. Qed.
  Lemma W2_lt_d : ((2 * W).-1 <= d)%N. Proof. done. Qed.
  Lemma d_le_W2 : (d <= 2 * W)%N. Proof. done. Qed.
  Lemma W_lt_n : (W < n)%N. Proof. done. Qed.

  Definition nblocks : nat := 8%N.
  Lemma nblocks_bound : (n < nblocks * W)%N. Proof. done. Qed.

  Definition npoints : nat := 15%N.
  Lemma npoints_gt0 : (0 < npoints)%N. Proof. done. Qed.
  Lemma npoints_le_card : (npoints <= (2 ^ d))%N.
  Proof.
    have H1 : (15 <= 2 ^ 4)%N by [].
    have H2 : (2 ^ 4 <= 2 ^ 9009)%N.
    { rewrite leq_exp2l //. }
    exact: (leq_trans H1 H2).
  Qed.
  Lemma nblocks2_le_npoints : ((2 * nblocks).-1 <= npoints)%N. Proof. done. Qed.
End HQCTiny3Params.

Module HQCTiny5Params <: HQCTinyParams.
  Include HQC5.

  Definition d : nat := d_val.
  Definition gen_K : {poly 'F_2} := gen_K_val.

  Lemma gen_K_monic : gen_K \is monic.
  Proof. exact: gen_K_monic_aux. Qed.

  Lemma size_gen_K : size gen_K = d.+1.
  Proof. exact: size_gen_K_aux. Qed.

  (* See HQCTiny1Params for explanation. *)
  Axiom gen_K_irreducible : irreducible_poly gen_K.

  Definition W : nat := 4505%N.
  Lemma W_gt0 : (0 < W)%N. Proof. done. Qed.
  Lemma W_le_d : (W <= d)%N. Proof. done. Qed.
  Lemma W2_lt_d : ((2 * W).-1 <= d)%N. Proof. done. Qed.
  Lemma d_le_W2 : (d <= 2 * W)%N. Proof. done. Qed.
  Lemma W_lt_n : (W < n)%N. Proof. done. Qed.

  Definition nblocks : nat := 13%N.
  Lemma nblocks_bound : (n < nblocks * W)%N. Proof. done. Qed.

  Definition npoints : nat := 25%N.
  Lemma npoints_gt0 : (0 < npoints)%N. Proof. done. Qed.
  Lemma npoints_le_card : (npoints <= (2 ^ d))%N.
  Proof.
    have H1 : (25 <= 2 ^ 5)%N by [].
    have H2 : (2 ^ 5 <= 2 ^ 9009)%N.
    { rewrite leq_exp2l //. }
    exact: (leq_trans H1 H2).
  Qed.
  Lemma nblocks2_le_npoints : ((2 * nblocks).-1 <= npoints)%N. Proof. done. Qed.
End HQCTiny5Params.