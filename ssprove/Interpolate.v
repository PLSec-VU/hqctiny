(******************************************************************************)
(*  Polynomial Split / Combine over Binary Extension Fields                   *)
(*                                                                            *)
(*  Given K = F2[X]/(gen) of degree d and a window size W,                    *)
(*  split packs W consecutive coefficients of a polynomial over F2            *)
(*  into a single K element; combine reconstructs the polynomial.             *)
(*                                                                            *)
(*  Proven: combine (split p nblocks) = p when size p ≤ nblocks * W.          *)
(******************************************************************************)

Set Warnings "-notation-overridden,-ambiguous-paths".
From mathcomp Require Import all_ssreflect all_algebra.
From mathcomp Require Import poly polydiv qpoly.
From mathcomp Require Import field.qfpoly.
Set Warnings "notation-overridden,ambiguous-paths".
Unset SsrOldRewriteGoalsOrder.
Open Scope ring_scope.
Import GRing.Theory.

From Stdlib Require Import Utf8.
From Stdlib Require Import Program.Equality.
From HB Require Import structures.

Module Type PointFieldParams.
  Parameter d   : nat.
  Parameter gen : {poly 'F_2}.
  Parameter gen_monic       : gen \is monic.
  Parameter size_gen        : size gen = d.+1.
  Parameter gen_irreducible : irreducible_poly gen.
End PointFieldParams.

Module PointFieldHelpers.
  Lemma prime2 : prime 2.
  Proof. apply/primeP; split; first done. move=> d0 Hd0. case: d0 Hd0 => [|[|[|d0]]] //=. Qed.
End PointFieldHelpers.

Module PointField (P : PointFieldParams).
  Import P.
  Definition gen_mi : monic_irreducible_poly gen := conj gen_irreducible gen_monic.
  Definition K := {poly %/ gen with gen_mi}.
  Definition a : K := 'qX.
  Lemma card_K : #|K| = (2 ^ d)%N.
  Proof. rewrite card_qfpoly (card_Fp PointFieldHelpers.prime2) P.size_gen. done. Qed.
End PointField.

Module Type SplitParams.
  Include PointFieldParams.
  Parameter W : nat.
  Parameter W_gt0 : (0 < W)%N.
  Parameter W_le_d : (W <= d)%N.
  Parameter W2_lt_d : ((2 * W).-1 <= d)%N.
End SplitParams.

Module SplitCombine (S : SplitParams).
  Include S.
  Module PF := PointField S. Import PF.
  Definition F2 := 'F_2.
  Local Notation polyF2 := {poly F2}.

  Definition split_block (p : polyF2) (k : nat) : K :=
    in_qpoly gen (take_poly W (drop_poly (k * W) p)).

  Fixpoint split_blocks (p : polyF2) (nblocks : nat) : list K :=
    match nblocks with
    | 0 => [::]
    | nb.+1 => split_blocks p nb ++ [:: split_block p nb]
    end.

  Lemma size_split_blocks p nblocks : size (split_blocks p nblocks) = nblocks.
  Proof. elim: nblocks => [|nb IH] //=. by rewrite size_cat IH /= addn1. Qed.

  Fixpoint combine_aux (blocks : list K) (pos : nat) : polyF2 :=
    match blocks with
    | [::] => 0
    | b :: bs => (b : polyF2) * 'X^(pos * W) + combine_aux bs pos.+1
    end.

  Opaque combine_aux.

  Definition combine (blocks : list K) : polyF2 := combine_aux blocks 0.

  Lemma combine_aux_cat blocks1 blocks2 pos :
    combine_aux (blocks1 ++ blocks2) pos =
    combine_aux blocks1 pos + combine_aux blocks2 (pos + size blocks1).
  Proof.
    Transparent combine_aux.
    elim: blocks1 pos => [|b bs IH] pos.
    - by rewrite /= addn0 add0r.
    - rewrite /=. rewrite IH. rewrite addSn addnS !addrA. done.
  Qed.

  Lemma combine_aux_add (A B : list K) pos :
    size A = size B ->
    combine_aux (map (fun '(a, b) => a + b) (zip A B)) pos =
    combine_aux A pos + combine_aux B pos.
  Proof.
    move=> Hsz.
    move: B pos Hsz.
    induction A as [|a tail].
    - intros B pos Hsz.
      destruct B as [|b bs]; simpl; try done.
      rewrite /combine_aux /= add0r. done.
    - intros B pos Hsz.
      destruct B as [|b bs]; simpl; try done.
      simpl in Hsz. injection Hsz as Hsz'.
      rewrite (IHtail bs (pos.+1) Hsz').
      rewrite mulrDl.
      set Tb := (b : polyF2) * 'X^(pos * W).
      set Ca := combine_aux tail pos.+1.
      rewrite -!addrA.
      congr (_ + _).
      rewrite addrA addrA (addrC Tb Ca).
      done.
  Qed.

  Lemma combine_add (A B : list K) :
    size A = size B ->
    combine (map (fun '(a, b) => a + b) (zip A B)) = combine A + combine B.
  Proof. exact: combine_aux_add. Qed.

  Lemma take_poly_take n m (p : polyF2) : (n <= m)%N -> take_poly n (take_poly m p) = take_poly n p.
  Proof.
    move=> Hnm. apply/polyP => i. rewrite !coef_take_poly. case: ifP => Hi.
    - have H_lt_m: (i < m)%N.
        rewrite leq_eqVlt in Hnm.
        case/orP: Hnm => [Heq | Hlt_nm].
        + move/eqP: Heq => Heq'. rewrite -Heq'. exact: Hi.
        + exact: (ltn_trans Hi Hlt_nm).
      by rewrite H_lt_m.
    - done.
  Qed.

  Lemma split_block_take k m (p : polyF2) :
    (k * W + W <= m)%N ->
    split_block p k = split_block (take_poly m p) k.
  Proof.
    move=> Hbound. rewrite /split_block.
    congr (in_qpoly gen _).
    apply/polyP => i.
    rewrite !coef_take_poly !coef_drop_poly.
    case: ifP => Hi.
    - rewrite coef_take_poly.
      have H_lt_m: (i + k * W < m)%N.
      { have Hlt: (i + k * W < k * W + W)%N by rewrite addnC ltn_add2l.
        rewrite leq_eqVlt in Hbound.
        case/orP: Hbound => [Heq | Hlt2].
        - by rewrite -(eqP Heq).
        - exact: (ltn_trans Hlt Hlt2). }
      by rewrite H_lt_m.
    - done.
  Qed.

  Lemma combine_split (p : polyF2) nblocks :
    (size p <= nblocks * W)%N ->
    combine (split_blocks p nblocks) = p.
  Proof.
    move=> Hsz.
    rewrite /combine.
    elim: nblocks p Hsz => [|nb IH] p Hsz.
    { rewrite mul0n in Hsz. move: Hsz; rewrite size_poly_leq0 => /eqP ->.
      by rewrite /split_blocks. }
    rewrite mulSn in Hsz.
    have Hsz_low : (size (take_poly (nb * W) p) <= nb * W)%N.
    { exact: size_take_poly. }
    have Hsz_hi : (size (drop_poly (nb * W) p) <= W)%N.
    { rewrite size_drop_poly leq_subLR.
      rewrite /= in Hsz.
      rewrite addnC.
      exact: Hsz. }
    rewrite /split_blocks /= -/split_blocks.
    rewrite combine_aux_cat size_split_blocks add0n.
    have -> : split_blocks p nb = split_blocks (take_poly (nb * W) p) nb.
    { clear IH Hsz Hsz_low Hsz_hi.
      move: p; elim: nb => [|k IHk] p //=.
      - rewrite IHk.
        have -> : split_blocks (take_poly (k * W) p) k = split_blocks (take_poly (k.+1 * W) p) k.
        { rewrite (IHk (take_poly (k.+1 * W) p)).
          rewrite take_poly_take.
          { clear IHk.
            case: k => [|k'].
            - exact: ltnW W_gt0.
            - by rewrite !mulSn /= leq_add2l addnC leq_addr. }
          done. }
        congr (_ ++ _).
        f_equal.
        apply: (split_block_take k (k.+1 * W) p).
        by rewrite mulSn addnC. }
    rewrite (IH (take_poly (nb * W) p) Hsz_low).
    rewrite /split_block /=.
    have sz_mk_gen : size (mk_monic gen) = d.+1.
    { rewrite /mk_monic size_gen gen_monic.
      have Hgt1 : (1 < d.+1)%N.
      { case: d W_gt0 W_le_d => [|[|d']] //=.
        move=> _ Hle. move: (leq_ltn_trans Hle W_gt0). by rewrite ltnn. }
      by rewrite Hgt1 /= size_gen. }
    have Hz := in_qpoly_small (R:=F2) (h:=gen)
      (p:=take_poly W (drop_poly (nb * W) p)).
    have Hz_cond : (size (take_poly W (drop_poly (nb * W) p)) < size (mk_monic gen))%N.
    { apply: (leq_ltn_trans (size_take_poly W _)).
      rewrite sz_mk_gen.
      apply: leq_ltn_trans W_le_d (ltnSn d). }
    rewrite -[Pdiv.CommonRing.rmodp _ _]/((in_qpoly gen
      (take_poly W (drop_poly (nb * W) p))) : polyF2).
    rewrite (Hz Hz_cond).
    rewrite (@take_poly_id F2 W (drop_poly (nb * W) p) Hsz_hi).
    rewrite addr0.
    apply: poly_take_drop.
  Qed.

  Definition split_poly (p : polyF2) (nblocks : nat) : {poly K} :=
    \poly_(k < nblocks) (split_block p k).

  Lemma size_split_poly p nblocks : (size (split_poly p nblocks) <= nblocks)%N.
  Proof. exact: size_poly. Qed.

  Lemma coef_split_poly p nblocks k :
    (split_poly p nblocks)`_k = if (k < nblocks)%N then split_block p k else 0.
  Proof. by rewrite coef_poly. Qed.

  Lemma split_block_add (p q : polyF2) k :
    split_block (p + q) k = split_block p k + split_block q k.
  Proof.
    rewrite /split_block drop_polyD take_polyD in_qpolyD.
    done.
  Qed.

  Lemma split_blocks_add (p q : polyF2) nblocks :
    split_blocks (p + q) nblocks =
    map (fun '(a, b) => a + b) (zip (split_blocks p nblocks) (split_blocks q nblocks)).
  Proof.
    elim: nblocks => [|nb IH].
    - done.
    - rewrite /split_blocks /= -/split_blocks.
      rewrite IH split_block_add.
      rewrite (@zip_cat K K (split_blocks p nb) [:: split_block p nb]
                                (split_blocks q nb) [:: split_block q nb]).
      { rewrite !size_split_blocks. done. }
      by rewrite map_cat.
  Qed.

  Lemma split_poly_add (p q : polyF2) nblocks :
    split_poly (p + q) nblocks = split_poly p nblocks + split_poly q nblocks.
  Proof.
    rewrite /split_poly.
    apply/polyP => k.
    rewrite coefD !coef_poly.
    case: ifP => Hk.
    - by rewrite split_block_add.
    - by rewrite add0r.
  Qed.

  Lemma coefp_ge_size (p : {poly K}) i : (size p <= i)%N -> p`_i = 0.
  Proof. by move=> H; rewrite nth_default. Qed.

  Definition coef_list (q : {poly K}) (n : nat) : list K :=
    [seq q`_i | i <- iota 0 n].

  Lemma size_coef_list q n : size (coef_list q n) = n.
  Proof. by rewrite /coef_list size_map size_iota. Qed.

  Lemma coef_list_add_aux (f g : nat -> K) n m :
    map (fun '(a, b) => a + b) (zip [seq f i | i <- iota m n] [seq g i | i <- iota m n]) =
    [seq f i + g i | i <- iota m n].
  Proof.
    elim: n m f g => [|n IH] m f g //=.
    rewrite /iota /= IH.
    congr (_ :: _).
  Qed.

  Lemma coef_list_add q r n :
    map (fun '(a, b) => a + b) (zip (coef_list q n) (coef_list r n)) =
    coef_list (q + r) n.
  Proof.
    rewrite /coef_list.
    rewrite coef_list_add_aux.
    apply: eq_map => i.
    by rewrite coefD.
  Qed.

  Lemma combine_aux_coef_list_pad (q : {poly K}) n pos :
    (size q <= n)%N ->
    combine_aux (coef_list q n) pos = combine_aux (coef_list q (size q)) pos.
  Proof.
    rewrite /coef_list => Hsz.
    elim: n Hsz => [|n IH] Hsz.
    - have /size_poly_leq0P Hq0 := Hsz. subst q.
      rewrite size_poly0 /combine_aux /=. done.
    - move: Hsz. rewrite leq_eqVlt => /orP.
      case=> [/eqP -> //|Hlt].
      rewrite ltnS in Hlt.
      replace (n.+1) with (n + 1)%N.
      + rewrite iotaD add0n map_cat combine_aux_cat.
        rewrite size_map size_iota /=.
        rewrite IH //.
        have -> : (q`_n : polyF2) * 'X^((pos + n) * W) + 0 = 0.
        { have H0 : q`_n = 0. apply: coefp_ge_size. exact: Hlt.
          by rewrite H0 mul0r addr0. }
        by rewrite addr0.
      + by rewrite addn1.
  Qed.

  Definition combine_poly (q : {poly K}) : polyF2 :=
    combine (coef_list q (size q)).

  Lemma combine_poly_add (q r : {poly K}) :
    combine_poly (q + r) = combine_poly q + combine_poly r.
  Proof.
    rewrite /combine_poly /combine.
    pose n := maxn (size q) (size r).
    have Hqn : (size q <= n)%N by rewrite /n leq_maxl.
    have Hrn : (size r <= n)%N by rewrite /n leq_maxr.
    have Hqrn : leq (size (q + r)) n.
    { have /leq_trans := size_polyD q r.
      apply.
      by rewrite /n geq_max Hqn Hrn. }
    rewrite -(combine_aux_coef_list_pad q n 0 Hqn).
    rewrite -(combine_aux_coef_list_pad r n 0 Hrn).
    rewrite -(combine_aux_coef_list_pad (q + r) n 0 Hqrn).
    rewrite -coef_list_add.
    apply: combine_aux_add.
    by rewrite !size_coef_list.
  Qed.

  Lemma map_iota_snoc (f : nat -> K) m n :
    [seq f i | i <- iota m n] ++ [:: f (m + n)] =
    f m :: [seq f i | i <- iota m.+1 n].
  Proof.
    elim: n m f => [|n IH] m f //=.
    - by rewrite [m+0]addn0.
    - rewrite /iota /=.
      congr (f m :: _).
      have Hadd : m + n.+1 = m.+1 + n.
        by change (addn m n.+1 = addn m.+1 n); rewrite addnS -addSn.
      rewrite Hadd -(IH m.+1 f).
      done.
  Qed.

  Lemma split_blocksE p nblocks :
    split_blocks p nblocks = [seq split_block p i | i <- iota 0 nblocks].
  Proof.
    elim: nblocks => [|nb IH] //=.
    rewrite IH map_iota_snoc. done.
  Qed.

  Lemma coef_list_split_poly p nblocks :
    coef_list (split_poly p nblocks) nblocks = split_blocks p nblocks.
  Proof.
    rewrite /coef_list split_blocksE.
    apply/eq_in_map => i.
    rewrite mem_iota => /andP[_ Hi].
    by rewrite coef_split_poly Hi.
  Qed.

  Lemma combine_poly_split (p : polyF2) nblocks :
    (size p <= nblocks * W)%N ->
    combine_poly (split_poly p nblocks) = p.
  Proof.
    move=> Hsz.
    rewrite /combine_poly /combine.
    have Hsz_sp : (size (split_poly p nblocks) <= nblocks)%N.
    { exact: size_split_poly. }
    rewrite -(combine_aux_coef_list_pad (split_poly p nblocks) nblocks 0 Hsz_sp).
    rewrite coef_list_split_poly.
    apply: combine_split.
    exact: Hsz.
  Qed.

  Definition all_coeffs_small (q : {poly K}) : Prop :=
    forall k, (k < size q)%N -> leq (size (q`_k : polyF2)) W.

  Lemma all_coeffs_small_take_poly q :
    all_coeffs_small q ->
    forall k, (k < size q)%N -> take_poly W (q`_k : polyF2) = (q`_k : polyF2).
  Proof.
    move=> Hacs k Hk.
    apply: take_poly_id.
    apply: Hacs.
    exact: Hk.
  Qed.

  Transparent combine_aux.

  Lemma combine_aux_shift blocks pos d :
    combine_aux blocks (pos + d) = combine_aux blocks pos * 'X^(d * W).
  Proof.
    elim: blocks pos => [|b bs IH] pos /=.
    - by rewrite mul0r.
    - rewrite -addSn IH.
      rewrite [X in 'X ^+ X]mulnDl exprD mulrA.
      by rewrite -mulrDl.
  Qed.

  Lemma combine_aux_coef_at (blocks : seq K) k idx :
    (idx < W)%N ->
    (forall i, (i < size blocks)%N -> (size ((nth 0%R blocks i) : polyF2) <= W)%N) ->
    (combine_aux blocks 0)`_(k * W + idx) =
    if (k < size blocks)%N then (nth 0%R blocks k : polyF2)`_idx else 0.
  Proof.
    move=> Hidx Hsmall.
    elim: blocks k idx Hidx Hsmall => [|b bs IH] k idx Hidx Hsmall /=.
    - by rewrite coef0.
    - case: k => [|k'].
      + rewrite mul0n add0n.
        rewrite coefD.
        rewrite expr0 mulr1.
        have -> : (combine_aux bs 1)`_idx = 0.
        { rewrite (combine_aux_shift bs 0 1).
          by rewrite coefMXn mul1n Hidx. }
        by rewrite addr0.
      + rewrite /=.
        rewrite coefD mul0n expr0 mulr1.
        have Hb_small : (size (b : polyF2) <= W)%N.
        { apply: (Hsmall 0%N). by rewrite /=. }
        have Hnot_lt : (k'.+1 * W + idx < W)%N = false.
        { have Hle : (W <= k'.+1 * W + idx)%N.
          { apply: leq_trans (leq_addr _ _).
            rewrite -{1}(mul1n W) leq_mul2r.
            by apply/orP; right. }
          by rewrite ltnNge Hle. }
        have Hsz_idx : (size (b : polyF2) <= k'.+1 * W + idx)%N.
        { have Hmid : (W <= k'.+1 * W)%N.
            by apply: leq_pmull W k'.+1 (ltn0Sn _).
          exact: leq_trans Hb_small (leq_trans Hmid (leq_addr _ _)). }
        rewrite [b`__]nth_default ?Hsz_idx // add0r.
        rewrite (combine_aux_shift bs 0 1) coefMXn.
        case: ifP => Hcase.
        * exfalso.
          move: Hnot_lt.
          by rewrite mul1n in Hcase; rewrite Hcase.
        * rewrite mul1n mulSn -addnA addKn.
          apply: IH => //.
          move=> i Hi.
          apply: (Hsmall (i.+1)).
          by rewrite /= ltnS Hi.
  Qed.

  Opaque combine_aux.

  Lemma coef_list_nth q n k :
    (k < n)%N -> nth 0 (coef_list q n) k = q`_k.
  Proof.
    rewrite /coef_list => Hk.
    by rewrite (nth_map 0) ?nth_iota // size_iota.
  Qed.

  (** Extended coefficient lemma for blocks up to size 2W *)
  Lemma combine_aux_coef_at_2W (blocks : seq K) k r :
    (r < W)%N ->
    (forall i, (i < size blocks)%N -> (size ((nth 0%R blocks i) : polyF2) < 2 * W)%N) ->
    (combine_aux blocks 0)`_(k * W + r) =
    ((if (k < size blocks)%N then ((nth 0%R blocks k) : polyF2)`_r else 0) +
     (if (0 < k)%N && (k.-1 < size blocks)%N
      then ((nth 0%R blocks (k.-1)) : polyF2)`_(r + W)
      else 0)).
  Proof.
    Transparent combine_aux.
    move: blocks k r; elim=> [|b bs IH] k r Hr_lt Hsz.
    - by rewrite /= coef0; case: k => [|k'] /=; rewrite ?addr0.
    - rewrite /= coefD expr0 mulr1.
      rewrite (combine_aux_shift bs 0 1) coefMXn.
      case: k => [|k'].
      + rewrite (mul0n W) !add0n /=.
        case: ifP => [Hge|Hnot].
        * done.
        * rewrite (mul1n W) ltnNge in Hnot.
          rewrite ltnNge in Hr_lt.
          rewrite Hr_lt in Hnot.
          done.
      + rewrite (mul1n W).
        case: ifP => [Hlt|Hge].
        * exfalso.
          have: (W <= k'.+1 * W + r)%N.
          { apply: (@leq_trans (k'.+1 * W)).
            - by rewrite -{1}(mul1n W) leq_pmul2r ?W_gt0.
            - exact: leq_addr. }
          move: Hlt; rewrite ltnNge => /negP Hlt.
          exact: Hlt.
        * have sub_eq : (k'.+1 * W + r - W = k' * W + r)%N.
          { by rewrite mulSn -addnA addKn. }
          rewrite [X in (combine_aux _ _)`_X]sub_eq.
          case: (posnP k') => [Hk0 | Hkpos].
          - subst k'; rewrite /= add0n.
            have IH0 := IH 0 r Hr_lt.
            have IH0_sz : forall i, (i < size bs)%N -> (size ((nth 0%R bs i) : polyF2) < 2 * W)%N.
            { move=> i Hi; apply: (Hsz i.+1); by rewrite /= ltnS Hi. }
            have Hbs0 := IH0 IH0_sz.
            rewrite /= in Hbs0.
            rewrite Hbs0 addr0.
            rewrite (mul1n W) ltnS addnC addrC //.
          - have Hb_sz : (size (b : polyF2) < 2 * W)%N.
            by apply: (Hsz 0%N); rewrite /=.
            have Hb_coef0 : b`_(k'.+1 * W + r) = 0.
            apply: nth_default.
            apply: (leq_trans (m := size b) (n := 2 * W) (p := k'.+1 * W + r)).
            { exact: ltnW Hb_sz. }
            apply: (leq_trans (m := 2 * W) (n := k'.+1 * W) (p := k'.+1 * W + r)).
            { rewrite (leq_mul2r W 2 k'.+1). apply/orP; right. rewrite ltnS. exact: Hkpos. }
            exact: leq_addr.
            rewrite Hb_coef0 add0r /= !ltnS.
            rewrite -[X in (b :: bs)`_X](prednK Hkpos) /=.
            have Hk'le : (k' <= size bs)%N = (k'.-1 < size bs)%N.
            by rewrite -ltnS prednK.
            rewrite Hk'le.
            have HIH := IH k' r Hr_lt.
            have HIH_sz : forall i, (i < size bs)%N -> (size ((nth 0%R bs i) : polyF2) < 2 * W)%N.
            by move=> i Hi; apply: (Hsz i.+1); rewrite /= ltnS Hi.
            move: (HIH HIH_sz).
            rewrite Hkpos /= => ->.
            done.
  Qed.
  Opaque combine_aux.

  (** ------------------------------------------------------------------ *)
  (**  Local ring isomorphism  F₂[x]<_{nblocks·W}  ≅  K[z]<_{nblocks}^{(W)}  *)
  (** ------------------------------------------------------------------ *)

  Lemma size_mk_monic_gen : size (mk_monic gen) = d.+1.
  Proof.
    rewrite /mk_monic size_gen gen_monic.
    have Hgt1 : (1 < d.+1)%N.
    { case: d W_gt0 W_le_d => [|[|d']] //=.
      move=> _ Hle. move: (leq_ltn_trans Hle W_gt0). by rewrite ltnn. }
    by rewrite Hgt1 /= size_gen.
  Qed.

  Lemma split_poly_combine_poly (q : {poly K}) nblocks :
    (size q <= nblocks)%N -> all_coeffs_small q ->
    split_poly (combine_poly q) nblocks = q.
  Proof.
    move=> Hsz Hacs.
    apply/polyP => k.
    rewrite coef_split_poly.
    case: ifP => Hk; last first.
    { apply/esym/coefp_ge_size.
      have Hnk : (nblocks <= k)%N.
        by rewrite leqNgt Hk.
      exact: leq_trans Hsz Hnk. }
    rewrite /split_block /combine_poly /combine.
    have Hcoef_small : forall i, (i < size (coef_list q (size q)))%N ->
      (size ((nth 0%R (coef_list q (size q)) i) : polyF2) <= W)%N.
    { rewrite size_coef_list => i Hi.
      rewrite coef_list_nth //.
      exact: Hacs _ Hi. }
    case: (ltnP k (size q)) => Hk_sz.
    - move: (Hacs k Hk_sz) => Hsz_qk.
      set X := take_poly W (drop_poly (k * W)
        (combine_aux (coef_list q (size q)) 0)).
      have HX : X = (q`_k : polyF2).
      { apply/polyP => j.
        rewrite /X coef_take_poly.
        case: ifP => Hj.
        - rewrite coef_drop_poly addnC.
          rewrite (combine_aux_coef_at _ _ _ Hj Hcoef_small).
          rewrite size_coef_list Hk_sz.
          by rewrite coef_list_nth.
        - symmetry; apply: nth_default.
          apply: leq_trans Hsz_qk _.
          by rewrite leqNgt Hj. }
      rewrite HX.
      apply/val_inj; apply: in_qpoly_small.
      apply: leq_ltn_trans Hsz_qk _.
      rewrite size_mk_monic_gen.
      exact: leq_ltn_trans W_le_d (ltnSn d).
    - have Hk_ge : (size q <= k)%N := Hk_sz.
      have -> : q`_k = 0.
      { apply: nth_default.
        exact: Hk_ge. }
      have -> : take_poly W (drop_poly (k * W)
        (combine_aux (coef_list q (size q)) 0)) = 0.
      { apply/polyP => j.
        rewrite coef_take_poly coef0.
        case: ifP => // Hj.
        rewrite coef_drop_poly addnC.
        rewrite (combine_aux_coef_at _ _ _ Hj Hcoef_small).
        rewrite size_coef_list.
        case: ifP => [Hlt | //].
        move: (leq_ltn_trans Hk_ge Hlt).
        by rewrite ltnn. }
      by rewrite in_qpoly0.
  Qed.

  Lemma combine_poly_split_combine (q : {poly K}) nblocks :
    (size q <= nblocks)%N -> all_coeffs_small q ->
    combine_poly (split_poly (combine_poly q) nblocks) = combine_poly q.
  Proof.
    move=> Hsz Hacs.
    by rewrite (split_poly_combine_poly q nblocks Hsz Hacs).
  Qed.

  Lemma combine_poly_mul_split_poly (p q : polyF2) nblocks :
    (size p <= nblocks * W)%N -> (size q <= nblocks * W)%N ->
    combine_poly (split_poly p nblocks * split_poly q nblocks) = p * q.
  Proof.
    move=> Hp Hq.
    pose block (a : polyF2) (i : nat) := take_poly W (drop_poly (i * W) a).
    have block_mulE : forall a b i j,
      ((split_block a i) * (split_block b j) : polyF2) = block a i * block b j.
    { move=> a b i j.
      rewrite /split_block /block.
      rewrite -in_qpolyM.
      apply: in_qpoly_small.
      apply: leq_ltn_trans (size_polyMleq _ _) _.
      have Hsz_ab : (size (take_poly W (drop_poly (i * W) a)) +
                     size (take_poly W (drop_poly (j * W) b)) <= 2 * W)%N.
      { apply: leq_trans (leq_add (size_take_poly _ _) (size_take_poly _ _)) _.
        by rewrite mul2n -addnn. }
      apply: (leq_ltn_trans (n := (2 * W).-1)).
      - rewrite -!subn1; apply: leq_sub2r; exact: Hsz_ab.
      - rewrite size_mk_monic_gen.
        apply: leq_trans W2_lt_d _.
        by rewrite leqnn. }
    set sp := split_poly p nblocks.
    set sq := split_poly q nblocks.
    pose P_p : {poly {poly F2}} := \poly_(j < nblocks) block p j.
    pose P_q : {poly {poly F2}} := \poly_(j < nblocks) block q j.

    Transparent combine_aux.
    have combine_aux_sum : forall (blocks : seq K) k,
      combine_aux blocks k = \sum_(i < size blocks) (nth 0%R blocks i : polyF2) * 'X^((i + k) * W).
    { move=> bl. elim: bl => [|b bl IH] k.
      - by rewrite big_ord0.
      - rewrite /= (IH k.+1) big_ord_recl /=.
        rewrite add0n. congr (_ + _).
        apply: eq_bigr => i _.
        by rewrite add0n /= addSn -addnS. }
    Opaque combine_aux.

    have combine_poly_sum : forall (P : {poly K}),
      combine_poly P = \sum_(i < size P) (P`_i : polyF2) * 'X^(i * W).
    { move=> P. rewrite /combine_poly /combine.
      rewrite combine_aux_sum.
      have -> : \sum_(i < size (coef_list P (size P))) (nth 0%R (coef_list P (size P)) i : polyF2) * 'X^((i + 0) * W) =
                \sum_(i < size P) (P`_i : polyF2) * 'X^(i * W).
      { rewrite size_coef_list. apply: eq_bigr => i _.
        rewrite addn0.
        by rewrite coef_list_nth // size_coef_list. }
      done. }

    have Hp_sum : P_p.['X^W] = p.
    { have Hp_eq : p = combine_poly sp by symmetry; exact: (combine_poly_split p nblocks Hp).
      rewrite {1}Hp_eq combine_poly_sum.
      have -> : \sum_(i < size sp) (sp`_i : polyF2) * 'X^(i * W) =
                \sum_(i < nblocks) (sp`_i : polyF2) * 'X^(i * W).
      { rewrite (big_ord_widen nblocks (fun i => (sp`_i : polyF2) * 'X^(i * W))).
        - exact: size_split_poly.
        - rewrite [LHS](big_mkcond _) [RHS](big_mkcond _).
          apply: eq_bigr => i _. case: (ltnP i (size sp)) => // Hge.
          have -> : sp`_i = 0 by apply: nth_default.
          by rewrite /= mul0r. }
      rewrite /P_p horner_poly. apply: eq_bigr => i _.
      congr (_ * _).
      - have Hlt : (i < nblocks)%N by exact: ltn_ord.
        rewrite coef_split_poly Hlt /split_block in_qpoly_small //.
        apply: (leq_ltn_trans (size_take_poly _ _)). rewrite size_mk_monic_gen.
        apply: (leq_trans _ W2_lt_d). move: W_gt0. case: W => // w _.
        by rewrite mul2n -addnn /= leq_addl.
      - move: (val i) => j. elim: j => [| j IHj].
        + by rewrite mul0n !expr0.
        + by rewrite exprS IHj -exprD mulSn. }

    have Hq_sum : P_q.['X^W] = q.
    { have Hq_eq : q = combine_poly sq by symmetry; exact: (combine_poly_split q nblocks Hq).
      rewrite {1}Hq_eq combine_poly_sum.
      have -> : \sum_(i < size sq) (sq`_i : polyF2) * 'X^(i * W) =
                \sum_(i < nblocks) (sq`_i : polyF2) * 'X^(i * W).
      { rewrite (big_ord_widen nblocks (fun i => (sq`_i : polyF2) * 'X^(i * W))).
        - exact: size_split_poly.
        - rewrite [LHS](big_mkcond _) [RHS](big_mkcond _).
          apply: eq_bigr => i _. case: (ltnP i (size sq)) => // Hge.
          have -> : sq`_i = 0 by apply: nth_default.
          by rewrite /= mul0r. }
      rewrite /P_q horner_poly. apply: eq_bigr => i _.
      congr (_ * _).
      - have Hlt : (i < nblocks)%N by exact: ltn_ord.
        rewrite coef_split_poly Hlt /split_block in_qpoly_small //.
        apply: (leq_ltn_trans (size_take_poly _ _)). rewrite size_mk_monic_gen.
        apply: (leq_trans _ W2_lt_d). move: W_gt0. case: W => // w _.
        by rewrite mul2n -addnn /= leq_addl.
      - move: (val i) => j. elim: j => [| j IHj].
        + by rewrite mul0n !expr0.
        + by rewrite exprS IHj -exprD mulSn. }

    have H_sum : forall m, ((sp * sq)`_m : polyF2) = \sum_(j < m.+1) block p j * block q (m - j)%N.
    { move=> m. rewrite coefM.
      elim/big_rec2: _ => [|i y1 y2 _ Hrec].
      - by [].
      - rewrite poly_of_qpolyD Hrec. congr (_ + _).
        rewrite /sp /sq !coef_split_poly.
        case: ifP => [Hj | Hj]; case: ifP => [Hmj | Hmj].
        + by rewrite block_mulE.
        + have Hq_ge : (nblocks * W <= (m - i)%N * W)%N.
          { rewrite leq_mul2r. apply/orP; right. by rewrite leqNgt Hmj. }
          have -> : block q (m - i)%N = 0.
          { rewrite /block.
            have -> : drop_poly ((m - i)%N * W) q = 0.
            { apply/polyP => c. rewrite coef_drop_poly coef0.
              apply: nth_default. apply: (leq_trans Hq).
              by apply: (leq_trans Hq_ge (leq_addl c _)). }
            apply/polyP => c. by rewrite coef_take_poly !coef0; case: ifP. }
          by rewrite ?mul0r ?mulr0.
        + have Hp_ge : (nblocks * W <= i * W)%N.
          { rewrite leq_mul2r. apply/orP; right. by rewrite leqNgt Hj. }
          have -> : block p i = 0.
          { rewrite /block.
            have -> : drop_poly (i * W) p = 0.
            { apply/polyP => c. rewrite coef_drop_poly coef0.
              apply: nth_default. apply: (leq_trans Hp).
              by apply: (leq_trans Hp_ge (leq_addl c _)). }
            apply/polyP => c. by rewrite coef_take_poly !coef0; case: ifP. }
          by rewrite ?mul0r ?mulr0.
        + have Hp_ge : (nblocks * W <= i * W)%N.
          { rewrite leq_mul2r. apply/orP; right. by rewrite leqNgt Hj. }
          have -> : block p i = 0.
          { rewrite /block.
            have -> : drop_poly (i * W) p = 0.
            { apply/polyP => c. rewrite coef_drop_poly coef0.
              apply: nth_default. apply: (leq_trans Hp).
              by apply: (leq_trans Hp_ge (leq_addl c _)). }
            apply/polyP => c. by rewrite coef_take_poly !coef0; case: ifP. }
          by rewrite ?mul0r ?mulr0. }

    have H_coef : forall m, ((sp * sq)`_m : polyF2) = (P_p * P_q)`_m.
    { move=> m. rewrite H_sum coefM.
      apply: eq_bigr => j _. rewrite !coef_poly.
      case: (ltnP j nblocks) => [Hj | Hj].
      - case: (ltnP (m - j)%N nblocks) => [Hmj | Hmj].
        + by [].
        + have Hq_ge : (nblocks * W <= (m - j)%N * W)%N.
          { rewrite leq_mul2r. apply/orP; right. by apply: Hmj. }
          have -> : block q (m - j)%N = 0.
          { rewrite /block.
            have -> : drop_poly ((m - j)%N * W) q = 0.
            { apply/polyP => c. rewrite coef_drop_poly coef0.
              apply: nth_default. apply: (leq_trans Hq).
              by apply: (leq_trans Hq_ge (leq_addl c _)). }
            apply/polyP => c. by rewrite coef_take_poly !coef0; case: ifP. }
          by rewrite ?mul0r ?mulr0.
      - have Hp_ge : (nblocks * W <= j * W)%N.
        { rewrite leq_mul2r. apply/orP; right. by apply: Hj. }
        have -> : block p j = 0.
        { rewrite /block.
          have -> : drop_poly (j * W) p = 0.
          { apply/polyP => c. rewrite coef_drop_poly coef0.
            apply: nth_default. apply: (leq_trans Hp).
            by apply: (leq_trans Hp_ge (leq_addl c _)). }
          apply/polyP => c. by rewrite coef_take_poly !coef0; case: ifP. }
        by rewrite ?mul0r ?mulr0. }

    have -> : p * q = (P_p * P_q).['X^W] by rewrite hornerM Hp_sum Hq_sum.
    rewrite combine_poly_sum.
    have Hsz_bound : (size (sp * sq)%R <= nblocks + nblocks)%N.
    { apply: (leq_trans (size_polyMleq sp sq)).
      apply: (leq_trans (leq_pred _)).
      by apply: leq_add; exact: size_split_poly. }
    have Hsz_P_bound : (size (P_p * P_q)%R <= nblocks + nblocks)%N.
    { apply: (leq_trans (size_polyMleq P_p P_q)).
      apply: (leq_trans (leq_pred _)).
      apply: leq_add.
      - exact: size_poly.
      - exact: size_poly. }
    have -> : \sum_(i < size (sp * sq)) ((sp * sq)`_i : polyF2) * 'X^(i * W) =
              \sum_(i < nblocks + nblocks) ((sp * sq)`_i : polyF2) * 'X^(i * W).
    { rewrite (big_ord_widen (nblocks + nblocks) (fun i => ((sp * sq)`_i : polyF2) * 'X^(i * W))) //.
      rewrite [LHS](big_mkcond _) [RHS](big_mkcond _).
      apply: eq_bigr => i _. case: (ltnP i (size (sp * sq))) => // Hge.
      have -> : (sp * sq)`_i = 0 by apply: nth_default.
      by rewrite /= mul0r. }
    have -> : (P_p * P_q) = \poly_(i < nblocks + nblocks) (P_p * P_q)`_i.
    { apply/polyP => m. rewrite coef_poly.
      case: (ltnP m (nblocks + nblocks)) => // Hge.
      by apply: nth_default; apply: (leq_trans Hsz_P_bound). }
    rewrite horner_poly.
    apply: eq_bigr => m _.
    rewrite H_coef.
    congr (_ * _).
    move: (val m) => j. elim: j => [| j IHj].
    - by rewrite mul0n !expr0.
    - by rewrite exprS -IHj -exprD mulSn.
  Qed.

  Section Homomrphism.
    Variable (nblocks : nat).

    Theorem split_combine_ring_iso :
      (forall (p : polyF2), (size p <= nblocks * W)%N ->
         combine_poly (split_poly p nblocks) = p)
      /\
      (forall (q : {poly K}), (size q <= nblocks)%N -> all_coeffs_small q ->
         split_poly (combine_poly q) nblocks = q)
      /\
      (forall (p q : polyF2) (n : nat),
         split_poly (p + q) n = split_poly p n + split_poly q n)
      /\
      (forall (p q : {poly K}),
         combine_poly (p + q) = combine_poly p + combine_poly q)
      /\
      (forall (q : {poly K}), (size q <= nblocks)%N -> all_coeffs_small q ->
         combine_poly (split_poly (combine_poly q) nblocks) = combine_poly q)
      /\
      (forall (p q : polyF2),
         (size p <= nblocks * W)%N -> (size q <= nblocks * W)%N ->
         combine_poly (split_poly p nblocks * split_poly q nblocks) = p * q).
    Proof.
      split.
      - move=> p H. exact: combine_poly_split.
      split.
      - move=> q Hsz Hacs. exact: split_poly_combine_poly.
      split.
      - exact: split_poly_add.
      split.
      - exact: combine_poly_add.
      split.
      - move=> q Hsz Hacs. exact: combine_poly_split_combine.
      - move=> p q Hp Hq. exact: combine_poly_mul_split_poly.
    Qed.

    Inductive local_ring_expr : bool -> Type :=
      | valF2 : forall (p : polyF2), (size p <= nblocks * W)%N -> local_ring_expr false
      | multSplit : local_ring_expr false -> local_ring_expr false -> local_ring_expr true
      | addSplit : forall (l1 l2: bool), local_ring_expr l1 -> local_ring_expr l2 -> local_ring_expr (l1 || l2).

    Fixpoint evalF2x (b : bool) (e : local_ring_expr b) : polyF2 :=
      match e in local_ring_expr label return polyF2 with
      | valF2 p _ => 
          p
      | multSplit e1 e2 => 
          (evalF2x false e1) * (evalF2x false e2)
      | addSplit l1 l2 e1 e2 => 
          (evalF2x l1 e1) + (evalF2x l2 e2)
      end.

    Fixpoint evalKx (b : bool) (e : local_ring_expr b) : {poly K} :=
      match e in local_ring_expr label return {poly K} with
      | valF2 p _ => 
          split_poly p nblocks
      | multSplit e1 e2 => 
          (evalKx false e1) * (evalKx false e2)
      | addSplit l1 l2 e1 e2 => 
          (evalKx l1 e1) + (evalKx l2 e2)
      end.

    (** Homomorphism: evalKx factors through split_poly on false-indexed expressions *)
    Lemma evalKx_split_poly (e : local_ring_expr false) :
      evalKx false e = split_poly (evalF2x false e) nblocks.
    Proof.
      dependent induction e.
      - (* valF2 *) done.
      - (* addSplit *)
        destruct l1; destruct l2; simpl in x0; try discriminate x0.
        apply JMeq_eq in x.
        subst e0.
        simpl.
        specialize (IHe1 e1 (erefl false) (@JMeq_refl _ e1)).
        specialize (IHe2 e2 (erefl false) (@JMeq_refl _ e2)).
        rewrite IHe1 IHe2.
        rewrite split_poly_add.
        reflexivity.
    Qed.

    (** Size bound preserved by evalF2x on false-indexed expressions *)
    Lemma evalF2x_false_size (e : local_ring_expr false) :
      (size (evalF2x false e) <= nblocks * W)%N.
    Proof.
      dependent induction e.
      - (* valF2 *) done.
      - (* addSplit *)
        destruct l1; destruct l2; simpl in x0; try discriminate x0.
        apply JMeq_eq in x.
        subst e0.
        simpl.
        specialize (IHe1 e1 (erefl false) (@JMeq_refl _ e1)).
        specialize (IHe2 e2 (erefl false) (@JMeq_refl _ e2)).
        apply: leq_trans (size_polyD _ _) _.
        rewrite geq_max.
        apply/andP; split; assumption.
    Qed.

    (** combine_poly undoes evalKx: combine_poly (evalKx b e) = evalF2x b e *)
    Lemma eval_combine b (e : local_ring_expr b) :
      combine_poly (evalKx b e) = evalF2x b e.
    Proof.
      dependent induction e.
      - (* valF2 *) simpl. apply/combine_poly_split. exact: i.
      - (* multSplit *) simpl.
        rewrite (evalKx_split_poly e1) (evalKx_split_poly e2).
        apply: combine_poly_mul_split_poly.
        + exact: evalF2x_false_size.
        + exact: evalF2x_false_size.
      - (* addSplit *) simpl.
        rewrite combine_poly_add.
        by rewrite IHe1 IHe2.
    Qed.

    Theorem evalK_inj_evalF2 b (e e' : local_ring_expr b) :
      evalKx b e = evalKx b e' -> evalF2x b e = evalF2x b e'.
    Proof.
      move=> Heq.
      have Hleft := eval_combine b e.
      have Hright := eval_combine b e'.
      rewrite Heq in Hleft.
      rewrite -Hleft Hright //.
    Qed.

  End Homomrphism.

  (** ****************************************************************** *)
  (** Bridge: evaluate K[z] at distinct points and interpolate back     *)
  (**                                                                   *)
  (** K ≅ F_{2^d} is a finite field with 2^d elements. We pick the     *)
  (** first n field elements (via the canonical enumeration) as         *)
  (** evaluation points. A polynomial of degree < n over a field is     *)
  (** uniquely determined by its values at n distinct points.           *)
  (** ****************************************************************** *)

  Section EvalBridge.

  Variable n : nat.
  Hypothesis n_le_card : (n <= #|K|)%N.

  (* n distinct evaluation points from the field enumeration *)
  Definition eval_pts : seq K := take n (enum K).

  Lemma eval_pts_uniq : uniq eval_pts.
  Proof. by rewrite /eval_pts take_uniq ?enum_uniq. Qed.

  Lemma size_eval_pts : size eval_pts = n.
  Proof.
    rewrite /eval_pts size_take -cardT card_K.
    move: n_le_card.
    rewrite card_K => Hle.
    case: ifPn => [Hlt|Hnlt].
    - by [].
    - apply/eqP; rewrite eqn_leq Hle.
      move: Hnlt; rewrite -leqNgt => Hge.
      by rewrite Hge.
  Qed.

  (* Evaluate a K-polynomial at the n chosen points *)
  Definition eval_points (q : {poly K}) : seq K :=
    [seq q.[x] | x <- eval_pts].

  Lemma size_eval_points q : size (eval_points q) = n.
  Proof. by rewrite /eval_points size_map size_eval_pts. Qed.

  (** Point-value ring: componentwise operations via zip *)
  Definition point_seq_zero : seq K := nseq n 0.
  Definition point_seq_one  : seq K := nseq n 1.

  Definition point_seq_add (s t : seq K) : seq K :=
    map (fun '(a, b) => a + b) (zip s t).

  Definition point_seq_mul (s t : seq K) : seq K :=
    map (fun '(a, b) => a * b) (zip s t).

  (** The evaluation map is a ring homomorphism K[z] → K^n *)
  Lemma eval_points_zero : eval_points (0 : {poly K}) = point_seq_zero.
  Proof.
    rewrite /eval_points /point_seq_zero.
    apply: (@eq_from_nth _ 0); rewrite ?size_map ?size_eval_pts ?size_nseq //.
    move=> i Hi; rewrite nth_nseq Hi.
    by rewrite (nth_map 0) ?size_eval_pts // horner0.
  Qed.

  Lemma eval_points_one : eval_points (1 : {poly K}) = point_seq_one.
  Proof.
    rewrite /eval_points /point_seq_one.
    apply: (@eq_from_nth _ 0); rewrite ?size_map ?size_eval_pts ?size_nseq //.
    move=> i Hi; rewrite nth_nseq Hi.
    by rewrite (nth_map 0) ?size_eval_pts // hornerC.
  Qed.

  Lemma eval_points_add (p q : {poly K}) :
    eval_points (p + q) = point_seq_add (eval_points p) (eval_points q).
  Proof.
    rewrite /eval_points /point_seq_add.
    elim: eval_pts => [|x xs IHxs] /=; first done.
    rewrite IHxs.
    congr (_ :: _).
    by rewrite hornerD.
  Qed.

  Lemma eval_points_mul (p q : {poly K}) :
    eval_points (p * q) = point_seq_mul (eval_points p) (eval_points q).
  Proof.
    rewrite /eval_points /point_seq_mul.
    elim: eval_pts => [|x xs IHxs] /=; first done.
    rewrite IHxs.
    congr (_ :: _).
    by rewrite hornerM.
  Qed.

  (** Injectivity: a polynomial of degree < n is uniquely determined
      by its values at n distinct points (the interpolation theorem). *)
  Lemma eval_points_inj (p q : {poly K}) :
    (size p <= n)%N -> (size q <= n)%N ->
    eval_points p = eval_points q -> p = q.
  Proof.
    move=> Hsp Hsq Heq.
    have H_agree x : x \in eval_pts -> p.[x] = q.[x].
    { move: Heq.
      rewrite /eval_points.
      move: eval_pts.
      elim=> [|y ys IHys] //= Hx.
      move: Hx; rewrite in_cons.
      move=> Hcase.
      move=> Hmem.
      move: Hmem; case/orP => [/eqP ->|Hin].
      - move: Hcase; case=> <- _; done.
      - move: Hcase; case=> _ Heq_tail.
        apply: IHys => //. }
    have H_roots : all (root (p - q)) eval_pts.
    { apply/allP => x Hx; apply/rootP.
      by rewrite !hornerE H_agree // subrr. }
    have Hsz: (size (p - q)%R <= n)%N.
    { have Hmax := @size_polyD K p (- q).
      rewrite size_polyN in Hmax.
      apply: leq_trans Hmax _.
      by rewrite geq_max Hsp Hsq. }
    rewrite -[p](subrK q).
    have Heq0 : p - q = 0.
    { apply: (@roots_geq_poly_eq0 K (p - q) eval_pts H_roots
        eval_pts_uniq).
      by rewrite size_eval_pts Hsz. }
    by rewrite Heq0 add0r.
  Qed.

  (** **************************************************************** *)
  (** Interpolation: reconstruct K[z] from point values                *)
  (**                                                                 *)
  (** Lagrange interpolation: given values at n distinct points,       *)
  (** reconstruct the unique degree-<n polynomial.                     *)
  (** **************************************************************** *)

  (* The i-th evaluation point as an element of K *)
  Definition pt (i : 'I_n) : K := nth 0 eval_pts i.

  Lemma pt_inj : injective pt.
  Proof.
    move=> i j Heq.
    apply/val_inj.
    have Hi : (i < size eval_pts)%N by rewrite size_eval_pts; exact: ltn_ord.
    have Hj : (j < size eval_pts)%N by rewrite size_eval_pts; exact: ltn_ord.
    have Hnth := @nth_uniq K 0 eval_pts (val i) (val j) Hi Hj eval_pts_uniq.
    move/eqP: Heq; rewrite /pt => Heq_bool.
    rewrite Hnth in Heq_bool.
    move/eqP: Heq_bool => /val_inj.
    by move=> ->.
  Qed.

  (* Lagrange basis polynomial L_i(X) = Π_{j≠i} (X-x_j)/(x_i-x_j) *)
  Definition lagrange_basis (i : 'I_n) : {poly K} :=
    let p := \prod_(j < n | j != i) ('X - (pt j)%:P) in
    (p.[pt i]^-1)%:P * p.

  Lemma lagrange_basis_eval (i j : 'I_n) :
    (lagrange_basis i).[pt j] = (i == j)%:R.
  Proof.
    rewrite /lagrange_basis hornerM hornerC.
    set p := \prod_(k < n | k != i) ('X - (pt k)%:P).
    have [<-|neq_ij] := altP eqP.
    - rewrite mulVf // horner_prod.
      apply/prodf_neq0 => k /eqP neq_ki.
      rewrite hornerXsubC subr_eq0.
      apply/eqP => /pt_inj /eqP Heq.
      apply: neq_ki.
      by apply/eqP; rewrite eq_sym.
    - have -> : p.[pt j] = 0.
        rewrite /p horner_prod.
        apply/eqP.
        have Hmem : j \in [pred k | k != i].
          rewrite inE eq_sym; exact: neq_ij.
        rewrite (bigD1 j) //= hornerXsubC subrr mul0r.
        done.
      by rewrite mulr0.
  Qed.

  Lemma size_lagrange_basis i : (size (lagrange_basis i) <= n)%N.
  Proof.
    rewrite /lagrange_basis.
    set p := \prod_(k < n | k != i) ('X - (pt k)%:P).
    have Hp_pt_neq0 : p.[pt i] != 0.
      rewrite /p horner_prod.
      apply/prodf_neq0 => k /eqP neq_ki.
      rewrite hornerXsubC subr_eq0.
      apply/eqP => /pt_inj /eqP Heq.
      apply: neq_ki.
      by apply/eqP; rewrite eq_sym.
    have Hinv_neq0 : p.[pt i]^-1 != 0 := invr_neq0 Hp_pt_neq0.
    rewrite (size_Cmul _ Hinv_neq0).
    rewrite /p -big_enum size_prod_XsubC -cardE.
    have /proper_card Hlt : [pred k | k != i] \proper predT.
      apply/properP; split.
      - by apply/subsetP.
      - exists i; first by rewrite inE.
        by rewrite inE /= eqxx.
    rewrite /predT in Hlt.
    rewrite card_ord in Hlt.
    rewrite /=.
    exact: Hlt.
  Qed.

  (* Interpolate: reconstruct polynomial from n point values *)
  Definition interpolate (pts : seq K) : {poly K} :=
    \sum_(i < n) (nth 0 pts i)%:P * lagrange_basis i.

  Lemma size_interpolate pts : (size (interpolate pts) <= n)%N.
  Proof.
    rewrite /interpolate.
    elim/big_ind: _ => [|p q IHp IHq|i _].
    - by rewrite size_poly0.
    - apply: leq_trans (size_polyD p q) _.
      by rewrite geq_max IHp IHq.
    - case: (eqVneq pts`_i 0) => [-> | Hnz].
      + by rewrite mul0r size_poly0.
      + by rewrite size_Cmul // size_lagrange_basis.
  Qed.

  Lemma interpolate_eval (pts : seq K) (j : 'I_n) :
    (interpolate pts).[pt j] = nth 0 pts j.
  Proof.
    rewrite /interpolate.
    rewrite (bigD1 j) //=.
    rewrite hornerD hornerM hornerC lagrange_basis_eval eqxx mulr1.
    rewrite horner_sum.
    rewrite big1 ?addr0 // => i /negPf neq_ij.
    rewrite hornerM hornerC lagrange_basis_eval neq_ij mulr0.
    done.
  Qed.

  (** Cancellation lemmas *)

  (* interpolate then evaluate at points = identity *)
  Lemma eval_interpolate (pts : seq K) (j : 'I_n) :
    (eval_points (interpolate pts))`_j = nth 0 pts j.
  Proof.
    rewrite /eval_points.
    rewrite (nth_map 0 0) /=.
    - rewrite size_eval_pts.
      exact: ltn_ord.
    - rewrite /pt.
      exact: interpolate_eval.
  Qed.

  (* evaluate then interpolate = identity for small polynomials *)
  Lemma interpolate_eval_points (q : {poly K}) :
    (size q <= n)%N ->
    interpolate (eval_points q) = q.
  Proof.
    move=> Hsz_q.
    apply: eval_points_inj => //.
    - exact: size_interpolate.
    - apply: (@eq_from_nth _ 0).
      + by rewrite !size_eval_points.
      + move=> i Hi.
        rewrite size_eval_points in Hi.
        have Hi_ord : (i < n)%N by exact: Hi.
        have := eval_interpolate (eval_points q) (Ordinal Hi_ord).
        by move=> /= ->.
  Qed.

  End EvalBridge.

End SplitCombine.
